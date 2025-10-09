package com.uk.gov.connectors.homeoffice

import org.springframework.web.bind.annotation.*
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.beans.factory.annotation.Autowired
import reactor.core.publisher.Mono
import javax.validation.Valid
import javax.validation.constraints.NotBlank
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable

@RestController
@RequestMapping("/api/connectors/homeoffice")
class HomeOfficeConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(HomeOfficeConnector::class.java)

    @PostMapping("/right-to-work")
    @Cacheable("homeoffice-rtw")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun checkRightToWork(@Valid @RequestBody request: RightToWorkRequest): Mono<RightToWorkResponse> {
        logger.info("Checking right to work for: {}", request.shareCode)
        
        return webClient.post()
            .uri("https://api.gov.uk/home-office/right-to-work/v1/check")
            .header("Authorization", "Bearer \${HOME_OFFICE_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                RightToWorkResponse(
                    shareCode = request.shareCode,
                    hasRightToWork = response["hasRightToWork"] as? Boolean ?: false,
                    workRestrictions = response["workRestrictions"] as? String ?: "NONE",
                    visaType = response["visaType"] as? String ?: "NOT_APPLICABLE",
                    validUntil = response["validUntil"] as? String ?: "INDEFINITE",
                    employerChecksRequired = response["employerChecksRequired"] as? Boolean ?: false,
                    documentType = response["documentType"] as? String ?: "UNKNOWN",
                    nationality = response["nationality"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error checking right to work for {}", request.shareCode, e) }
            .onErrorReturn(RightToWorkResponse(
                shareCode = request.shareCode,
                hasRightToWork = false,
                workRestrictions = "ERROR",
                visaType = "ERROR",
                validUntil = "ERROR",
                employerChecksRequired = true,
                documentType = "ERROR",
                nationality = "ERROR"
            ))
    }

    @PostMapping("/right-to-rent")
    @Cacheable("homeoffice-rtr")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun checkRightToRent(@Valid @RequestBody request: RightToRentRequest): Mono<RightToRentResponse> {
        logger.info("Checking right to rent for: {}", request.shareCode)
        
        return webClient.post()
            .uri("https://api.gov.uk/home-office/right-to-rent/v1/check")
            .header("Authorization", "Bearer \${HOME_OFFICE_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                RightToRentResponse(
                    shareCode = request.shareCode,
                    hasRightToRent = response["hasRightToRent"] as? Boolean ?: false,
                    rentRestrictions = response["rentRestrictions"] as? String ?: "NONE",
                    validUntil = response["validUntil"] as? String ?: "INDEFINITE",
                    landlordChecksRequired = response["landlordChecksRequired"] as? Boolean ?: false,
                    documentType = response["documentType"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error checking right to rent for {}", request.shareCode, e) }
            .onErrorReturn(RightToRentResponse(
                shareCode = request.shareCode,
                hasRightToRent = false,
                rentRestrictions = "ERROR",
                validUntil = "ERROR",
                landlordChecksRequired = true,
                documentType = "ERROR"
            ))
    }

    @GetMapping("/settled-status/{applicationNumber}")
    @Cacheable("homeoffice-settled-status")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getSettledStatus(@PathVariable applicationNumber: String): Mono<SettledStatusResponse> {
        logger.info("Checking settled status for: {}", applicationNumber)
        
        return webClient.get()
            .uri("https://api.gov.uk/home-office/settled-status/v1/{applicationNumber}", applicationNumber)
            .header("Authorization", "Bearer \${HOME_OFFICE_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                SettledStatusResponse(
                    applicationNumber = applicationNumber,
                    status = response["status"] as? String ?: "UNKNOWN",
                    grantedDate = response["grantedDate"] as? String ?: "UNKNOWN",
                    validUntil = response["validUntil"] as? String ?: "INDEFINITE",
                    statusType = response["statusType"] as? String ?: "UNKNOWN", // SETTLED, PRE_SETTLED
                    eligibleForBenefits = response["eligibleForBenefits"] as? Boolean ?: false,
                    travelDocumentRequired = response["travelDocumentRequired"] as? Boolean ?: true
                )
            }
            .doOnError { e -> logger.error("Error checking settled status for {}", applicationNumber, e) }
            .onErrorReturn(SettledStatusResponse(
                applicationNumber = applicationNumber,
                status = "ERROR",
                grantedDate = "ERROR",
                validUntil = "ERROR",
                statusType = "ERROR",
                eligibleForBenefits = false,
                travelDocumentRequired = true
            ))
    }

    @PostMapping("/immigration-status")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getImmigrationStatus(@Valid @RequestBody request: ImmigrationStatusRequest): Mono<ImmigrationStatusResponse> {
        logger.info("Getting immigration status for: {}", request.documentNumber)
        
        return webClient.post()
            .uri("https://api.gov.uk/home-office/immigration-status/v1")
            .header("Authorization", "Bearer \${HOME_OFFICE_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                ImmigrationStatusResponse(
                    documentNumber = request.documentNumber,
                    immigrationStatus = response["immigrationStatus"] as? String ?: "UNKNOWN",
                    visaType = response["visaType"] as? String ?: "NONE",
                    entryDate = response["entryDate"] as? String ?: "UNKNOWN",
                    leaveToRemainUntil = response["leaveToRemainUntil"] as? String ?: "UNKNOWN",
                    conditions = (response["conditions"] as? List<String>) ?: emptyList(),
                    sponsorRequired = response["sponsorRequired"] as? Boolean ?: false,
                    biometricResidencePermit = response["biometricResidencePermit"] as? Boolean ?: false
                )
            }
            .doOnError { e -> logger.error("Error getting immigration status for {}", request.documentNumber, e) }
            .onErrorReturn(ImmigrationStatusResponse(
                documentNumber = request.documentNumber,
                immigrationStatus = "ERROR",
                visaType = "ERROR",
                entryDate = "ERROR",
                leaveToRemainUntil = "ERROR",
                conditions = emptyList(),
                sponsorRequired = false,
                biometricResidencePermit = false
            ))
    }
}

data class RightToWorkRequest(
    @field:NotBlank val shareCode: String,
    @field:NotBlank val dateOfBirth: String
)

data class RightToWorkResponse(
    val shareCode: String,
    val hasRightToWork: Boolean,
    val workRestrictions: String,
    val visaType: String,
    val validUntil: String,
    val employerChecksRequired: Boolean,
    val documentType: String,
    val nationality: String
)

data class RightToRentRequest(
    @field:NotBlank val shareCode: String,
    @field:NotBlank val dateOfBirth: String
)

data class RightToRentResponse(
    val shareCode: String,
    val hasRightToRent: Boolean,
    val rentRestrictions: String,
    val validUntil: String,
    val landlordChecksRequired: Boolean,
    val documentType: String
)

data class SettledStatusResponse(
    val applicationNumber: String,
    val status: String,
    val grantedDate: String,
    val validUntil: String,
    val statusType: String,
    val eligibleForBenefits: Boolean,
    val travelDocumentRequired: Boolean
)

data class ImmigrationStatusRequest(
    @field:NotBlank val documentNumber: String,
    @field:NotBlank val documentType: String,
    @field:NotBlank val nationality: String,
    @field:NotBlank val dateOfBirth: String
)

data class ImmigrationStatusResponse(
    val documentNumber: String,
    val immigrationStatus: String,
    val visaType: String,
    val entryDate: String,
    val leaveToRemainUntil: String,
    val conditions: List<String>,
    val sponsorRequired: Boolean,
    val biometricResidencePermit: Boolean
)