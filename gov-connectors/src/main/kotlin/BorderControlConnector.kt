package com.uk.gov.connectors.border

import org.springframework.web.bind.annotation.*
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.beans.factory.annotation.Autowired
import reactor.core.publisher.Mono
import javax.validation.Valid
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Pattern
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable

@RestController
@RequestMapping("/api/connectors/border-control")
class BorderControlConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(BorderControlConnector::class.java)

    @GetMapping("/passport-status/{passportNumber}")
    @Cacheable("passport-status")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPassportStatus(@PathVariable passportNumber: String): Mono<PassportStatusResponse> {
        logger.info("Getting passport status for: {}", passportNumber)
        
        return webClient.get()
            .uri("https://api.homeoffice.gov.uk/passports/v1/{passportNumber}", passportNumber)
            .header("Authorization", "Bearer \${HOME_OFFICE_PASSPORT_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                PassportStatusResponse(
                    passportNumber = passportNumber,
                    holderName = response["holderName"] as? String ?: "UNKNOWN",
                    nationality = response["nationality"] as? String ?: "UNKNOWN",
                    dateOfBirth = response["dateOfBirth"] as? String ?: "UNKNOWN",
                    placeOfBirth = response["placeOfBirth"] as? String ?: "UNKNOWN",
                    issueDate = response["issueDate"] as? String ?: "UNKNOWN",
                    expiryDate = response["expiryDate"] as? String ?: "UNKNOWN",
                    status = response["status"] as? String ?: "UNKNOWN", // VALID, EXPIRED, CANCELLED, LOST_STOLEN
                    passportType = response["passportType"] as? String ?: "UNKNOWN", // ADULT, CHILD, DIPLOMATIC, OFFICIAL
                    issuingOffice = response["issuingOffice"] as? String ?: "UNKNOWN",
                    machineReadable = response["machineReadable"] as? Boolean ?: false,
                    biometric = response["biometric"] as? Boolean ?: false,
                    validForTravel = response["validForTravel"] as? Boolean ?: false,
                    renewalEligible = response["renewalEligible"] as? Boolean ?: false,
                    restrictions = (response["restrictions"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting passport status for {}", passportNumber, e) }
            .onErrorReturn(PassportStatusResponse(
                passportNumber = passportNumber,
                holderName = "ERROR",
                nationality = "ERROR",
                dateOfBirth = "ERROR",
                placeOfBirth = "ERROR",
                issueDate = "ERROR",
                expiryDate = "ERROR",
                status = "ERROR",
                passportType = "ERROR",
                issuingOffice = "ERROR",
                machineReadable = false,
                biometric = false,
                validForTravel = false,
                renewalEligible = false,
                restrictions = emptyList()
            ))
    }

    @GetMapping("/travel-history/{personId}")
    @Cacheable("travel-history")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getTravelHistory(@PathVariable personId: String): Mono<TravelHistoryResponse> {
        logger.info("Getting travel history for person: {}", personId)
        
        return webClient.get()
            .uri("https://api.borderforce.gov.uk/travel-history/v1/{personId}?limit=50", personId)
            .header("Authorization", "Bearer \${BORDER_FORCE_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val movements = (response["movements"] as? List<Map<String, Any>>) ?: emptyList()
                TravelHistoryResponse(
                    personId = personId,
                    totalMovements = movements.size,
                    entriesUK = movements.count { (it["movementType"] as? String) == "ENTRY" },
                    exitsUK = movements.count { (it["movementType"] as? String) == "EXIT" },
                    currentlyInUK = response["currentlyInUK"] as? Boolean ?: false,
                    lastEntryDate = response["lastEntryDate"] as? String,
                    lastExitDate = response["lastExitDate"] as? String,
                    movements = movements.map { movement ->
                        BorderMovement(
                            movementType = movement["movementType"] as? String ?: "UNKNOWN",
                            date = movement["date"] as? String ?: "UNKNOWN",
                            time = movement["time"] as? String ?: "UNKNOWN",
                            port = movement["port"] as? String ?: "UNKNOWN",
                            country = movement["country"] as? String ?: "UNKNOWN",
                            transportMode = movement["transportMode"] as? String ?: "UNKNOWN",
                            documentUsed = movement["documentUsed"] as? String ?: "UNKNOWN",
                            reasonForTravel = movement["reasonForTravel"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting travel history for {}", personId, e) }
            .onErrorReturn(TravelHistoryResponse(
                personId = personId,
                totalMovements = 0,
                entriesUK = 0,
                exitsUK = 0,
                currentlyInUK = false,
                lastEntryDate = null,
                lastExitDate = null,
                movements = emptyList()
            ))
    }

    @GetMapping("/visa-status/{visaNumber}")
    @Cacheable("visa-status")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getVisaStatus(@PathVariable visaNumber: String): Mono<VisaStatusResponse> {
        logger.info("Getting visa status for: {}", visaNumber)
        
        return webClient.get()
            .uri("https://api.ukvi.homeoffice.gov.uk/visas/v1/{visaNumber}", visaNumber)
            .header("Authorization", "Bearer \${UKVI_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                VisaStatusResponse(
                    visaNumber = visaNumber,
                    holderName = response["holderName"] as? String ?: "UNKNOWN",
                    nationality = response["nationality"] as? String ?: "UNKNOWN",
                    visaType = response["visaType"] as? String ?: "UNKNOWN",
                    category = response["category"] as? String ?: "UNKNOWN",
                    status = response["status"] as? String ?: "UNKNOWN", // VALID, EXPIRED, CANCELLED, CURTAILED
                    validFrom = response["validFrom"] as? String ?: "UNKNOWN",
                    validUntil = response["validUntil"] as? String ?: "UNKNOWN",
                    multipleEntry = response["multipleEntry"] as? Boolean ?: false,
                    workAuthorised = response["workAuthorised"] as? Boolean ?: false,
                    studyAuthorised = response["studyAuthorised"] as? Boolean ?: false,
                    publicFundsRestriction = response["publicFundsRestriction"] as? Boolean ?: false,
                    sponsorName = response["sponsorName"] as? String ?: "UNKNOWN",
                    sponsorLicenseNumber = response["sponsorLicenseNumber"] as? String,
                    conditions = (response["conditions"] as? List<String>) ?: emptyList(),
                    endorsements = (response["endorsements"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting visa status for {}", visaNumber, e) }
            .onErrorReturn(VisaStatusResponse(
                visaNumber = visaNumber,
                holderName = "ERROR",
                nationality = "ERROR",
                visaType = "ERROR",
                category = "ERROR",
                status = "ERROR",
                validFrom = "ERROR",
                validUntil = "ERROR",
                multipleEntry = false,
                workAuthorised = false,
                studyAuthorised = false,
                publicFundsRestriction = false,
                sponsorName = "ERROR",
                sponsorLicenseNumber = null,
                conditions = emptyList(),
                endorsements = emptyList()
            ))
    }

    @GetMapping("/customs-declarations/{personId}")
    @Cacheable("customs-declarations")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCustomsDeclarations(@PathVariable personId: String): Mono<CustomsDeclarationsResponse> {
        logger.info("Getting customs declarations for person: {}", personId)
        
        return webClient.get()
            .uri("https://api.hmrc.gov.uk/customs/declarations/v1/{personId}?limit=20", personId)
            .header("Authorization", "Bearer \${HMRC_CUSTOMS_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val declarations = (response["declarations"] as? List<Map<String, Any>>) ?: emptyList()
                CustomsDeclarationsResponse(
                    personId = personId,
                    totalDeclarations = declarations.size,
                    totalDutyPaid = declarations.sumOf { (it["dutyPaid"] as? Double) ?: 0.0 },
                    totalVATPaid = declarations.sumOf { (it["vatPaid"] as? Double) ?: 0.0 },
                    declarations = declarations.map { declaration ->
                        CustomsDeclaration(
                            declarationNumber = declaration["declarationNumber"] as? String ?: "UNKNOWN",
                            date = declaration["date"] as? String ?: "UNKNOWN",
                            port = declaration["port"] as? String ?: "UNKNOWN",
                            declarationType = declaration["declarationType"] as? String ?: "UNKNOWN",
                            goodsDescription = declaration["goodsDescription"] as? String ?: "UNKNOWN",
                            value = declaration["value"] as? Double ?: 0.0,
                            dutyPaid = declaration["dutyPaid"] as? Double ?: 0.0,
                            vatPaid = declaration["vatPaid"] as? Double ?: 0.0,
                            currency = declaration["currency"] as? String ?: "GBP",
                            originCountry = declaration["originCountry"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting customs declarations for {}", personId, e) }
            .onErrorReturn(CustomsDeclarationsResponse(
                personId = personId,
                totalDeclarations = 0,
                totalDutyPaid = 0.0,
                totalVATPaid = 0.0,
                declarations = emptyList()
            ))
    }
}

data class PassportStatusResponse(
    val passportNumber: String,
    val holderName: String,
    val nationality: String,
    val dateOfBirth: String,
    val placeOfBirth: String,
    val issueDate: String,
    val expiryDate: String,
    val status: String,
    val passportType: String,
    val issuingOffice: String,
    val machineReadable: Boolean,
    val biometric: Boolean,
    val validForTravel: Boolean,
    val renewalEligible: Boolean,
    val restrictions: List<String>
)

data class TravelHistoryResponse(
    val personId: String,
    val totalMovements: Int,
    val entriesUK: Int,
    val exitsUK: Int,
    val currentlyInUK: Boolean,
    val lastEntryDate: String?,
    val lastExitDate: String?,
    val movements: List<BorderMovement>
)

data class BorderMovement(
    val movementType: String,
    val date: String,
    val time: String,
    val port: String,
    val country: String,
    val transportMode: String,
    val documentUsed: String,
    val reasonForTravel: String
)

data class VisaStatusResponse(
    val visaNumber: String,
    val holderName: String,
    val nationality: String,
    val visaType: String,
    val category: String,
    val status: String,
    val validFrom: String,
    val validUntil: String,
    val multipleEntry: Boolean,
    val workAuthorised: Boolean,
    val studyAuthorised: Boolean,
    val publicFundsRestriction: Boolean,
    val sponsorName: String,
    val sponsorLicenseNumber: String?,
    val conditions: List<String>,
    val endorsements: List<String>
)

data class CustomsDeclarationsResponse(
    val personId: String,
    val totalDeclarations: Int,
    val totalDutyPaid: Double,
    val totalVATPaid: Double,
    val declarations: List<CustomsDeclaration>
)

data class CustomsDeclaration(
    val declarationNumber: String,
    val date: String,
    val port: String,
    val declarationType: String,
    val goodsDescription: String,
    val value: Double,
    val dutyPaid: Double,
    val vatPaid: Double,
    val currency: String,
    val originCountry: String
)