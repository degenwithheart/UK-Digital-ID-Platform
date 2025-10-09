package com.uk.gov.connectors.security

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
@RequestMapping("/api/connectors/security")
class SecurityConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(SecurityConnector::class.java)

    @GetMapping("/sia-licensing/{licenseNumber}")
    @Cacheable("sia-licensing")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getSIALicense(@PathVariable licenseNumber: String): Mono<SIALicenseResponse> {
        logger.info("Getting SIA license for: {}", licenseNumber)
        
        return webClient.get()
            .uri("https://api.sia.homeoffice.gov.uk/licenses/v1/{licenseNumber}", licenseNumber)
            .header("Authorization", "Bearer \${SIA_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val sectors = (response["sectors"] as? List<String>) ?: emptyList()
                SIALicenseResponse(
                    licenseNumber = licenseNumber,
                    holderName = response["holderName"] as? String ?: "UNKNOWN",
                    status = response["status"] as? String ?: "UNKNOWN",
                    issueDate = response["issueDate"] as? String ?: "UNKNOWN",
                    expiryDate = response["expiryDate"] as? String ?: "UNKNOWN",
                    licenseType = response["licenseType"] as? String ?: "UNKNOWN", // FRONT_LINE, NON_FRONT_LINE
                    authorizedSectors = sectors,
                    restrictions = (response["restrictions"] as? List<String>) ?: emptyList(),
                    conditions = (response["conditions"] as? List<String>) ?: emptyList(),
                    trainingProvider = response["trainingProvider"] as? String ?: "UNKNOWN",
                    qualificationLevel = response["qualificationLevel"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error getting SIA license for {}", licenseNumber, e) }
            .onErrorReturn(SIALicenseResponse(
                licenseNumber = licenseNumber,
                holderName = "ERROR",
                status = "ERROR",
                issueDate = "ERROR",
                expiryDate = "ERROR",
                licenseType = "ERROR",
                authorizedSectors = emptyList(),
                restrictions = emptyList(),
                conditions = emptyList(),
                trainingProvider = "ERROR",
                qualificationLevel = "ERROR"
            ))
    }

    @GetMapping("/counter-terrorism-check/{personId}")
    @Cacheable("counter-terrorism-check")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCounterTerrorismCheck(@PathVariable personId: String): Mono<CounterTerrorismResponse> {
        logger.info("Getting counter-terrorism check for person: {}", personId)
        
        return webClient.get()
            .uri("https://api.mi5.gov.uk/security-checks/v1/{personId}", personId)
            .header("Authorization", "Bearer \${MI5_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                CounterTerrorismResponse(
                    personId = personId,
                    checkId = response["checkId"] as? String ?: java.util.UUID.randomUUID().toString(),
                    clearanceLevel = response["clearanceLevel"] as? String ?: "UNKNOWN", // CLEAR, REVIEW_REQUIRED, DENIED
                    riskAssessment = response["riskAssessment"] as? String ?: "UNKNOWN", // LOW, MEDIUM, HIGH, CRITICAL
                    watchListStatus = response["watchListStatus"] as? String ?: "NOT_LISTED",
                    sanctionsStatus = response["sanctionsStatus"] as? String ?: "CLEAR",
                    lastChecked = response["lastChecked"] as? String ?: java.time.Instant.now().toString(),
                    checkValidity = response["checkValidity"] as? String ?: "30_DAYS",
                    restrictions = (response["restrictions"] as? List<String>) ?: emptyList(),
                    securityNotes = response["securityNotes"] as? String ?: "NONE"
                )
            }
            .doOnError { e -> logger.error("Error getting counter-terrorism check for {}", personId, e) }
            .onErrorReturn(CounterTerrorismResponse(
                personId = personId,
                checkId = "ERROR",
                clearanceLevel = "ERROR",
                riskAssessment = "HIGH",
                watchListStatus = "ERROR",
                sanctionsStatus = "ERROR",
                lastChecked = java.time.Instant.now().toString(),
                checkValidity = "ERROR",
                restrictions = emptyList(),
                securityNotes = "ERROR_IN_PROCESSING"
            ))
    }

    @GetMapping("/firearms-licensing/{certificateNumber}")
    @Cacheable("firearms-licensing")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getFirearmsLicense(@PathVariable certificateNumber: String): Mono<FirearmsLicenseResponse> {
        logger.info("Getting firearms license for certificate: {}", certificateNumber)
        
        return webClient.get()
            .uri("https://api.police.uk/firearms/v1/{certificateNumber}", certificateNumber)
            .header("Authorization", "Bearer \${POLICE_FIREARMS_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val authorizedWeapons = (response["authorizedWeapons"] as? List<Map<String, Any>>) ?: emptyList()
                val conditions = (response["conditions"] as? List<String>) ?: emptyList()
                
                FirearmsLicenseResponse(
                    certificateNumber = certificateNumber,
                    holderName = response["holderName"] as? String ?: "UNKNOWN",
                    certificateType = response["certificateType"] as? String ?: "UNKNOWN", // FIREARM, SHOTGUN, SECTION_5
                    status = response["status"] as? String ?: "UNKNOWN",
                    issueDate = response["issueDate"] as? String ?: "UNKNOWN",
                    expiryDate = response["expiryDate"] as? String ?: "UNKNOWN",
                    issuingForce = response["issuingForce"] as? String ?: "UNKNOWN",
                    renewalDue = response["renewalDue"] as? Boolean ?: false,
                    totalAuthorizedWeapons = authorizedWeapons.size,
                    authorizedWeapons = authorizedWeapons.map { weapon ->
                        AuthorizedWeapon(
                            type = weapon["type"] as? String ?: "UNKNOWN",
                            make = weapon["make"] as? String ?: "UNKNOWN",
                            model = weapon["model"] as? String ?: "UNKNOWN",
                            calibre = weapon["calibre"] as? String ?: "UNKNOWN",
                            serialNumber = weapon["serialNumber"] as? String ?: "UNKNOWN",
                            purpose = weapon["purpose"] as? String ?: "UNKNOWN"
                        )
                    },
                    conditions = conditions,
                    restrictions = (response["restrictions"] as? List<String>) ?: emptyList(),
                    storageRequirements = response["storageRequirements"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error getting firearms license for {}", certificateNumber, e) }
            .onErrorReturn(FirearmsLicenseResponse(
                certificateNumber = certificateNumber,
                holderName = "ERROR",
                certificateType = "ERROR",
                status = "ERROR",
                issueDate = "ERROR",
                expiryDate = "ERROR",
                issuingForce = "ERROR",
                renewalDue = false,
                totalAuthorizedWeapons = 0,
                authorizedWeapons = emptyList(),
                conditions = emptyList(),
                restrictions = emptyList(),
                storageRequirements = "ERROR"
            ))
    }

    @PostMapping("/security-clearance-check")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun requestSecurityClearanceCheck(@Valid @RequestBody request: SecurityClearanceRequest): Mono<SecurityClearanceResponse> {
        logger.info("Requesting security clearance check for: {}", request.applicantName)
        
        return webClient.post()
            .uri("https://api.cabinetoffice.gov.uk/security-clearance/v1/request")
            .header("Authorization", "Bearer \${CABINET_OFFICE_API_KEY}")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                SecurityClearanceResponse(
                    applicationId = response["applicationId"] as? String ?: java.util.UUID.randomUUID().toString(),
                    applicantName = request.applicantName,
                    clearanceLevel = request.clearanceLevel,
                    status = response["status"] as? String ?: "PENDING", // PENDING, IN_PROGRESS, APPROVED, DENIED
                    applicationDate = java.time.Instant.now().toString(),
                    estimatedCompletionDate = response["estimatedCompletionDate"] as? String ?: "UNKNOWN",
                    investigatingAgency = response["investigatingAgency"] as? String ?: "UKVI",
                    sponsoringDepartment = request.sponsoringDepartment,
                    interviewRequired = response["interviewRequired"] as? Boolean ?: false,
                    polygraphRequired = response["polygraphRequired"] as? Boolean ?: false,
                    referenceChecks = response["referenceChecks"] as? Int ?: 0,
                    trackingReference = response["trackingReference"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error requesting security clearance for {}", request.applicantName, e) }
            .onErrorReturn(SecurityClearanceResponse(
                applicationId = "ERROR",
                applicantName = request.applicantName,
                clearanceLevel = request.clearanceLevel,
                status = "ERROR",
                applicationDate = java.time.Instant.now().toString(),
                estimatedCompletionDate = "ERROR",
                investigatingAgency = "ERROR",
                sponsoringDepartment = request.sponsoringDepartment,
                interviewRequired = false,
                polygraphRequired = false,
                referenceChecks = 0,
                trackingReference = "ERROR"
            ))
    }
}

data class SIALicenseResponse(
    val licenseNumber: String,
    val holderName: String,
    val status: String,
    val issueDate: String,
    val expiryDate: String,
    val licenseType: String,
    val authorizedSectors: List<String>,
    val restrictions: List<String>,
    val conditions: List<String>,
    val trainingProvider: String,
    val qualificationLevel: String
)

data class CounterTerrorismResponse(
    val personId: String,
    val checkId: String,
    val clearanceLevel: String,
    val riskAssessment: String,
    val watchListStatus: String,
    val sanctionsStatus: String,
    val lastChecked: String,
    val checkValidity: String,
    val restrictions: List<String>,
    val securityNotes: String
)

data class FirearmsLicenseResponse(
    val certificateNumber: String,
    val holderName: String,
    val certificateType: String,
    val status: String,
    val issueDate: String,
    val expiryDate: String,
    val issuingForce: String,
    val renewalDue: Boolean,
    val totalAuthorizedWeapons: Int,
    val authorizedWeapons: List<AuthorizedWeapon>,
    val conditions: List<String>,
    val restrictions: List<String>,
    val storageRequirements: String
)

data class AuthorizedWeapon(
    val type: String,
    val make: String,
    val model: String,
    val calibre: String,
    val serialNumber: String,
    val purpose: String
)

data class SecurityClearanceRequest(
    @field:NotBlank val applicantName: String,
    @field:NotBlank val dateOfBirth: String,
    @field:NotBlank val clearanceLevel: String, // BASELINE, CTC, SC, DV
    @field:NotBlank val sponsoringDepartment: String,
    val position: String?,
    val contractorName: String?
)

data class SecurityClearanceResponse(
    val applicationId: String,
    val applicantName: String,
    val clearanceLevel: String,
    val status: String,
    val applicationDate: String,
    val estimatedCompletionDate: String,
    val investigatingAgency: String,
    val sponsoringDepartment: String,
    val interviewRequired: Boolean,
    val polygraphRequired: Boolean,
    val referenceChecks: Int,
    val trackingReference: String
)