package com.uk.gov.connectors.local

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
@RequestMapping("/api/connectors/local-government")
class LocalGovernmentConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(LocalGovernmentConnector::class.java)

    @GetMapping("/council-tax/{propertyReference}")
    @Cacheable("council-tax")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCouncilTaxDetails(@PathVariable @Pattern(regexp = "^[A-Z]{2}\\d{6}[A-Z]$") propertyReference: String): Mono<CouncilTaxResponse> {
        logger.info("Getting council tax details for property: {}", propertyReference)
        
        return webClient.get()
            .uri("https://api.counciltax.gov.uk/property/v1/{propertyReference}", propertyReference)
            .header("Authorization", "Bearer \${COUNCIL_TAX_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                CouncilTaxResponse(
                    propertyReference = propertyReference,
                    address = response["address"] as? String ?: "UNKNOWN",
                    councilTaxBand = response["councilTaxBand"] as? String ?: "UNKNOWN",
                    annualCharge = response["annualCharge"] as? Double ?: 0.0,
                    currentBalance = response["currentBalance"] as? Double ?: 0.0,
                    accountHolder = response["accountHolder"] as? String ?: "UNKNOWN",
                    paymentStatus = response["paymentStatus"] as? String ?: "UNKNOWN",
                    localAuthority = response["localAuthority"] as? String ?: "UNKNOWN",
                    exemptions = (response["exemptions"] as? List<String>) ?: emptyList(),
                    discounts = (response["discounts"] as? List<String>) ?: emptyList(),
                    paymentHistory = ((response["paymentHistory"] as? List<Map<String, Any>>) ?: emptyList()).map { payment ->
                        PaymentRecord(
                            amount = payment["amount"] as? Double ?: 0.0,
                            date = payment["date"] as? String ?: "UNKNOWN",
                            method = payment["method"] as? String ?: "UNKNOWN",
                            reference = payment["reference"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting council tax details for {}", propertyReference, e) }
            .onErrorReturn(CouncilTaxResponse(
                propertyReference = propertyReference,
                address = "ERROR",
                councilTaxBand = "ERROR",
                annualCharge = 0.0,
                currentBalance = 0.0,
                accountHolder = "ERROR",
                paymentStatus = "ERROR",
                localAuthority = "ERROR",
                exemptions = emptyList(),
                discounts = emptyList(),
                paymentHistory = emptyList()
            ))
    }

    @GetMapping("/electoral-roll/{voterName}/{postcode}")
    @Cacheable("electoral-roll")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun checkElectoralRoll(
        @PathVariable voterName: String,
        @PathVariable @Pattern(regexp = "^[A-Z]{1,2}\\d[A-Z\\d]?\\s?\\d[A-Z]{2}$") postcode: String
    ): Mono<ElectoralRollResponse> {
        logger.info("Checking electoral roll for {} in {}", voterName, postcode)
        
        return webClient.get()
            .uri("https://api.electoralcommission.org.uk/voter/v1/check?name={name}&postcode={postcode}", voterName, postcode)
            .header("Authorization", "Bearer \${ELECTORAL_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                ElectoralRollResponse(
                    voterName = voterName,
                    postcode = postcode,
                    registered = response["registered"] as? Boolean ?: false,
                    constituency = response["constituency"] as? String ?: "UNKNOWN",
                    ward = response["ward"] as? String ?: "UNKNOWN",
                    localAuthority = response["localAuthority"] as? String ?: "UNKNOWN",
                    registrationDate = response["registrationDate"] as? String ?: "UNKNOWN",
                    voterNumber = response["voterNumber"] as? String ?: "UNKNOWN",
                    eligibleToVote = response["eligibleToVote"] as? Boolean ?: false,
                    postalVote = response["postalVote"] as? Boolean ?: false,
                    proxyVote = response["proxyVote"] as? Boolean ?: false
                )
            }
            .doOnError { e -> logger.error("Error checking electoral roll for {} in {}", voterName, postcode, e) }
            .onErrorReturn(ElectoralRollResponse(
                voterName = voterName,
                postcode = postcode,
                registered = false,
                constituency = "ERROR",
                ward = "ERROR",
                localAuthority = "ERROR",
                registrationDate = "ERROR",
                voterNumber = "ERROR",
                eligibleToVote = false,
                postalVote = false,
                proxyVote = false
            ))
    }

    @GetMapping("/planning-applications/{propertyReference}")
    @Cacheable("planning-applications")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPlanningApplications(@PathVariable propertyReference: String): Mono<PlanningApplicationsResponse> {
        logger.info("Getting planning applications for property: {}", propertyReference)
        
        return webClient.get()
            .uri("https://api.planningportal.co.uk/applications/v1/property/{propertyReference}", propertyReference)
            .header("Authorization", "Bearer \${PLANNING_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val applications = (response["applications"] as? List<Map<String, Any>>) ?: emptyList()
                PlanningApplicationsResponse(
                    propertyReference = propertyReference,
                    totalApplications = applications.size,
                    activeApplications = applications.count { (it["status"] as? String) in listOf("PENDING", "UNDER_REVIEW") },
                    approvedApplications = applications.count { (it["status"] as? String) == "APPROVED" },
                    rejectedApplications = applications.count { (it["status"] as? String) == "REJECTED" },
                    applications = applications.map { app ->
                        PlanningApplication(
                            applicationNumber = app["applicationNumber"] as? String ?: "UNKNOWN",
                            description = app["description"] as? String ?: "UNKNOWN",
                            applicationDate = app["applicationDate"] as? String ?: "UNKNOWN",
                            decisionDate = app["decisionDate"] as? String,
                            status = app["status"] as? String ?: "UNKNOWN",
                            applicantName = app["applicantName"] as? String ?: "UNKNOWN",
                            planningOfficer = app["planningOfficer"] as? String ?: "UNKNOWN",
                            consultationEndDate = app["consultationEndDate"] as? String
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting planning applications for {}", propertyReference, e) }
            .onErrorReturn(PlanningApplicationsResponse(
                propertyReference = propertyReference,
                totalApplications = 0,
                activeApplications = 0,
                approvedApplications = 0,
                rejectedApplications = 0,
                applications = emptyList()
            ))
    }

    @GetMapping("/licensing/{businessName}/{postcode}")
    @Cacheable("business-licensing")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getBusinessLicenses(
        @PathVariable businessName: String,
        @PathVariable @Pattern(regexp = "^[A-Z]{1,2}\\d[A-Z\\d]?\\s?\\d[A-Z]{2}$") postcode: String
    ): Mono<BusinessLicenseResponse> {
        logger.info("Getting business licenses for {} in {}", businessName, postcode)
        
        return webClient.get()
            .uri("https://api.businesslicensing.gov.uk/licenses/v1/search?business={business}&postcode={postcode}", businessName, postcode)
            .header("Authorization", "Bearer \${LICENSING_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val licenses = (response["licenses"] as? List<Map<String, Any>>) ?: emptyList()
                BusinessLicenseResponse(
                    businessName = businessName,
                    postcode = postcode,
                    totalLicenses = licenses.size,
                    activeLicenses = licenses.count { (it["status"] as? String) == "ACTIVE" },
                    expiredLicenses = licenses.count { (it["status"] as? String) == "EXPIRED" },
                    licenses = licenses.map { license ->
                        BusinessLicense(
                            licenseNumber = license["licenseNumber"] as? String ?: "UNKNOWN",
                            type = license["type"] as? String ?: "UNKNOWN",
                            description = license["description"] as? String ?: "UNKNOWN",
                            issueDate = license["issueDate"] as? String ?: "UNKNOWN",
                            expiryDate = license["expiryDate"] as? String ?: "UNKNOWN",
                            status = license["status"] as? String ?: "UNKNOWN",
                            issuingAuthority = license["issuingAuthority"] as? String ?: "UNKNOWN",
                            conditions = (license["conditions"] as? List<String>) ?: emptyList(),
                            renewalRequired = license["renewalRequired"] as? Boolean ?: false
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting business licenses for {} in {}", businessName, postcode, e) }
            .onErrorReturn(BusinessLicenseResponse(
                businessName = businessName,
                postcode = postcode,
                totalLicenses = 0,
                activeLicenses = 0,
                expiredLicenses = 0,
                licenses = emptyList()
            ))
    }
}

data class CouncilTaxResponse(
    val propertyReference: String,
    val address: String,
    val councilTaxBand: String,
    val annualCharge: Double,
    val currentBalance: Double,
    val accountHolder: String,
    val paymentStatus: String,
    val localAuthority: String,
    val exemptions: List<String>,
    val discounts: List<String>,
    val paymentHistory: List<PaymentRecord>
)

data class PaymentRecord(
    val amount: Double,
    val date: String,
    val method: String,
    val reference: String
)

data class ElectoralRollResponse(
    val voterName: String,
    val postcode: String,
    val registered: Boolean,
    val constituency: String,
    val ward: String,
    val localAuthority: String,
    val registrationDate: String,
    val voterNumber: String,
    val eligibleToVote: Boolean,
    val postalVote: Boolean,
    val proxyVote: Boolean
)

data class PlanningApplicationsResponse(
    val propertyReference: String,
    val totalApplications: Int,
    val activeApplications: Int,
    val approvedApplications: Int,
    val rejectedApplications: Int,
    val applications: List<PlanningApplication>
)

data class PlanningApplication(
    val applicationNumber: String,
    val description: String,
    val applicationDate: String,
    val decisionDate: String?,
    val status: String,
    val applicantName: String,
    val planningOfficer: String,
    val consultationEndDate: String?
)

data class BusinessLicenseResponse(
    val businessName: String,
    val postcode: String,
    val totalLicenses: Int,
    val activeLicenses: Int,
    val expiredLicenses: Int,
    val licenses: List<BusinessLicense>
)

data class BusinessLicense(
    val licenseNumber: String,
    val type: String,
    val description: String,
    val issueDate: String,
    val expiryDate: String,
    val status: String,
    val issuingAuthority: String,
    val conditions: List<String>,
    val renewalRequired: Boolean
)