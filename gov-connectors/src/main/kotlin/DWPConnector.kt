package com.uk.gov.connectors.dwp

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
@RequestMapping("/api/connectors/dwp")
class DWPConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(DWPConnector::class.java)

    @GetMapping("/verify-ni-number/{niNumber}")
    @Cacheable("dwp-ni-verification")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyNationalInsuranceNumber(@PathVariable @Pattern(regexp = "^[A-Z]{2}[0-9]{6}[A-Z]$") niNumber: String): Mono<NIVerificationResponse> {
        logger.info("Verifying NI number: {}", niNumber)
        
        return webClient.get()
            .uri("https://api.gov.uk/dwp/ni-verification/v1/{niNumber}", niNumber)
            .header("Authorization", "Bearer \${DWP_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                NIVerificationResponse(
                    niNumber = niNumber,
                    valid = response["valid"] as? Boolean ?: true,
                    status = response["status"] as? String ?: "ACTIVE",
                    issuedDate = response["issuedDate"] as? String ?: "UNKNOWN",
                    contributionYears = response["contributionYears"] as? Int ?: 0,
                    qualifyingYears = response["qualifyingYears"] as? Int ?: 0,
                    currentYearContributions = response["currentYearContributions"] as? Double ?: 0.0
                )
            }
            .doOnError { e -> logger.error("Error verifying NI number {}", niNumber, e) }
            .onErrorReturn(NIVerificationResponse(
                niNumber = niNumber,
                valid = false,
                status = "ERROR",
                issuedDate = "UNKNOWN",
                contributionYears = 0,
                qualifyingYears = 0,
                currentYearContributions = 0.0
            ))
    }

    @GetMapping("/benefits-eligibility/{niNumber}")
    @Cacheable("dwp-benefits")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getBenefitsEligibility(@PathVariable niNumber: String): Mono<BenefitsEligibilityResponse> {
        logger.info("Checking benefits eligibility for: {}", niNumber)
        
        return webClient.get()
            .uri("https://api.gov.uk/dwp/benefits-eligibility/v1/{niNumber}", niNumber)
            .header("Authorization", "Bearer \${DWP_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val currentBenefits = (response["currentBenefits"] as? List<Map<String, Any>>) ?: emptyList()
                BenefitsEligibilityResponse(
                    niNumber = niNumber,
                    universalCreditEligible = response["universalCreditEligible"] as? Boolean ?: false,
                    universalCreditCurrent = hasBenefit(currentBenefits, "Universal Credit"),
                    pipEligible = response["pipEligible"] as? Boolean ?: false,
                    pipCurrent = hasBenefit(currentBenefits, "Personal Independence Payment"),
                    jsaEligible = response["jsaEligible"] as? Boolean ?: false,
                    jsaCurrent = hasBenefit(currentBenefits, "Jobseeker's Allowance"),
                    esaEligible = response["esaEligible"] as? Boolean ?: false,
                    esaCurrent = hasBenefit(currentBenefits, "Employment and Support Allowance"),
                    statePensionEligible = response["statePensionEligible"] as? Boolean ?: false,
                    statePensionCurrent = hasBenefit(currentBenefits, "State Pension"),
                    currentBenefits = currentBenefits.map { it["benefitType"] as? String ?: "Unknown" }
                )
            }
            .doOnError { e -> logger.error("Error checking benefits eligibility for {}", niNumber, e) }
            .onErrorReturn(BenefitsEligibilityResponse(
                niNumber = niNumber,
                universalCreditEligible = false,
                universalCreditCurrent = false,
                pipEligible = false,
                pipCurrent = false,
                jsaEligible = false,
                jsaCurrent = false,
                esaEligible = false,
                esaCurrent = false,
                statePensionEligible = false,
                statePensionCurrent = false,
                currentBenefits = emptyList()
            ))
    }

    @GetMapping("/pension-entitlements/{niNumber}")
    @Cacheable("dwp-pension")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPensionEntitlements(@PathVariable niNumber: String): Mono<PensionEntitlementsResponse> {
        logger.info("Getting pension entitlements for: {}", niNumber)
        
        return webClient.get()
            .uri("https://api.gov.uk/dwp/pension-forecast/v1/{niNumber}", niNumber)
            .header("Authorization", "Bearer \${DWP_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                PensionEntitlementsResponse(
                    niNumber = niNumber,
                    statePensionAge = response["statePensionAge"] as? Int ?: 67,
                    statePensionDate = response["statePensionDate"] as? String ?: "UNKNOWN",
                    currentWeeklyAmount = (response["currentWeeklyAmount"] as? Number)?.toDouble() ?: 0.0,
                    forecastWeeklyAmount = (response["forecastWeeklyAmount"] as? Number)?.toDouble() ?: 0.0,
                    maximumWeeklyAmount = (response["maximumWeeklyAmount"] as? Number)?.toDouble() ?: 203.85,
                    qualifyingYears = response["qualifyingYears"] as? Int ?: 0,
                    qualifyingYearsRequired = response["qualifyingYearsRequired"] as? Int ?: 35,
                    gapsInRecord = response["gapsInRecord"] as? Int ?: 0,
                    canImprove = response["canImprove"] as? Boolean ?: true
                )
            }
            .doOnError { e -> logger.error("Error getting pension entitlements for {}", niNumber, e) }
            .onErrorReturn(PensionEntitlementsResponse(
                niNumber = niNumber,
                statePensionAge = 67,
                statePensionDate = "UNKNOWN",
                currentWeeklyAmount = 0.0,
                forecastWeeklyAmount = 0.0,
                maximumWeeklyAmount = 203.85,
                qualifyingYears = 0,
                qualifyingYearsRequired = 35,
                gapsInRecord = 0,
                canImprove = false
            ))
    }

    @PostMapping("/employment-history")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getEmploymentHistory(@Valid @RequestBody request: EmploymentHistoryRequest): Mono<EmploymentHistoryResponse> {
        logger.info("Getting employment history for: {}", request.niNumber)
        
        return webClient.post()
            .uri("https://api.gov.uk/dwp/employment-history/v1")
            .header("Authorization", "Bearer \${DWP_API_KEY}")
            .header("X-Correlation-ID", java.util.UUID.randomUUID().toString())
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val employmentRecords = (response["employmentRecords"] as? List<Map<String, Any>>) ?: emptyList()
                EmploymentHistoryResponse(
                    niNumber = request.niNumber,
                    totalEmployers = employmentRecords.size,
                    currentEmployment = response["currentEmployment"] as? Boolean ?: false,
                    totalEarningsToDate = (response["totalEarningsToDate"] as? Number)?.toDouble() ?: 0.0,
                    currentTaxYear = response["currentTaxYear"] as? String ?: "2024-25",
                    currentYearEarnings = (response["currentYearEarnings"] as? Number)?.toDouble() ?: 0.0,
                    employmentRecords = employmentRecords.map { record ->
                        EmploymentRecord(
                            employerName = record["employerName"] as? String ?: "Unknown",
                            startDate = record["startDate"] as? String ?: "Unknown",
                            endDate = record["endDate"] as? String,
                            earnings = (record["earnings"] as? Number)?.toDouble() ?: 0.0,
                            payeReference = record["payeReference"] as? String ?: "Unknown"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting employment history for {}", request.niNumber, e) }
            .onErrorReturn(EmploymentHistoryResponse(
                niNumber = request.niNumber,
                totalEmployers = 0,
                currentEmployment = false,
                totalEarningsToDate = 0.0,
                currentTaxYear = "2024-25",
                currentYearEarnings = 0.0,
                employmentRecords = emptyList()
            ))
    }

    private fun hasBenefit(benefits: List<Map<String, Any>>, benefitType: String): Boolean {
        return benefits.any { benefit ->
            (benefit["benefitType"] as? String)?.contains(benefitType, ignoreCase = true) == true
        }
    }
}

data class NIVerificationResponse(
    val niNumber: String,
    val valid: Boolean,
    val status: String,
    val issuedDate: String,
    val contributionYears: Int,
    val qualifyingYears: Int,
    val currentYearContributions: Double
)

data class BenefitsEligibilityResponse(
    val niNumber: String,
    val universalCreditEligible: Boolean,
    val universalCreditCurrent: Boolean,
    val pipEligible: Boolean,
    val pipCurrent: Boolean,
    val jsaEligible: Boolean,
    val jsaCurrent: Boolean,
    val esaEligible: Boolean,
    val esaCurrent: Boolean,
    val statePensionEligible: Boolean,
    val statePensionCurrent: Boolean,
    val currentBenefits: List<String>
)

data class PensionEntitlementsResponse(
    val niNumber: String,
    val statePensionAge: Int,
    val statePensionDate: String,
    val currentWeeklyAmount: Double,
    val forecastWeeklyAmount: Double,
    val maximumWeeklyAmount: Double,
    val qualifyingYears: Int,
    val qualifyingYearsRequired: Int,
    val gapsInRecord: Int,
    val canImprove: Boolean
)

data class EmploymentHistoryRequest(
    @field:NotBlank val niNumber: String,
    val fromYear: String?,
    val toYear: String?
)

data class EmploymentHistoryResponse(
    val niNumber: String,
    val totalEmployers: Int,
    val currentEmployment: Boolean,
    val totalEarningsToDate: Double,
    val currentTaxYear: String,
    val currentYearEarnings: Double,
    val employmentRecords: List<EmploymentRecord>
)

data class EmploymentRecord(
    val employerName: String,
    val startDate: String,
    val endDate: String?,
    val earnings: Double,
    val payeReference: String
)