package com.uk.gov.connectors.environment

import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import reactor.core.publisher.Mono
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Department for Environment, Food & Rural Affairs Connector
 * Provides access to environmental compliance, farming permits, and rural affairs data
 */
@Service
class DEFRAConnector {

    private val logger: Logger = LoggerFactory.getLogger(DEFRAConnector::class.java)
    private val webClient = WebClient.builder()
        .baseUrl("https://api.defra.gov.uk")
        .build()

    /**
     * Verify environmental permits and licenses
     */
    @Cacheable("environmental-permits")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyEnvironmentalPermits(
        nationalInsuranceNumber: String,
        companyNumber: String? = null
    ): Mono<EnvironmentalPermits> {
        logger.info("Verifying environmental permits for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/permits/verify?ni={ni}&company={company}", nationalInsuranceNumber, companyNumber)
            .retrieve()
            .bodyToMono(EnvironmentalPermits::class.java)
            .doOnSuccess { result ->
                logger.info("Environmental permits verified: ${result.activePermits.size} active permits")
            }
            .onErrorReturn(EnvironmentalPermits(
                activePermits = emptyList(),
                expiredPermits = emptyList(),
                pendingApplications = emptyList()
            ))
    }

    /**
     * Get farming subsidies and grants
     */
    @Cacheable("farming-subsidies")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getFarmingSubsidies(nationalInsuranceNumber: String): Mono<FarmingSubsidies> {
        logger.info("Fetching farming subsidies for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/subsidies/farmer?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(FarmingSubsidies::class.java)
            .doOnSuccess { result ->
                logger.info("Farming subsidies retrieved: £${result.totalSubsidies}")
            }
            .onErrorReturn(FarmingSubsidies(
                totalSubsidies = 0.0,
                activeSchemes = emptyList(),
                paymentHistory = emptyList()
            ))
    }

    /**
     * Check environmental compliance status
     */
    @Cacheable("environmental-compliance")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun checkEnvironmentalCompliance(businessId: String): Mono<EnvironmentalCompliance> {
        logger.info("Checking environmental compliance for business: $businessId")
        
        return webClient.get()
            .uri("/v1/compliance/check?business={id}", businessId)
            .retrieve()
            .bodyToMono(EnvironmentalCompliance::class.java)
            .doOnSuccess { result ->
                logger.info("Environmental compliance checked: ${result.complianceStatus}")
            }
            .onErrorReturn(EnvironmentalCompliance(
                complianceStatus = "UNKNOWN",
                violations = emptyList(),
                inspections = emptyList()
            ))
    }
}

// Data Classes
data class EnvironmentalPermits(
    val activePermits: List<EnvironmentalPermit>,
    val expiredPermits: List<EnvironmentalPermit>,
    val pendingApplications: List<PermitApplication>
)

data class EnvironmentalPermit(
    val permitId: String,
    val type: String,
    val issueDate: String,
    val expiryDate: String,
    val status: String,
    val conditions: List<String>
)

data class PermitApplication(
    val applicationId: String,
    val type: String,
    val submissionDate: String,
    val status: String,
    val estimatedDecisionDate: String?
)

data class FarmingSubsidies(
    val totalSubsidies: Double,
    val activeSchemes: List<SubsidyScheme>,
    val paymentHistory: List<SubsidyPayment>
)

data class SubsidyScheme(
    val schemeId: String,
    val name: String,
    val type: String,
    val amount: Double,
    val startDate: String,
    val endDate: String
)

data class SubsidyPayment(
    val paymentId: String,
    val scheme: String,
    val amount: Double,
    val paymentDate: String,
    val status: String
)

data class EnvironmentalCompliance(
    val complianceStatus: String,
    val violations: List<EnvironmentalViolation>,
    val inspections: List<EnvironmentalInspection>
)

data class EnvironmentalViolation(
    val violationId: String,
    val type: String,
    val severity: String,
    val date: String,
    val description: String,
    val fineAmount: Double?,
    val resolved: Boolean
)

data class EnvironmentalInspection(
    val inspectionId: String,
    val date: String,
    val inspector: String,
    val outcome: String,
    val followUpRequired: Boolean
)