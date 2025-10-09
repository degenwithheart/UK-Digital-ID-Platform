package com.uk.gov.connectors.business

import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import reactor.core.publisher.Mono
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Department for Business & Trade Connector
 * Provides access to business registrations, trade licenses, and commercial activities
 */
@Service
class BusinessTradeConnector {

    private val logger: Logger = LoggerFactory.getLogger(BusinessTradeConnector::class.java)
    private val webClient = WebClient.builder()
        .baseUrl("https://api.businesstrade.gov.uk")
        .build()

    /**
     * Verify business registrations and trade licenses
     */
    @Cacheable("business-registrations")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyBusinessRegistrations(
        nationalInsuranceNumber: String,
        companyNumber: String? = null
    ): Mono<BusinessRegistrations> {
        logger.info("Verifying business registrations for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/businesses/verify?ni={ni}&company={company}", nationalInsuranceNumber, companyNumber)
            .retrieve()
            .bodyToMono(BusinessRegistrations::class.java)
            .doOnSuccess { result ->
                logger.info("Business registrations verified: ${result.activeBusinesses.size} active businesses")
            }
            .onErrorReturn(BusinessRegistrations(
                activeBusinesses = emptyList(),
                tradeLicenses = emptyList(),
                regulatoryApprovals = emptyList()
            ))
    }

    /**
     * Get export/import licenses
     */
    @Cacheable("trade-licenses")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getTradeLicenses(businessId: String): Mono<TradeLicenses> {
        logger.info("Fetching trade licenses for business: $businessId")
        
        return webClient.get()
            .uri("/v1/licenses/trade?business={id}", businessId)
            .retrieve()
            .bodyToMono(TradeLicenses::class.java)
            .doOnSuccess { result ->
                logger.info("Trade licenses retrieved: ${result.activeLicenses.size} active licenses")
            }
            .onErrorReturn(TradeLicenses(
                activeLicenses = emptyList(),
                pendingApplications = emptyList(),
                expiredLicenses = emptyList()
            ))
    }

    /**
     * Check commercial compliance status
     */
    @Cacheable("commercial-compliance")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun checkCommercialCompliance(businessId: String): Mono<CommercialCompliance> {
        logger.info("Checking commercial compliance for business: $businessId")
        
        return webClient.get()
            .uri("/v1/compliance/commercial?business={id}", businessId)
            .retrieve()
            .bodyToMono(CommercialCompliance::class.java)
            .doOnSuccess { result ->
                logger.info("Commercial compliance checked: ${result.complianceStatus}")
            }
            .onErrorReturn(CommercialCompliance(
                complianceStatus = "UNKNOWN",
                violations = emptyList(),
                inspections = emptyList()
            ))
    }
}

// Data Classes
data class BusinessRegistrations(
    val activeBusinesses: List<BusinessRegistration>,
    val tradeLicenses: List<TradeLicense>,
    val regulatoryApprovals: List<RegulatoryApproval>
)

data class BusinessRegistration(
    val registrationId: String,
    val businessName: String,
    val type: String,
    val registrationDate: String,
    val status: String,
    val address: String,
    val sicCodes: List<String>
)

data class TradeLicense(
    val licenseId: String,
    val type: String,
    val issueDate: String,
    val expiryDate: String,
    val status: String,
    val restrictions: List<String>
)

data class TradeLicenses(
    val activeLicenses: List<TradeLicense>,
    val pendingApplications: List<LicenseApplication>,
    val expiredLicenses: List<TradeLicense>
)

data class LicenseApplication(
    val applicationId: String,
    val type: String,
    val submissionDate: String,
    val status: String,
    val estimatedDecisionDate: String?
)

data class RegulatoryApproval(
    val approvalId: String,
    val type: String,
    val authority: String,
    val issueDate: String,
    val status: String
)

data class CommercialCompliance(
    val complianceStatus: String,
    val violations: List<CommercialViolation>,
    val inspections: List<CommercialInspection>
)

data class CommercialViolation(
    val violationId: String,
    val type: String,
    val severity: String,
    val date: String,
    val description: String,
    val fineAmount: Double?,
    val resolved: Boolean
)

data class CommercialInspection(
    val inspectionId: String,
    val date: String,
    val inspector: String,
    val outcome: String,
    val followUpRequired: Boolean
)