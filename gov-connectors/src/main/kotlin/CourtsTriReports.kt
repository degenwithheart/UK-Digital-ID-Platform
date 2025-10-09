package com.uk.gov.connectors.courts

import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import reactor.core.publisher.Mono
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * HM Courts & Tribunals Service Connector
 * Provides access to court records, hearing schedules, and legal case information
 */
@Service
class CourtsTriReports {

    private val logger: Logger = LoggerFactory.getLogger(CourtsTriReports::class.java)
    private val webClient = WebClient.builder()
        .baseUrl("https://api.justice.gov.uk")
        .build()

    /**
     * Verify court case involvement
     */
    @Cacheable("court-cases")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyCaseInvolvement(
        nationalInsuranceNumber: String,
        caseNumber: String? = null
    ): Mono<CourtCaseVerification> {
        logger.info("Verifying court case involvement for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/cases/verify?ni={ni}&case={case}", nationalInsuranceNumber, caseNumber)
            .retrieve()
            .bodyToMono(CourtCaseVerification::class.java)
            .doOnSuccess { result ->
                logger.info("Court case verification completed: ${result.status}")
            }
            .onErrorReturn(CourtCaseVerification(
                status = "NOT_FOUND",
                activeCases = emptyList(),
                historicalCases = emptyList(),
                warrants = emptyList()
            ))
    }

    /**
     * Get ongoing legal proceedings
     */
    @Cacheable("legal-proceedings")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getOngoingProceedings(nationalInsuranceNumber: String): Mono<LegalProceedings> {
        logger.info("Fetching ongoing legal proceedings for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/proceedings/active?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(LegalProceedings::class.java)
            .doOnSuccess { result ->
                logger.info("Legal proceedings retrieved: ${result.activeProceedings.size} active cases")
            }
            .onErrorReturn(LegalProceedings(
                activeProceedings = emptyList(),
                upcomingHearings = emptyList(),
                judgments = emptyList()
            ))
    }

    /**
     * Check for outstanding warrants
     */
    @Cacheable("warrants")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun checkWarrants(nationalInsuranceNumber: String): Mono<WarrantStatus> {
        logger.info("Checking warrant status for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/warrants/check?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(WarrantStatus::class.java)
            .doOnSuccess { result ->
                logger.info("Warrant check completed: ${result.activeWarrants.size} active warrants")
            }
            .onErrorReturn(WarrantStatus(
                hasActiveWarrants = false,
                activeWarrants = emptyList(),
                historicalWarrants = emptyList()
            ))
    }
}

// Data Classes
data class CourtCaseVerification(
    val status: String,
    val activeCases: List<CourtCase>,
    val historicalCases: List<CourtCase>,
    val warrants: List<Warrant>
)

data class CourtCase(
    val caseNumber: String,
    val caseType: String,
    val court: String,
    val status: String,
    val dateOpened: String,
    val nextHearing: String?,
    val charges: List<String>
)

data class LegalProceedings(
    val activeProceedings: List<Proceeding>,
    val upcomingHearings: List<Hearing>,
    val judgments: List<Judgment>
)

data class Proceeding(
    val proceedingId: String,
    val type: String,
    val court: String,
    val status: String,
    val parties: List<String>
)

data class Hearing(
    val hearingId: String,
    val date: String,
    val time: String,
    val court: String,
    val type: String
)

data class Judgment(
    val judgmentId: String,
    val date: String,
    val court: String,
    val outcome: String,
    val penalty: String?
)

data class WarrantStatus(
    val hasActiveWarrants: Boolean,
    val activeWarrants: List<Warrant>,
    val historicalWarrants: List<Warrant>
)

data class Warrant(
    val warrantId: String,
    val type: String,
    val issueDate: String,
    val issuingCourt: String,
    val status: String,
    val reason: String
)