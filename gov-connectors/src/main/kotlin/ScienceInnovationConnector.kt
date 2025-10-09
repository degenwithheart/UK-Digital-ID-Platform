package com.uk.gov.connectors.science

import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import reactor.core.publisher.Mono
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Department for Science, Innovation & Technology Connector
 * Provides access to research grants, technology licenses, and innovation programs
 */
@Service
class ScienceInnovationConnector {

    private val logger: Logger = LoggerFactory.getLogger(ScienceInnovationConnector::class.java)
    private val webClient = WebClient.builder()
        .baseUrl("https://api.scienceinnovation.gov.uk")
        .build()

    @Cacheable("research-grants")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getResearchGrants(nationalInsuranceNumber: String): Mono<ResearchGrants> {
        return webClient.get()
            .uri("/v1/grants/research?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(ResearchGrants::class.java)
            .onErrorReturn(ResearchGrants(emptyList(), emptyList()))
    }

    @Cacheable("technology-licenses")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getTechnologyLicenses(nationalInsuranceNumber: String): Mono<TechnologyLicenses> {
        return webClient.get()
            .uri("/v1/licenses/technology?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(TechnologyLicenses::class.java)
            .onErrorReturn(TechnologyLicenses(emptyList(), emptyList()))
    }
}

data class ResearchGrants(
    val activeGrants: List<ResearchGrant>,
    val publications: List<ResearchPublication>
)

data class ResearchGrant(val grantId: String, val title: String, val amount: Double, val startDate: String, val status: String)
data class ResearchPublication(val publicationId: String, val title: String, val journal: String, val publishDate: String)

data class TechnologyLicenses(
    val patents: List<Patent>,
    val trademarks: List<Trademark>
)

data class Patent(val patentId: String, val title: String, val issueDate: String, val expiryDate: String, val status: String)
data class Trademark(val trademarkId: String, val name: String, val classes: List<String>, val registrationDate: String)