package com.uk.gov.connectors.housing

import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import reactor.core.publisher.Mono
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Department for Levelling Up, Housing & Communities Connector
 * Provides access to housing records, community grants, and planning permissions
 */
@Service
class HousingCommunitiesConnector {

    private val logger: Logger = LoggerFactory.getLogger(HousingCommunitiesConnector::class.java)
    private val webClient = WebClient.builder()
        .baseUrl("https://api.communities.gov.uk")
        .build()

    @Cacheable("housing-records")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getHousingRecords(nationalInsuranceNumber: String): Mono<HousingRecords> {
        return webClient.get()
            .uri("/v1/housing/records?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(HousingRecords::class.java)
            .onErrorReturn(HousingRecords(emptyList(), emptyList(), emptyList()))
    }

    @Cacheable("planning-permissions")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPlanningPermissions(nationalInsuranceNumber: String): Mono<PlanningPermissions> {
        return webClient.get()
            .uri("/v1/planning/permissions?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(PlanningPermissions::class.java)
            .onErrorReturn(PlanningPermissions(emptyList(), emptyList()))
    }
}

data class HousingRecords(
    val socialHousing: List<SocialHousingRecord>,
    val housingBenefits: List<HousingBenefit>,
    val homelessnessApplications: List<HomelessnessApplication>
)

data class SocialHousingRecord(val tenancyId: String, val property: String, val startDate: String, val status: String)
data class HousingBenefit(val benefitId: String, val amount: Double, val startDate: String, val status: String)
data class HomelessnessApplication(val applicationId: String, val date: String, val outcome: String, val status: String)

data class PlanningPermissions(
    val activePermissions: List<PlanningPermission>,
    val applications: List<PlanningApplication>
)

data class PlanningPermission(val permissionId: String, val address: String, val type: String, val issueDate: String)
data class PlanningApplication(val applicationId: String, val address: String, val type: String, val status: String)