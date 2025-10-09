package com.uk.gov.connectors.culture

import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import reactor.core.publisher.Mono
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Department for Culture, Media & Sport Connector
 * Provides access to cultural heritage, media licenses, and sports governance data
 */
@Service
class CultureMediaSportConnector {

    private val logger: Logger = LoggerFactory.getLogger(CultureMediaSportConnector::class.java)
    private val webClient = WebClient.builder()
        .baseUrl("https://api.culture.gov.uk")
        .build()

    /**
     * Verify media and broadcasting licenses
     */
    @Cacheable("media-licenses")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyMediaLicenses(
        nationalInsuranceNumber: String,
        organizationId: String? = null
    ): Mono<MediaLicenses> {
        logger.info("Verifying media licenses for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/licenses/media?ni={ni}&org={org}", nationalInsuranceNumber, organizationId)
            .retrieve()
            .bodyToMono(MediaLicenses::class.java)
            .doOnSuccess { result ->
                logger.info("Media licenses verified: ${result.activeLicenses.size} active licenses")
            }
            .onErrorReturn(MediaLicenses(
                activeLicenses = emptyList(),
                broadcastingPermits = emptyList(),
                copyrightRegistrations = emptyList()
            ))
    }

    /**
     * Get sports governance and coaching credentials
     */
    @Cacheable("sports-credentials")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getSportsCredentials(nationalInsuranceNumber: String): Mono<SportsCredentials> {
        logger.info("Fetching sports credentials for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/sports/credentials?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(SportsCredentials::class.java)
            .doOnSuccess { result ->
                logger.info("Sports credentials retrieved: ${result.activeCredentials.size} credentials")
            }
            .onErrorReturn(SportsCredentials(
                activeCredentials = emptyList(),
                coachingQualifications = emptyList(),
                sportsOrganisations = emptyList()
            ))
    }

    /**
     * Check cultural heritage involvement
     */
    @Cacheable("cultural-heritage")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCulturalHeritageInvolvement(nationalInsuranceNumber: String): Mono<CulturalHeritage> {
        logger.info("Checking cultural heritage involvement for NI: ${nationalInsuranceNumber.take(4)}****")
        
        return webClient.get()
            .uri("/v1/heritage/involvement?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(CulturalHeritage::class.java)
            .doOnSuccess { result ->
                logger.info("Cultural heritage involvement retrieved")
            }
            .onErrorReturn(CulturalHeritage(
                museumMemberships = emptyList(),
                heritageRoles = emptyList(),
                artsCouncilGrants = emptyList()
            ))
    }
}

// Data Classes
data class MediaLicenses(
    val activeLicenses: List<MediaLicense>,
    val broadcastingPermits: List<BroadcastingPermit>,
    val copyrightRegistrations: List<CopyrightRegistration>
)

data class MediaLicense(
    val licenseId: String,
    val type: String,
    val issueDate: String,
    val expiryDate: String,
    val status: String,
    val restrictions: List<String>
)

data class BroadcastingPermit(
    val permitId: String,
    val type: String,
    val frequency: String?,
    val coverage: String,
    val status: String
)

data class CopyrightRegistration(
    val registrationId: String,
    val workTitle: String,
    val type: String,
    val registrationDate: String,
    val status: String
)

data class SportsCredentials(
    val activeCredentials: List<SportsCredential>,
    val coachingQualifications: List<CoachingQualification>,
    val sportsOrganisations: List<SportsOrganisation>
)

data class SportsCredential(
    val credentialId: String,
    val sport: String,
    val level: String,
    val issueDate: String,
    val expiryDate: String,
    val status: String
)

data class CoachingQualification(
    val qualificationId: String,
    val sport: String,
    val level: String,
    val issuingBody: String,
    val issueDate: String
)

data class SportsOrganisation(
    val organisationId: String,
    val name: String,
    val role: String,
    val startDate: String,
    val status: String
)

data class CulturalHeritage(
    val museumMemberships: List<MuseumMembership>,
    val heritageRoles: List<HeritageRole>,
    val artsCouncilGrants: List<ArtsGrant>
)

data class MuseumMembership(
    val membershipId: String,
    val museum: String,
    val type: String,
    val startDate: String,
    val status: String
)

data class HeritageRole(
    val roleId: String,
    val organisation: String,
    val position: String,
    val startDate: String,
    val status: String
)

data class ArtsGrant(
    val grantId: String,
    val purpose: String,
    val amount: Double,
    val awardDate: String,
    val status: String
)