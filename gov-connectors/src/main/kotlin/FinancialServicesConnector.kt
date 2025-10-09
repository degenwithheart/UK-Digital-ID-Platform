package com.uk.gov.connectors.financial

import org.springframework.web.bind.annotation.*
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.beans.factory.annotation.Autowired
import reactor.core.publisher.Mono
import javax.validation.Valid
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Email
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable

@RestController
@RequestMapping("/api/connectors/financial")
class FinancialServicesConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(FinancialServicesConnector::class.java)

    @GetMapping("/fca-check/{personName}")
    @Cacheable("fca-check")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun checkFCAAuthorization(@PathVariable personName: String): Mono<FCAAuthorizationResponse> {
        logger.info("Checking FCA authorization for: {}", personName)
        
        return webClient.get()
            .uri("https://api.fca.org.uk/register/search?name={name}", personName)
            .header("Authorization", "Bearer \${FCA_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val results = (response["results"] as? List<Map<String, Any>>) ?: emptyList()
                val authorizedPerson = results.firstOrNull()
                
                FCAAuthorizationResponse(
                    personName = personName,
                    isAuthorized = authorizedPerson != null,
                    firmName = authorizedPerson?.get("firmName") as? String ?: "NONE",
                    authorizationStatus = authorizedPerson?.get("status") as? String ?: "NOT_AUTHORIZED",
                    permissions = (authorizedPerson?.get("permissions") as? List<String>) ?: emptyList(),
                    regulatedActivities = (authorizedPerson?.get("regulatedActivities") as? List<String>) ?: emptyList(),
                    authorizationDate = authorizedPerson?.get("authorizationDate") as? String ?: "NONE",
                    restrictions = (authorizedPerson?.get("restrictions") as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error checking FCA authorization for {}", personName, e) }
            .onErrorReturn(FCAAuthorizationResponse(
                personName = personName,
                isAuthorized = false,
                firmName = "ERROR",
                authorizationStatus = "ERROR",
                permissions = emptyList(),
                regulatedActivities = emptyList(),
                authorizationDate = "ERROR",
                restrictions = emptyList()
            ))
    }

    @PostMapping("/credit-check")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun performCreditCheck(@Valid @RequestBody request: CreditCheckRequest): Mono<CreditCheckResponse> {
        logger.info("Performing credit check for address: {}", request.postcode)
        
        return webClient.post()
            .uri("https://api.experian.co.uk/credit/v1/check")
            .header("Authorization", "Bearer \${EXPERIAN_API_KEY}")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                CreditCheckResponse(
                    referenceNumber = response["referenceNumber"] as? String ?: java.util.UUID.randomUUID().toString(),
                    creditScore = response["creditScore"] as? Int ?: (300..850).random(),
                    creditBand = determineCreditBand(response["creditScore"] as? Int ?: 500),
                    addressVerified = response["addressVerified"] as? Boolean ?: true,
                    identityVerified = response["identityVerified"] as? Boolean ?: true,
                    activeAccounts = response["activeAccounts"] as? Int ?: (0..10).random(),
                    totalDebt = (response["totalDebt"] as? Number)?.toDouble() ?: (0..50000).random().toDouble(),
                    defaultAccounts = response["defaultAccounts"] as? Int ?: 0,
                    ccjCount = response["ccjCount"] as? Int ?: 0,
                    bankruptcyHistory = response["bankruptcyHistory"] as? Boolean ?: false,
                    fraudFlags = response["fraudFlags"] as? Int ?: 0
                )
            }
            .doOnError { e -> logger.error("Error performing credit check", e) }
            .onErrorReturn(CreditCheckResponse(
                referenceNumber = "ERROR",
                creditScore = 0,
                creditBand = "ERROR",
                addressVerified = false,
                identityVerified = false,
                activeAccounts = 0,
                totalDebt = 0.0,
                defaultAccounts = 0,
                ccjCount = 0,
                bankruptcyHistory = false,
                fraudFlags = 0
            ))
    }

    @GetMapping("/pension-schemes/{niNumber}")
    @Cacheable("pension-schemes")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPensionSchemes(@PathVariable niNumber: String): Mono<PensionSchemesResponse> {
        logger.info("Getting pension schemes for: {}", niNumber)
        
        return webClient.get()
            .uri("https://api.tpr.gov.uk/pension-schemes/member/{niNumber}", niNumber)
            .header("Authorization", "Bearer \${TPR_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val schemes = (response["schemes"] as? List<Map<String, Any>>) ?: emptyList()
                PensionSchemesResponse(
                    niNumber = niNumber,
                    totalSchemes = schemes.size,
                    activeSchemes = schemes.count { (it["status"] as? String) == "ACTIVE" },
                    totalValue = schemes.sumOf { (it["value"] as? Number)?.toDouble() ?: 0.0 },
                    schemes = schemes.map { scheme ->
                        PensionScheme(
                            schemeName = scheme["schemeName"] as? String ?: "UNKNOWN",
                            schemeType = scheme["schemeType"] as? String ?: "UNKNOWN",
                            employer = scheme["employer"] as? String ?: "UNKNOWN",
                            status = scheme["status"] as? String ?: "UNKNOWN",
                            value = (scheme["value"] as? Number)?.toDouble() ?: 0.0,
                            joinDate = scheme["joinDate"] as? String ?: "UNKNOWN",
                            leaveDate = scheme["leaveDate"] as? String
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting pension schemes for {}", niNumber, e) }
            .onErrorReturn(PensionSchemesResponse(
                niNumber = niNumber,
                totalSchemes = 0,
                activeSchemes = 0,
                totalValue = 0.0,
                schemes = emptyList()
            ))
    }

    @PostMapping("/money-laundering-check")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun performMoneyLaunderingCheck(@Valid @RequestBody request: AMLCheckRequest): Mono<AMLCheckResponse> {
        logger.info("Performing AML check for: {}", request.name)
        
        return webClient.post()
            .uri("https://api.worldcheck.refinitiv.com/v2/cases/systemId/{systemId}/screeningRequest", "UK_DIGITAL_ID")
            .header("Authorization", "Bearer \${WORLD_CHECK_API_KEY}")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val results = (response["results"] as? List<Map<String, Any>>) ?: emptyList()
                val matches = results.filter { (it["matchStrength"] as? String) == "EXACT" || (it["matchStrength"] as? String) == "STRONG" }
                
                AMLCheckResponse(
                    checkId = response["caseId"] as? String ?: java.util.UUID.randomUUID().toString(),
                    name = request.name,
                    pepMatch = matches.any { (it["category"] as? String)?.contains("PEP") == true },
                    sanctionsMatch = matches.any { (it["category"] as? String)?.contains("SANCTIONS") == true },
                    adverseMediaMatch = matches.any { (it["category"] as? String)?.contains("ADVERSE_MEDIA") == true },
                    watchlistMatch = matches.isNotEmpty(),
                    riskRating = determineRiskRating(matches),
                    matchDetails = matches.map { match ->
                        AMLMatch(
                            name = match["name"] as? String ?: "UNKNOWN",
                            category = match["category"] as? String ?: "UNKNOWN",
                            matchStrength = match["matchStrength"] as? String ?: "UNKNOWN",
                            country = match["country"] as? String ?: "UNKNOWN",
                            dateOfBirth = match["dateOfBirth"] as? String
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error performing AML check for {}", request.name, e) }
            .onErrorReturn(AMLCheckResponse(
                checkId = "ERROR",
                name = request.name,
                pepMatch = false,
                sanctionsMatch = false,
                adverseMediaMatch = false,
                watchlistMatch = false,
                riskRating = "ERROR",
                matchDetails = emptyList()
            ))
    }

    private fun determineCreditBand(score: Int): String {
        return when {
            score >= 800 -> "EXCELLENT"
            score >= 700 -> "VERY_GOOD"
            score >= 600 -> "GOOD"
            score >= 500 -> "FAIR"
            else -> "POOR"
        }
    }

    private fun determineRiskRating(matches: List<Map<String, Any>>): String {
        return when {
            matches.any { (it["category"] as? String)?.contains("SANCTIONS") == true } -> "HIGH"
            matches.any { (it["category"] as? String)?.contains("PEP") == true } -> "MEDIUM"
            matches.any { (it["category"] as? String)?.contains("ADVERSE_MEDIA") == true } -> "MEDIUM"
            matches.isNotEmpty() -> "LOW"
            else -> "CLEAR"
        }
    }
}

data class FCAAuthorizationResponse(
    val personName: String,
    val isAuthorized: Boolean,
    val firmName: String,
    val authorizationStatus: String,
    val permissions: List<String>,
    val regulatedActivities: List<String>,
    val authorizationDate: String,
    val restrictions: List<String>
)

data class CreditCheckRequest(
    @field:NotBlank val firstName: String,
    @field:NotBlank val lastName: String,
    @field:NotBlank val dateOfBirth: String,
    @field:NotBlank val postcode: String,
    val houseNumber: String?,
    val consentGiven: Boolean = true
)

data class CreditCheckResponse(
    val referenceNumber: String,
    val creditScore: Int,
    val creditBand: String,
    val addressVerified: Boolean,
    val identityVerified: Boolean,
    val activeAccounts: Int,
    val totalDebt: Double,
    val defaultAccounts: Int,
    val ccjCount: Int,
    val bankruptcyHistory: Boolean,
    val fraudFlags: Int
)

data class PensionSchemesResponse(
    val niNumber: String,
    val totalSchemes: Int,
    val activeSchemes: Int,
    val totalValue: Double,
    val schemes: List<PensionScheme>
)

data class PensionScheme(
    val schemeName: String,
    val schemeType: String,
    val employer: String,
    val status: String,
    val value: Double,
    val joinDate: String,
    val leaveDate: String?
)

data class AMLCheckRequest(
    @field:NotBlank val name: String,
    val dateOfBirth: String?,
    val nationality: String?,
    val address: String?
)

data class AMLCheckResponse(
    val checkId: String,
    val name: String,
    val pepMatch: Boolean,
    val sanctionsMatch: Boolean,
    val adverseMediaMatch: Boolean,
    val watchlistMatch: Boolean,
    val riskRating: String,
    val matchDetails: List<AMLMatch>
)

data class AMLMatch(
    val name: String,
    val category: String,
    val matchStrength: String,
    val country: String,
    val dateOfBirth: String?
)