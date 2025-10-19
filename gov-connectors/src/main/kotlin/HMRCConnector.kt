package com.uk.gov.connectors

import org.springframework.web.bind.annotation.*
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.beans.factory.annotation.Autowired
import reactor.core.publisher.Mono
import javax.validation.Valid
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Min
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import com.uk.gov.connectors.service.SyncService

@RestController
@RequestMapping("/api/connectors")
class HMRCConnector @Autowired constructor(
    private val webClient: WebClient,
    private val syncService: SyncService
) {

    private val logger: Logger = LoggerFactory.getLogger(HMRCConnector::class.java)

    @PostMapping("/sync")
    fun syncCitizenData(@Valid @RequestBody payload: SyncRequest): Mono<Map<String, Any>> {
        logger.info("Syncing citizen data for {}", payload.citizenId)
        // Simulate calling HMRC API with timeout for speed
        return webClient.post()
            .uri("https://api.hmrc.gov.uk/test/individuals/income") // Mock URL
            .bodyValue(payload)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .doOnNext { response ->
                // Publish sync event
                syncService.publishEvent("hmrc_data_synced", mapOf("citizen_id" to payload.citizenId, "status" to "success"))
                // Encrypt sensitive data
                if (response.containsKey("taxPaid")) {
                    response["taxPaid"] = syncService.encryptData(response["taxPaid"].toString())
                }
            }
            .doOnError { e ->
                logger.error("Error syncing citizen data for {}", payload.citizenId, e)
                syncService.publishEvent("hmrc_sync_failed", mapOf("citizen_id" to payload.citizenId, "error" to e.message))
            }
            .onErrorReturn(mapOf("status" to "error", "message" to "HMRC API unavailable"))
    }

    @GetMapping("/tax-records/{nino}")
    fun getTaxRecords(@PathVariable @NotBlank nino: String): Mono<Map<String, Any>> {
        val cacheKey = "hmrc:tax:$nino"
        return syncService.getCachedData(cacheKey)
            .flatMap { cached ->
                if (cached != null) {
                    Mono.just(com.fasterxml.jackson.databind.ObjectMapper().readValue(cached, Map::class.java))
                } else {
                    webClient.get()
                        .uri("https://api.hmrc.gov.uk/test/individuals/income/$nino")
                        .retrieve()
                        .bodyToMono(Map::class.java)
                        .defaultIfEmpty(mapOf("nino" to nino, "taxPaid" to 15000.0, "status" to "verified"))
                        .doOnNext { data ->
                            val json = com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(data)
                            syncService.cacheData(cacheKey, json, 3600) // cache for 1 hour
                        }
                }
            }
    }

    @PostMapping("/verify-eligibility")
    fun verifyEligibility(@Valid @RequestBody request: EligibilityRequest): Mono<EligibilityResponse> {
        // Simulate eligibility check with fast computation
        return Mono.just(
            EligibilityResponse(
                eligible = request.income < 20000,
                benefits = if (request.income < 20000) listOf("Universal Credit", "Housing Benefit") else emptyList()
            )
        )
    }

    @GetMapping("/vat-status/{vatNumber}")
    @Cacheable("hmrc-vat")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getVATStatus(@PathVariable @Pattern(regexp = "^GB[0-9]{9}$") vatNumber: String): Mono<VATStatusResponse> {
        logger.info("Getting VAT status for: {}", vatNumber)
        
        return webClient.get()
            .uri("https://api.hmrc.gov.uk/organisations/vat/{vatNumber}", vatNumber)
            .header("Authorization", "Bearer \${HMRC_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                VATStatusResponse(
                    vatNumber = vatNumber,
                    status = response["status"] as? String ?: "ACTIVE",
                    registrationDate = response["registrationDate"] as? String ?: "UNKNOWN",
                    deregistrationDate = response["deregistrationDate"] as? String,
                    nextReturn = response["nextReturn"] as? String ?: "UNKNOWN",
                    outstandingAmount = (response["outstandingAmount"] as? Number)?.toDouble() ?: 0.0
                )
            }
            .doOnError { e -> logger.error("Error getting VAT status for {}", vatNumber, e) }
            .onErrorReturn(VATStatusResponse(
                vatNumber = vatNumber,
                status = "ERROR",
                registrationDate = "ERROR",
                deregistrationDate = null,
                nextReturn = "ERROR", 
                outstandingAmount = 0.0
            ))
    }

    @GetMapping("/paye-records/{payeReference}")
    @Cacheable("hmrc-paye")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPAYERecords(@PathVariable payeReference: String): Mono<PAYERecordsResponse> {
        logger.info("Getting PAYE records for: {}", payeReference)
        
        return webClient.get()
            .uri("https://api.hmrc.gov.uk/employers/paye/{payeReference}", payeReference)
            .header("Authorization", "Bearer \${HMRC_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                PAYERecordsResponse(
                    payeReference = payeReference,
                    employerName = response["employerName"] as? String ?: "UNKNOWN",
                    status = response["status"] as? String ?: "ACTIVE",
                    numberOfEmployees = response["numberOfEmployees"] as? Int ?: 0,
                    lastReturn = response["lastReturn"] as? String ?: "UNKNOWN",
                    outstandingLiability = (response["outstandingLiability"] as? Number)?.toDouble() ?: 0.0
                )
            }
            .doOnError { e -> logger.error("Error getting PAYE records for {}", payeReference, e) }
            .onErrorReturn(PAYERecordsResponse(
                payeReference = payeReference,
                employerName = "ERROR",
                status = "ERROR",
                numberOfEmployees = 0,
                lastReturn = "ERROR",
                outstandingLiability = 0.0
            ))
    }

    @GetMapping("/corporation-tax/{companyNumber}")
    @Cacheable("hmrc-ct")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCorporationTaxStatus(@PathVariable companyNumber: String): Mono<CorporationTaxResponse> {
        logger.info("Getting corporation tax status for: {}", companyNumber)
        
        return webClient.get()
            .uri("https://api.hmrc.gov.uk/organisations/corporation-tax/{companyNumber}", companyNumber)
            .header("Authorization", "Bearer \${HMRC_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                CorporationTaxResponse(
                    companyNumber = companyNumber,
                    status = response["status"] as? String ?: "ACTIVE",
                    nextReturn = response["nextReturn"] as? String ?: "UNKNOWN",
                    lastReturn = response["lastReturn"] as? String ?: "UNKNOWN",
                    outstandingAmount = (response["outstandingAmount"] as? Number)?.toDouble() ?: 0.0,
                    accountingPeriodEnd = response["accountingPeriodEnd"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error getting corporation tax status for {}", companyNumber, e) }
            .onErrorReturn(CorporationTaxResponse(
                companyNumber = companyNumber,
                status = "ERROR",
                nextReturn = "ERROR",
                lastReturn = "ERROR", 
                outstandingAmount = 0.0,
                accountingPeriodEnd = "ERROR"
            ))
    }
}

data class SyncRequest(
    @field:NotBlank val citizenId: String,
    @field:Min(0) val dataSize: Int
)

data class EligibilityRequest(
    @field:NotBlank val nino: String,
    @field:Min(0) val income: Double
)

data class EligibilityResponse(val eligible: Boolean, val benefits: List<String>)

data class VATStatusResponse(
    val vatNumber: String,
    val status: String,
    val registrationDate: String,
    val deregistrationDate: String?,
    val nextReturn: String,
    val outstandingAmount: Double
)

data class PAYERecordsResponse(
    val payeReference: String,
    val employerName: String,
    val status: String,
    val numberOfEmployees: Int,
    val lastReturn: String,
    val outstandingLiability: Double
)

data class CorporationTaxResponse(
    val companyNumber: String,
    val status: String,
    val nextReturn: String,
    val lastReturn: String,
    val outstandingAmount: Double,
    val accountingPeriodEnd: String
)