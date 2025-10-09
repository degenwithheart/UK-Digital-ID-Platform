package com.uk.gov.connectors.law

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
@RequestMapping("/api/connectors/law-enforcement")
class LawEnforcementConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(LawEnforcementConnector::class.java)

    @GetMapping("/criminal-record-check/{personName}/{dateOfBirth}")
    @Cacheable("criminal-records")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCriminalRecordCheck(
        @PathVariable personName: String,
        @PathVariable dateOfBirth: String
    ): Mono<CriminalRecordResponse> {
        logger.info("Getting criminal record check for: {}", personName)
        
        return webClient.get()
            .uri("https://api.dbs.gov.uk/criminal-records/v1/check?name={name}&dob={dob}", personName, dateOfBirth)
            .header("Authorization", "Bearer \${DBS_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val convictions = (response["convictions"] as? List<Map<String, Any>>) ?: emptyList()
                val cautions = (response["cautions"] as? List<Map<String, Any>>) ?: emptyList()
                
                CriminalRecordResponse(
                    personName = personName,
                    dateOfBirth = dateOfBirth,
                    checkId = response["checkId"] as? String ?: java.util.UUID.randomUUID().toString(),
                    clearance = response["clearance"] as? String ?: "UNKNOWN", // CLEAR, CAUTIONS, CONVICTIONS, ENHANCED_CHECK_REQUIRED
                    totalConvictions = convictions.size,
                    totalCautions = cautions.size,
                    riskLevel = calculateRiskLevel(convictions, cautions),
                    convictions = convictions.map { conviction ->
                        CriminalConviction(
                            offence = conviction["offence"] as? String ?: "UNKNOWN",
                            date = conviction["date"] as? String ?: "UNKNOWN",
                            sentence = conviction["sentence"] as? String ?: "UNKNOWN",
                            court = conviction["court"] as? String ?: "UNKNOWN",
                            spent = conviction["spent"] as? Boolean ?: false
                        )
                    },
                    cautions = cautions.map { caution ->
                        CriminalCaution(
                            offence = caution["offence"] as? String ?: "UNKNOWN",
                            date = caution["date"] as? String ?: "UNKNOWN",
                            issuingForce = caution["issuingForce"] as? String ?: "UNKNOWN",
                            spent = caution["spent"] as? Boolean ?: false
                        )
                    },
                    checkDate = java.time.Instant.now().toString()
                )
            }
            .doOnError { e -> logger.error("Error getting criminal record check for {}", personName, e) }
            .onErrorReturn(CriminalRecordResponse(
                personName = personName,
                dateOfBirth = dateOfBirth,
                checkId = "ERROR",
                clearance = "ERROR",
                totalConvictions = 0,
                totalCautions = 0,
                riskLevel = "HIGH",
                convictions = emptyList(),
                cautions = emptyList(),
                checkDate = java.time.Instant.now().toString()
            ))
    }

    @GetMapping("/court-records/{caseNumber}")
    @Cacheable("court-records")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCourtRecord(@PathVariable @Pattern(regexp = "^[A-Z]{2}\\d{8}$") caseNumber: String): Mono<CourtRecordResponse> {
        logger.info("Getting court record for case: {}", caseNumber)
        
        return webClient.get()
            .uri("https://api.courtsservice.gov.uk/cases/v1/{caseNumber}", caseNumber)
            .header("Authorization", "Bearer \${COURTS_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val hearings = (response["hearings"] as? List<Map<String, Any>>) ?: emptyList()
                val judgments = (response["judgments"] as? List<Map<String, Any>>) ?: emptyList()
                
                CourtRecordResponse(
                    caseNumber = caseNumber,
                    courtName = response["courtName"] as? String ?: "UNKNOWN",
                    caseType = response["caseType"] as? String ?: "UNKNOWN", // CIVIL, CRIMINAL, FAMILY
                    status = response["status"] as? String ?: "UNKNOWN", // ACTIVE, CLOSED, PENDING
                    parties = (response["parties"] as? List<String>) ?: emptyList(),
                    startDate = response["startDate"] as? String ?: "UNKNOWN",
                    endDate = response["endDate"] as? String,
                    judge = response["judge"] as? String ?: "UNKNOWN",
                    totalHearings = hearings.size,
                    hearings = hearings.map { hearing ->
                        CourtHearing(
                            hearingDate = hearing["hearingDate"] as? String ?: "UNKNOWN",
                            hearingType = hearing["hearingType"] as? String ?: "UNKNOWN",
                            outcome = hearing["outcome"] as? String ?: "UNKNOWN",
                            nextHearing = hearing["nextHearing"] as? String
                        )
                    },
                    judgments = judgments.map { judgment ->
                        CourtJudgment(
                            judgmentDate = judgment["judgmentDate"] as? String ?: "UNKNOWN",
                            judgmentType = judgment["judgmentType"] as? String ?: "UNKNOWN",
                            amount = judgment["amount"] as? Double ?: 0.0,
                            currency = judgment["currency"] as? String ?: "GBP",
                            satisfied = judgment["satisfied"] as? Boolean ?: false
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting court record for {}", caseNumber, e) }
            .onErrorReturn(CourtRecordResponse(
                caseNumber = caseNumber,
                courtName = "ERROR",
                caseType = "ERROR",
                status = "ERROR",
                parties = emptyList(),
                startDate = "ERROR",
                endDate = null,
                judge = "ERROR",
                totalHearings = 0,
                hearings = emptyList(),
                judgments = emptyList()
            ))
    }

    @GetMapping("/driving-penalties/{licenseNumber}")
    @Cacheable("driving-penalties")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getDrivingPenalties(@PathVariable @Pattern(regexp = "^[A-Z]{5}\\d{6}[A-Z]{2}\\d[A-Z]{2}$") licenseNumber: String): Mono<DrivingPenaltiesResponse> {
        logger.info("Getting driving penalties for license: {}", licenseNumber)
        
        return webClient.get()
            .uri("https://api.dvla.gov.uk/penalties/v1/{licenseNumber}", licenseNumber)
            .header("Authorization", "Bearer \${DVLA_PENALTIES_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val penalties = (response["penalties"] as? List<Map<String, Any>>) ?: emptyList()
                val points = penalties.sumOf { (it["points"] as? Int) ?: 0 }
                
                DrivingPenaltiesResponse(
                    licenseNumber = licenseNumber,
                    totalPenalties = penalties.size,
                    totalPoints = points,
                    activePenalties = penalties.count { (it["status"] as? String) == "ACTIVE" },
                    riskCategory = when {
                        points >= 12 -> "HIGH_RISK"
                        points >= 9 -> "MEDIUM_RISK"
                        points >= 6 -> "LOW_RISK"
                        else -> "MINIMAL_RISK"
                    },
                    disqualificationRisk = points >= 12,
                    penalties = penalties.map { penalty ->
                        DrivingPenalty(
                            offenceCode = penalty["offenceCode"] as? String ?: "UNKNOWN",
                            offenceDescription = penalty["offenceDescription"] as? String ?: "UNKNOWN",
                            date = penalty["date"] as? String ?: "UNKNOWN",
                            points = penalty["points"] as? Int ?: 0,
                            fine = penalty["fine"] as? Double ?: 0.0,
                            court = penalty["court"] as? String ?: "UNKNOWN",
                            status = penalty["status"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting driving penalties for {}", licenseNumber, e) }
            .onErrorReturn(DrivingPenaltiesResponse(
                licenseNumber = licenseNumber,
                totalPenalties = 0,
                totalPoints = 0,
                activePenalties = 0,
                riskCategory = "ERROR",
                disqualificationRisk = false,
                penalties = emptyList()
            ))
    }

    @PostMapping("/enhanced-dbs-check")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun requestEnhancedDBSCheck(@Valid @RequestBody request: EnhancedDBSRequest): Mono<EnhancedDBSResponse> {
        logger.info("Requesting enhanced DBS check for: {}", request.applicantName)
        
        return webClient.post()
            .uri("https://api.dbs.gov.uk/enhanced-checks/v1/request")
            .header("Authorization", "Bearer \${DBS_ENHANCED_API_KEY}")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                EnhancedDBSResponse(
                    applicationId = response["applicationId"] as? String ?: java.util.UUID.randomUUID().toString(),
                    applicantName = request.applicantName,
                    dateOfBirth = request.dateOfBirth,
                    position = request.position,
                    checkType = request.checkType,
                    status = response["status"] as? String ?: "PENDING", // PENDING, IN_PROGRESS, COMPLETE, ERROR
                    applicationDate = java.time.Instant.now().toString(),
                    estimatedCompletionDate = response["estimatedCompletionDate"] as? String ?: "UNKNOWN",
                    fee = response["fee"] as? Double ?: 0.0,
                    trackingReference = response["trackingReference"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error requesting enhanced DBS check for {}", request.applicantName, e) }
            .onErrorReturn(EnhancedDBSResponse(
                applicationId = "ERROR",
                applicantName = request.applicantName,
                dateOfBirth = request.dateOfBirth,
                position = request.position,
                checkType = request.checkType,
                status = "ERROR",
                applicationDate = java.time.Instant.now().toString(),
                estimatedCompletionDate = "ERROR",
                fee = 0.0,
                trackingReference = "ERROR"
            ))
    }

    private fun calculateRiskLevel(convictions: List<Map<String, Any>>, cautions: List<Map<String, Any>>): String {
        val recentConvictions = convictions.count { 
            val dateStr = it["date"] as? String ?: return@count false
            // Simple heuristic - consider convictions in last 5 years as recent
            try {
                val convictionYear = dateStr.substring(0, 4).toInt()
                val currentYear = java.time.Year.now().value
                currentYear - convictionYear <= 5
            } catch (e: Exception) { false }
        }
        
        return when {
            recentConvictions >= 2 -> "HIGH"
            recentConvictions == 1 -> "MEDIUM"
            cautions.isNotEmpty() -> "LOW"
            else -> "MINIMAL"
        }
    }
}

data class CriminalRecordResponse(
    val personName: String,
    val dateOfBirth: String,
    val checkId: String,
    val clearance: String,
    val totalConvictions: Int,
    val totalCautions: Int,
    val riskLevel: String,
    val convictions: List<CriminalConviction>,
    val cautions: List<CriminalCaution>,
    val checkDate: String
)

data class CriminalConviction(
    val offence: String,
    val date: String,
    val sentence: String,
    val court: String,
    val spent: Boolean
)

data class CriminalCaution(
    val offence: String,
    val date: String,
    val issuingForce: String,
    val spent: Boolean
)

data class CourtRecordResponse(
    val caseNumber: String,
    val courtName: String,
    val caseType: String,
    val status: String,
    val parties: List<String>,
    val startDate: String,
    val endDate: String?,
    val judge: String,
    val totalHearings: Int,
    val hearings: List<CourtHearing>,
    val judgments: List<CourtJudgment>
)

data class CourtHearing(
    val hearingDate: String,
    val hearingType: String,
    val outcome: String,
    val nextHearing: String?
)

data class CourtJudgment(
    val judgmentDate: String,
    val judgmentType: String,
    val amount: Double,
    val currency: String,
    val satisfied: Boolean
)

data class DrivingPenaltiesResponse(
    val licenseNumber: String,
    val totalPenalties: Int,
    val totalPoints: Int,
    val activePenalties: Int,
    val riskCategory: String,
    val disqualificationRisk: Boolean,
    val penalties: List<DrivingPenalty>
)

data class DrivingPenalty(
    val offenceCode: String,
    val offenceDescription: String,
    val date: String,
    val points: Int,
    val fine: Double,
    val court: String,
    val status: String
)

data class EnhancedDBSRequest(
    @field:NotBlank val applicantName: String,
    @field:NotBlank val dateOfBirth: String,
    @field:NotBlank val position: String,
    @field:NotBlank val checkType: String, // ENHANCED, ENHANCED_WITH_BARRED_LIST
    val organisationName: String?
)

data class EnhancedDBSResponse(
    val applicationId: String,
    val applicantName: String,
    val dateOfBirth: String,
    val position: String,
    val checkType: String,
    val status: String,
    val applicationDate: String,
    val estimatedCompletionDate: String,
    val fee: Double,
    val trackingReference: String
)