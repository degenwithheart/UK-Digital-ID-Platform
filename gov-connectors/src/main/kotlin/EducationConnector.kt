package com.uk.gov.connectors.education

import org.springframework.web.bind.annotation.*
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.beans.factory.annotation.Autowired
import reactor.core.publisher.Mono
import javax.validation.Valid
import javax.validation.constraints.NotBlank
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable

@RestController
@RequestMapping("/api/connectors/education")
class EducationConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(EducationConnector::class.java)

    @GetMapping("/qualifications/{candidateNumber}")
    @Cacheable("education-qualifications")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getQualifications(@PathVariable candidateNumber: String): Mono<QualificationsResponse> {
        logger.info("Getting qualifications for candidate: {}", candidateNumber)
        
        return webClient.get()
            .uri("https://api.ucas.com/qualifications/v1/{candidateNumber}", candidateNumber)
            .header("Authorization", "Bearer \${UCAS_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val qualifications = (response["qualifications"] as? List<Map<String, Any>>) ?: emptyList()
                QualificationsResponse(
                    candidateNumber = candidateNumber,
                    totalQualifications = qualifications.size,
                    aLevels = qualifications.filter { (it["type"] as? String) == "A_LEVEL" }.size,
                    gcses = qualifications.filter { (it["type"] as? String) == "GCSE" }.size,
                    degrees = qualifications.filter { (it["type"] as? String) == "DEGREE" }.size,
                    qualifications = qualifications.map { qual ->
                        Qualification(
                            type = qual["type"] as? String ?: "UNKNOWN",
                            subject = qual["subject"] as? String ?: "UNKNOWN",
                            grade = qual["grade"] as? String ?: "UNKNOWN",
                            year = qual["year"] as? Int ?: 0,
                            institution = qual["institution"] as? String ?: "UNKNOWN",
                            verified = qual["verified"] as? Boolean ?: false
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting qualifications for {}", candidateNumber, e) }
            .onErrorReturn(QualificationsResponse(
                candidateNumber = candidateNumber,
                totalQualifications = 0,
                aLevels = 0,
                gcses = 0,
                degrees = 0,
                qualifications = emptyList()
            ))
    }

    @GetMapping("/university-enrollment/{studentId}")
    @Cacheable("university-enrollment")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getUniversityEnrollment(@PathVariable studentId: String): Mono<UniversityEnrollmentResponse> {
        logger.info("Getting university enrollment for student: {}", studentId)
        
        return webClient.get()
            .uri("https://api.hesa.ac.uk/students/v1/{studentId}", studentId)
            .header("Authorization", "Bearer \${HESA_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                UniversityEnrollmentResponse(
                    studentId = studentId,
                    currentlyEnrolled = response["currentlyEnrolled"] as? Boolean ?: false,
                    institution = response["institution"] as? String ?: "UNKNOWN",
                    course = response["course"] as? String ?: "UNKNOWN",
                    level = response["level"] as? String ?: "UNKNOWN", // UNDERGRADUATE, POSTGRADUATE
                    startDate = response["startDate"] as? String ?: "UNKNOWN",
                    expectedEndDate = response["expectedEndDate"] as? String ?: "UNKNOWN",
                    studyMode = response["studyMode"] as? String ?: "UNKNOWN", // FULL_TIME, PART_TIME
                    fundingSource = response["fundingSource"] as? String ?: "UNKNOWN"
                )
            }
            .doOnError { e -> logger.error("Error getting university enrollment for {}", studentId, e) }
            .onErrorReturn(UniversityEnrollmentResponse(
                studentId = studentId,
                currentlyEnrolled = false,
                institution = "ERROR",
                course = "ERROR",
                level = "ERROR",
                startDate = "ERROR",
                expectedEndDate = "ERROR",
                studyMode = "ERROR",
                fundingSource = "ERROR"
            ))
    }

    @GetMapping("/professional-qualifications/{personName}")
    @Cacheable("professional-qualifications")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getProfessionalQualifications(@PathVariable personName: String): Mono<ProfessionalQualificationsResponse> {
        logger.info("Getting professional qualifications for: {}", personName)
        
        return webClient.get()
            .uri("https://api.ofqual.gov.uk/qualifications/search?name={name}", personName)
            .header("Authorization", "Bearer \${OFQUAL_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val qualifications = (response["qualifications"] as? List<Map<String, Any>>) ?: emptyList()
                ProfessionalQualificationsResponse(
                    personName = personName,
                    totalQualifications = qualifications.size,
                    professionalBodies = qualifications.mapNotNull { it["awardingBody"] as? String }.distinct(),
                    qualifications = qualifications.map { qual ->
                        ProfessionalQualification(
                            title = qual["title"] as? String ?: "UNKNOWN",
                            level = qual["level"] as? String ?: "UNKNOWN",
                            awardingBody = qual["awardingBody"] as? String ?: "UNKNOWN",
                            dateAwarded = qual["dateAwarded"] as? String ?: "UNKNOWN",
                            expiryDate = qual["expiryDate"] as? String,
                            status = qual["status"] as? String ?: "ACTIVE",
                            certificateNumber = qual["certificateNumber"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting professional qualifications for {}", personName, e) }
            .onErrorReturn(ProfessionalQualificationsResponse(
                personName = personName,
                totalQualifications = 0,
                professionalBodies = emptyList(),
                qualifications = emptyList()
            ))
    }

    @PostMapping("/verify-degree")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyDegree(@Valid @RequestBody request: DegreeVerificationRequest): Mono<DegreeVerificationResponse> {
        logger.info("Verifying degree for: {}", request.graduateName)
        
        return webClient.post()
            .uri("https://api.hedd.ac.uk/verify")
            .header("Authorization", "Bearer \${HEDD_API_KEY}")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                DegreeVerificationResponse(
                    verificationId = response["verificationId"] as? String ?: java.util.UUID.randomUUID().toString(),
                    graduateName = request.graduateName,
                    verified = response["verified"] as? Boolean ?: false,
                    institution = response["institution"] as? String ?: "UNKNOWN",
                    degreeTitle = response["degreeTitle"] as? String ?: "UNKNOWN",
                    classification = response["classification"] as? String ?: "UNKNOWN",
                    graduationDate = response["graduationDate"] as? String ?: "UNKNOWN",
                    verificationDate = java.time.Instant.now().toString(),
                    verificationStatus = if (response["verified"] as? Boolean == true) "VERIFIED" else "NOT_VERIFIED"
                )
            }
            .doOnError { e -> logger.error("Error verifying degree for {}", request.graduateName, e) }
            .onErrorReturn(DegreeVerificationResponse(
                verificationId = "ERROR",
                graduateName = request.graduateName,
                verified = false,
                institution = "ERROR",
                degreeTitle = "ERROR",
                classification = "ERROR",
                graduationDate = "ERROR",
                verificationDate = java.time.Instant.now().toString(),
                verificationStatus = "ERROR"
            ))
    }
}

data class QualificationsResponse(
    val candidateNumber: String,
    val totalQualifications: Int,
    val aLevels: Int,
    val gcses: Int,
    val degrees: Int,
    val qualifications: List<Qualification>
)

data class Qualification(
    val type: String,
    val subject: String,
    val grade: String,
    val year: Int,
    val institution: String,
    val verified: Boolean
)

data class UniversityEnrollmentResponse(
    val studentId: String,
    val currentlyEnrolled: Boolean,
    val institution: String,
    val course: String,
    val level: String,
    val startDate: String,
    val expectedEndDate: String,
    val studyMode: String,
    val fundingSource: String
)

data class ProfessionalQualificationsResponse(
    val personName: String,
    val totalQualifications: Int,
    val professionalBodies: List<String>,
    val qualifications: List<ProfessionalQualification>
)

data class ProfessionalQualification(
    val title: String,
    val level: String,
    val awardingBody: String,
    val dateAwarded: String,
    val expiryDate: String?,
    val status: String,
    val certificateNumber: String
)

data class DegreeVerificationRequest(
    @field:NotBlank val graduateName: String,
    @field:NotBlank val institution: String,
    @field:NotBlank val degreeTitle: String,
    val graduationYear: Int?
)

data class DegreeVerificationResponse(
    val verificationId: String,
    val graduateName: String,
    val verified: Boolean,
    val institution: String,
    val degreeTitle: String,
    val classification: String,
    val graduationDate: String,
    val verificationDate: String,
    val verificationStatus: String
)