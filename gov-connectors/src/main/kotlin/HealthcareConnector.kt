package com.uk.gov.connectors.healthcare

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
@RequestMapping("/api/connectors/healthcare")
class HealthcareConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(HealthcareConnector::class.java)

    @GetMapping("/gp-registration/{nhsNumber}")
    @Cacheable("gp-registration")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getGPRegistration(@PathVariable @Pattern(regexp = "^\\d{10}$") nhsNumber: String): Mono<GPRegistrationResponse> {
        logger.info("Getting GP registration for NHS number: {}", nhsNumber)
        
        return webClient.get()
            .uri("https://api.spine.nhs.uk/gp-registration/v1/{nhsNumber}", nhsNumber)
            .header("Authorization", "Bearer \${NHS_SPINE_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                GPRegistrationResponse(
                    nhsNumber = nhsNumber,
                    registered = response["registered"] as? Boolean ?: false,
                    gpPracticeCode = response["gpPracticeCode"] as? String ?: "UNKNOWN",
                    gpPracticeName = response["gpPracticeName"] as? String ?: "UNKNOWN",
                    gpPracticeAddress = response["gpPracticeAddress"] as? String ?: "UNKNOWN",
                    registrationDate = response["registrationDate"] as? String ?: "UNKNOWN",
                    gpName = response["gpName"] as? String ?: "UNKNOWN",
                    ccgCode = response["ccgCode"] as? String ?: "UNKNOWN",
                    ccgName = response["ccgName"] as? String ?: "UNKNOWN",
                    dispensingPractice = response["dispensingPractice"] as? Boolean ?: false,
                    listSize = response["listSize"] as? Int ?: 0,
                    openingHours = (response["openingHours"] as? Map<String, String>) ?: emptyMap()
                )
            }
            .doOnError { e -> logger.error("Error getting GP registration for {}", nhsNumber, e) }
            .onErrorReturn(GPRegistrationResponse(
                nhsNumber = nhsNumber,
                registered = false,
                gpPracticeCode = "ERROR",
                gpPracticeName = "ERROR",
                gpPracticeAddress = "ERROR",
                registrationDate = "ERROR",
                gpName = "ERROR",
                ccgCode = "ERROR",
                ccgName = "ERROR",
                dispensingPractice = false,
                listSize = 0,
                openingHours = emptyMap()
            ))
    }

    @GetMapping("/professional-registration/{gmpNumber}")
    @Cacheable("professional-registration")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getMedicalProfessionalRegistration(@PathVariable gmpNumber: String): Mono<MedicalProfessionalResponse> {
        logger.info("Getting medical professional registration for GMP: {}", gmpNumber)
        
        return webClient.get()
            .uri("https://api.gmc-uk.org/doctors/v1/{gmpNumber}", gmpNumber)
            .header("Authorization", "Bearer \${GMC_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val qualifications = (response["qualifications"] as? List<Map<String, Any>>) ?: emptyList()
                val specialties = (response["specialties"] as? List<Map<String, Any>>) ?: emptyList()
                
                MedicalProfessionalResponse(
                    gmpNumber = gmpNumber,
                    fullName = response["fullName"] as? String ?: "UNKNOWN",
                    registrationStatus = response["registrationStatus"] as? String ?: "UNKNOWN",
                    licenseToPractice = response["licenseToPractice"] as? Boolean ?: false,
                    registrationDate = response["registrationDate"] as? String ?: "UNKNOWN",
                    currentEmployer = response["currentEmployer"] as? String ?: "UNKNOWN",
                    primaryWorkplace = response["primaryWorkplace"] as? String ?: "UNKNOWN",
                    qualifications = qualifications.map { qual ->
                        MedicalQualification(
                            qualification = qual["qualification"] as? String ?: "UNKNOWN",
                            institution = qual["institution"] as? String ?: "UNKNOWN",
                            dateObtained = qual["dateObtained"] as? String ?: "UNKNOWN",
                            country = qual["country"] as? String ?: "UNKNOWN"
                        )
                    },
                    specialties = specialties.map { spec ->
                        MedicalSpecialty(
                            specialty = spec["specialty"] as? String ?: "UNKNOWN",
                            certificationDate = spec["certificationDate"] as? String ?: "UNKNOWN",
                            certifyingBody = spec["certifyingBody"] as? String ?: "UNKNOWN",
                            status = spec["status"] as? String ?: "UNKNOWN"
                        )
                    },
                    restrictions = (response["restrictions"] as? List<String>) ?: emptyList(),
                    warnings = (response["warnings"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting medical professional registration for {}", gmpNumber, e) }
            .onErrorReturn(MedicalProfessionalResponse(
                gmpNumber = gmpNumber,
                fullName = "ERROR",
                registrationStatus = "ERROR",
                licenseToPractice = false,
                registrationDate = "ERROR",
                currentEmployer = "ERROR",
                primaryWorkplace = "ERROR",
                qualifications = emptyList(),
                specialties = emptyList(),
                restrictions = emptyList(),
                warnings = emptyList()
            ))
    }

    @GetMapping("/pharmacy-registration/{gphcNumber}")
    @Cacheable("pharmacy-registration")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPharmacyRegistration(@PathVariable gphcNumber: String): Mono<PharmacyRegistrationResponse> {
        logger.info("Getting pharmacy registration for GPhC: {}", gphcNumber)
        
        return webClient.get()
            .uri("https://api.pharmacyregulation.org/pharmacists/v1/{gphcNumber}", gphcNumber)
            .header("Authorization", "Bearer \${GPHC_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                PharmacyRegistrationResponse(
                    gphcNumber = gphcNumber,
                    fullName = response["fullName"] as? String ?: "UNKNOWN",
                    registrationStatus = response["registrationStatus"] as? String ?: "UNKNOWN",
                    registrationClass = response["registrationClass"] as? String ?: "UNKNOWN", // PHARMACIST, PHARMACY_TECHNICIAN
                    registrationDate = response["registrationDate"] as? String ?: "UNKNOWN",
                    expiryDate = response["expiryDate"] as? String ?: "UNKNOWN",
                    currentEmployer = response["currentEmployer"] as? String ?: "UNKNOWN",
                    workplaceAddress = response["workplaceAddress"] as? String ?: "UNKNOWN",
                    independentPrescriber = response["independentPrescriber"] as? Boolean ?: false,
                    supplementaryPrescriber = response["supplementaryPrescriber"] as? Boolean ?: false,
                    cpdCompliant = response["cpdCompliant"] as? Boolean ?: false,
                    annotations = (response["annotations"] as? List<String>) ?: emptyList(),
                    conditions = (response["conditions"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting pharmacy registration for {}", gphcNumber, e) }
            .onErrorReturn(PharmacyRegistrationResponse(
                gphcNumber = gphcNumber,
                fullName = "ERROR",
                registrationStatus = "ERROR",
                registrationClass = "ERROR",
                registrationDate = "ERROR",
                expiryDate = "ERROR",
                currentEmployer = "ERROR",
                workplaceAddress = "ERROR",
                independentPrescriber = false,
                supplementaryPrescriber = false,
                cpdCompliant = false,
                annotations = emptyList(),
                conditions = emptyList()
            ))
    }

    @GetMapping("/health-screening/{nhsNumber}")
    @Cacheable("health-screening")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getHealthScreeningStatus(@PathVariable @Pattern(regexp = "^\\d{10}$") nhsNumber: String): Mono<HealthScreeningResponse> {
        logger.info("Getting health screening status for NHS number: {}", nhsNumber)
        
        return webClient.get()
            .uri("https://api.nhsscreening.nhs.uk/screening/v1/{nhsNumber}", nhsNumber)
            .header("Authorization", "Bearer \${NHS_SCREENING_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val screenings = (response["screenings"] as? List<Map<String, Any>>) ?: emptyList()
                HealthScreeningResponse(
                    nhsNumber = nhsNumber,
                    totalScreenings = screenings.size,
                    upToDateScreenings = screenings.count { (it["status"] as? String) == "UP_TO_DATE" },
                    overdueScreenings = screenings.count { (it["status"] as? String) == "OVERDUE" },
                    screenings = screenings.map { screening ->
                        HealthScreening(
                            type = screening["type"] as? String ?: "UNKNOWN",
                            lastScreeningDate = screening["lastScreeningDate"] as? String,
                            nextDueDate = screening["nextDueDate"] as? String ?: "UNKNOWN",
                            status = screening["status"] as? String ?: "UNKNOWN",
                            result = screening["result"] as? String,
                            location = screening["location"] as? String ?: "UNKNOWN",
                            invitationSent = screening["invitationSent"] as? Boolean ?: false
                        )
                    },
                    eligibleScreenings = (response["eligibleScreenings"] as? List<String>) ?: emptyList(),
                    excludedScreenings = (response["excludedScreenings"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting health screening status for {}", nhsNumber, e) }
            .onErrorReturn(HealthScreeningResponse(
                nhsNumber = nhsNumber,
                totalScreenings = 0,
                upToDateScreenings = 0,
                overdueScreenings = 0,
                screenings = emptyList(),
                eligibleScreenings = emptyList(),
                excludedScreenings = emptyList()
            ))
    }
}

data class GPRegistrationResponse(
    val nhsNumber: String,
    val registered: Boolean,
    val gpPracticeCode: String,
    val gpPracticeName: String,
    val gpPracticeAddress: String,
    val registrationDate: String,
    val gpName: String,
    val ccgCode: String,
    val ccgName: String,
    val dispensingPractice: Boolean,
    val listSize: Int,
    val openingHours: Map<String, String>
)

data class MedicalProfessionalResponse(
    val gmpNumber: String,
    val fullName: String,
    val registrationStatus: String,
    val licenseTopractice: Boolean,
    val registrationDate: String,
    val currentEmployer: String,
    val primaryWorkplace: String,
    val qualifications: List<MedicalQualification>,
    val specialties: List<MedicalSpecialty>,
    val restrictions: List<String>,
    val warnings: List<String>
)

data class MedicalQualification(
    val qualification: String,
    val institution: String,
    val dateObtained: String,
    val country: String
)

data class MedicalSpecialty(
    val specialty: String,
    val certificationDate: String,
    val certifyingBody: String,
    val status: String
)

data class PharmacyRegistrationResponse(
    val gphcNumber: String,
    val fullName: String,
    val registrationStatus: String,
    val registrationClass: String,
    val registrationDate: String,
    val expiryDate: String,
    val currentEmployer: String,
    val workplaceAddress: String,
    val independentPrescriber: Boolean,
    val supplementaryPrescriber: Boolean,
    val cpdCompliant: Boolean,
    val annotations: List<String>,
    val conditions: List<String>
)

data class HealthScreeningResponse(
    val nhsNumber: String,
    val totalScreenings: Int,
    val upToDateScreenings: Int,
    val overdueScreenings: Int,
    val screenings: List<HealthScreening>,
    val eligibleScreenings: List<String>,
    val excludedScreenings: List<String>
)

data class HealthScreening(
    val type: String,
    val lastScreeningDate: String?,
    val nextDueDate: String,
    val status: String,
    val result: String?,
    val location: String,
    val invitationSent: Boolean
)