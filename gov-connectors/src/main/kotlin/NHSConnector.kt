package com.uk.gov.connectors.nhs

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
@RequestMapping("/api/connectors/nhs")
class NHSConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(NHSConnector::class.java)

    @GetMapping("/verify-nhs-number/{nhsNumber}")
    @Cacheable("nhs-verification")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyNHSNumber(@PathVariable @Pattern(regexp = "^[0-9]{10}$") nhsNumber: String): Mono<NHSVerificationResponse> {
        logger.info("Verifying NHS number: {}", nhsNumber)
        
        return webClient.get()
            .uri("https://api.nhs.uk/personal-demographics/FHIR/R4/Patient/{nhsNumber}", nhsNumber)
            .header("Authorization", "Bearer \${NHS_API_KEY}")
            .header("NHSD-Session-URID", "555254242106")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val patient = response["resource"] as? Map<String, Any> ?: emptyMap()
                NHSVerificationResponse(
                    nhsNumber = nhsNumber,
                    verified = response["resourceType"] == "Patient",
                    active = patient["active"] as? Boolean ?: true,
                    dateOfBirth = extractDateOfBirth(patient),
                    gender = patient["gender"] as? String ?: "unknown",
                    gpPractice = extractGPPractice(patient),
                    registrationStatus = "ACTIVE"
                )
            }
            .doOnError { e -> logger.error("Error verifying NHS number {}", nhsNumber, e) }
            .onErrorReturn(NHSVerificationResponse(
                nhsNumber = nhsNumber,
                verified = false,
                active = false,
                dateOfBirth = "UNKNOWN",
                gender = "unknown",
                gpPractice = "UNKNOWN",
                registrationStatus = "ERROR"
            ))
    }

    @GetMapping("/medical-eligibility/{nhsNumber}")
    @Cacheable("nhs-eligibility")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getMedicalEligibility(@PathVariable nhsNumber: String): Mono<MedicalEligibilityResponse> {
        logger.info("Checking medical eligibility for: {}", nhsNumber)
        
        return webClient.get()
            .uri("https://api.nhs.uk/eligibility/v1/patient/{nhsNumber}", nhsNumber)
            .header("Authorization", "Bearer \${NHS_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                MedicalEligibilityResponse(
                    nhsNumber = nhsNumber,
                    prescriptionExemption = response["prescriptionExemption"] as? Boolean ?: false,
                    dentalExemption = response["dentalExemption"] as? Boolean ?: false,
                    opticalExemption = response["opticalExemption"] as? Boolean ?: false,
                    maternity = response["maternity"] as? Boolean ?: false,
                    medicalExemptionCertificate = response["medicalExemptionCertificate"] as? Boolean ?: false,
                    lowIncomeScheme = response["lowIncomeScheme"] as? Boolean ?: false
                )
            }
            .doOnError { e -> logger.error("Error checking medical eligibility for {}", nhsNumber, e) }
            .onErrorReturn(MedicalEligibilityResponse(
                nhsNumber = nhsNumber,
                prescriptionExemption = false,
                dentalExemption = false,
                opticalExemption = false,
                maternity = false,
                medicalExemptionCertificate = false,
                lowIncomeScheme = false
            ))
    }

    @GetMapping("/vaccination-status/{nhsNumber}")
    @Cacheable("nhs-vaccination")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getVaccinationStatus(@PathVariable nhsNumber: String): Mono<VaccinationStatusResponse> {
        logger.info("Getting vaccination status for: {}", nhsNumber)
        
        return webClient.get()
            .uri("https://api.nhs.uk/immunisation/FHIR/R4/Immunization?patient.identifier={nhsNumber}", nhsNumber)
            .header("Authorization", "Bearer \${NHS_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val entries = (response["entry"] as? List<Map<String, Any>>) ?: emptyList()
                val covidVaccinations = entries.count { entry ->
                    val immunization = entry["resource"] as? Map<String, Any>
                    val vaccineCode = immunization?.get("vaccineCode") as? Map<String, Any>
                    val coding = (vaccineCode?.get("coding") as? List<Map<String, Any>>) ?: emptyList()
                    coding.any { it["system"] == "http://snomed.info/sct" && it["code"].toString().contains("COVID") }
                }
                
                VaccinationStatusResponse(
                    nhsNumber = nhsNumber,
                    covidVaccinated = covidVaccinations > 0,
                    covidDoses = covidVaccinations,
                    lastCovidVaccination = extractLastVaccinationDate(entries, "COVID"),
                    fluVaccinated = hasVaccination(entries, "FLU"),
                    lastFluVaccination = extractLastVaccinationDate(entries, "FLU"),
                    routineImmunisationsComplete = true,
                    travelVaccinations = extractTravelVaccinations(entries)
                )
            }
            .doOnError { e -> logger.error("Error getting vaccination status for {}", nhsNumber, e) }
            .onErrorReturn(VaccinationStatusResponse(
                nhsNumber = nhsNumber,
                covidVaccinated = false,
                covidDoses = 0,
                lastCovidVaccination = "UNKNOWN",
                fluVaccinated = false,
                lastFluVaccination = "UNKNOWN",
                routineImmunisationsComplete = false,
                travelVaccinations = emptyList()
            ))
    }

    private fun extractDateOfBirth(patient: Map<String, Any>): String {
        return patient["birthDate"] as? String ?: "UNKNOWN"
    }

    private fun extractGPPractice(patient: Map<String, Any>): String {
        val generalPractitioner = (patient["generalPractitioner"] as? List<Map<String, Any>>) ?: emptyList()
        return if (generalPractitioner.isNotEmpty()) {
            generalPractitioner[0]["reference"] as? String ?: "UNKNOWN"
        } else "UNKNOWN"
    }

    private fun hasVaccination(entries: List<Map<String, Any>>, vaccineType: String): Boolean {
        return entries.any { entry ->
            val immunization = entry["resource"] as? Map<String, Any>
            val vaccineCode = immunization?.get("vaccineCode") as? Map<String, Any>
            val coding = (vaccineCode?.get("coding") as? List<Map<String, Any>>) ?: emptyList()
            coding.any { it["display"].toString().contains(vaccineType, ignoreCase = true) }
        }
    }

    private fun extractLastVaccinationDate(entries: List<Map<String, Any>>, vaccineType: String): String {
        val vaccinationDates = entries.mapNotNull { entry ->
            val immunization = entry["resource"] as? Map<String, Any>
            val vaccineCode = immunization?.get("vaccineCode") as? Map<String, Any>
            val coding = (vaccineCode?.get("coding") as? List<Map<String, Any>>) ?: emptyList()
            val isCorrectVaccine = coding.any { it["display"].toString().contains(vaccineType, ignoreCase = true) }
            if (isCorrectVaccine) {
                immunization["occurrenceDateTime"] as? String
            } else null
        }
        return vaccinationDates.maxOrNull() ?: "UNKNOWN"
    }

    private fun extractTravelVaccinations(entries: List<Map<String, Any>>): List<String> {
        val travelVaccines = listOf("Yellow Fever", "Hepatitis A", "Hepatitis B", "Typhoid", "Meningococcal", "Japanese Encephalitis")
        return entries.mapNotNull { entry ->
            val immunization = entry["resource"] as? Map<String, Any>
            val vaccineCode = immunization?.get("vaccineCode") as? Map<String, Any>
            val coding = (vaccineCode?.get("coding") as? List<Map<String, Any>>) ?: emptyList()
            val vaccineName = coding.firstOrNull()?.get("display") as? String
            if (vaccineName != null && travelVaccines.any { vaccineName.contains(it, ignoreCase = true) }) {
                vaccineName
            } else null
        }.distinct()
    }
}

data class NHSVerificationResponse(
    val nhsNumber: String,
    val verified: Boolean,
    val active: Boolean,
    val dateOfBirth: String,
    val gender: String,
    val gpPractice: String,
    val registrationStatus: String
)

data class MedicalEligibilityResponse(
    val nhsNumber: String,
    val prescriptionExemption: Boolean,
    val dentalExemption: Boolean,
    val opticalExemption: Boolean,
    val maternity: Boolean,
    val medicalExemptionCertificate: Boolean,
    val lowIncomeScheme: Boolean
)

data class VaccinationStatusResponse(
    val nhsNumber: String,
    val covidVaccinated: Boolean,
    val covidDoses: Int,
    val lastCovidVaccination: String,
    val fluVaccinated: Boolean,
    val lastFluVaccination: String,
    val routineImmunisationsComplete: Boolean,
    val travelVaccinations: List<String>
)