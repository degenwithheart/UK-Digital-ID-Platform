package com.uk.gov.connectors.professional

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
@RequestMapping("/api/connectors/professional-bodies")
class ProfessionalBodiesConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(ProfessionalBodiesConnector::class.java)

    @GetMapping("/law-society/{solicitorNumber}")
    @Cacheable("law-society")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getSolicitorRegistration(@PathVariable solicitorNumber: String): Mono<SolicitorRegistrationResponse> {
        logger.info("Getting solicitor registration for: {}", solicitorNumber)
        
        return webClient.get()
            .uri("https://api.lawsociety.org.uk/solicitors/v1/{solicitorNumber}", solicitorNumber)
            .header("Authorization", "Bearer \${LAW_SOCIETY_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val qualifications = (response["qualifications"] as? List<Map<String, Any>>) ?: emptyList()
                val specializations = (response["specializations"] as? List<String>) ?: emptyList()
                
                SolicitorRegistrationResponse(
                    solicitorNumber = solicitorNumber,
                    fullName = response["fullName"] as? String ?: "UNKNOWN",
                    status = response["status"] as? String ?: "UNKNOWN", // PRACTISING, NON_PRACTISING, SUSPENDED
                    admissionDate = response["admissionDate"] as? String ?: "UNKNOWN",
                    currentFirm = response["currentFirm"] as? String ?: "UNKNOWN",
                    firmAddress = response["firmAddress"] as? String ?: "UNKNOWN",
                    practiceRights = response["practiceRights"] as? String ?: "UNKNOWN",
                    higherRightsOfAudience = response["higherRightsOfAudience"] as? Boolean ?: false,
                    sraRegulated = response["sraRegulated"] as? Boolean ?: true,
                    qualifications = qualifications.map { qual ->
                        LegalQualification(
                            type = qual["type"] as? String ?: "UNKNOWN",
                            institution = qual["institution"] as? String ?: "UNKNOWN",
                            dateObtained = qual["dateObtained"] as? String ?: "UNKNOWN",
                            jurisdiction = qual["jurisdiction"] as? String ?: "UNKNOWN"
                        )
                    },
                    specializations = specializations,
                    disciplinaryHistory = (response["disciplinaryHistory"] as? List<String>) ?: emptyList(),
                    cpdCompliant = response["cpdCompliant"] as? Boolean ?: false
                )
            }
            .doOnError { e -> logger.error("Error getting solicitor registration for {}", solicitorNumber, e) }
            .onErrorReturn(SolicitorRegistrationResponse(
                solicitorNumber = solicitorNumber,
                fullName = "ERROR",
                status = "ERROR",
                admissionDate = "ERROR",
                currentFirm = "ERROR",
                firmAddress = "ERROR",
                practiceRights = "ERROR",
                higherRightsOfAudience = false,
                sraRegulated = false,
                qualifications = emptyList(),
                specializations = emptyList(),
                disciplinaryHistory = emptyList(),
                cpdCompliant = false
            ))
    }

    @GetMapping("/bar-council/{barNumber}")
    @Cacheable("bar-council")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getBarristerRegistration(@PathVariable barNumber: String): Mono<BarristerRegistrationResponse> {
        logger.info("Getting barrister registration for: {}", barNumber)
        
        return webClient.get()
            .uri("https://api.barcouncil.org.uk/barristers/v1/{barNumber}", barNumber)
            .header("Authorization", "Bearer \${BAR_COUNCIL_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val qualifications = (response["qualifications"] as? List<Map<String, Any>>) ?: emptyList()
                val chambers = (response["chambers"] as? Map<String, Any>) ?: emptyMap()
                
                BarristerRegistrationResponse(
                    barNumber = barNumber,
                    fullName = response["fullName"] as? String ?: "UNKNOWN",
                    status = response["status"] as? String ?: "UNKNOWN", // PRACTISING, NON_PRACTISING, SUSPENDED
                    callDate = response["callDate"] as? String ?: "UNKNOWN",
                    inn = response["inn"] as? String ?: "UNKNOWN", // GRAY'S_INN, LINCOLN'S_INN, INNER_TEMPLE, MIDDLE_TEMPLE
                    qc = response["qc"] as? Boolean ?: false,
                    chambers = BarristerChambers(
                        name = chambers["name"] as? String ?: "UNKNOWN",
                        address = chambers["address"] as? String ?: "UNKNOWN",
                        clerkName = chambers["clerkName"] as? String ?: "UNKNOWN"
                    ),
                    practiceAreas = (response["practiceAreas"] as? List<String>) ?: emptyList(),
                    qualifications = qualifications.map { qual ->
                        LegalQualification(
                            type = qual["type"] as? String ?: "UNKNOWN",
                            institution = qual["institution"] as? String ?: "UNKNOWN",
                            dateObtained = qual["dateObtained"] as? String ?: "UNKNOWN",
                            jurisdiction = qual["jurisdiction"] as? String ?: "UNKNOWN"
                        )
                    },
                    publicAccess = response["publicAccess"] as? Boolean ?: false,
                    bsbRegulated = response["bsbRegulated"] as? Boolean ?: true,
                    disciplinaryHistory = (response["disciplinaryHistory"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting barrister registration for {}", barNumber, e) }
            .onErrorReturn(BarristerRegistrationResponse(
                barNumber = barNumber,
                fullName = "ERROR",
                status = "ERROR",
                callDate = "ERROR",
                inn = "ERROR",
                qc = false,
                chambers = BarristerChambers("ERROR", "ERROR", "ERROR"),
                practiceAreas = emptyList(),
                qualifications = emptyList(),
                publicAccess = false,
                bsbRegulated = false,
                disciplinaryHistory = emptyList()
            ))
    }

    @GetMapping("/icaew/{membershipNumber}")
    @Cacheable("icaew-membership")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getICAEWMembership(@PathVariable membershipNumber: String): Mono<ICAEWMembershipResponse> {
        logger.info("Getting ICAEW membership for: {}", membershipNumber)
        
        return webClient.get()
            .uri("https://api.icaew.com/members/v1/{membershipNumber}", membershipNumber)
            .header("Authorization", "Bearer \${ICAEW_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val qualifications = (response["qualifications"] as? List<Map<String, Any>>) ?: emptyList()
                val licenses = (response["licenses"] as? List<Map<String, Any>>) ?: emptyList()
                
                ICAEWMembershipResponse(
                    membershipNumber = membershipNumber,
                    fullName = response["fullName"] as? String ?: "UNKNOWN",
                    membershipType = response["membershipType"] as? String ?: "UNKNOWN", // ACA, FCA, AFFILIATE
                    status = response["status"] as? String ?: "UNKNOWN",
                    memberSince = response["memberSince"] as? String ?: "UNKNOWN",
                    currentEmployer = response["currentEmployer"] as? String ?: "UNKNOWN",
                    publicPractice = response["publicPractice"] as? Boolean ?: false,
                    authorisedAuditor = response["authorisedAuditor"] as? Boolean ?: false,
                    probateAgent = response["probateAgent"] as? Boolean ?: false,
                    investmentBusiness = response["investmentBusiness"] as? Boolean ?: false,
                    qualifications = qualifications.map { qual ->
                        AccountingQualification(
                            type = qual["type"] as? String ?: "UNKNOWN",
                            dateObtained = qual["dateObtained"] as? String ?: "UNKNOWN",
                            certificateNumber = qual["certificateNumber"] as? String ?: "UNKNOWN"
                        )
                    },
                    licenses = licenses.map { license ->
                        ProfessionalLicense(
                            type = license["type"] as? String ?: "UNKNOWN",
                            number = license["number"] as? String ?: "UNKNOWN",
                            expiryDate = license["expiryDate"] as? String ?: "UNKNOWN",
                            status = license["status"] as? String ?: "UNKNOWN"
                        )
                    },
                    cpdCompliant = response["cpdCompliant"] as? Boolean ?: false,
                    disciplinaryActions = (response["disciplinaryActions"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting ICAEW membership for {}", membershipNumber, e) }
            .onErrorReturn(ICAEWMembershipResponse(
                membershipNumber = membershipNumber,
                fullName = "ERROR",
                membershipType = "ERROR",
                status = "ERROR",
                memberSince = "ERROR",
                currentEmployer = "ERROR",
                publicPractice = false,
                authorisedAuditor = false,
                probateAgent = false,
                investmentBusiness = false,
                qualifications = emptyList(),
                licenses = emptyList(),
                cpdCompliant = false,
                disciplinaryActions = emptyList()
            ))
    }

    @GetMapping("/architecture/{aribaNumber}")
    @Cacheable("architect-registration")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getArchitectRegistration(@PathVariable aribaNumber: String): Mono<ArchitectRegistrationResponse> {
        logger.info("Getting architect registration for: {}", aribaNumber)
        
        return webClient.get()
            .uri("https://api.arb.org.uk/architects/v1/{aribaNumber}", aribaNumber)
            .header("Authorization", "Bearer \${ARB_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val qualifications = (response["qualifications"] as? List<Map<String, Any>>) ?: emptyList()
                ArchitectRegistrationResponse(
                    aribaNumber = aribaNumber,
                    fullName = response["fullName"] as? String ?: "UNKNOWN",
                    registrationStatus = response["registrationStatus"] as? String ?: "UNKNOWN",
                    registrationDate = response["registrationDate"] as? String ?: "UNKNOWN",
                    currentPractice = response["currentPractice"] as? String ?: "UNKNOWN",
                    practiceAddress = response["practiceAddress"] as? String ?: "UNKNOWN",
                    qualifications = qualifications.map { qual ->
                        ArchitectureQualification(
                            institution = qual["institution"] as? String ?: "UNKNOWN",
                            qualification = qual["qualification"] as? String ?: "UNKNOWN",
                            dateAwarded = qual["dateAwarded"] as? String ?: "UNKNOWN",
                            country = qual["country"] as? String ?: "UNKNOWN"
                        )
                    },
                    specializations = (response["specializations"] as? List<String>) ?: emptyList(),
                    professionalIndemnity = response["professionalIndemnity"] as? Boolean ?: false,
                    cpdCompliant = response["cpdCompliant"] as? Boolean ?: false,
                    disciplinaryHistory = (response["disciplinaryHistory"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting architect registration for {}", aribaNumber, e) }
            .onErrorReturn(ArchitectRegistrationResponse(
                aribaNumber = aribaNumber,
                fullName = "ERROR",
                registrationStatus = "ERROR",
                registrationDate = "ERROR",
                currentPractice = "ERROR",
                practiceAddress = "ERROR",
                qualifications = emptyList(),
                specializations = emptyList(),
                professionalIndemnity = false,
                cpdCompliant = false,
                disciplinaryHistory = emptyList()
            ))
    }
}

data class SolicitorRegistrationResponse(
    val solicitorNumber: String,
    val fullName: String,
    val status: String,
    val admissionDate: String,
    val currentFirm: String,
    val firmAddress: String,
    val practiceRights: String,
    val higherRightsOfAudience: Boolean,
    val sraRegulated: Boolean,
    val qualifications: List<LegalQualification>,
    val specializations: List<String>,
    val disciplinaryHistory: List<String>,
    val cpdCompliant: Boolean
)

data class BarristerRegistrationResponse(
    val barNumber: String,
    val fullName: String,
    val status: String,
    val callDate: String,
    val inn: String,
    val qc: Boolean,
    val chambers: BarristerChambers,
    val practiceAreas: List<String>,
    val qualifications: List<LegalQualification>,
    val publicAccess: Boolean,
    val bsbRegulated: Boolean,
    val disciplinaryHistory: List<String>
)

data class BarristerChambers(
    val name: String,
    val address: String,
    val clerkName: String
)

data class LegalQualification(
    val type: String,
    val institution: String,
    val dateObtained: String,
    val jurisdiction: String
)

data class ICAEWMembershipResponse(
    val membershipNumber: String,
    val fullName: String,
    val membershipType: String,
    val status: String,
    val memberSince: String,
    val currentEmployer: String,
    val publicPractice: Boolean,
    val authorisedAuditor: Boolean,
    val probateAgent: Boolean,
    val investmentBusiness: Boolean,
    val qualifications: List<AccountingQualification>,
    val licenses: List<ProfessionalLicense>,
    val cpdCompliant: Boolean,
    val disciplinaryActions: List<String>
)

data class AccountingQualification(
    val type: String,
    val dateObtained: String,
    val certificateNumber: String
)

data class ProfessionalLicense(
    val type: String,
    val number: String,
    val expiryDate: String,
    val status: String
)

data class ArchitectRegistrationResponse(
    val aribaNumber: String,
    val fullName: String,
    val registrationStatus: String,
    val registrationDate: String,
    val currentPractice: String,
    val practiceAddress: String,
    val qualifications: List<ArchitectureQualification>,
    val specializations: List<String>,
    val professionalIndemnity: Boolean,
    val cpdCompliant: Boolean,
    val disciplinaryHistory: List<String>
)

data class ArchitectureQualification(
    val institution: String,
    val qualification: String,
    val dateAwarded: String,
    val country: String
)