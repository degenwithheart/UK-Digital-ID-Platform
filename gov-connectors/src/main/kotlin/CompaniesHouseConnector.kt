package com.uk.gov.connectors.companieshouse

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
@RequestMapping("/api/connectors/companies-house")
class CompaniesHouseConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(CompaniesHouseConnector::class.java)

    @GetMapping("/company/{companyNumber}")
    @Cacheable("companies-house-company")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCompanyDetails(@PathVariable @Pattern(regexp = "^[0-9]{8}|[A-Z]{2}[0-9]{6}$") companyNumber: String): Mono<CompanyDetailsResponse> {
        logger.info("Getting company details for: {}", companyNumber)
        
        return webClient.get()
            .uri("https://api.companieshouse.gov.uk/company/{companyNumber}", companyNumber)
            .header("Authorization", "Basic \${COMPANIES_HOUSE_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val address = response["registered_office_address"] as? Map<String, Any> ?: emptyMap()
                CompanyDetailsResponse(
                    companyNumber = companyNumber,
                    companyName = response["company_name"] as? String ?: "UNKNOWN",
                    status = response["company_status"] as? String ?: "UNKNOWN",
                    incorporationDate = response["date_of_creation"] as? String ?: "UNKNOWN",
                    companyType = response["type"] as? String ?: "UNKNOWN",
                    registeredOfficeAddress = formatAddress(address),
                    sicCodes = (response["sic_codes"] as? List<String>) ?: emptyList(),
                    hasBeenLiquidated = response["has_been_liquidated"] as? Boolean ?: false,
                    canFile = response["can_file"] as? Boolean ?: true,
                    hasCharges = response["has_charges"] as? Boolean ?: false,
                    hasInsolvencyHistory = response["has_insolvency_history"] as? Boolean ?: false
                )
            }
            .doOnError { e -> logger.error("Error getting company details for {}", companyNumber, e) }
            .onErrorReturn(CompanyDetailsResponse(
                companyNumber = companyNumber,
                companyName = "ERROR",
                status = "ERROR",
                incorporationDate = "ERROR",
                companyType = "ERROR",
                registeredOfficeAddress = "ERROR",
                sicCodes = emptyList(),
                hasBeenLiquidated = false,
                canFile = false,
                hasCharges = false,
                hasInsolvencyHistory = false
            ))
    }

    @GetMapping("/directors/{companyNumber}")
    @Cacheable("companies-house-directors")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getCompanyDirectors(@PathVariable companyNumber: String): Mono<DirectorsResponse> {
        logger.info("Getting directors for company: {}", companyNumber)
        
        return webClient.get()
            .uri("https://api.companieshouse.gov.uk/company/{companyNumber}/officers", companyNumber)
            .header("Authorization", "Basic \${COMPANIES_HOUSE_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val officers = (response["items"] as? List<Map<String, Any>>) ?: emptyList()
                val directors = officers.filter { officer ->
                    val officerRole = officer["officer_role"] as? String ?: ""
                    officerRole.contains("director", ignoreCase = true)
                }
                
                DirectorsResponse(
                    companyNumber = companyNumber,
                    totalDirectors = directors.size,
                    activeDirectors = directors.count { (it["resigned_on"] as? String) == null },
                    directors = directors.map { director ->
                        Director(
                            name = director["name"] as? String ?: "UNKNOWN",
                            officerRole = director["officer_role"] as? String ?: "UNKNOWN",
                            appointedOn = director["appointed_on"] as? String ?: "UNKNOWN",
                            resignedOn = director["resigned_on"] as? String,
                            nationality = director["nationality"] as? String ?: "UNKNOWN",
                            occupation = director["occupation"] as? String ?: "UNKNOWN",
                            countryOfResidence = director["country_of_residence"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting directors for company {}", companyNumber, e) }
            .onErrorReturn(DirectorsResponse(
                companyNumber = companyNumber,
                totalDirectors = 0,
                activeDirectors = 0,
                directors = emptyList()
            ))
    }

    @GetMapping("/psc/{companyNumber}")
    @Cacheable("companies-house-psc")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPSCDetails(@PathVariable companyNumber: String): Mono<PSCResponse> {
        logger.info("Getting PSC details for company: {}", companyNumber)
        
        return webClient.get()
            .uri("https://api.companieshouse.gov.uk/company/{companyNumber}/persons-with-significant-control", companyNumber)
            .header("Authorization", "Basic \${COMPANIES_HOUSE_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val items = (response["items"] as? List<Map<String, Any>>) ?: emptyList()
                PSCResponse(
                    companyNumber = companyNumber,
                    totalPSCs = items.size,
                    pscs = items.map { psc ->
                        PSC(
                            name = psc["name"] as? String ?: "UNKNOWN",
                            kind = psc["kind"] as? String ?: "UNKNOWN",
                            notifiedOn = psc["notified_on"] as? String ?: "UNKNOWN",
                            naturesOfControl = (psc["natures_of_control"] as? List<String>) ?: emptyList(),
                            nationality = psc["nationality"] as? String ?: "UNKNOWN",
                            countryOfResidence = psc["country_of_residence"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting PSC details for company {}", companyNumber, e) }
            .onErrorReturn(PSCResponse(
                companyNumber = companyNumber,
                totalPSCs = 0,
                pscs = emptyList()
            ))
    }

    @GetMapping("/filing-history/{companyNumber}")
    @Cacheable("companies-house-filing")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getFilingHistory(@PathVariable companyNumber: String): Mono<FilingHistoryResponse> {
        logger.info("Getting filing history for company: {}", companyNumber)
        
        return webClient.get()
            .uri("https://api.companieshouse.gov.uk/company/{companyNumber}/filing-history?items_per_page=20", companyNumber)
            .header("Authorization", "Basic \${COMPANIES_HOUSE_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val items = (response["items"] as? List<Map<String, Any>>) ?: emptyList()
                FilingHistoryResponse(
                    companyNumber = companyNumber,
                    totalFilings = response["total_count"] as? Int ?: 0,
                    recentFilings = items.take(10).map { filing ->
                        Filing(
                            transactionId = filing["transaction_id"] as? String ?: "UNKNOWN",
                            category = filing["category"] as? String ?: "UNKNOWN",
                            description = filing["description"] as? String ?: "UNKNOWN",
                            date = filing["date"] as? String ?: "UNKNOWN",
                            type = filing["type"] as? String ?: "UNKNOWN"
                        )
                    },
                    lastAnnualReturn = findLastFilingByCategory(items, "annual-return"),
                    lastConfirmationStatement = findLastFilingByCategory(items, "confirmation-statement"),
                    complianceStatus = determineComplianceStatus(items)
                )
            }
            .doOnError { e -> logger.error("Error getting filing history for company {}", companyNumber, e) }
            .onErrorReturn(FilingHistoryResponse(
                companyNumber = companyNumber,
                totalFilings = 0,
                recentFilings = emptyList(),
                lastAnnualReturn = "UNKNOWN",
                lastConfirmationStatement = "UNKNOWN",
                complianceStatus = "ERROR"
            ))
    }

    @PostMapping("/verify-directorship")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyDirectorship(@Valid @RequestBody request: DirectorshipVerificationRequest): Mono<DirectorshipVerificationResponse> {
        logger.info("Verifying directorship for: {}", request.personName)
        
        return webClient.get()
            .uri("https://api.companieshouse.gov.uk/search/officers?q={name}&items_per_page=20", request.personName)
            .header("Authorization", "Basic \${COMPANIES_HOUSE_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val officers = (response["items"] as? List<Map<String, Any>>) ?: emptyList()
                val currentDirectorships = officers.filter { officer ->
                    val matches = (officer["matches"] as? Map<String, Any>) ?: emptyMap()
                    val snippet = matches["snippet"] as? List<String> ?: emptyList()
                    snippet.any { it.contains("director", ignoreCase = true) } &&
                            officer["date_of_birth"] != null
                }
                
                DirectorshipVerificationResponse(
                    personName = request.personName,
                    hasDirectorships = currentDirectorships.isNotEmpty(),
                    totalDirectorships = currentDirectorships.size,
                    activeDirectorships = currentDirectorships.count { 
                        (it["resigned_on"] as? String) == null 
                    },
                    companies = currentDirectorships.map { officer ->
                        CompanyDirectorship(
                            companyName = (officer["matches"] as? Map<String, Any>)?.get("title") as? String ?: "UNKNOWN",
                            companyNumber = "UNKNOWN", // Would need additional call to get this
                            appointedOn = officer["appointed_on"] as? String ?: "UNKNOWN",
                            resignedOn = officer["resigned_on"] as? String,
                            officerRole = officer["officer_role"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error verifying directorship for {}", request.personName, e) }
            .onErrorReturn(DirectorshipVerificationResponse(
                personName = request.personName,
                hasDirectorships = false,
                totalDirectorships = 0,
                activeDirectorships = 0,
                companies = emptyList()
            ))
    }

    private fun formatAddress(address: Map<String, Any>): String {
        val parts = listOf(
            address["address_line_1"],
            address["address_line_2"], 
            address["locality"],
            address["region"],
            address["postal_code"],
            address["country"]
        ).filterNotNull().map { it.toString() }
        
        return if (parts.isNotEmpty()) parts.joinToString(", ") else "UNKNOWN"
    }

    private fun findLastFilingByCategory(filings: List<Map<String, Any>>, category: String): String {
        return filings.firstOrNull { filing ->
            (filing["category"] as? String)?.contains(category, ignoreCase = true) == true
        }?.get("date") as? String ?: "NONE"
    }

    private fun determineComplianceStatus(filings: List<Map<String, Any>>): String {
        val recentFilings = filings.take(5)
        val hasRecentConfirmationStatement = recentFilings.any { filing ->
            (filing["category"] as? String)?.contains("confirmation-statement", ignoreCase = true) == true
        }
        
        return if (hasRecentConfirmationStatement) "COMPLIANT" else "OVERDUE"
    }
}

data class CompanyDetailsResponse(
    val companyNumber: String,
    val companyName: String,
    val status: String,
    val incorporationDate: String,
    val companyType: String,
    val registeredOfficeAddress: String,
    val sicCodes: List<String>,
    val hasBeenLiquidated: Boolean,
    val canFile: Boolean,
    val hasCharges: Boolean,
    val hasInsolvencyHistory: Boolean
)

data class DirectorsResponse(
    val companyNumber: String,
    val totalDirectors: Int,
    val activeDirectors: Int,
    val directors: List<Director>
)

data class Director(
    val name: String,
    val officerRole: String,
    val appointedOn: String,
    val resignedOn: String?,
    val nationality: String,
    val occupation: String,
    val countryOfResidence: String
)

data class PSCResponse(
    val companyNumber: String,
    val totalPSCs: Int,
    val pscs: List<PSC>
)

data class PSC(
    val name: String,
    val kind: String,
    val notifiedOn: String,
    val naturesOfControl: List<String>,
    val nationality: String,
    val countryOfResidence: String
)

data class FilingHistoryResponse(
    val companyNumber: String,
    val totalFilings: Int,
    val recentFilings: List<Filing>,
    val lastAnnualReturn: String,
    val lastConfirmationStatement: String,
    val complianceStatus: String
)

data class Filing(
    val transactionId: String,
    val category: String,
    val description: String,
    val date: String,
    val type: String
)

data class DirectorshipVerificationRequest(
    @field:NotBlank val personName: String,
    val dateOfBirth: String?
)

data class DirectorshipVerificationResponse(
    val personName: String,
    val hasDirectorships: Boolean,
    val totalDirectorships: Int,
    val activeDirectorships: Int,
    val companies: List<CompanyDirectorship>
)

data class CompanyDirectorship(
    val companyName: String,
    val companyNumber: String,
    val appointedOn: String,
    val resignedOn: String?,
    val officerRole: String
)