package com.uk.gov.connectors.property

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
@RequestMapping("/api/connectors/land-registry")
class LandRegistryConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(LandRegistryConnector::class.java)

    @GetMapping("/property-ownership/{titleNumber}")
    @Cacheable("property-ownership")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPropertyOwnership(@PathVariable titleNumber: String): Mono<PropertyOwnershipResponse> {
        logger.info("Getting property ownership for title: {}", titleNumber)
        
        return webClient.get()
            .uri("https://api.landregistry.gov.uk/ownership/v1/{titleNumber}", titleNumber)
            .header("Authorization", "Bearer \${LAND_REGISTRY_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val owners = (response["owners"] as? List<Map<String, Any>>) ?: emptyList()
                val charges = (response["charges"] as? List<Map<String, Any>>) ?: emptyList()
                
                PropertyOwnershipResponse(
                    titleNumber = titleNumber,
                    propertyAddress = response["propertyAddress"] as? String ?: "UNKNOWN",
                    tenure = response["tenure"] as? String ?: "UNKNOWN", // FREEHOLD, LEASEHOLD
                    propertyDescription = response["propertyDescription"] as? String ?: "UNKNOWN",
                    registrationDate = response["registrationDate"] as? String ?: "UNKNOWN",
                    lastUpdated = response["lastUpdated"] as? String ?: "UNKNOWN",
                    priceLastPaid = response["priceLastPaid"] as? Double ?: 0.0,
                    priceLastPaidDate = response["priceLastPaidDate"] as? String,
                    totalOwners = owners.size,
                    totalCharges = charges.size,
                    owners = owners.map { owner ->
                        PropertyOwner(
                            name = owner["name"] as? String ?: "UNKNOWN",
                            address = owner["address"] as? String ?: "UNKNOWN",
                            ownershipType = owner["ownershipType"] as? String ?: "UNKNOWN", // SOLE_OWNER, JOINT_TENANTS, TENANTS_IN_COMMON
                            dateOfEntry = owner["dateOfEntry"] as? String ?: "UNKNOWN",
                            share = owner["share"] as? String // For tenants in common
                        )
                    },
                    charges = charges.map { charge ->
                        PropertyCharge(
                            type = charge["type"] as? String ?: "UNKNOWN",
                            chargee = charge["chargee"] as? String ?: "UNKNOWN",
                            dateOfCharge = charge["dateOfCharge"] as? String ?: "UNKNOWN",
                            amount = charge["amount"] as? Double ?: 0.0,
                            status = charge["status"] as? String ?: "UNKNOWN"
                        )
                    },
                    restrictions = (response["restrictions"] as? List<String>) ?: emptyList(),
                    covenants = (response["covenants"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting property ownership for {}", titleNumber, e) }
            .onErrorReturn(PropertyOwnershipResponse(
                titleNumber = titleNumber,
                propertyAddress = "ERROR",
                tenure = "ERROR",
                propertyDescription = "ERROR",
                registrationDate = "ERROR",
                lastUpdated = "ERROR",
                priceLastPaid = 0.0,
                priceLastPaidDate = null,
                totalOwners = 0,
                totalCharges = 0,
                owners = emptyList(),
                charges = emptyList(),
                restrictions = emptyList(),
                covenants = emptyList()
            ))
    }

    @GetMapping("/property-transactions/{postcode}")
    @Cacheable("property-transactions")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getPropertyTransactions(@PathVariable @Pattern(regexp = "^[A-Z]{1,2}\\d[A-Z\\d]?\\s?\\d[A-Z]{2}$") postcode: String): Mono<PropertyTransactionsResponse> {
        logger.info("Getting property transactions for postcode: {}", postcode)
        
        return webClient.get()
            .uri("https://api.landregistry.gov.uk/transactions/v1?postcode={postcode}&limit=50", postcode)
            .header("Authorization", "Bearer \${LAND_REGISTRY_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val transactions = (response["transactions"] as? List<Map<String, Any>>) ?: emptyList()
                val averagePrice = if (transactions.isNotEmpty()) {
                    transactions.mapNotNull { (it["price"] as? Double) }.average()
                } else 0.0
                
                PropertyTransactionsResponse(
                    postcode = postcode,
                    totalTransactions = transactions.size,
                    averagePrice = averagePrice,
                    medianPrice = calculateMedianPrice(transactions),
                    priceRange = PriceRange(
                        lowest = transactions.mapNotNull { (it["price"] as? Double) }.minOrNull() ?: 0.0,
                        highest = transactions.mapNotNull { (it["price"] as? Double) }.maxOrNull() ?: 0.0
                    ),
                    transactions = transactions.map { transaction ->
                        PropertyTransaction(
                            address = transaction["address"] as? String ?: "UNKNOWN",
                            price = transaction["price"] as? Double ?: 0.0,
                            date = transaction["date"] as? String ?: "UNKNOWN",
                            propertyType = transaction["propertyType"] as? String ?: "UNKNOWN",
                            tenure = transaction["tenure"] as? String ?: "UNKNOWN",
                            newBuild = transaction["newBuild"] as? Boolean ?: false,
                            transactionCategory = transaction["transactionCategory"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting property transactions for {}", postcode, e) }
            .onErrorReturn(PropertyTransactionsResponse(
                postcode = postcode,
                totalTransactions = 0,
                averagePrice = 0.0,
                medianPrice = 0.0,
                priceRange = PriceRange(0.0, 0.0),
                transactions = emptyList()
            ))
    }

    @GetMapping("/leasehold-valuation/{titleNumber}")
    @Cacheable("leasehold-valuation")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getLeaseholdValuation(@PathVariable titleNumber: String): Mono<LeaseholdValuationResponse> {
        logger.info("Getting leasehold valuation for title: {}", titleNumber)
        
        return webClient.get()
            .uri("https://api.valuationtribunal.gov.uk/leasehold/v1/{titleNumber}", titleNumber)
            .header("Authorization", "Bearer \${VALUATION_TRIBUNAL_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val serviceCharges = (response["serviceCharges"] as? List<Map<String, Any>>) ?: emptyList()
                val disputes = (response["disputes"] as? List<Map<String, Any>>) ?: emptyList()
                
                LeaseholdValuationResponse(
                    titleNumber = titleNumber,
                    propertyAddress = response["propertyAddress"] as? String ?: "UNKNOWN",
                    leaseStartDate = response["leaseStartDate"] as? String ?: "UNKNOWN",
                    originalTerm = response["originalTerm"] as? Int ?: 0,
                    remainingTerm = response["remainingTerm"] as? Int ?: 0,
                    groundRent = response["groundRent"] as? Double ?: 0.0,
                    groundRentReviewPeriod = response["groundRentReviewPeriod"] as? String ?: "UNKNOWN",
                    freeholder = response["freeholder"] as? String ?: "UNKNOWN",
                    managementCompany = response["managementCompany"] as? String ?: "UNKNOWN",
                    annualServiceCharge = response["annualServiceCharge"] as? Double ?: 0.0,
                    serviceCharges = serviceCharges.map { charge ->
                        ServiceCharge(
                            year = charge["year"] as? String ?: "UNKNOWN",
                            amount = charge["amount"] as? Double ?: 0.0,
                            breakdown = (charge["breakdown"] as? Map<String, Double>) ?: emptyMap()
                        )
                    },
                    disputes = disputes.map { dispute ->
                        LeaseholdDispute(
                            caseNumber = dispute["caseNumber"] as? String ?: "UNKNOWN",
                            disputeType = dispute["disputeType"] as? String ?: "UNKNOWN",
                            filingDate = dispute["filingDate"] as? String ?: "UNKNOWN",
                            status = dispute["status"] as? String ?: "UNKNOWN",
                            outcome = dispute["outcome"] as? String
                        )
                    },
                    extensionRights = response["extensionRights"] as? Boolean ?: false,
                    enfranchisementRights = response["enfranchisementRights"] as? Boolean ?: false,
                    marriageValue = response["marriageValue"] as? Double ?: 0.0
                )
            }
            .doOnError { e -> logger.error("Error getting leasehold valuation for {}", titleNumber, e) }
            .onErrorReturn(LeaseholdValuationResponse(
                titleNumber = titleNumber,
                propertyAddress = "ERROR",
                leaseStartDate = "ERROR",
                originalTerm = 0,
                remainingTerm = 0,
                groundRent = 0.0,
                groundRentReviewPeriod = "ERROR",
                freeholder = "ERROR",
                managementCompany = "ERROR",
                annualServiceCharge = 0.0,
                serviceCharges = emptyList(),
                disputes = emptyList(),
                extensionRights = false,
                enfranchisementRights = false,
                marriageValue = 0.0
            ))
    }

    @PostMapping("/property-search")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun searchProperties(@Valid @RequestBody request: PropertySearchRequest): Mono<PropertySearchResponse> {
        logger.info("Searching properties with criteria: {}", request.toString())
        
        return webClient.post()
            .uri("https://api.landregistry.gov.uk/search/v1")
            .header("Authorization", "Bearer \${LAND_REGISTRY_API_KEY}")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val results = (response["results"] as? List<Map<String, Any>>) ?: emptyList()
                PropertySearchResponse(
                    totalResults = response["totalResults"] as? Int ?: 0,
                    searchCriteria = request,
                    results = results.map { result ->
                        PropertySearchResult(
                            titleNumber = result["titleNumber"] as? String ?: "UNKNOWN",
                            address = result["address"] as? String ?: "UNKNOWN",
                            tenure = result["tenure"] as? String ?: "UNKNOWN",
                            price = result["price"] as? Double ?: 0.0,
                            registrationDate = result["registrationDate"] as? String ?: "UNKNOWN",
                            matchScore = result["matchScore"] as? Double ?: 0.0
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error searching properties", e) }
            .onErrorReturn(PropertySearchResponse(
                totalResults = 0,
                searchCriteria = request,
                results = emptyList()
            ))
    }

    private fun calculateMedianPrice(transactions: List<Map<String, Any>>): Double {
        val prices = transactions.mapNotNull { (it["price"] as? Double) }.sorted()
        return if (prices.isEmpty()) {
            0.0
        } else if (prices.size % 2 == 0) {
            (prices[prices.size / 2 - 1] + prices[prices.size / 2]) / 2.0
        } else {
            prices[prices.size / 2]
        }
    }
}

data class PropertyOwnershipResponse(
    val titleNumber: String,
    val propertyAddress: String,
    val tenure: String,
    val propertyDescription: String,
    val registrationDate: String,
    val lastUpdated: String,
    val priceLastPaid: Double,
    val priceLastPaidDate: String?,
    val totalOwners: Int,
    val totalCharges: Int,
    val owners: List<PropertyOwner>,
    val charges: List<PropertyCharge>,
    val restrictions: List<String>,
    val covenants: List<String>
)

data class PropertyOwner(
    val name: String,
    val address: String,
    val ownershipType: String,
    val dateOfEntry: String,
    val share: String?
)

data class PropertyCharge(
    val type: String,
    val chargee: String,
    val dateOfCharge: String,
    val amount: Double,
    val status: String
)

data class PropertyTransactionsResponse(
    val postcode: String,
    val totalTransactions: Int,
    val averagePrice: Double,
    val medianPrice: Double,
    val priceRange: PriceRange,
    val transactions: List<PropertyTransaction>
)

data class PriceRange(
    val lowest: Double,
    val highest: Double
)

data class PropertyTransaction(
    val address: String,
    val price: Double,
    val date: String,
    val propertyType: String,
    val tenure: String,
    val newBuild: Boolean,
    val transactionCategory: String
)

data class LeaseholdValuationResponse(
    val titleNumber: String,
    val propertyAddress: String,
    val leaseStartDate: String,
    val originalTerm: Int,
    val remainingTerm: Int,
    val groundRent: Double,
    val groundRentReviewPeriod: String,
    val freeholder: String,
    val managementCompany: String,
    val annualServiceCharge: Double,
    val serviceCharges: List<ServiceCharge>,
    val disputes: List<LeaseholdDispute>,
    val extensionRights: Boolean,
    val enfranchisementRights: Boolean,
    val marriageValue: Double
)

data class ServiceCharge(
    val year: String,
    val amount: Double,
    val breakdown: Map<String, Double>
)

data class LeaseholdDispute(
    val caseNumber: String,
    val disputeType: String,
    val filingDate: String,
    val status: String,
    val outcome: String?
)

data class PropertySearchRequest(
    @field:NotBlank val searchType: String, // ADDRESS, OWNER_NAME, TITLE_NUMBER
    @field:NotBlank val searchTerm: String,
    val postcode: String?,
    val propertyType: String?,
    val tenure: String?,
    val priceRange: PriceRange?
)

data class PropertySearchResponse(
    val totalResults: Int,
    val searchCriteria: PropertySearchRequest,
    val results: List<PropertySearchResult>
)

data class PropertySearchResult(
    val titleNumber: String,
    val address: String,
    val tenure: String,
    val price: Double,
    val registrationDate: String,
    val matchScore: Double
)