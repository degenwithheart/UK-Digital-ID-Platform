package com.uk.gov.connectors.dvla

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
@RequestMapping("/api/connectors/dvla")
class DVLAConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(DVLAConnector::class.java)

    @GetMapping("/driving-license/{licenseNumber}")
    @Cacheable("dvla-licenses")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getDrivingLicense(@PathVariable @Pattern(regexp = "^[A-Z]{5}[0-9]{6}[A-Z]{2}[0-9]{2}$") licenseNumber: String): Mono<DrivingLicenseResponse> {
        logger.info("Fetching driving license for: {}", licenseNumber)
        
        return webClient.get()
            .uri("https://api.dvla.gov.uk/v1/drivers/{license}", licenseNumber)
            .header("Authorization", "Bearer \${DVLA_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                DrivingLicenseResponse(
                    licenseNumber = licenseNumber,
                    status = response["status"] as? String ?: "VALID",
                    expiryDate = response["expiryDate"] as? String ?: "2030-12-31",
                    categories = (response["categories"] as? List<String>) ?: listOf("B"),
                    endorsements = (response["endorsements"] as? Int) ?: 0,
                    valid = (response["valid"] as? Boolean) ?: true
                )
            }
            .doOnError { e -> logger.error("Error fetching driving license for {}", licenseNumber, e) }
            .onErrorReturn(DrivingLicenseResponse(
                licenseNumber = licenseNumber,
                status = "ERROR",
                expiryDate = "UNKNOWN",
                categories = emptyList(),
                endorsements = 0,
                valid = false
            ))
    }

    @GetMapping("/vehicle/{registrationNumber}")
    @Cacheable("dvla-vehicles")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getVehicleDetails(@PathVariable @Pattern(regexp = "^[A-Z]{2}[0-9]{2}\\s?[A-Z]{3}$") registrationNumber: String): Mono<VehicleResponse> {
        logger.info("Fetching vehicle details for: {}", registrationNumber)
        
        return webClient.get()
            .uri("https://api.dvla.gov.uk/v1/vehicles/{registration}", registrationNumber)
            .header("Authorization", "Bearer \${DVLA_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                VehicleResponse(
                    registrationNumber = registrationNumber,
                    make = response["make"] as? String ?: "UNKNOWN",
                    model = response["model"] as? String ?: "UNKNOWN",
                    yearOfManufacture = response["yearOfManufacture"] as? Int ?: 2020,
                    fuelType = response["fuelType"] as? String ?: "PETROL",
                    co2Emissions = response["co2Emissions"] as? Int ?: 120,
                    motStatus = response["motStatus"] as? String ?: "VALID",
                    motExpiryDate = response["motExpiryDate"] as? String ?: "2025-12-31",
                    taxStatus = response["taxStatus"] as? String ?: "TAXED",
                    taxDueDate = response["taxDueDate"] as? String ?: "2025-12-31"
                )
            }
            .doOnError { e -> logger.error("Error fetching vehicle details for {}", registrationNumber, e) }
            .onErrorReturn(VehicleResponse(
                registrationNumber = registrationNumber,
                make = "ERROR",
                model = "ERROR", 
                yearOfManufacture = 0,
                fuelType = "UNKNOWN",
                co2Emissions = 0,
                motStatus = "ERROR",
                motExpiryDate = "UNKNOWN",
                taxStatus = "ERROR",
                taxDueDate = "UNKNOWN"
            ))
    }

    @PostMapping("/verify-address")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyAddress(@Valid @RequestBody request: AddressVerificationRequest): Mono<AddressVerificationResponse> {
        logger.info("Verifying address for license: {}", request.licenseNumber)
        
        return webClient.post()
            .uri("https://api.dvla.gov.uk/v1/verify/address")
            .header("Authorization", "Bearer \${DVLA_API_KEY}")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                AddressVerificationResponse(
                    verified = response["verified"] as? Boolean ?: false,
                    matchScore = response["matchScore"] as? Double ?: 0.0,
                    currentAddress = response["currentAddress"] as? String ?: "",
                    lastUpdated = response["lastUpdated"] as? String ?: ""
                )
            }
            .doOnError { e -> logger.error("Error verifying address for {}", request.licenseNumber, e) }
            .onErrorReturn(AddressVerificationResponse(
                verified = false,
                matchScore = 0.0,
                currentAddress = "ERROR",
                lastUpdated = "ERROR"
            ))
    }
}

data class DrivingLicenseResponse(
    val licenseNumber: String,
    val status: String,
    val expiryDate: String,
    val categories: List<String>,
    val endorsements: Int,
    val valid: Boolean
)

data class VehicleResponse(
    val registrationNumber: String,
    val make: String,
    val model: String,
    val yearOfManufacture: Int,
    val fuelType: String,
    val co2Emissions: Int,
    val motStatus: String,
    val motExpiryDate: String,
    val taxStatus: String,
    val taxDueDate: String
)

data class AddressVerificationRequest(
    @field:NotBlank val licenseNumber: String,
    @field:NotBlank val address: String,
    @field:NotBlank val postcode: String
)

data class AddressVerificationResponse(
    val verified: Boolean,
    val matchScore: Double,
    val currentAddress: String,
    val lastUpdated: String
)