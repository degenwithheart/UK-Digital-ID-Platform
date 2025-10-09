package com.uk.gov.connectors.transport

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
@RequestMapping("/api/connectors/transport")
class TransportConnector @Autowired constructor(private val webClient: WebClient) {

    private val logger: Logger = LoggerFactory.getLogger(TransportConnector::class.java)

    @GetMapping("/public-transport-entitlements/{personId}")
    @Cacheable("transport-entitlements")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getTransportEntitlements(@PathVariable personId: String): Mono<TransportEntitlementsResponse> {
        logger.info("Getting transport entitlements for person: {}", personId)
        
        return webClient.get()
            .uri("https://api.tfl.gov.uk/entitlements/v1/{personId}", personId)
            .header("Authorization", "Bearer \${TFL_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val entitlements = (response["entitlements"] as? List<Map<String, Any>>) ?: emptyList()
                TransportEntitlementsResponse(
                    personId = personId,
                    totalEntitlements = entitlements.size,
                    activeEntitlements = entitlements.count { (it["status"] as? String) == "ACTIVE" },
                    eligibleForFreeTravel = entitlements.any { 
                        (it["type"] as? String) in listOf("FREEDOM_PASS", "DISABLED_PERSONS_RAILCARD", "SENIOR_RAILCARD")
                    },
                    entitlements = entitlements.map { entitlement ->
                        TransportEntitlement(
                            type = entitlement["type"] as? String ?: "UNKNOWN",
                            description = entitlement["description"] as? String ?: "UNKNOWN",
                            status = entitlement["status"] as? String ?: "UNKNOWN",
                            startDate = entitlement["startDate"] as? String ?: "UNKNOWN",
                            endDate = entitlement["endDate"] as? String,
                            discountPercentage = entitlement["discountPercentage"] as? Int ?: 0,
                            eligibleServices = (entitlement["eligibleServices"] as? List<String>) ?: emptyList(),
                            cardNumber = entitlement["cardNumber"] as? String
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting transport entitlements for {}", personId, e) }
            .onErrorReturn(TransportEntitlementsResponse(
                personId = personId,
                totalEntitlements = 0,
                activeEntitlements = 0,
                eligibleForFreeTravel = false,
                entitlements = emptyList()
            ))
    }

    @GetMapping("/vehicle-mot/{registrationNumber}")
    @Cacheable("vehicle-mot")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getVehicleMOT(@PathVariable @Pattern(regexp = "^[A-Z]{2}\\d{2}\\s?[A-Z]{3}$|^[A-Z]\\d{1,3}\\s?[A-Z]{3}$") registrationNumber: String): Mono<MOTResponse> {
        logger.info("Getting MOT details for vehicle: {}", registrationNumber)
        
        return webClient.get()
            .uri("https://api.dvsa.gov.uk/mot/v1/{registrationNumber}", registrationNumber)
            .header("Authorization", "Bearer \${DVSA_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val motTests = (response["motTests"] as? List<Map<String, Any>>) ?: emptyList()
                val latestTest = motTests.firstOrNull()
                
                MOTResponse(
                    registrationNumber = registrationNumber,
                    make = response["make"] as? String ?: "UNKNOWN",
                    model = response["model"] as? String ?: "UNKNOWN",
                    colour = response["colour"] as? String ?: "UNKNOWN",
                    yearOfManufacture = response["yearOfManufacture"] as? Int ?: 0,
                    engineSize = response["engineSize"] as? Int ?: 0,
                    fuelType = response["fuelType"] as? String ?: "UNKNOWN",
                    motValid = latestTest?.get("result") as? String == "PASS",
                    motExpiryDate = latestTest?.get("expiryDate") as? String ?: "UNKNOWN",
                    lastTestDate = latestTest?.get("completedDate") as? String ?: "UNKNOWN",
                    lastTestResult = latestTest?.get("result") as? String ?: "UNKNOWN",
                    odometerReading = latestTest?.get("odometerValue") as? Int ?: 0,
                    testNumber = latestTest?.get("motTestNumber") as? String ?: "UNKNOWN",
                    testCentre = latestTest?.get("testCentre") as? String ?: "UNKNOWN",
                    defects = ((latestTest?.get("rfrAndComments") as? List<Map<String, Any>>) ?: emptyList()).map { defect ->
                        MOTDefect(
                            type = defect["type"] as? String ?: "UNKNOWN",
                            text = defect["text"] as? String ?: "UNKNOWN",
                            dangerous = defect["dangerous"] as? Boolean ?: false,
                            location = defect["location"] as? String ?: "UNKNOWN"
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting MOT details for {}", registrationNumber, e) }
            .onErrorReturn(MOTResponse(
                registrationNumber = registrationNumber,
                make = "ERROR",
                model = "ERROR",
                colour = "ERROR",
                yearOfManufacture = 0,
                engineSize = 0,
                fuelType = "ERROR",
                motValid = false,
                motExpiryDate = "ERROR",
                lastTestDate = "ERROR",
                lastTestResult = "ERROR",
                odometerReading = 0,
                testNumber = "ERROR",
                testCentre = "ERROR",
                defects = emptyList()
            ))
    }

    @GetMapping("/taxi-licensing/{licenseNumber}")
    @Cacheable("taxi-licensing")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getTaxiLicense(@PathVariable licenseNumber: String): Mono<TaxiLicenseResponse> {
        logger.info("Getting taxi license details for: {}", licenseNumber)
        
        return webClient.get()
            .uri("https://api.taxilicensing.gov.uk/licenses/v1/{licenseNumber}", licenseNumber)
            .header("Authorization", "Bearer \${TAXI_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                TaxiLicenseResponse(
                    licenseNumber = licenseNumber,
                    driverName = response["driverName"] as? String ?: "UNKNOWN",
                    licenseType = response["licenseType"] as? String ?: "UNKNOWN", // HACKNEY_CARRIAGE, PRIVATE_HIRE
                    status = response["status"] as? String ?: "UNKNOWN",
                    issueDate = response["issueDate"] as? String ?: "UNKNOWN",
                    expiryDate = response["expiryDate"] as? String ?: "UNKNOWN",
                    issuingAuthority = response["issuingAuthority"] as? String ?: "UNKNOWN",
                    vehicleRegistration = response["vehicleRegistration"] as? String ?: "UNKNOWN",
                    validForWheelchair = response["validForWheelchair"] as? Boolean ?: false,
                    insuranceValid = response["insuranceValid"] as? Boolean ?: false,
                    dbsCheckValid = response["dbsCheckValid"] as? Boolean ?: false,
                    conditions = (response["conditions"] as? List<String>) ?: emptyList(),
                    endorsements = (response["endorsements"] as? List<String>) ?: emptyList()
                )
            }
            .doOnError { e -> logger.error("Error getting taxi license for {}", licenseNumber, e) }
            .onErrorReturn(TaxiLicenseResponse(
                licenseNumber = licenseNumber,
                driverName = "ERROR",
                licenseType = "ERROR",
                status = "ERROR",
                issueDate = "ERROR",
                expiryDate = "ERROR",
                issuingAuthority = "ERROR",
                vehicleRegistration = "ERROR",
                validForWheelchair = false,
                insuranceValid = false,
                dbsCheckValid = false,
                conditions = emptyList(),
                endorsements = emptyList()
            ))
    }

    @GetMapping("/hgv-operator/{operatorLicense}")
    @Cacheable("hgv-operator")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getHGVOperatorLicense(@PathVariable operatorLicense: String): Mono<HGVOperatorResponse> {
        logger.info("Getting HGV operator license for: {}", operatorLicense)
        
        return webClient.get()
            .uri("https://api.dvsa.gov.uk/operators/v1/{operatorLicense}", operatorLicense)
            .header("Authorization", "Bearer \${DVSA_OPERATOR_API_KEY}")
            .retrieve()
            .bodyToMono(Map::class.java)
            .timeout(java.time.Duration.ofSeconds(5))
            .map { response ->
                val vehicles = (response["vehicles"] as? List<Map<String, Any>>) ?: emptyList()
                val drivers = (response["drivers"] as? List<Map<String, Any>>) ?: emptyList()
                
                HGVOperatorResponse(
                    operatorLicense = operatorLicense,
                    operatorName = response["operatorName"] as? String ?: "UNKNOWN",
                    tradingName = response["tradingName"] as? String ?: "UNKNOWN",
                    licenseStatus = response["licenseStatus"] as? String ?: "UNKNOWN",
                    licenseType = response["licenseType"] as? String ?: "UNKNOWN", // STANDARD_NATIONAL, STANDARD_INTERNATIONAL, RESTRICTED
                    authorisedVehicles = response["authorisedVehicles"] as? Int ?: 0,
                    authorisedTrailers = response["authorisedTrailers"] as? Int ?: 0,
                    currentVehicles = vehicles.size,
                    currentDrivers = drivers.size,
                    mainOperatingCentre = response["mainOperatingCentre"] as? String ?: "UNKNOWN",
                    transportManager = response["transportManager"] as? String ?: "UNKNOWN",
                    repute = response["repute"] as? String ?: "UNKNOWN", // GOOD, LOSS_OF_REPUTE
                    financialStanding = response["financialStanding"] as? String ?: "UNKNOWN",
                    professionalCompetence = response["professionalCompetence"] as? String ?: "UNKNOWN",
                    expiryDate = response["expiryDate"] as? String ?: "UNKNOWN",
                    vehicles = vehicles.map { vehicle ->
                        HGVVehicle(
                            registrationNumber = vehicle["registrationNumber"] as? String ?: "UNKNOWN",
                            makeModel = vehicle["makeModel"] as? String ?: "UNKNOWN",
                            grossWeight = vehicle["grossWeight"] as? Int ?: 0,
                            trailerAuthorisation = vehicle["trailerAuthorisation"] as? Boolean ?: false
                        )
                    }
                )
            }
            .doOnError { e -> logger.error("Error getting HGV operator license for {}", operatorLicense, e) }
            .onErrorReturn(HGVOperatorResponse(
                operatorLicense = operatorLicense,
                operatorName = "ERROR",
                tradingName = "ERROR",
                licenseStatus = "ERROR",
                licenseType = "ERROR",
                authorisedVehicles = 0,
                authorisedTrailers = 0,
                currentVehicles = 0,
                currentDrivers = 0,
                mainOperatingCentre = "ERROR",
                transportManager = "ERROR",
                repute = "ERROR",
                financialStanding = "ERROR",
                professionalCompetence = "ERROR",
                expiryDate = "ERROR",
                vehicles = emptyList()
            ))
    }
}

data class TransportEntitlementsResponse(
    val personId: String,
    val totalEntitlements: Int,
    val activeEntitlements: Int,
    val eligibleForFreeTravel: Boolean,
    val entitlements: List<TransportEntitlement>
)

data class TransportEntitlement(
    val type: String,
    val description: String,
    val status: String,
    val startDate: String,
    val endDate: String?,
    val discountPercentage: Int,
    val eligibleServices: List<String>,
    val cardNumber: String?
)

data class MOTResponse(
    val registrationNumber: String,
    val make: String,
    val model: String,
    val colour: String,
    val yearOfManufacture: Int,
    val engineSize: Int,
    val fuelType: String,
    val motValid: Boolean,
    val motExpiryDate: String,
    val lastTestDate: String,
    val lastTestResult: String,
    val odometerReading: Int,
    val testNumber: String,
    val testCentre: String,
    val defects: List<MOTDefect>
)

data class MOTDefect(
    val type: String,
    val text: String,
    val dangerous: Boolean,
    val location: String
)

data class TaxiLicenseResponse(
    val licenseNumber: String,
    val driverName: String,
    val licenseType: String,
    val status: String,
    val issueDate: String,
    val expiryDate: String,
    val issuingAuthority: String,
    val vehicleRegistration: String,
    val validForWheelchair: Boolean,
    val insuranceValid: Boolean,
    val dbsCheckValid: Boolean,
    val conditions: List<String>,
    val endorsements: List<String>
)

data class HGVOperatorResponse(
    val operatorLicense: String,
    val operatorName: String,
    val tradingName: String,
    val licenseStatus: String,
    val licenseType: String,
    val authorisedVehicles: Int,
    val authorisedTrailers: Int,
    val currentVehicles: Int,
    val currentDrivers: Int,
    val mainOperatingCentre: String,
    val transportManager: String,
    val repute: String,
    val financialStanding: String,
    val professionalCompetence: String,
    val expiryDate: String,
    val vehicles: List<HGVVehicle>
)

data class HGVVehicle(
    val registrationNumber: String,
    val makeModel: String,
    val grossWeight: Int,
    val trailerAuthorisation: Boolean
)