package com.uk.gov.connectors.energy

import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import reactor.core.publisher.Mono
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Department for Energy Security & Net Zero Connector
 * Provides access to energy licenses, renewable energy certificates, and carbon credits
 */
@Service
class EnergySecurityConnector {

    private val logger: Logger = LoggerFactory.getLogger(EnergySecurityConnector::class.java)
    private val webClient = WebClient.builder()
        .baseUrl("https://api.energysecurity.gov.uk")
        .build()

    @Cacheable("energy-licenses")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun verifyEnergyLicenses(nationalInsuranceNumber: String): Mono<EnergyLicenses> {
        return webClient.get()
            .uri("/v1/licenses/energy?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(EnergyLicenses::class.java)
            .onErrorReturn(EnergyLicenses(emptyList(), emptyList(), emptyList()))
    }

    @Cacheable("renewable-certificates")
    @Retryable(value = [Exception::class], maxAttempts = 3, backoff = Backoff(delay = 1000))
    fun getRenewableCertificates(nationalInsuranceNumber: String): Mono<RenewableCertificates> {
        return webClient.get()
            .uri("/v1/renewable/certificates?ni={ni}", nationalInsuranceNumber)
            .retrieve()
            .bodyToMono(RenewableCertificates::class.java)
            .onErrorReturn(RenewableCertificates(emptyList(), emptyList()))
    }
}

data class EnergyLicenses(
    val activeLicenses: List<EnergyLicense>,
    val renewablePermits: List<RenewablePermit>,
    val carbonCredits: List<CarbonCredit>
)

data class EnergyLicense(
    val licenseId: String,
    val type: String,
    val capacity: String,
    val issueDate: String,
    val status: String
)

data class RenewablePermit(val permitId: String, val type: String, val capacity: String, val status: String)
data class CarbonCredit(val creditId: String, val amount: Double, val issueDate: String, val status: String)
data class RenewableCertificates(val certificates: List<Certificate>, val tradingRecords: List<TradingRecord>)
data class Certificate(val certId: String, val type: String, val mwh: Double, val issueDate: String)
data class TradingRecord(val recordId: String, val type: String, val amount: Double, val tradeDate: String)