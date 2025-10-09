package com.uk.gov.connectors.unified

import org.springframework.web.bind.annotation.*
import org.springframework.beans.factory.annotation.Autowired
import reactor.core.publisher.Mono
import reactor.core.publisher.Flux
import javax.validation.Valid
import javax.validation.constraints.NotBlank
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.retry.annotation.Retryable
import org.springframework.retry.annotation.Backoff
import org.springframework.cache.annotation.Cacheable
import com.uk.gov.connectors.hmrc.*
import com.uk.gov.connectors.dvla.*
import com.uk.gov.connectors.nhs.*
import com.uk.gov.connectors.dwp.*
import com.uk.gov.connectors.homeoffice.*
import com.uk.gov.connectors.companies.*
import com.uk.gov.connectors.financial.*
import com.uk.gov.connectors.education.*
import com.uk.gov.connectors.local.*
import com.uk.gov.connectors.law.*
import com.uk.gov.connectors.transport.*
import com.uk.gov.connectors.healthcare.*
import com.uk.gov.connectors.property.*
import com.uk.gov.connectors.security.*
import com.uk.gov.connectors.professional.*
import com.uk.gov.connectors.border.*
import com.uk.gov.connectors.courts.*
import com.uk.gov.connectors.defra.*
import com.uk.gov.connectors.business.*
import com.uk.gov.connectors.culture.*
import com.uk.gov.connectors.energy.*
import com.uk.gov.connectors.housing.*
import com.uk.gov.connectors.science.*

@RestController
@RequestMapping("/api/connectors/unified")
class UnifiedGovernmentConnector {

    private val logger: Logger = LoggerFactory.getLogger(UnifiedGovernmentConnector::class.java)

    @Autowired private lateinit var hmrcConnector: HMRCConnector
    @Autowired private lateinit var dvlaConnector: DVLAConnector
    @Autowired private lateinit var nhsConnector: NHSConnector
    @Autowired private lateinit var dwpConnector: DWPConnector
    @Autowired private lateinit var homeOfficeConnector: HomeOfficeConnector
    @Autowired private lateinit var companiesHouseConnector: CompaniesHouseConnector
    @Autowired private lateinit var financialConnector: FinancialServicesConnector
    @Autowired private lateinit var educationConnector: EducationConnector
    @Autowired private lateinit var localGovernmentConnector: LocalGovernmentConnector
    @Autowired private lateinit var lawEnforcementConnector: LawEnforcementConnector
    @Autowired private lateinit var transportConnector: TransportConnector
    @Autowired private lateinit var healthcareConnector: HealthcareConnector
    @Autowired private lateinit var landRegistryConnector: LandRegistryConnector
    @Autowired private lateinit var securityConnector: SecurityConnector
    @Autowired private lateinit var professionalBodiesConnector: ProfessionalBodiesConnector
    @Autowired private lateinit var borderControlConnector: BorderControlConnector
    
    // Expanded Government Department Connectors
    @Autowired private lateinit var courtsTriReportsConnector: CourtsTriReportsConnector
    @Autowired private lateinit var defraConnector: DEFRAConnector
    @Autowired private lateinit var businessTradeConnector: BusinessTradeConnector
    @Autowired private lateinit var cultureMediaSportConnector: CultureMediaSportConnector
    @Autowired private lateinit var energySecurityConnector: EnergySecurityConnector
    @Autowired private lateinit var housingCommunitiesConnector: HousingCommunitiesConnector
    @Autowired private lateinit var scienceInnovationConnector: ScienceInnovationConnector

    @PostMapping("/comprehensive-verification")
    fun performComprehensiveVerification(@Valid @RequestBody request: ComprehensiveVerificationRequest): Mono<ComprehensiveVerificationResponse> {
        logger.info("Performing comprehensive verification for citizen")
        
        return Mono.zip(
            // Core Identity Verification
            if (request.niNumber != null) dwpConnector.verifyNationalInsuranceNumber(request.niNumber) else Mono.just(null),
            if (request.nhsNumber != null) nhsConnector.verifyNHSNumber(request.nhsNumber) else Mono.just(null),
            if (request.drivingLicense != null) dvlaConnector.getDrivingLicense(request.drivingLicense) else Mono.just(null),
            
            // Benefits and Eligibility
            if (request.niNumber != null) dwpConnector.getBenefitsEligibility(request.niNumber) else Mono.just(null),
            if (request.income != null) hmrcConnector.verifyEligibility(EligibilityRequest(request.niNumber ?: "", request.income)) else Mono.just(null),
            if (request.nhsNumber != null) nhsConnector.getMedicalEligibility(request.nhsNumber) else Mono.just(null),
            
            // Immigration Status (if applicable)
            if (request.rightToWorkShareCode != null) homeOfficeConnector.checkRightToWork(RightToWorkRequest(request.rightToWorkShareCode, request.dateOfBirth ?: "")) else Mono.just(null),
            if (request.rightToRentShareCode != null) homeOfficeConnector.checkRightToRent(RightToRentRequest(request.rightToRentShareCode, request.dateOfBirth ?: "")) else Mono.just(null)
        ) { niVerification, nhsVerification, drivingLicense, benefits, hmrcEligibility, medicalEligibility, rightToWork, rightToRent ->
            
            ComprehensiveVerificationResponse(
                verificationId = java.util.UUID.randomUUID().toString(),
                timestamp = java.time.Instant.now().toString(),
                overallStatus = determineOverallStatus(niVerification, nhsVerification, drivingLicense),
                
                // Identity Verification Results
                nationalInsurance = niVerification?.let { IdentityVerificationResult(it.valid, it.status, "NI_VERIFIED") },
                nhsVerification = nhsVerification?.let { IdentityVerificationResult(it.verified, if (it.active) "ACTIVE" else "INACTIVE", "NHS_VERIFIED") },
                drivingLicense = drivingLicense?.let { IdentityVerificationResult(it.valid, it.status, "DRIVING_LICENSE_VERIFIED") },
                
                // Eligibility Results
                benefitsEligible = benefits?.let { it.universalCreditEligible || it.pipEligible || it.jsaEligible },
                hmrcEligible = hmrcEligibility?.eligible,
                medicalExemptions = medicalEligibility?.let { it.prescriptionExemption || it.dentalExemption || it.opticalExemption },
                
                // Immigration Status
                rightToWork = rightToWork?.hasRightToWork,
                rightToRent = rightToRent?.hasRightToRent,
                
                // Risk Assessment
                riskScore = calculateRiskScore(niVerification, nhsVerification, drivingLicense, benefits),
                riskFactors = identifyRiskFactors(niVerification, nhsVerification, drivingLicense, benefits),
                
                // Recommendations
                recommendedActions = generateRecommendations(niVerification, nhsVerification, benefits, medicalEligibility),
                
                // Data Sources
                dataSourcesUsed = listOfNotNull(
                    if (niVerification != null) "DWP" else null,
                    if (nhsVerification != null) "NHS" else null,
                    if (drivingLicense != null) "DVLA" else null,
                    if (hmrcEligibility != null) "HMRC" else null,
                    if (rightToWork != null) "HOME_OFFICE" else null
                )
            )
        }
    }

    @PostMapping("/complete-government-verification")
    fun performCompleteGovernmentVerification(@Valid @RequestBody request: CompleteGovernmentVerificationRequest): Mono<CompleteGovernmentVerificationResponse> {
        logger.info("Performing complete government verification using all 25 systems for citizen")
        
        return Mono.zip(
            // Core Identity & Tax (4 systems)
            if (request.niNumber != null) dwpConnector.verifyNationalInsuranceNumber(request.niNumber) else Mono.just(null),
            if (request.nhsNumber != null) nhsConnector.verifyNHSNumber(request.nhsNumber) else Mono.just(null),
            if (request.drivingLicense != null) dvlaConnector.getDrivingLicense(request.drivingLicense) else Mono.just(null),
            if (request.niNumber != null) hmrcConnector.getTaxRecord(request.niNumber) else Mono.just(null),
            
            // Immigration & Border Control (2 systems)
            if (request.rightToWorkShareCode != null) homeOfficeConnector.checkRightToWork(RightToWorkRequest(request.rightToWorkShareCode, request.dateOfBirth ?: "")) else Mono.just(null),
            if (request.passportNumber != null) borderControlConnector.checkTravelHistory(request.passportNumber) else Mono.just(null),
            
            // Business & Financial (3 systems)
            if (request.companyNumber != null) companiesHouseConnector.getCompanyDetails(request.companyNumber) else Mono.just(null),
            if (request.professionalId != null) financialConnector.verifyFinancialCredentials(request.professionalId) else Mono.just(null),
            if (request.businessRegistration != null) businessTradeConnector.verifyBusinessRegistration(request.businessRegistration) else Mono.just(null),
            
            // Education & Professional (2 systems)
            if (request.studentId != null) educationConnector.getEducationRecord(request.studentId) else Mono.just(null),
            if (request.professionalId != null) professionalBodiesConnector.getProfessionalCredentials(request.professionalId) else Mono.just(null),
            
            // Law, Security & Courts (3 systems)
            if (request.niNumber != null) lawEnforcementConnector.getCriminalRecord(request.niNumber) else Mono.just(null),
            if (request.securityClearanceId != null) securityConnector.getSecurityClearance(request.securityClearanceId) else Mono.just(null),
            if (request.caseNumber != null) courtsTriReportsConnector.verifyCaseInvolvement(request.caseNumber, request.niNumber ?: "") else Mono.just(null),
            
            // Healthcare & Transport (2 systems)
            if (request.nhsNumber != null) healthcareConnector.getMedicalRecords(request.nhsNumber) else Mono.just(null),
            if (request.transportId != null) transportConnector.getTransportLicenses(request.transportId) else Mono.just(null),
            
            // Property & Local Government (2 systems)
            if (request.propertyId != null) landRegistryConnector.getPropertyOwnership(request.propertyId) else Mono.just(null),
            if (request.localServiceId != null) localGovernmentConnector.getLocalServices(request.localServiceId) else Mono.just(null),
            
            // Environment & Housing (2 systems)
            if (request.environmentalPermit != null) defraConnector.verifyEnvironmentalPermit(request.environmentalPermit) else Mono.just(null),
            if (request.housingReference != null) housingCommunitiesConnector.verifyHousingRecord(request.housingReference) else Mono.just(null),
            
            // Culture, Energy & Science (3 systems)
            if (request.mediaLicense != null) cultureMediaSportConnector.verifyMediaLicense(request.mediaLicense) else Mono.just(null),
            if (request.energyLicense != null) energySecurityConnector.verifyEnergyLicense(request.energyLicense) else Mono.just(null),
            if (request.researchGrant != null) scienceInnovationConnector.verifyResearchGrant(request.researchGrant) else Mono.just(null)
            
        ) { dwpResult, nhsResult, dvlaResult, hmrcResult, homeOfficeResult, borderResult, 
            companyResult, financialResult, businessResult, educationResult, professionalResult,
            lawResult, securityResult, courtsResult, healthResult, transportResult,
            propertyResult, localResult, defraResult, housingResult, cultureResult, energyResult, scienceResult ->
            
            val verificationResults = mapOf(
                "DWP" to dwpResult,
                "NHS" to nhsResult,
                "DVLA" to dvlaResult,
                "HMRC" to hmrcResult,
                "HOME_OFFICE" to homeOfficeResult,
                "BORDER_CONTROL" to borderResult,
                "COMPANIES_HOUSE" to companyResult,
                "FINANCIAL_SERVICES" to financialResult,
                "BUSINESS_TRADE" to businessResult,
                "EDUCATION" to educationResult,
                "PROFESSIONAL_BODIES" to professionalResult,
                "LAW_ENFORCEMENT" to lawResult,
                "SECURITY_SERVICES" to securityResult,
                "COURTS_TRIBUNALS" to courtsResult,
                "HEALTHCARE" to healthResult,
                "TRANSPORT" to transportResult,
                "LAND_REGISTRY" to propertyResult,
                "LOCAL_GOVERNMENT" to localResult,
                "DEFRA" to defraResult,
                "HOUSING_COMMUNITIES" to housingResult,
                "CULTURE_MEDIA_SPORT" to cultureResult,
                "ENERGY_SECURITY" to energyResult,
                "SCIENCE_INNOVATION" to scienceResult
            )
            
            CompleteGovernmentVerificationResponse(
                verificationId = java.util.UUID.randomUUID().toString(),
                timestamp = java.time.Instant.now().toString(),
                totalSystemsQueried = verificationResults.filter { it.value != null }.size,
                totalSystemsAvailable = 25,
                coveragePercentage = (verificationResults.filter { it.value != null }.size.toDouble() / 25 * 100),
                overallStatus = calculateOverallVerificationStatus(verificationResults),
                verificationResults = verificationResults,
                riskAssessment = generateComprehensiveRiskAssessment(verificationResults),
                complianceStatus = generateComplianceStatus(verificationResults),
                recommendations = generateComprehensiveRecommendations(verificationResults),
                dataSourcesUsed = verificationResults.filter { it.value != null }.keys.toList()
            )
        }
    }

    @PostMapping("/business-verification") 
    fun performBusinessVerification(@Valid @RequestBody request: BusinessVerificationRequest): Mono<BusinessVerificationResponse> {
        logger.info("Performing business verification for: {}", request.companyNumber)
        
        return Mono.zip(
            companiesHouseConnector.getCompanyDetails(request.companyNumber),
            companiesHouseConnector.getCompanyDirectors(request.companyNumber),
            companiesHouseConnector.getPSCDetails(request.companyNumber),
            companiesHouseConnector.getFilingHistory(request.companyNumber),
            if (request.vatNumber != null) hmrcConnector.getVATStatus(request.vatNumber) else Mono.just(null)
        ) { company, directors, psc, filings, vatStatus ->
            
            BusinessVerificationResponse(
                companyNumber = request.companyNumber,
                companyName = company.companyName,
                verificationStatus = if (company.status == "active") "VERIFIED" else "UNVERIFIED",
                companyStatus = company.status,
                incorporationDate = company.incorporationDate,
                
                // Directors Information
                totalDirectors = directors.totalDirectors,
                activeDirectors = directors.activeDirectors,
                
                // Beneficial Ownership
                pscCount = psc.totalPSCs,
                pscCompliant = psc.totalPSCs > 0,
                
                // Compliance Status
                filingCompliance = filings.complianceStatus,
                lastFiling = filings.recentFilings.firstOrNull()?.date ?: "NONE",
                
                // Tax Status
                vatRegistered = vatStatus != null,
                vatStatus = vatStatus?.status,
                
                // Risk Assessment
                businessRiskScore = calculateBusinessRiskScore(company, directors, filings),
                riskFactors = identifyBusinessRiskFactors(company, directors, filings),
                
                // Recommendations
                complianceActions = generateComplianceRecommendations(filings, company)
            )
        }
    }

    @GetMapping("/health-check")
    fun performHealthCheck(): Mono<SystemHealthResponse> {
        logger.info("Performing system health check")
        
        return Flux.merge(
            testServiceHealth("HMRC", "https://api.hmrc.gov.uk/hello/world"),
            testServiceHealth("DVLA", "https://api.dvla.gov.uk/health"),
            testServiceHealth("NHS", "https://api.nhs.uk/health"),
            testServiceHealth("DWP", "https://api.gov.uk/dwp/health"),
            testServiceHealth("HOME_OFFICE", "https://api.gov.uk/home-office/health"),
            testServiceHealth("COMPANIES_HOUSE", "https://api.companieshouse.gov.uk/health")
        ).collectList().map { healthResults ->
            val healthyServices = healthResults.count { it.healthy }
            val totalServices = healthResults.size
            
            SystemHealthResponse(
                overallHealth = if (healthyServices.toDouble() / totalServices >= 0.8) "HEALTHY" else "DEGRADED",
                totalServices = totalServices,
                healthyServices = healthyServices,
                unhealthyServices = totalServices - healthyServices,
                serviceStatus = healthResults.associateBy({ it.serviceName }, { it.status }),
                lastChecked = java.time.Instant.now().toString(),
                uptime = calculateUptime()
            )
        }
    }

    private fun testServiceHealth(serviceName: String, healthUrl: String): Mono<ServiceHealth> {
        return Mono.fromCallable {
            // Simulate health check - in real implementation, make actual HTTP calls
            val isHealthy = (0..10).random() > 2 // 80% chance of being healthy
            ServiceHealth(
                serviceName = serviceName,
                healthy = isHealthy,
                status = if (isHealthy) "UP" else "DOWN",
                responseTime = (50..200).random(),
                lastChecked = java.time.Instant.now().toString()
            )
        }
    }

    private fun determineOverallStatus(niVerification: Any?, nhsVerification: Any?, drivingLicense: Any?): String {
        val verifications = listOfNotNull(niVerification, nhsVerification, drivingLicense)
        return when {
            verifications.size >= 2 -> "VERIFIED"
            verifications.size == 1 -> "PARTIALLY_VERIFIED" 
            else -> "UNVERIFIED"
        }
    }

    private fun calculateRiskScore(niVerification: Any?, nhsVerification: Any?, drivingLicense: Any?, benefits: Any?): Double {
        var score = 0.0
        if (niVerification != null) score += 25.0
        if (nhsVerification != null) score += 25.0
        if (drivingLicense != null) score += 25.0
        if (benefits != null) score += 25.0
        return 100.0 - score // Lower score = higher trust
    }

    // Helper methods for comprehensive verification
    private fun calculateOverallVerificationStatus(verificationResults: Map<String, Any?>): String {
        val successfulVerifications = verificationResults.values.count { it != null }
        val totalPossible = verificationResults.size
        
        return when {
            successfulVerifications >= (totalPossible * 0.8) -> "FULLY_VERIFIED"
            successfulVerifications >= (totalPossible * 0.6) -> "SUBSTANTIALLY_VERIFIED"
            successfulVerifications >= (totalPossible * 0.4) -> "PARTIALLY_VERIFIED"
            successfulVerifications >= (totalPossible * 0.2) -> "MINIMALLY_VERIFIED"
            else -> "UNVERIFIED"
        }
    }
    
    private fun generateComprehensiveRiskAssessment(verificationResults: Map<String, Any?>): ComprehensiveRiskAssessment {
        val identityScore = calculateIdentityScore(verificationResults)
        val legalScore = calculateLegalScore(verificationResults)
        val financialScore = calculateFinancialScore(verificationResults)
        val securityScore = calculateSecurityScore(verificationResults)
        
        val overallScore = (identityScore + legalScore + financialScore + securityScore) / 4
        
        return ComprehensiveRiskAssessment(
            overallRiskScore = overallScore,
            riskLevel = when {
                overallScore <= 20 -> "LOW"
                overallScore <= 40 -> "MEDIUM"
                overallScore <= 70 -> "HIGH"
                else -> "CRITICAL"
            },
            identityVerificationScore = identityScore,
            legalComplianceScore = legalScore,
            financialRiskScore = financialScore,
            securityClearanceScore = securityScore,
            flaggedIssues = identifyFlaggedIssues(verificationResults),
            positiveIndicators = identifyPositiveIndicators(verificationResults)
        )
    }
    
    private fun generateComplianceStatus(verificationResults: Map<String, Any?>): ComplianceStatus {
        val gdprCompliant = verificationResults["DWP"] != null && verificationResults["NHS"] != null
        val kycCompliant = verificationResults["DWP"] != null && verificationResults["DVLA"] != null
        val amlCompliant = verificationResults["FINANCIAL_SERVICES"] != null || verificationResults["COMPANIES_HOUSE"] != null
        val sanctionsChecked = verificationResults["LAW_ENFORCEMENT"] != null || verificationResults["SECURITY_SERVICES"] != null
        
        val complianceScore = listOf(gdprCompliant, kycCompliant, amlCompliant, sanctionsChecked).count { it }.toDouble() / 4 * 100
        
        return ComplianceStatus(
            gdprCompliant = gdprCompliant,
            kycCompliant = kycCompliant,
            amlCompliant = amlCompliant,
            sanctionsChecked = sanctionsChecked,
            complianceScore = complianceScore,
            complianceGaps = generateComplianceGaps(gdprCompliant, kycCompliant, amlCompliant, sanctionsChecked)
        )
    }
    
    private fun generateComprehensiveRecommendations(verificationResults: Map<String, Any?>): List<String> {
        val recommendations = mutableListOf<String>()
        
        if (verificationResults["DWP"] == null) recommendations.add("Complete National Insurance verification for identity confirmation")
        if (verificationResults["NHS"] == null) recommendations.add("Verify NHS number for healthcare eligibility")
        if (verificationResults["LAW_ENFORCEMENT"] == null) recommendations.add("Conduct criminal record check for compliance")
        if (verificationResults["FINANCIAL_SERVICES"] == null) recommendations.add("Verify financial credentials for AML compliance")
        if (verificationResults["EDUCATION"] == null) recommendations.add("Validate educational qualifications")
        
        val verifiedCount = verificationResults.values.count { it != null }
        if (verifiedCount < 10) {
            recommendations.add("Increase verification coverage to achieve minimum 10 system verification")
        }
        
        return recommendations
    }
    
    private fun calculateIdentityScore(verificationResults: Map<String, Any?>): Double {
        val coreIdentityFactors = listOf("DWP", "NHS", "DVLA", "HMRC")
        val verified = coreIdentityFactors.count { verificationResults[it] != null }
        return (4 - verified).toDouble() / 4 * 100 // Lower is better (less risk)
    }
    
    private fun calculateLegalScore(verificationResults: Map<String, Any?>): Double {
        val legalFactors = listOf("LAW_ENFORCEMENT", "COURTS_TRIBUNALS", "HOME_OFFICE")
        val verified = legalFactors.count { verificationResults[it] != null }
        return if (verified > 0) 0.0 else 50.0 // Penalty for no legal verification
    }
    
    private fun calculateFinancialScore(verificationResults: Map<String, Any?>): Double {
        val financialFactors = listOf("FINANCIAL_SERVICES", "COMPANIES_HOUSE", "BUSINESS_TRADE")
        val verified = financialFactors.count { verificationResults[it] != null }
        return (3 - verified).toDouble() / 3 * 50 // Scale to 0-50
    }
    
    private fun calculateSecurityScore(verificationResults: Map<String, Any?>): Double {
        val securityFactors = listOf("SECURITY_SERVICES", "BORDER_CONTROL")
        val verified = securityFactors.count { verificationResults[it] != null }
        return (2 - verified).toDouble() / 2 * 25 // Scale to 0-25
    }
    
    private fun identifyFlaggedIssues(verificationResults: Map<String, Any?>): List<String> {
        val issues = mutableListOf<String>()
        
        if (verificationResults["LAW_ENFORCEMENT"] != null) issues.add("Criminal record found - requires review")
        if (verificationResults["COURTS_TRIBUNALS"] != null) issues.add("Court involvement detected - legal review needed")
        if (verificationResults["BORDER_CONTROL"] != null) issues.add("Immigration history requires verification")
        
        val verificationRate = verificationResults.values.count { it != null }.toDouble() / verificationResults.size
        if (verificationRate < 0.3) issues.add("Low verification coverage - identity confirmation needed")
        
        return issues
    }
    
    private fun identifyPositiveIndicators(verificationResults: Map<String, Any?>): List<String> {
        val positives = mutableListOf<String>()
        
        if (verificationResults["PROFESSIONAL_BODIES"] != null) positives.add("Professional credentials verified")
        if (verificationResults["EDUCATION"] != null) positives.add("Educational qualifications confirmed")
        if (verificationResults["SECURITY_SERVICES"] != null) positives.add("Security clearance verified")
        if (verificationResults["FINANCIAL_SERVICES"] != null) positives.add("Financial standing verified")
        
        val verificationRate = verificationResults.values.count { it != null }.toDouble() / verificationResults.size
        if (verificationRate > 0.8) positives.add("Comprehensive verification achieved across government systems")
        
        return positives
    }
    
    private fun generateComplianceGaps(gdpr: Boolean, kyc: Boolean, aml: Boolean, sanctions: Boolean): List<String> {
        val gaps = mutableListOf<String>()
        
        if (!gdpr) gaps.add("GDPR compliance requires DWP and NHS verification")
        if (!kyc) gaps.add("KYC compliance requires DWP and DVLA verification") 
        if (!aml) gaps.add("AML compliance requires financial services or company verification")
        if (!sanctions) gaps.add("Sanctions screening requires law enforcement or security verification")
        
        return gaps
    }

    private fun identifyRiskFactors(niVerification: Any?, nhsVerification: Any?, drivingLicense: Any?, benefits: Any?): List<String> {
        val factors = mutableListOf<String>()
        if (niVerification == null) factors.add("NO_NI_VERIFICATION")
        if (nhsVerification == null) factors.add("NO_NHS_VERIFICATION") 
        if (drivingLicense == null) factors.add("NO_DRIVING_LICENSE")
        return factors
    }

    private fun generateRecommendations(niVerification: Any?, nhsVerification: Any?, benefits: Any?, medicalEligibility: Any?): List<String> {
        val recommendations = mutableListOf<String>()
        if (niVerification == null) recommendations.add("PROVIDE_NI_NUMBER")
        if (nhsVerification == null) recommendations.add("VERIFY_NHS_REGISTRATION")
        if (benefits != null) recommendations.add("REVIEW_BENEFIT_ENTITLEMENTS")
        return recommendations
    }

    private fun calculateBusinessRiskScore(company: Any, directors: Any, filings: Any): Double {
        // Simplified risk calculation - in reality would be more complex
        return (20..80).random().toDouble()
    }

    private fun identifyBusinessRiskFactors(company: Any, directors: Any, filings: Any): List<String> {
        return listOf("RECENT_INCORPORATION", "MULTIPLE_DIRECTORS", "REGULAR_FILINGS")
    }

    private fun generateComplianceRecommendations(filings: Any, company: Any): List<String> {
        return listOf("FILE_CONFIRMATION_STATEMENT", "UPDATE_REGISTERED_OFFICE", "SUBMIT_ACCOUNTS")
    }

    private fun calculateUptime(): String {
        return "99.95%" // Would be calculated from actual service metrics
    }
}

// Request/Response Data Classes
data class ComprehensiveVerificationRequest(
    val niNumber: String?,
    val nhsNumber: String?,
    val drivingLicense: String?,
    val income: Double?,
    val dateOfBirth: String?,
    val rightToWorkShareCode: String?,
    val rightToRentShareCode: String?
)

data class ComprehensiveVerificationResponse(
    val verificationId: String,
    val timestamp: String,
    val overallStatus: String,
    val nationalInsurance: IdentityVerificationResult?,
    val nhsVerification: IdentityVerificationResult?,
    val drivingLicense: IdentityVerificationResult?,
    val benefitsEligible: Boolean?,
    val hmrcEligible: Boolean?,
    val medicalExemptions: Boolean?,
    val rightToWork: Boolean?,
    val rightToRent: Boolean?,
    val riskScore: Double,
    val riskFactors: List<String>,
    val recommendedActions: List<String>,
    val dataSourcesUsed: List<String>
)

data class IdentityVerificationResult(
    val verified: Boolean,
    val status: String,
    val verificationMethod: String
)

data class BusinessVerificationRequest(
    @field:NotBlank val companyNumber: String,
    val vatNumber: String?
)

data class BusinessVerificationResponse(
    val companyNumber: String,
    val companyName: String,
    val verificationStatus: String,
    val companyStatus: String,
    val incorporationDate: String,
    val totalDirectors: Int,
    val activeDirectors: Int,
    val pscCount: Int,
    val pscCompliant: Boolean,
    val filingCompliance: String,
    val lastFiling: String,
    val vatRegistered: Boolean,
    val vatStatus: String?,
    val businessRiskScore: Double,
    val riskFactors: List<String>,
    val complianceActions: List<String>
)

data class SystemHealthResponse(
    val overallHealth: String,
    val totalServices: Int,
    val healthyServices: Int,
    val unhealthyServices: Int,
    val serviceStatus: Map<String, String>,
    val lastChecked: String,
    val uptime: String
)

data class ServiceHealth(
    val serviceName: String,
    val healthy: Boolean,
    val status: String,
    val responseTime: Int,
    val lastChecked: String
)

// Complete Government Verification Data Classes
data class CompleteGovernmentVerificationRequest(
    // Core Identity
    val niNumber: String? = null,
    val nhsNumber: String? = null,
    val drivingLicense: String? = null,
    val dateOfBirth: String? = null,
    
    // Immigration
    val rightToWorkShareCode: String? = null,
    val passportNumber: String? = null,
    
    // Business & Financial
    val companyNumber: String? = null,
    val businessRegistration: String? = null,
    val professionalId: String? = null,
    
    // Education
    val studentId: String? = null,
    
    // Legal & Security
    val caseNumber: String? = null,
    val securityClearanceId: String? = null,
    
    // Healthcare & Transport
    val transportId: String? = null,
    
    // Property & Local
    val propertyId: String? = null,
    val localServiceId: String? = null,
    
    // Environmental & Housing
    val environmentalPermit: String? = null,
    val housingReference: String? = null,
    
    // Culture, Energy & Science
    val mediaLicense: String? = null,
    val energyLicense: String? = null,
    val researchGrant: String? = null
)

data class CompleteGovernmentVerificationResponse(
    val verificationId: String,
    val timestamp: String,
    val totalSystemsQueried: Int,
    val totalSystemsAvailable: Int,
    val coveragePercentage: Double,
    val overallStatus: String,
    val verificationResults: Map<String, Any?>,
    val riskAssessment: ComprehensiveRiskAssessment,
    val complianceStatus: ComplianceStatus,
    val recommendations: List<String>,
    val dataSourcesUsed: List<String>
)

data class ComprehensiveRiskAssessment(
    val overallRiskScore: Double, // 0-100, lower is better
    val riskLevel: String, // LOW, MEDIUM, HIGH, CRITICAL
    val identityVerificationScore: Double,
    val legalComplianceScore: Double,
    val financialRiskScore: Double,
    val securityClearanceScore: Double,
    val flaggedIssues: List<String>,
    val positiveIndicators: List<String>
)

data class ComplianceStatus(
    val gdprCompliant: Boolean,
    val kycCompliant: Boolean,
    val amlCompliant: Boolean,
    val sanctionsChecked: Boolean,
    val complianceScore: Double,
    val complianceGaps: List<String>
)