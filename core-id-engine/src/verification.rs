use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use futures::future::join_all;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    IdentityVerificationRequest, VerificationResult, VerificationStatus, 
    DataSource, SourceResult, Alert, AlertType, AlertSeverity,
    crypto::CryptoEngine,
    cache::CacheManager,
    database::DatabaseManager,
    sync::SyncService,
    CoreEngineError
};

#[derive(Clone)]
pub struct VerificationManager {
    crypto_engine: Arc<CryptoEngine>,
    cache_manager: Arc<CacheManager>,
    database_manager: Arc<DatabaseManager>,
    sync_service: Arc<SyncService>,
    connector_clients: Arc<RwLock<HashMap<DataSource, ConnectorClient>>>,
    verification_rules: Arc<RwLock<Vec<VerificationRule>>>,
}

#[derive(Debug, Clone)]
struct ConnectorClient {
    base_url: String,
    api_key: String,
    timeout_ms: u64,
    retry_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerificationRule {
    pub rule_id: String,
    pub data_sources: Vec<DataSource>,
    pub min_confidence_threshold: f64,
    pub risk_weight: f64,
    pub required_fields: Vec<String>,
    pub cross_reference_required: bool,
}

impl VerificationManager {
    pub async fn new(
        crypto_engine: Arc<CryptoEngine>,
        cache_manager: Arc<CacheManager>,
        database_manager: Arc<DatabaseManager>,
        sync_service: Arc<SyncService>,
    ) -> Result<Self> {
        let mut connector_clients = HashMap::new();
        
        // Initialize government connector clients
        let connectors = vec![
            (DataSource::HMRC, "http://gov-connectors:8080/api/connectors/hmrc"),
            (DataSource::DVLA, "http://gov-connectors:8080/api/connectors/dvla"),
            (DataSource::NHS, "http://gov-connectors:8080/api/connectors/nhs"),
            (DataSource::DWP, "http://gov-connectors:8080/api/connectors/dwp"),
            (DataSource::HomeOffice, "http://gov-connectors:8080/api/connectors/home-office"),
            (DataSource::CompaniesHouse, "http://gov-connectors:8080/api/connectors/companies-house"),
            (DataSource::FinancialServices, "http://gov-connectors:8080/api/connectors/financial-services"),
            (DataSource::Education, "http://gov-connectors:8080/api/connectors/education"),
            (DataSource::LocalGovernment, "http://gov-connectors:8080/api/connectors/local-government"),
            (DataSource::LawEnforcement, "http://gov-connectors:8080/api/connectors/law-enforcement"),
            (DataSource::Transport, "http://gov-connectors:8080/api/connectors/transport"),
            (DataSource::Healthcare, "http://gov-connectors:8080/api/connectors/healthcare"),
            (DataSource::LandRegistry, "http://gov-connectors:8080/api/connectors/land-registry"),
            (DataSource::Security, "http://gov-connectors:8080/api/connectors/security"),
            (DataSource::ProfessionalBodies, "http://gov-connectors:8080/api/connectors/professional-bodies"),
            (DataSource::BorderControl, "http://gov-connectors:8080/api/connectors/border-control"),
        ];

        for (source, url) in connectors {
            connector_clients.insert(source, ConnectorClient {
                base_url: url.to_string(),
                api_key: std::env::var("GOV_CONNECTORS_API_KEY").unwrap_or_default(),
                timeout_ms: 5000,
                retry_attempts: 3,
            });
        }

        let verification_rules = Self::load_verification_rules().await?;

        Ok(Self {
            crypto_engine,
            cache_manager,
            database_manager,
            sync_service,
            connector_clients: Arc::new(RwLock::new(connector_clients)),
            verification_rules: Arc::new(RwLock::new(verification_rules)),
        })
    }

    pub async fn verify(&self, request: &IdentityVerificationRequest) -> Result<VerificationResult> {
        let start_time = std::time::Instant::now();
        let mut source_results = HashMap::new();
        let mut alerts = Vec::new();

        // Check cache first
        if let Some(cached_result) = self.check_cache(request).await? {
            return Ok(cached_result);
        }

        // Parallel verification across all requested data sources
        let verification_tasks = request.data_sources.iter().map(|source| {
            let engine = self.clone();
            let req = request.clone();
            let source_clone = source.clone();
            
            tokio::spawn(async move {
                engine.verify_single_source(&req, &source_clone).await
            })
        }).collect::<Vec<_>>();

        let task_results = join_all(verification_tasks).await;

        // Process results and handle errors
        for (i, task_result) in task_results.into_iter().enumerate() {
            match task_result {
                Ok(Ok(result)) => {
                    source_results.insert(request.data_sources[i].clone(), result);
                }
                Ok(Err(e)) => {
                    alerts.push(Alert {
                        alert_type: AlertType::SystemError,
                        severity: AlertSeverity::Medium,
                        message: format!("Verification failed for {:?}: {}", request.data_sources[i], e),
                        source: request.data_sources[i].clone(),
                        timestamp: Utc::now(),
                    });
                }
                Err(e) => {
                    alerts.push(Alert {
                        alert_type: AlertType::SystemError,
                        severity: AlertSeverity::High,
                        message: format!("Task failed for {:?}: {}", request.data_sources[i], e),
                        source: request.data_sources[i].clone(),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // Calculate overall verification metrics
        let verification_result = self.calculate_verification_result(
            request,
            source_results,
            alerts,
            start_time.elapsed().as_millis() as u64,
        ).await?;

        // Cache the result
        self.cache_result(request, &verification_result).await?;

        // Store in database for audit
        self.store_verification_result(request, &verification_result).await?;

        // Publish sync event
        let event = crate::sync::SyncEvent::IdentityVerified {
            citizen_id: request.citizen_id.clone(),
            status: verification_result.status.clone(),
        };
        if let Err(e) = self.sync_service.publish_event(event).await {
            tracing::warn!("Failed to publish sync event: {:?}", e);
        }

        Ok(verification_result)
    }

    async fn verify_single_source(
        &self,
        request: &IdentityVerificationRequest,
        source: &DataSource,
    ) -> Result<SourceResult> {
        let start_time = std::time::Instant::now();
        
        let clients = self.connector_clients.read().await;
        let client = clients.get(source)
            .ok_or_else(|| CoreEngineError::InvalidRequest(format!("Unknown data source: {:?}", source)))?;

        // Make HTTP request to government connector
        let http_client = reqwest::Client::new();
        let response = http_client
            .post(&format!("{}/verify", client.base_url))
            .header("Authorization", format!("Bearer {}", client.api_key))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "request_id": request.request_id,
                "citizen_id": request.citizen_id,
                "verification_type": request.verification_type,
                "metadata": request.metadata
            }))
            .timeout(std::time::Duration::from_millis(client.timeout_ms))
            .send()
            .await
            .context("Failed to send request to government connector")?;

        if !response.status().is_success() {
            return Err(CoreEngineError::VerificationFailed(
                format!("Government connector returned status: {}", response.status())
            ).into());
        }

        let response_data: serde_json::Value = response.json().await
            .context("Failed to parse response from government connector")?;

        // Calculate confidence based on response completeness and data quality
        let confidence = self.calculate_source_confidence(&response_data, source).await?;
        let data_points = self.count_data_points(&response_data).await;

        Ok(SourceResult {
            source: source.clone(),
            status: "SUCCESS".to_string(),
            confidence,
            data_points,
            response_time_ms: start_time.elapsed().as_millis() as u64,
            last_updated: Utc::now(),
        })
    }

    async fn calculate_verification_result(
        &self,
        request: &IdentityVerificationRequest,
        source_results: HashMap<DataSource, SourceResult>,
        mut alerts: Vec<Alert>,
        processing_time_ms: u64,
    ) -> Result<VerificationResult> {
        
        // Calculate weighted confidence score
        let total_confidence: f64 = source_results.values()
            .map(|result| result.confidence * self.get_source_weight(&result.source))
            .sum();
        let total_weight: f64 = source_results.values()
            .map(|result| self.get_source_weight(&result.source))
            .sum();
        let confidence_score = if total_weight > 0.0 { total_confidence / total_weight } else { 0.0 };

        // Calculate risk score based on alerts and data inconsistencies
        let risk_score = self.calculate_risk_score(&source_results, &alerts).await?;

        // Determine identity match based on cross-referencing
        let identity_match = self.determine_identity_match(&source_results).await?;

        // Calculate data completeness
        let data_completeness = source_results.len() as f64 / request.data_sources.len() as f64;

        // Generate additional alerts for data quality issues
        alerts.extend(self.analyze_data_quality(&source_results).await?);

        // Determine overall status
        let status = self.determine_verification_status(
            confidence_score,
            risk_score,
            identity_match,
            &alerts
        ).await?;

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &source_results,
            &alerts,
            confidence_score,
            risk_score
        ).await?;

        Ok(VerificationResult {
            request_id: request.request_id,
            verification_id: Uuid::new_v4(),
            status,
            confidence_score,
            risk_score,
            identity_match,
            data_completeness,
            verification_timestamp: Utc::now(),
            processing_time_ms,
            source_results,
            alerts,
            recommendations,
        })
    }

    async fn calculate_source_confidence(&self, data: &serde_json::Value, source: &DataSource) -> Result<f64> {
        // Analyze response quality and completeness
        let mut confidence = 0.8; // Base confidence
        
        if let Some(obj) = data.as_object() {
            // Check for required fields based on data source
            let required_fields = self.get_required_fields(source).await;
            let present_fields = obj.keys().count();
            let field_completeness = present_fields as f64 / required_fields.len().max(1) as f64;
            
            confidence *= field_completeness.min(1.0);
            
            // Check for error indicators
            if obj.contains_key("error") || obj.get("status").map_or(false, |s| s == "ERROR") {
                confidence *= 0.3;
            }
            
            // Boost confidence for verified/official data
            if obj.get("verified").map_or(false, |v| v.as_bool().unwrap_or(false)) {
                confidence = (confidence * 1.2).min(1.0);
            }
        }

        Ok(confidence)
    }

    async fn count_data_points(&self, data: &serde_json::Value) -> u32 {
        match data {
            serde_json::Value::Object(obj) => obj.len() as u32,
            serde_json::Value::Array(arr) => arr.len() as u32,
            _ => 1,
        }
    }

    fn get_source_weight(&self, source: &DataSource) -> f64 {
        match source {
            DataSource::NHS | DataSource::HMRC | DataSource::DVLA => 1.0,
            DataSource::DWP | DataSource::HomeOffice => 0.9,
            DataSource::Security | DataSource::LawEnforcement => 0.95,
            DataSource::FinancialServices | DataSource::CompaniesHouse => 0.85,
            _ => 0.75,
        }
    }

    async fn calculate_risk_score(&self, results: &HashMap<DataSource, SourceResult>, alerts: &[Alert]) -> Result<f64> {
        let mut risk_score = 0.0;
        
        // Base risk from alerts
        for alert in alerts {
            risk_score += match alert.severity {
                AlertSeverity::Critical => 0.4,
                AlertSeverity::High => 0.25,
                AlertSeverity::Medium => 0.15,
                AlertSeverity::Low => 0.05,
            };
        }
        
        // Risk from low confidence sources
        for result in results.values() {
            if result.confidence < 0.5 {
                risk_score += 0.1;
            }
        }
        
        // Risk from incomplete data
        let completeness = results.len() as f64 / 16.0; // Assuming 16 total sources
        if completeness < 0.5 {
            risk_score += 0.2;
        }
        
        Ok(risk_score.min(1.0))
    }

    async fn determine_identity_match(&self, results: &HashMap<DataSource, SourceResult>) -> Result<bool> {
        let high_confidence_sources = results.values()
            .filter(|result| result.confidence > 0.8)
            .count();
        
        // Require at least 3 high-confidence sources for positive identity match
        Ok(high_confidence_sources >= 3)
    }

    async fn analyze_data_quality(&self, results: &HashMap<DataSource, SourceResult>) -> Result<Vec<Alert>> {
        let mut alerts = Vec::new();
        
        // Check for sources with low confidence
        for result in results.values() {
            if result.confidence < 0.6 {
                alerts.push(Alert {
                    alert_type: AlertType::MissingData,
                    severity: AlertSeverity::Medium,
                    message: format!("Low confidence data from {:?}: {:.2}", result.source, result.confidence),
                    source: result.source.clone(),
                    timestamp: Utc::now(),
                });
            }
            
            // Check for slow response times
            if result.response_time_ms > 5000 {
                alerts.push(Alert {
                    alert_type: AlertType::SystemError,
                    severity: AlertSeverity::Low,
                    message: format!("Slow response from {:?}: {}ms", result.source, result.response_time_ms),
                    source: result.source.clone(),
                    timestamp: Utc::now(),
                });
            }
        }
        
        Ok(alerts)
    }

    async fn determine_verification_status(
        &self,
        confidence: f64,
        risk: f64,
        identity_match: bool,
        alerts: &[Alert]
    ) -> Result<VerificationStatus> {
        let critical_alerts = alerts.iter().any(|a| matches!(a.severity, AlertSeverity::Critical));
        
        if critical_alerts || risk > 0.7 {
            Ok(VerificationStatus::RequiresManualReview)
        } else if confidence > 0.8 && identity_match && risk < 0.3 {
            Ok(VerificationStatus::Completed)
        } else if confidence > 0.6 && risk < 0.5 {
            Ok(VerificationStatus::PartialSuccess)
        } else {
            Ok(VerificationStatus::Failed)
        }
    }

    async fn generate_recommendations(
        &self,
        results: &HashMap<DataSource, SourceResult>,
        alerts: &[Alert],
        confidence: f64,
        risk: f64
    ) -> Result<Vec<String>> {
        let mut recommendations = Vec::new();
        
        if confidence < 0.7 {
            recommendations.push("Consider requesting additional verification documents".to_string());
        }
        
        if risk > 0.5 {
            recommendations.push("Enhanced due diligence recommended".to_string());
        }
        
        let missing_sources = 16 - results.len();
        if missing_sources > 5 {
            recommendations.push(format!("Attempt verification with {} additional data sources", missing_sources));
        }
        
        if alerts.iter().any(|a| matches!(a.alert_type, AlertType::DataMismatch)) {
            recommendations.push("Manual review required for data inconsistencies".to_string());
        }
        
        Ok(recommendations)
    }

    async fn get_required_fields(&self, source: &DataSource) -> Vec<String> {
        match source {
            DataSource::NHS => vec!["nhsNumber".to_string(), "registered".to_string(), "verified".to_string()],
            DataSource::DVLA => vec!["licenseNumber".to_string(), "valid".to_string(), "holderName".to_string()],
            DataSource::HMRC => vec!["utr".to_string(), "status".to_string(), "registrationDate".to_string()],
            DataSource::DWP => vec!["niNumber".to_string(), "contributionRecord".to_string(), "verified".to_string()],
            _ => vec!["status".to_string(), "verified".to_string()],
        }
    }

    async fn check_cache(&self, request: &IdentityVerificationRequest) -> Result<Option<VerificationResult>> {
        let cache_key = format!("verification:{}:{:?}", request.citizen_id, request.verification_type);
        self.cache_manager.get(&cache_key).await
    }

    async fn cache_result(&self, request: &IdentityVerificationRequest, result: &VerificationResult) -> Result<()> {
        let cache_key = format!("verification:{}:{:?}", request.citizen_id, request.verification_type);
        let ttl = std::time::Duration::from_secs(3600); // Cache for 1 hour
        self.cache_manager.set(&cache_key, result, ttl).await
    }

    async fn store_verification_result(&self, request: &IdentityVerificationRequest, result: &VerificationResult) -> Result<()> {
        self.database_manager.store_verification(request, result).await
    }

    async fn load_verification_rules() -> Result<Vec<VerificationRule>> {
        Ok(vec![
            VerificationRule {
                rule_id: "basic_identity".to_string(),
                data_sources: vec![DataSource::NHS, DataSource::DVLA, DataSource::HMRC],
                min_confidence_threshold: 0.7,
                risk_weight: 1.0,
                required_fields: vec!["name".to_string(), "dateOfBirth".to_string()],
                cross_reference_required: true,
            },
            VerificationRule {
                rule_id: "comprehensive_check".to_string(),
                data_sources: vec![
                    DataSource::NHS, DataSource::DVLA, DataSource::HMRC, DataSource::DWP,
                    DataSource::HomeOffice, DataSource::LawEnforcement, DataSource::FinancialServices
                ],
                min_confidence_threshold: 0.8,
                risk_weight: 1.2,
                required_fields: vec!["name".to_string(), "dateOfBirth".to_string(), "address".to_string()],
                cross_reference_required: true,
            },
        ])
    }
}

impl Clone for VerificationEngine {
    fn clone(&self) -> Self {
        Self {
            crypto_engine: self.crypto_engine.clone(),
            cache_manager: self.cache_manager.clone(),
            database_manager: self.database_manager.clone(),
            connector_clients: self.connector_clients.clone(),
            verification_rules: self.verification_rules.clone(),
        }
    }
}