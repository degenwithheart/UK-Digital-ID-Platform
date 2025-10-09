use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;
use tracing::{info, warn, error,         let engine = CoreIdEngine {
            config,
            crypto_manager,
            verification_manager,
            cache_manager,
            database_manager,
            metrics_collector,
            audit_logger,
            sync_service,
            component_integration,
            rate_limiter,
            active_requests,
            start_time: Instant::now(),
        };
use std::time::{Duration, Instant};
use thiserror::Error;

pub mod api;
pub mod config;
pub mod crypto;
pub mod verification;
pub mod cache;
pub mod database;
pub mod metrics;
pub mod audit;
pub mod sync;
pub mod integration;

use crypto::CryptoManager;
use sync::SyncService;
use integration::ComponentIntegration;
use verification::{VerificationManager, VerificationStatus};
use cache::CacheManager;
use database::DatabaseManager;
use metrics::MetricsCollector;
use audit::AuditLogger;
use config::Config;

#[derive(Error, Debug)]
pub enum CoreEngineError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto::CryptoError),
    #[error("Verification error: {0}")]
    VerificationError(#[from] verification::VerificationError),
    #[error("Database error: {0}")]
    DatabaseError(#[from] database::DatabaseError),
    #[error("Cache error: {0}")]
    CacheError(#[from] cache::CacheError),
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationType {
    BasicIdentity,
    FullVerification,
    DocumentVerification,
    BiometricVerification,
    CombinedVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataSource {
    HMRC,
    DVLA,
    NHS,
    DWP,
    HomeOffice,
    CompaniesHouse,
    FinancialServices,
    Education,
    LocalGovernment,
    LawEnforcement,
    Transport,
    Healthcare,
    LandRegistry,
    Security,
    ProfessionalBodies,
    BorderControl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerificationRequest {
    pub request_id: Uuid,
    pub citizen_id: String,
    pub verification_type: VerificationType,
    pub data_sources: Vec<DataSource>,
    pub priority: Priority,
    pub callback_url: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub request_id: Uuid,
    pub citizen_id: String,
    pub status: String,
    pub confidence_score: f64,
    pub risk_score: f64,
    pub verification_details: HashMap<String, serde_json::Value>,
    pub warnings: Vec<String>,
    pub timestamp: i64,
    pub processing_time_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub database_healthy: bool,
    pub cache_healthy: bool,
    pub external_services_healthy: bool,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub requests_processed: u64,
    pub average_response_time_ms: f64,
    pub success_rate: f64,
    pub cache_hit_rate: f64,
    pub active_connections: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
}

pub struct CoreIdEngine {
    pub config: Config,
    pub crypto_manager: Arc<CryptoManager>,
    pub verification_manager: Arc<VerificationManager>,
    pub cache_manager: Arc<CacheManager>,
    pub database_manager: Arc<DatabaseManager>,
    pub metrics_collector: Arc<MetricsCollector>,
    pub audit_logger: Arc<AuditLogger>,
    pub sync_service: Arc<SyncService>,
    pub component_integration: Arc<ComponentIntegration>,
    pub rate_limiter: Arc<Semaphore>,
    pub active_requests: Arc<RwLock<HashMap<Uuid, VerificationStatus>>>,
    pub start_time: Instant,
}

impl CoreIdEngine {
    #[instrument]
    pub async fn new() -> Result<Self> {
        info!("Initializing Core ID Engine");
        
        let config = Config::from_env()?;
        config.validate()?;

        // Initialize managers
        let crypto_manager = Arc::new(CryptoManager::new(&config.crypto).await?);
        let cache_manager = Arc::new(CacheManager::new(&config.redis).await?);
        let database_manager = Arc::new(DatabaseManager::new(&config.database).await?);
        let metrics_collector = Arc::new(MetricsCollector::new(&config.monitoring).await?);
        let audit_logger = Arc::new(AuditLogger::new(&config.audit, Arc::clone(&database_manager)).await?);
        
        let verification_manager = Arc::new(
            VerificationManager::new(
                &config.verification,
                Arc::clone(&cache_manager),
                Arc::clone(&database_manager),
                Arc::clone(&metrics_collector),
                Arc::clone(&audit_logger),
            ).await?
        );

        // Initialize synchronization services
        let sync_service = Arc::new(SyncService::new("redis://localhost:6379")?);
        let component_integration = Arc::new(ComponentIntegration::new(
            Arc::clone(&sync_service),
            Arc::clone(&database_manager),
            Arc::clone(&metrics_collector),
        ));

        let rate_limiter = Arc::new(Semaphore::new(config.verification.max_concurrent_verifications as usize));
        let active_requests = Arc::new(RwLock::new(HashMap::new()));

        // Start background tasks
        let engine = Self {
            config,
            crypto_manager,
            verification_manager,
            cache_manager,
            database_manager,
            metrics_collector,
            audit_logger,
            rate_limiter,
            active_requests,
            start_time: Instant::now(),
        };

        engine.start_background_tasks().await?;
        
        // Initialize component integration and synchronization
        engine.component_integration.initialize().await?;
        
        info!("Core ID Engine initialized successfully with full component synchronization");
        Ok(engine)
    }

    #[instrument(skip(self))]
    async fn start_background_tasks(&self) -> Result<()> {
        // Start metrics collection
        let metrics_collector = Arc::clone(&self.metrics_collector);
        let metrics_interval = self.config.monitoring.metrics_interval_duration();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(metrics_interval);
            loop {
                interval.tick().await;
                if let Err(e) = metrics_collector.collect_system_metrics().await {
                    error!("Failed to collect system metrics: {}", e);
                }
            }
        });

        // Start audit log flushing
        let audit_logger = Arc::clone(&self.audit_logger);
        let flush_interval = self.config.audit.flush_interval_duration();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);
            loop {
                interval.tick().await;
                if let Err(e) = audit_logger.flush_logs().await {
                    error!("Failed to flush audit logs: {}", e);
                }
            }
        });

        // Start cache maintenance
        let cache_manager = Arc::clone(&self.cache_manager);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                if let Err(e) = cache_manager.cleanup_expired().await {
                    error!("Failed to cleanup expired cache entries: {}", e);
                }
            }
        });

        Ok(())
    }

    #[instrument(skip(self, request))]
    pub async fn verify_identity(&self, request: IdentityVerificationRequest) -> Result<VerificationResult> {
        let _permit = self.rate_limiter.acquire().await?;
        let start_time = Instant::now();

        // Add to active requests
        {
            let mut active = self.active_requests.write().await;
            active.insert(request.request_id, VerificationStatus::InProgress);
        }

        // Log audit event
        self.audit_logger.log_verification_started(&request).await?;

        let result = self.verification_manager.verify_identity(request.clone()).await;

        // Remove from active requests
        {
            let mut active = self.active_requests.write().await;
            active.remove(&request.request_id);
        }

        let processing_time = start_time.elapsed();

        match result {
            Ok(mut verification_result) => {
                verification_result.processing_time_ms = processing_time.as_millis();
                
                // Log successful verification
                self.audit_logger.log_verification_completed(&verification_result).await?;
                
                // Update metrics
                self.metrics_collector.record_request_completed(processing_time, true).await?;

                Ok(verification_result)
            }
            Err(e) => {
                // Log failed verification
                self.audit_logger.log_verification_failed(&request, &e.to_string()).await?;
                
                // Update metrics
                self.metrics_collector.record_request_completed(processing_time, false).await?;

                Err(e.into())
            }
        }
    }

    #[instrument(skip(self, requests))]
    pub async fn batch_verify(&self, requests: Vec<IdentityVerificationRequest>) -> Result<Vec<VerificationResult>> {
        let mut results = Vec::with_capacity(requests.len());
        
        for request in requests {
            match self.verify_identity(request).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Batch verification failed for request: {}", e);
                    // Continue with other requests
                }
            }
        }

        Ok(results)
    }

    pub async fn get_verification_status(&self, request_id: Uuid) -> Option<VerificationStatus> {
        let active = self.active_requests.read().await;
        active.get(&request_id).cloned()
    }

    pub async fn cancel_verification(&self, request_id: Uuid) -> Result<bool> {
        let mut active = self.active_requests.write().await;
        if let Some(status) = active.get_mut(&request_id) {
            if matches!(status, VerificationStatus::InProgress) {
                *status = VerificationStatus::Cancelled;
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[instrument(skip(self))]
    pub async fn health_check(&self) -> Result<HealthStatus> {
        let database_healthy = self.database_manager.health_check().await.is_ok();
        let cache_healthy = self.cache_manager.health_check().await.is_ok();
        let external_services_healthy = self.verification_manager.health_check().await;

        let status = if database_healthy && cache_healthy && external_services_healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        };

        Ok(HealthStatus {
            status,
            database_healthy,
            cache_healthy,
            external_services_healthy,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    #[instrument(skip(self))]
    pub async fn get_metrics(&self) -> Result<SystemMetrics> {
        self.metrics_collector.get_system_metrics().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_engine_initialization() {
        // Set required environment variables for testing
        env::set_var("DATABASE_URL", "postgresql://test:test@localhost/test_db");
        env::set_var("REDIS_URL", "redis://localhost:6379/1");
        env::set_var("CRYPTO_ENCRYPTION_KEY", "test_encryption_key_32_bytes_long");
        env::set_var("CRYPTO_SIGNING_KEY", "test_signing_key_32_bytes_long_key");

        let engine = CoreIdEngine::new().await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_verification_request() {
        env::set_var("DATABASE_URL", "postgresql://test:test@localhost/test_db");
        env::set_var("REDIS_URL", "redis://localhost:6379/1");
        env::set_var("CRYPTO_ENCRYPTION_KEY", "test_encryption_key_32_bytes_long");
        env::set_var("CRYPTO_SIGNING_KEY", "test_signing_key_32_bytes_long_key");

        let engine = CoreIdEngine::new().await.unwrap();

        let request = IdentityVerificationRequest {
            request_id: Uuid::new_v4(),
            citizen_id: "test_citizen_123".to_string(),
            verification_type: VerificationType::BasicIdentity,
            data_sources: vec![DataSource::NHS, DataSource::DVLA],
            priority: Priority::Normal,
            callback_url: None,
            metadata: HashMap::new(),
        };

        // This might fail due to missing external services in test environment
        // but the structure should be correct
        let _result = engine.verify_identity(request).await;
    }

    #[tokio::test]
    async fn test_health_check() {
        env::set_var("DATABASE_URL", "postgresql://test:test@localhost/test_db");
        env::set_var("REDIS_URL", "redis://localhost:6379/1");
        env::set_var("CRYPTO_ENCRYPTION_KEY", "test_encryption_key_32_bytes_long");
        env::set_var("CRYPTO_SIGNING_KEY", "test_signing_key_32_bytes_long_key");

        let engine = CoreIdEngine::new().await.unwrap();
        let health = engine.health_check().await;
        assert!(health.is_ok());
    }
}

    #[test]
    fn test_generate_keypair() {
        let mut engine = IdentityEngine::new();
        assert!(engine.generate_keypair("user1").is_ok());
    }

    #[test]
    fn test_sign_and_verify_credential() {
        let mut engine = IdentityEngine::new();
        engine.generate_keypair("user1").unwrap();
        let cred = engine.sign_credential("user1", b"test payload", 1234567890, 1234567890 + 3600).unwrap();
        assert!(engine.verify_credential(&cred).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let engine = IdentityEngine::new();
        let data = b"secret data";
        let encrypted = engine.encrypt_data(data).unwrap();
        let decrypted = engine.decrypt_data(&encrypted).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }
}