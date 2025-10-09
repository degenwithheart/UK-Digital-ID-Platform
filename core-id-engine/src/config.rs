use serde::{Deserialize, Serialize};
use std::env;
use anyhow::{Result, Context};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub crypto: CryptoConfig,
    pub verification: VerificationConfig,
    pub monitoring: MonitoringConfig,
    pub audit: AuditConfig,
    pub rate_limiting: RateLimitingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: u32,
    pub timeout_seconds: u64,
    pub graceful_shutdown_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: u64,
    pub idle_timeout: u64,
    pub max_lifetime: u64,
    pub enable_logging: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub connection_timeout: u64,
    pub command_timeout: u64,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub encryption_key: String,
    pub signing_key: String,
    pub hash_cost: u32,
    pub token_expiry_hours: u64,
    pub enable_zk_proofs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    pub max_concurrent_verifications: u32,
    pub verification_timeout_seconds: u64,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
    pub batch_size: u32,
    pub confidence_threshold: f64,
    pub enable_parallel_processing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_metrics: bool,
    pub metrics_interval_seconds: u64,
    pub health_check_interval_seconds: u64,
    pub prometheus_port: u16,
    pub jaeger_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub enable_audit_logging: bool,
    pub log_level: String,
    pub retention_days: u32,
    pub batch_size: u32,
    pub flush_interval_seconds: u64,
    pub enable_real_time_alerts: bool,
    pub alert_threshold_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub enable_per_ip_limiting: bool,
    pub enable_per_user_limiting: bool,
    pub cleanup_interval_seconds: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            server: ServerConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            redis: RedisConfig::from_env()?,
            crypto: CryptoConfig::from_env()?,
            verification: VerificationConfig::from_env()?,
            monitoring: MonitoringConfig::from_env()?,
            audit: AuditConfig::from_env()?,
            rate_limiting: RateLimitingConfig::from_env()?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err(anyhow::anyhow!("Server port cannot be 0"));
        }
        if self.server.max_connections == 0 {
            return Err(anyhow::anyhow!("Max connections must be greater than 0"));
        }

        // Validate database configuration
        if self.database.url.is_empty() {
            return Err(anyhow::anyhow!("Database URL is required"));
        }
        if self.database.max_connections == 0 {
            return Err(anyhow::anyhow!("Database max connections must be greater than 0"));
        }

        // Validate Redis configuration
        if self.redis.url.is_empty() {
            return Err(anyhow::anyhow!("Redis URL is required"));
        }
        if self.redis.pool_size == 0 {
            return Err(anyhow::anyhow!("Redis pool size must be greater than 0"));
        }

        // Validate crypto configuration
        if self.crypto.encryption_key.is_empty() {
            return Err(anyhow::anyhow!("Encryption key is required"));
        }
        if self.crypto.signing_key.is_empty() {
            return Err(anyhow::anyhow!("Signing key is required"));
        }
        if self.crypto.hash_cost < 4 || self.crypto.hash_cost > 31 {
            return Err(anyhow::anyhow!("Hash cost must be between 4 and 31"));
        }

        // Validate verification configuration
        if self.verification.confidence_threshold < 0.0 || self.verification.confidence_threshold > 1.0 {
            return Err(anyhow::anyhow!("Confidence threshold must be between 0.0 and 1.0"));
        }

        // Validate audit configuration
        if self.audit.alert_threshold_score < 0.0 || self.audit.alert_threshold_score > 1.0 {
            return Err(anyhow::anyhow!("Alert threshold score must be between 0.0 and 1.0"));
        }

        Ok(())
    }
}

impl ServerConfig {
    pub fn from_env() -> Result<Self> {
        Ok(ServerConfig {
            host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .context("Invalid SERVER_PORT")?,
            max_connections: env::var("SERVER_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "1000".to_string())
                .parse()
                .context("Invalid SERVER_MAX_CONNECTIONS")?,
            timeout_seconds: env::var("SERVER_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .context("Invalid SERVER_TIMEOUT")?,
            graceful_shutdown_timeout: env::var("SERVER_GRACEFUL_SHUTDOWN_TIMEOUT")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid SERVER_GRACEFUL_SHUTDOWN_TIMEOUT")?,
        })
    }

    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    pub fn graceful_shutdown_duration(&self) -> Duration {
        Duration::from_secs(self.graceful_shutdown_timeout)
    }
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self> {
        Ok(DatabaseConfig {
            url: env::var("DATABASE_URL")
                .context("DATABASE_URL environment variable is required")?,
            max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid DATABASE_MAX_CONNECTIONS")?,
            min_connections: env::var("DATABASE_MIN_CONNECTIONS")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .context("Invalid DATABASE_MIN_CONNECTIONS")?,
            acquire_timeout: env::var("DATABASE_ACQUIRE_TIMEOUT")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid DATABASE_ACQUIRE_TIMEOUT")?,
            idle_timeout: env::var("DATABASE_IDLE_TIMEOUT")
                .unwrap_or_else(|_| "600".to_string())
                .parse()
                .context("Invalid DATABASE_IDLE_TIMEOUT")?,
            max_lifetime: env::var("DATABASE_MAX_LIFETIME")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .context("Invalid DATABASE_MAX_LIFETIME")?,
            enable_logging: env::var("DATABASE_ENABLE_LOGGING")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .context("Invalid DATABASE_ENABLE_LOGGING")?,
        })
    }
}

impl RedisConfig {
    pub fn from_env() -> Result<Self> {
        Ok(RedisConfig {
            url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            pool_size: env::var("REDIS_POOL_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid REDIS_POOL_SIZE")?,
            connection_timeout: env::var("REDIS_CONNECTION_TIMEOUT")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .context("Invalid REDIS_CONNECTION_TIMEOUT")?,
            command_timeout: env::var("REDIS_COMMAND_TIMEOUT")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .context("Invalid REDIS_COMMAND_TIMEOUT")?,
            retry_attempts: env::var("REDIS_RETRY_ATTEMPTS")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .context("Invalid REDIS_RETRY_ATTEMPTS")?,
            retry_delay_ms: env::var("REDIS_RETRY_DELAY_MS")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .context("Invalid REDIS_RETRY_DELAY_MS")?,
        })
    }

    pub fn connection_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.connection_timeout)
    }

    pub fn command_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.command_timeout)
    }

    pub fn retry_delay_duration(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms)
    }
}

impl CryptoConfig {
    pub fn from_env() -> Result<Self> {
        Ok(CryptoConfig {
            encryption_key: env::var("CRYPTO_ENCRYPTION_KEY")
                .context("CRYPTO_ENCRYPTION_KEY environment variable is required")?,
            signing_key: env::var("CRYPTO_SIGNING_KEY")
                .context("CRYPTO_SIGNING_KEY environment variable is required")?,
            hash_cost: env::var("CRYPTO_HASH_COST")
                .unwrap_or_else(|_| "12".to_string())
                .parse()
                .context("Invalid CRYPTO_HASH_COST")?,
            token_expiry_hours: env::var("CRYPTO_TOKEN_EXPIRY_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .context("Invalid CRYPTO_TOKEN_EXPIRY_HOURS")?,
            enable_zk_proofs: env::var("CRYPTO_ENABLE_ZK_PROOFS")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .context("Invalid CRYPTO_ENABLE_ZK_PROOFS")?,
        })
    }

    pub fn token_expiry_duration(&self) -> Duration {
        Duration::from_secs(self.token_expiry_hours * 3600)
    }
}

impl VerificationConfig {
    pub fn from_env() -> Result<Self> {
        Ok(VerificationConfig {
            max_concurrent_verifications: env::var("VERIFICATION_MAX_CONCURRENT")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .context("Invalid VERIFICATION_MAX_CONCURRENT")?,
            verification_timeout_seconds: env::var("VERIFICATION_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .context("Invalid VERIFICATION_TIMEOUT")?,
            retry_attempts: env::var("VERIFICATION_RETRY_ATTEMPTS")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .context("Invalid VERIFICATION_RETRY_ATTEMPTS")?,
            retry_delay_ms: env::var("VERIFICATION_RETRY_DELAY_MS")
                .unwrap_or_else(|_| "1000".to_string())
                .parse()
                .context("Invalid VERIFICATION_RETRY_DELAY_MS")?,
            batch_size: env::var("VERIFICATION_BATCH_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid VERIFICATION_BATCH_SIZE")?,
            confidence_threshold: env::var("VERIFICATION_CONFIDENCE_THRESHOLD")
                .unwrap_or_else(|_| "0.8".to_string())
                .parse()
                .context("Invalid VERIFICATION_CONFIDENCE_THRESHOLD")?,
            enable_parallel_processing: env::var("VERIFICATION_ENABLE_PARALLEL")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .context("Invalid VERIFICATION_ENABLE_PARALLEL")?,
        })
    }

    pub fn verification_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.verification_timeout_seconds)
    }

    pub fn retry_delay_duration(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms)
    }
}

impl MonitoringConfig {
    pub fn from_env() -> Result<Self> {
        Ok(MonitoringConfig {
            enable_metrics: env::var("MONITORING_ENABLE_METRICS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .context("Invalid MONITORING_ENABLE_METRICS")?,
            metrics_interval_seconds: env::var("MONITORING_METRICS_INTERVAL")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .context("Invalid MONITORING_METRICS_INTERVAL")?,
            health_check_interval_seconds: env::var("MONITORING_HEALTH_CHECK_INTERVAL")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .context("Invalid MONITORING_HEALTH_CHECK_INTERVAL")?,
            prometheus_port: env::var("MONITORING_PROMETHEUS_PORT")
                .unwrap_or_else(|_| "9090".to_string())
                .parse()
                .context("Invalid MONITORING_PROMETHEUS_PORT")?,
            jaeger_endpoint: env::var("MONITORING_JAEGER_ENDPOINT").ok(),
        })
    }

    pub fn metrics_interval_duration(&self) -> Duration {
        Duration::from_secs(self.metrics_interval_seconds)
    }

    pub fn health_check_interval_duration(&self) -> Duration {
        Duration::from_secs(self.health_check_interval_seconds)
    }
}

impl AuditConfig {
    pub fn from_env() -> Result<Self> {
        Ok(AuditConfig {
            enable_audit_logging: env::var("AUDIT_ENABLE_LOGGING")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .context("Invalid AUDIT_ENABLE_LOGGING")?,
            log_level: env::var("AUDIT_LOG_LEVEL")
                .unwrap_or_else(|_| "INFO".to_string()),
            retention_days: env::var("AUDIT_RETENTION_DAYS")
                .unwrap_or_else(|_| "365".to_string())
                .parse()
                .context("Invalid AUDIT_RETENTION_DAYS")?,
            batch_size: env::var("AUDIT_BATCH_SIZE")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .context("Invalid AUDIT_BATCH_SIZE")?,
            flush_interval_seconds: env::var("AUDIT_FLUSH_INTERVAL")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid AUDIT_FLUSH_INTERVAL")?,
            enable_real_time_alerts: env::var("AUDIT_ENABLE_REAL_TIME_ALERTS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .context("Invalid AUDIT_ENABLE_REAL_TIME_ALERTS")?,
            alert_threshold_score: env::var("AUDIT_ALERT_THRESHOLD_SCORE")
                .unwrap_or_else(|_| "0.9".to_string())
                .parse()
                .context("Invalid AUDIT_ALERT_THRESHOLD_SCORE")?,
        })
    }

    pub fn flush_interval_duration(&self) -> Duration {
        Duration::from_secs(self.flush_interval_seconds)
    }
}

impl RateLimitingConfig {
    pub fn from_env() -> Result<Self> {
        Ok(RateLimitingConfig {
            requests_per_minute: env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .context("Invalid RATE_LIMIT_REQUESTS_PER_MINUTE")?,
            burst_size: env::var("RATE_LIMIT_BURST_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid RATE_LIMIT_BURST_SIZE")?,
            enable_per_ip_limiting: env::var("RATE_LIMIT_ENABLE_PER_IP")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .context("Invalid RATE_LIMIT_ENABLE_PER_IP")?,
            enable_per_user_limiting: env::var("RATE_LIMIT_ENABLE_PER_USER")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .context("Invalid RATE_LIMIT_ENABLE_PER_USER")?,
            cleanup_interval_seconds: env::var("RATE_LIMIT_CLEANUP_INTERVAL")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .context("Invalid RATE_LIMIT_CLEANUP_INTERVAL")?,
        })
    }

    pub fn cleanup_interval_duration(&self) -> Duration {
        Duration::from_secs(self.cleanup_interval_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_validation() {
        // Set required environment variables
        env::set_var("DATABASE_URL", "postgresql://test:test@localhost/test");
        env::set_var("CRYPTO_ENCRYPTION_KEY", "test_encryption_key");
        env::set_var("CRYPTO_SIGNING_KEY", "test_signing_key");

        let config = Config::from_env().unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_config() {
        // Set invalid values
        env::set_var("SERVER_PORT", "0");
        env::set_var("DATABASE_URL", "");

        let config = Config::from_env();
        if let Ok(config) = config {
            assert!(config.validate().is_err());
        }
    }
}