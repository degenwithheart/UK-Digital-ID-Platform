use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::{Result, Context};

use crate::{IdentityVerificationRequest, VerificationResult, VerificationType};

#[derive(Clone)]
pub struct MetricsCollector {
    metrics: Arc<RwLock<SystemMetrics>>,
    start_time: DateTime<Utc>,
    performance_history: Arc<RwLock<Vec<PerformanceSnapshot>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub total_verifications: u64,
    pub successful_verifications: u64,
    pub failed_verifications: u64,
    pub average_processing_time_ms: f64,
    pub requests_per_second: f64,
    pub cache_hit_rate: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub verification_type_breakdown: HashMap<String, u64>,
    pub error_rates: HashMap<String, f64>,
    pub response_time_percentiles: ResponseTimePercentiles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTimePercentiles {
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub timestamp: DateTime<Utc>,
    pub requests_per_second: f64,
    pub average_response_time_ms: f64,
    pub error_rate: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub active_connections: u32,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            total_verifications: 0,
            successful_verifications: 0,
            failed_verifications: 0,
            average_processing_time_ms: 0.0,
            requests_per_second: 0.0,
            cache_hit_rate: 0.0,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
            verification_type_breakdown: HashMap::new(),
            error_rates: HashMap::new(),
            response_time_percentiles: ResponseTimePercentiles {
                p50: 0.0,
                p90: 0.0,
                p95: 0.0,
                p99: 0.0,
            },
        }
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            start_time: Utc::now(),
            performance_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn record_verification_success(
        &self,
        verification_type: &VerificationType,
        processing_time_ms: u64,
    ) {
        let mut metrics = self.metrics.write().await;
        
        metrics.total_verifications += 1;
        metrics.successful_verifications += 1;
        
        // Update average processing time using exponential moving average
        let alpha = 0.1; // Smoothing factor
        if metrics.average_processing_time_ms == 0.0 {
            metrics.average_processing_time_ms = processing_time_ms as f64;
        } else {
            metrics.average_processing_time_ms = 
                alpha * processing_time_ms as f64 + (1.0 - alpha) * metrics.average_processing_time_ms;
        }
        
        // Update verification type breakdown
        let type_key = format!("{:?}", verification_type);
        *metrics.verification_type_breakdown.entry(type_key).or_insert(0) += 1;
        
        // Calculate requests per second
        let uptime_seconds = (Utc::now() - self.start_time).num_seconds() as f64;
        if uptime_seconds > 0.0 {
            metrics.requests_per_second = metrics.total_verifications as f64 / uptime_seconds;
        }
    }

    pub async fn record_verification_failure(
        &self,
        verification_type: &VerificationType,
        error: &str,
    ) {
        let mut metrics = self.metrics.write().await;
        
        metrics.total_verifications += 1;
        metrics.failed_verifications += 1;
        
        // Update error rates
        let error_key = if error.contains("timeout") {
            "timeout_errors"
        } else if error.contains("authentication") {
            "auth_errors"
        } else if error.contains("rate limit") {
            "rate_limit_errors"
        } else {
            "general_errors"
        };
        
        let total_requests = metrics.total_verifications as f64;
        let error_count = *metrics.error_rates.entry(error_key.to_string()).or_insert(0.0) + 1.0;
        metrics.error_rates.insert(error_key.to_string(), error_count / total_requests);
        
        // Update verification type breakdown
        let type_key = format!("{:?}", verification_type);
        *metrics.verification_type_breakdown.entry(type_key).or_insert(0) += 1;
        
        // Calculate requests per second
        let uptime_seconds = (Utc::now() - self.start_time).num_seconds() as f64;
        if uptime_seconds > 0.0 {
            metrics.requests_per_second = metrics.total_verifications as f64 / uptime_seconds;
        }
    }

    pub async fn update_system_resources(&self, memory_mb: f64, cpu_percent: f64) {
        let mut metrics = self.metrics.write().await;
        metrics.memory_usage_mb = memory_mb;
        metrics.cpu_usage_percent = cpu_percent;
    }

    pub async fn update_cache_metrics(&self, hit_rate: f64) {
        let mut metrics = self.metrics.write().await;
        metrics.cache_hit_rate = hit_rate;
    }

    pub async fn record_response_times(&self, response_times: Vec<u64>) {
        if response_times.is_empty() {
            return;
        }

        let mut sorted_times: Vec<f64> = response_times.iter().map(|&t| t as f64).collect();
        sorted_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let len = sorted_times.len();
        let p50_index = len * 50 / 100;
        let p90_index = len * 90 / 100;
        let p95_index = len * 95 / 100;
        let p99_index = len * 99 / 100;

        let mut metrics = self.metrics.write().await;
        metrics.response_time_percentiles = ResponseTimePercentiles {
            p50: sorted_times.get(p50_index.saturating_sub(1)).copied().unwrap_or(0.0),
            p90: sorted_times.get(p90_index.saturating_sub(1)).copied().unwrap_or(0.0),
            p95: sorted_times.get(p95_index.saturating_sub(1)).copied().unwrap_or(0.0),
            p99: sorted_times.get(p99_index.saturating_sub(1)).copied().unwrap_or(0.0),
        };
    }

    pub async fn get_current_metrics(&self) -> Result<SystemMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    pub async fn get_uptime(&self) -> u64 {
        (Utc::now() - self.start_time).num_seconds() as u64
    }

    pub async fn take_performance_snapshot(&self, active_connections: u32) -> Result<()> {
        let metrics = self.metrics.read().await;
        let snapshot = PerformanceSnapshot {
            timestamp: Utc::now(),
            requests_per_second: metrics.requests_per_second,
            average_response_time_ms: metrics.average_processing_time_ms,
            error_rate: metrics.failed_verifications as f64 / metrics.total_verifications.max(1) as f64,
            memory_usage_mb: metrics.memory_usage_mb,
            cpu_usage_percent: metrics.cpu_usage_percent,
            active_connections,
        };
        
        let mut history = self.performance_history.write().await;
        history.push(snapshot);
        
        // Keep only last 1000 snapshots (roughly 16 hours if taken every minute)
        if history.len() > 1000 {
            history.remove(0);
        }
        
        Ok(())
    }

    pub async fn get_performance_history(&self, hours: u32) -> Result<Vec<PerformanceSnapshot>> {
        let history = self.performance_history.read().await;
        let cutoff_time = Utc::now() - chrono::Duration::hours(hours as i64);
        
        let filtered: Vec<PerformanceSnapshot> = history
            .iter()
            .filter(|snapshot| snapshot.timestamp >= cutoff_time)
            .cloned()
            .collect();
        
        Ok(filtered)
    }

    pub async fn get_health_summary(&self) -> Result<HealthSummary> {
        let metrics = self.metrics.read().await;
        
        let error_rate = if metrics.total_verifications > 0 {
            metrics.failed_verifications as f64 / metrics.total_verifications as f64
        } else {
            0.0
        };
        
        let health_score = self.calculate_health_score(&metrics, error_rate).await;
        
        Ok(HealthSummary {
            health_score,
            error_rate,
            average_response_time_ms: metrics.average_processing_time_ms,
            requests_per_second: metrics.requests_per_second,
            cache_hit_rate: metrics.cache_hit_rate,
            memory_usage_mb: metrics.memory_usage_mb,
            cpu_usage_percent: metrics.cpu_usage_percent,
            uptime_seconds: self.get_uptime().await,
            status: if health_score >= 0.8 {
                "healthy".to_string()
            } else if health_score >= 0.6 {
                "degraded".to_string()
            } else {
                "unhealthy".to_string()
            },
        })
    }

    async fn calculate_health_score(&self, metrics: &SystemMetrics, error_rate: f64) -> f64 {
        let mut score = 1.0;
        
        // Penalize high error rates
        if error_rate > 0.1 {
            score *= 0.3;
        } else if error_rate > 0.05 {
            score *= 0.7;
        } else if error_rate > 0.01 {
            score *= 0.9;
        }
        
        // Penalize slow response times
        if metrics.average_processing_time_ms > 10000.0 {
            score *= 0.3;
        } else if metrics.average_processing_time_ms > 5000.0 {
            score *= 0.7;
        } else if metrics.average_processing_time_ms > 2000.0 {
            score *= 0.9;
        }
        
        // Penalize high resource usage
        if metrics.cpu_usage_percent > 90.0 {
            score *= 0.5;
        } else if metrics.cpu_usage_percent > 70.0 {
            score *= 0.8;
        }
        
        if metrics.memory_usage_mb > 8192.0 { // 8GB
            score *= 0.5;
        } else if metrics.memory_usage_mb > 4096.0 { // 4GB
            score *= 0.8;
        }
        
        // Boost for good cache performance
        if metrics.cache_hit_rate > 0.9 {
            score = (score * 1.1).min(1.0);
        } else if metrics.cache_hit_rate < 0.5 {
            score *= 0.9;
        }
        
        score.max(0.0).min(1.0)
    }

    // Prometheus-style metrics export
    pub async fn export_prometheus_metrics(&self) -> Result<String> {
        let metrics = self.metrics.read().await;
        let mut output = String::new();
        
        // Counter metrics
        output.push_str(&format!("# HELP identity_verifications_total Total number of identity verifications\n"));
        output.push_str(&format!("# TYPE identity_verifications_total counter\n"));
        output.push_str(&format!("identity_verifications_total {}\n", metrics.total_verifications));
        
        output.push_str(&format!("# HELP identity_verifications_successful_total Successful identity verifications\n"));
        output.push_str(&format!("# TYPE identity_verifications_successful_total counter\n"));
        output.push_str(&format!("identity_verifications_successful_total {}\n", metrics.successful_verifications));
        
        output.push_str(&format!("# HELP identity_verifications_failed_total Failed identity verifications\n"));
        output.push_str(&format!("# TYPE identity_verifications_failed_total counter\n"));
        output.push_str(&format!("identity_verifications_failed_total {}\n", metrics.failed_verifications));
        
        // Gauge metrics
        output.push_str(&format!("# HELP identity_verification_duration_ms Average verification duration\n"));
        output.push_str(&format!("# TYPE identity_verification_duration_ms gauge\n"));
        output.push_str(&format!("identity_verification_duration_ms {}\n", metrics.average_processing_time_ms));
        
        output.push_str(&format!("# HELP identity_requests_per_second Current requests per second\n"));
        output.push_str(&format!("# TYPE identity_requests_per_second gauge\n"));
        output.push_str(&format!("identity_requests_per_second {}\n", metrics.requests_per_second));
        
        output.push_str(&format!("# HELP identity_cache_hit_rate Cache hit rate\n"));
        output.push_str(&format!("# TYPE identity_cache_hit_rate gauge\n"));
        output.push_str(&format!("identity_cache_hit_rate {}\n", metrics.cache_hit_rate));
        
        output.push_str(&format!("# HELP identity_memory_usage_mb Memory usage in MB\n"));
        output.push_str(&format!("# TYPE identity_memory_usage_mb gauge\n"));
        output.push_str(&format!("identity_memory_usage_mb {}\n", metrics.memory_usage_mb));
        
        output.push_str(&format!("# HELP identity_cpu_usage_percent CPU usage percentage\n"));
        output.push_str(&format!("# TYPE identity_cpu_usage_percent gauge\n"));
        output.push_str(&format!("identity_cpu_usage_percent {}\n", metrics.cpu_usage_percent));
        
        // Response time percentiles
        output.push_str(&format!("# HELP identity_response_time_percentile Response time percentiles\n"));
        output.push_str(&format!("# TYPE identity_response_time_percentile gauge\n"));
        output.push_str(&format!("identity_response_time_percentile{{percentile=\"50\"}} {}\n", metrics.response_time_percentiles.p50));
        output.push_str(&format!("identity_response_time_percentile{{percentile=\"90\"}} {}\n", metrics.response_time_percentiles.p90));
        output.push_str(&format!("identity_response_time_percentile{{percentile=\"95\"}} {}\n", metrics.response_time_percentiles.p95));
        output.push_str(&format!("identity_response_time_percentile{{percentile=\"99\"}} {}\n", metrics.response_time_percentiles.p99));
        
        Ok(output)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthSummary {
    pub health_score: f64,
    pub error_rate: f64,
    pub average_response_time_ms: f64,
    pub requests_per_second: f64,
    pub cache_hit_rate: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub uptime_seconds: u64,
    pub status: String,
}

// Background task to collect system resource metrics
pub async fn start_metrics_collection_task(metrics_collector: Arc<MetricsCollector>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        // Collect system metrics (simplified - in production would use proper system monitoring)
        let memory_usage = get_memory_usage().await.unwrap_or(0.0);
        let cpu_usage = get_cpu_usage().await.unwrap_or(0.0);
        
        metrics_collector.update_system_resources(memory_usage, cpu_usage).await;
        
        // Take performance snapshot every minute
        if let Err(e) = metrics_collector.take_performance_snapshot(0).await {
            tracing::error!("Failed to take performance snapshot: {}", e);
        }
    }
}

// Simplified system metrics collection (replace with proper system monitoring in production)
async fn get_memory_usage() -> Result<f64> {
    // In production, use a proper system monitoring library like sysinfo
    Ok(512.0) // Placeholder: 512 MB
}

async fn get_cpu_usage() -> Result<f64> {
    // In production, use a proper system monitoring library like sysinfo
    Ok(25.0) // Placeholder: 25% CPU usage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VerificationType;

    #[tokio::test]
    async fn test_metrics_collection() {
        let collector = MetricsCollector::new();
        
        // Record some test metrics
        collector.record_verification_success(&VerificationType::BasicIdentity, 1500).await;
        collector.record_verification_success(&VerificationType::ComprehensiveVerification, 2500).await;
        collector.record_verification_failure(&VerificationType::BasicIdentity, "timeout error").await;
        
        let metrics = collector.get_current_metrics().await.unwrap();
        assert_eq!(metrics.total_verifications, 3);
        assert_eq!(metrics.successful_verifications, 2);
        assert_eq!(metrics.failed_verifications, 1);
        assert!(metrics.average_processing_time_ms > 0.0);
    }
}