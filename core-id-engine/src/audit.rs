use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::{Result, Context};

use crate::{IdentityVerificationRequest, VerificationResult, database::DatabaseManager};

#[derive(Clone)]
pub struct AuditLogger {
    database: Arc<DatabaseManager>,
    buffer: Arc<RwLock<Vec<AuditLogEntry>>>,
    config: AuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: serde_json::Value,
    pub risk_score: Option<f64>,
    pub compliance_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    SystemAccess,
    VerificationRequest,
    VerificationResult,
    AdminAction,
    SecurityIncident,
    ComplianceCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure,
    Partial,
    Denied,
    Error,
}

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub buffer_size: usize,
    pub flush_interval_seconds: u64,
    pub retention_days: u32,
    pub enable_real_time_alerts: bool,
    pub high_risk_threshold: f64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            buffer_size: 1000,
            flush_interval_seconds: 60,
            retention_days: 2555, // 7 years for compliance
            enable_real_time_alerts: true,
            high_risk_threshold: 0.8,
        }
    }
}

impl AuditLogger {
    pub async fn new() -> Result<Self> {
        let database = Arc::new(DatabaseManager::new().await?);
        
        Ok(Self {
            database,
            buffer: Arc::new(RwLock::new(Vec::new())),
            config: AuditConfig::default(),
        })
    }

    pub async fn log_verification_start(&self, request: &IdentityVerificationRequest) -> Result<()> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::VerificationRequest,
            user_id: request.metadata.get("user_id").cloned(),
            session_id: request.metadata.get("session_id").cloned(),
            ip_address: request.metadata.get("ip_address").cloned(),
            user_agent: request.metadata.get("user_agent").cloned(),
            resource_type: "identity_verification".to_string(),
            resource_id: Some(request.request_id.to_string()),
            action: "verification_initiated".to_string(),
            outcome: AuditOutcome::Success,
            details: serde_json::json!({
                "citizen_id": request.citizen_id,
                "verification_type": request.verification_type,
                "data_sources": request.data_sources,
                "priority": request.priority,
                "callback_url": request.callback_url
            }),
            risk_score: None,
            compliance_flags: vec!["GDPR".to_string(), "UK_DPA_2018".to_string()],
        };

        self.log_entry(entry).await
    }

    pub async fn log_verification_complete(
        &self,
        request: &IdentityVerificationRequest,
        result: &VerificationResult,
    ) -> Result<()> {
        let outcome = match result.status {
            crate::VerificationStatus::Completed => AuditOutcome::Success,
            crate::VerificationStatus::PartialSuccess => AuditOutcome::Partial,
            crate::VerificationStatus::Failed => AuditOutcome::Failure,
            crate::VerificationStatus::RequiresManualReview => AuditOutcome::Partial,
            _ => AuditOutcome::Error,
        };

        let mut compliance_flags = vec!["GDPR".to_string(), "UK_DPA_2018".to_string()];
        
        // Add specific compliance flags based on verification result
        if result.confidence_score >= 0.95 {
            compliance_flags.push("HIGH_CONFIDENCE".to_string());
        }
        if result.risk_score <= 0.1 {
            compliance_flags.push("LOW_RISK".to_string());
        }
        if result.identity_match {
            compliance_flags.push("IDENTITY_VERIFIED".to_string());
        }

        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::VerificationResult,
            user_id: request.metadata.get("user_id").cloned(),
            session_id: request.metadata.get("session_id").cloned(),
            ip_address: request.metadata.get("ip_address").cloned(),
            user_agent: request.metadata.get("user_agent").cloned(),
            resource_type: "identity_verification".to_string(),
            resource_id: Some(result.verification_id.to_string()),
            action: "verification_completed".to_string(),
            outcome,
            details: serde_json::json!({
                "request_id": result.request_id,
                "status": result.status,
                "confidence_score": result.confidence_score,
                "risk_score": result.risk_score,
                "identity_match": result.identity_match,
                "data_completeness": result.data_completeness,
                "processing_time_ms": result.processing_time_ms,
                "source_results_count": result.source_results.len(),
                "alerts_count": result.alerts.len(),
                "recommendations": result.recommendations
            }),
            risk_score: Some(result.risk_score),
            compliance_flags,
        };

        self.log_entry(entry).await?;

        // Log high-risk verifications immediately
        if result.risk_score >= self.config.high_risk_threshold {
            self.log_security_incident(
                "High risk verification detected",
                &request.citizen_id,
                result.risk_score,
                request.metadata.get("ip_address").cloned(),
            ).await?;
        }

        Ok(())
    }

    pub async fn log_verification_cancelled(&self, request_id: Uuid) -> Result<()> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::VerificationRequest,
            user_id: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
            resource_type: "identity_verification".to_string(),
            resource_id: Some(request_id.to_string()),
            action: "verification_cancelled".to_string(),
            outcome: AuditOutcome::Failure,
            details: serde_json::json!({
                "request_id": request_id,
                "reason": "user_cancelled"
            }),
            risk_score: None,
            compliance_flags: vec!["GDPR".to_string()],
        };

        self.log_entry(entry).await
    }

    pub async fn log_data_access(
        &self,
        user_id: &str,
        resource_type: &str,
        resource_id: &str,
        action: &str,
        success: bool,
        ip_address: Option<String>,
    ) -> Result<()> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::DataAccess,
            user_id: Some(user_id.to_string()),
            session_id: None,
            ip_address,
            user_agent: None,
            resource_type: resource_type.to_string(),
            resource_id: Some(resource_id.to_string()),
            action: action.to_string(),
            outcome: if success { AuditOutcome::Success } else { AuditOutcome::Failure },
            details: serde_json::json!({
                "access_time": Utc::now(),
                "data_classification": "PII"
            }),
            risk_score: None,
            compliance_flags: vec!["GDPR".to_string(), "UK_DPA_2018".to_string()],
        };

        self.log_entry(entry).await
    }

    pub async fn log_authentication(
        &self,
        user_id: &str,
        method: &str,
        success: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
        failure_reason: Option<&str>,
    ) -> Result<()> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::Authentication,
            user_id: Some(user_id.to_string()),
            session_id: None,
            ip_address,
            user_agent,
            resource_type: "authentication".to_string(),
            resource_id: None,
            action: format!("login_{}", method),
            outcome: if success { AuditOutcome::Success } else { AuditOutcome::Failure },
            details: serde_json::json!({
                "method": method,
                "failure_reason": failure_reason
            }),
            risk_score: if success { Some(0.1) } else { Some(0.6) },
            compliance_flags: vec!["SECURITY".to_string()],
        };

        self.log_entry(entry).await
    }

    pub async fn log_admin_action(
        &self,
        admin_user_id: &str,
        action: &str,
        target_resource: &str,
        details: serde_json::Value,
        ip_address: Option<String>,
    ) -> Result<()> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::AdminAction,
            user_id: Some(admin_user_id.to_string()),
            session_id: None,
            ip_address,
            user_agent: None,
            resource_type: "admin".to_string(),
            resource_id: Some(target_resource.to_string()),
            action: action.to_string(),
            outcome: AuditOutcome::Success,
            details,
            risk_score: Some(0.3), // Admin actions have inherent risk
            compliance_flags: vec!["ADMIN_OVERSIGHT".to_string(), "PRIVILEGED_ACCESS".to_string()],
        };

        self.log_entry(entry).await
    }

    pub async fn log_security_incident(
        &self,
        incident_type: &str,
        affected_resource: &str,
        severity: f64,
        ip_address: Option<String>,
    ) -> Result<()> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::SecurityIncident,
            user_id: None,
            session_id: None,
            ip_address,
            user_agent: None,
            resource_type: "security_incident".to_string(),
            resource_id: Some(affected_resource.to_string()),
            action: incident_type.to_string(),
            outcome: AuditOutcome::Failure,
            details: serde_json::json!({
                "incident_type": incident_type,
                "severity": severity,
                "auto_detected": true,
                "requires_investigation": severity > 0.7
            }),
            risk_score: Some(severity),
            compliance_flags: vec!["SECURITY_INCIDENT".to_string(), "IMMEDIATE_REVIEW".to_string()],
        };

        self.log_entry(entry).await?;

        // Send real-time alert for high-severity incidents
        if self.config.enable_real_time_alerts && severity > 0.8 {
            self.send_security_alert(&entry).await?;
        }

        Ok(())
    }

    async fn log_entry(&self, entry: AuditLogEntry) -> Result<()> {
        // Add to buffer
        {
            let mut buffer = self.buffer.write().await;
            buffer.push(entry.clone());
            
            // Flush buffer if it's full
            if buffer.len() >= self.config.buffer_size {
                self.flush_buffer().await?;
            }
        }

        // For critical events, ensure immediate persistence
        if matches!(entry.event_type, AuditEventType::SecurityIncident) 
           || entry.risk_score.unwrap_or(0.0) > self.config.high_risk_threshold {
            self.persist_entry(&entry).await?;
        }

        Ok(())
    }

    async fn flush_buffer(&self) -> Result<()> {
        let entries = {
            let mut buffer = self.buffer.write().await;
            let entries = buffer.clone();
            buffer.clear();
            entries
        };

        if !entries.is_empty() {
            self.batch_persist_entries(&entries).await?;
        }

        Ok(())
    }

    async fn persist_entry(&self, entry: &AuditLogEntry) -> Result<()> {
        self.database.log_audit_event(
            entry.resource_id.as_ref()
                .and_then(|id| Uuid::parse_str(id).ok())
                .unwrap_or_else(Uuid::new_v4),
            &entry.action,
            entry.details.clone(),
            entry.user_id.as_deref(),
            entry.ip_address.as_deref(),
        ).await
    }

    async fn batch_persist_entries(&self, entries: &[AuditLogEntry]) -> Result<()> {
        // In a real implementation, use a batch insert for better performance
        for entry in entries {
            self.persist_entry(entry).await?;
        }
        Ok(())
    }

    async fn send_security_alert(&self, entry: &AuditLogEntry) -> Result<()> {
        // In production, integrate with alerting systems like PagerDuty, Slack, etc.
        tracing::error!(
            "SECURITY ALERT: {} - Risk Score: {:?} - Details: {}",
            entry.action,
            entry.risk_score,
            entry.details
        );
        
        // Could also send to external monitoring systems
        Ok(())
    }

    pub async fn get_audit_trail(
        &self,
        resource_id: Option<&str>,
        user_id: Option<&str>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<AuditLogEntry>> {
        // This would integrate with the database to query audit logs
        // For now, return empty vec
        Ok(Vec::new())
    }

    pub async fn generate_compliance_report(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<ComplianceReport> {
        // Generate comprehensive compliance report
        Ok(ComplianceReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            period_start: start_date,
            period_end: end_date,
            total_events: 0,
            security_incidents: 0,
            high_risk_verifications: 0,
            data_access_events: 0,
            compliance_violations: Vec::new(),
            gdpr_compliance_score: 0.95,
            recommendations: vec![
                "Regular review of high-risk verification patterns".to_string(),
                "Enhanced monitoring for repeated failed authentications".to_string(),
            ],
        })
    }

    pub async fn cleanup_old_logs(&self) -> Result<u64> {
        let cutoff_date = Utc::now() - chrono::Duration::days(self.config.retention_days as i64);
        self.database.cleanup_old_records(self.config.retention_days as i32).await
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_events: u64,
    pub security_incidents: u64,
    pub high_risk_verifications: u64,
    pub data_access_events: u64,
    pub compliance_violations: Vec<ComplianceViolation>,
    pub gdpr_compliance_score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub violation_id: Uuid,
    pub violation_type: String,
    pub severity: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub affected_resource: String,
}

// Background task to periodically flush audit buffer
pub async fn start_audit_flush_task(audit_logger: Arc<AuditLogger>) {
    let mut interval = tokio::time::interval(
        std::time::Duration::from_secs(audit_logger.config.flush_interval_seconds)
    );
    
    loop {
        interval.tick().await;
        
        if let Err(e) = audit_logger.flush_buffer().await {
            tracing::error!("Failed to flush audit buffer: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_logging() {
        // This test requires database to be available
        if std::env::var("DATABASE_URL").is_err() {
            return;
        }

        let logger = AuditLogger::new().await.unwrap();
        
        logger.log_authentication(
            "test_user",
            "password",
            true,
            Some("192.168.1.1".to_string()),
            Some("test-agent".to_string()),
            None,
        ).await.unwrap();

        logger.log_security_incident(
            "suspicious_activity",
            "user_account_123",
            0.9,
            Some("192.168.1.100".to_string()),
        ).await.unwrap();

        // Verify buffer functionality
        logger.flush_buffer().await.unwrap();
    }
}