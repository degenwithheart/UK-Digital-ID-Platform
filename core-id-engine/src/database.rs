use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::{Result, Context};
use std::collections::HashMap;

use crate::{IdentityVerificationRequest, VerificationResult, DataSource};

#[derive(Clone)]
pub struct DatabaseManager {
    pool: PgPool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub id: Uuid,
    pub request_id: Uuid,
    pub citizen_id: String,
    pub verification_type: String,
    pub status: String,
    pub confidence_score: f64,
    pub risk_score: f64,
    pub identity_match: bool,
    pub processing_time_ms: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub verification_id: Uuid,
    pub action: String,
    pub details: serde_json::Value,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl DatabaseManager {
    pub async fn new() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:password@postgres:5432/identity_db".to_string());

        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(5)
            .connect(&database_url)
            .await
            .context("Failed to create database connection pool")?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await
            .context("Failed to run database migrations")?;

        Ok(Self { pool })
    }

    pub async fn store_verification(
        &self,
        request: &IdentityVerificationRequest,
        result: &VerificationResult,
    ) -> Result<Uuid> {
        let record_id = Uuid::new_v4();
        
        sqlx::query!(
            r#"
            INSERT INTO verification_records (
                id, request_id, citizen_id, verification_type, status,
                confidence_score, risk_score, identity_match, processing_time_ms,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            record_id,
            result.request_id,
            request.citizen_id,
            serde_json::to_string(&request.verification_type)?,
            serde_json::to_string(&result.status)?,
            result.confidence_score,
            result.risk_score,
            result.identity_match,
            result.processing_time_ms as i64,
            Utc::now(),
            Utc::now()
        )
        .execute(&self.pool)
        .await
        .context("Failed to store verification record")?;

        // Store source results
        for (source, source_result) in &result.source_results {
            self.store_source_result(record_id, source, source_result).await?;
        }

        // Store alerts
        for alert in &result.alerts {
            self.store_alert(record_id, alert).await?;
        }

        Ok(record_id)
    }

    async fn store_source_result(
        &self,
        verification_id: Uuid,
        source: &DataSource,
        result: &crate::SourceResult,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO source_results (
                id, verification_id, source, status, confidence,
                data_points, response_time_ms, last_updated, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            Uuid::new_v4(),
            verification_id,
            serde_json::to_string(source)?,
            result.status,
            result.confidence,
            result.data_points as i32,
            result.response_time_ms as i64,
            result.last_updated,
            Utc::now()
        )
        .execute(&self.pool)
        .await
        .context("Failed to store source result")?;

        Ok(())
    }

    async fn store_alert(
        &self,
        verification_id: Uuid,
        alert: &crate::Alert,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO alerts (
                id, verification_id, alert_type, severity, message,
                source, timestamp, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            Uuid::new_v4(),
            verification_id,
            serde_json::to_string(&alert.alert_type)?,
            serde_json::to_string(&alert.severity)?,
            alert.message,
            serde_json::to_string(&alert.source)?,
            alert.timestamp,
            Utc::now()
        )
        .execute(&self.pool)
        .await
        .context("Failed to store alert")?;

        Ok(())
    }

    pub async fn get_verification_history(
        &self,
        citizen_id: &str,
        limit: i32,
    ) -> Result<Vec<VerificationRecord>> {
        let records = sqlx::query_as!(
            VerificationRecord,
            r#"
            SELECT 
                id, request_id, citizen_id, verification_type, status,
                confidence_score, risk_score, identity_match, processing_time_ms,
                created_at, updated_at
            FROM verification_records
            WHERE citizen_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            citizen_id,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch verification history")?;

        Ok(records)
    }

    pub async fn get_verification_by_id(&self, verification_id: Uuid) -> Result<Option<VerificationRecord>> {
        let record = sqlx::query_as!(
            VerificationRecord,
            r#"
            SELECT 
                id, request_id, citizen_id, verification_type, status,
                confidence_score, risk_score, identity_match, processing_time_ms,
                created_at, updated_at
            FROM verification_records
            WHERE id = $1
            "#,
            verification_id
        )
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch verification record")?;

        Ok(record)
    }

    pub async fn get_system_statistics(&self) -> Result<SystemStatistics> {
        let total_verifications: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM verification_records"
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to get total verifications")?;

        let successful_verifications: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM verification_records WHERE status LIKE '%Completed%'"
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to get successful verifications")?;

        let avg_processing_time: (Option<f64>,) = sqlx::query_as(
            "SELECT AVG(processing_time_ms) FROM verification_records"
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to get average processing time")?;

        let avg_confidence: (Option<f64>,) = sqlx::query_as(
            "SELECT AVG(confidence_score) FROM verification_records"
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to get average confidence")?;

        Ok(SystemStatistics {
            total_verifications: total_verifications.0 as u64,
            successful_verifications: successful_verifications.0 as u64,
            average_processing_time_ms: avg_processing_time.0.unwrap_or(0.0),
            average_confidence_score: avg_confidence.0.unwrap_or(0.0),
        })
    }

    pub async fn log_audit_event(
        &self,
        verification_id: Uuid,
        action: &str,
        details: serde_json::Value,
        user_id: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO audit_logs (
                id, verification_id, action, details, user_id, ip_address, timestamp
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            Uuid::new_v4(),
            verification_id,
            action,
            details,
            user_id,
            ip_address,
            Utc::now()
        )
        .execute(&self.pool)
        .await
        .context("Failed to log audit event")?;

        Ok(())
    }

    pub async fn get_audit_logs(
        &self,
        verification_id: Option<Uuid>,
        limit: i32,
    ) -> Result<Vec<AuditLogEntry>> {
        let logs = if let Some(verification_id) = verification_id {
            sqlx::query_as!(
                AuditLogEntry,
                r#"
                SELECT id, verification_id, action, details, user_id, ip_address, timestamp
                FROM audit_logs
                WHERE verification_id = $1
                ORDER BY timestamp DESC
                LIMIT $2
                "#,
                verification_id,
                limit
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as!(
                AuditLogEntry,
                r#"
                SELECT id, verification_id, action, details, user_id, ip_address, timestamp
                FROM audit_logs
                ORDER BY timestamp DESC
                LIMIT $1
                "#,
                limit
            )
            .fetch_all(&self.pool)
            .await?
        };

        Ok(logs)
    }

    pub async fn cleanup_old_records(&self, days: i32) -> Result<u64> {
        let result = sqlx::query!(
            "DELETE FROM verification_records WHERE created_at < NOW() - INTERVAL '%1 days'",
            days
        )
        .execute(&self.pool)
        .await
        .context("Failed to cleanup old records")?;

        Ok(result.rows_affected())
    }

    pub async fn get_verification_trends(&self, days: i32) -> Result<Vec<VerificationTrend>> {
        let trends = sqlx::query!(
            r#"
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as total_verifications,
                AVG(confidence_score) as avg_confidence,
                AVG(risk_score) as avg_risk_score,
                COUNT(CASE WHEN status LIKE '%Completed%' THEN 1 END) as successful_count
            FROM verification_records
            WHERE created_at >= NOW() - INTERVAL '%1 days'
            GROUP BY DATE(created_at)
            ORDER BY date DESC
            "#,
            days
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to get verification trends")?;

        let mut result = Vec::new();
        for row in trends {
            result.push(VerificationTrend {
                date: row.date.unwrap(),
                total_verifications: row.total_verifications.unwrap_or(0) as u64,
                avg_confidence: row.avg_confidence.unwrap_or(0.0),
                avg_risk_score: row.avg_risk_score.unwrap_or(0.0),
                successful_count: row.successful_count.unwrap_or(0) as u64,
            });
        }

        Ok(result)
    }

    pub async fn health_check(&self) -> Result<bool> {
        let result: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("Database health check failed")?;

        Ok(result.0 == 1)
    }

    // Batch operations for better performance
    pub async fn batch_store_verifications(
        &self,
        requests: &[IdentityVerificationRequest],
        results: &[VerificationResult],
    ) -> Result<Vec<Uuid>> {
        let mut transaction = self.pool.begin().await.context("Failed to begin transaction")?;
        let mut record_ids = Vec::new();

        for (request, result) in requests.iter().zip(results.iter()) {
            let record_id = Uuid::new_v4();
            record_ids.push(record_id);

            sqlx::query!(
                r#"
                INSERT INTO verification_records (
                    id, request_id, citizen_id, verification_type, status,
                    confidence_score, risk_score, identity_match, processing_time_ms,
                    created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
                record_id,
                result.request_id,
                request.citizen_id,
                serde_json::to_string(&request.verification_type)?,
                serde_json::to_string(&result.status)?,
                result.confidence_score,
                result.risk_score,
                result.identity_match,
                result.processing_time_ms as i64,
                Utc::now(),
                Utc::now()
            )
            .execute(&mut *transaction)
            .await
            .context("Failed to store verification record in batch")?;
        }

        transaction.commit().await.context("Failed to commit batch transaction")?;
        Ok(record_ids)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatistics {
    pub total_verifications: u64,
    pub successful_verifications: u64,
    pub average_processing_time_ms: f64,
    pub average_confidence_score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationTrend {
    pub date: chrono::NaiveDate,
    pub total_verifications: u64,
    pub avg_confidence: f64,
    pub avg_risk_score: f64,
    pub successful_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_operations() {
        // This test requires PostgreSQL to be running
        if std::env::var("DATABASE_URL").is_err() {
            return; // Skip test if database is not available
        }

        let db = DatabaseManager::new().await.unwrap();
        let stats = db.get_system_statistics().await.unwrap();
        
        // Just verify we can connect and query
        assert!(stats.total_verifications >= 0);
    }
}