use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
    compression::CompressionLayer,
};
use uuid::Uuid;
use anyhow::Result;

use crate::{
    CoreIdEngine, IdentityVerificationRequest, VerificationResult,
    HealthStatus, SystemMetrics,
};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<CoreIdEngine>,
}

pub async fn create_app() -> Result<Router> {
    let engine = Arc::new(CoreIdEngine::new().await?);
    let state = AppState { engine };

    let app = Router::new()
        // Health and monitoring endpoints
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics))
        .route("/metrics/prometheus", get(get_prometheus_metrics))
        
        // Core verification endpoints
        .route("/verify", post(verify_identity))
        .route("/verify/batch", post(batch_verify))
        .route("/verify/:request_id/status", get(get_verification_status))
        .route("/verify/:request_id/cancel", post(cancel_verification))
        
        // History and analytics
        .route("/history/:citizen_id", get(get_verification_history))
        .route("/analytics/trends", get(get_verification_trends))
        
        // Admin endpoints
        .route("/admin/cache/clear", post(clear_cache))
        .route("/admin/system/status", get(get_system_status))
        
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any)
                )
        )
        .with_state(state);

    Ok(app)
}

// Health check endpoint
async fn health_check(State(state): State<AppState>) -> Result<Json<HealthStatus>, StatusCode> {
    match state.engine.health_check().await {
        Ok(status) => Ok(Json(status)),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

// Get system metrics
async fn get_metrics(State(state): State<AppState>) -> Result<Json<SystemMetrics>, StatusCode> {
    match state.engine.get_metrics().await {
        Ok(metrics) => Ok(Json(metrics)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Prometheus metrics endpoint
async fn get_prometheus_metrics(State(state): State<AppState>) -> Result<String, StatusCode> {
    match state.engine.metrics_collector.export_prometheus_metrics().await {
        Ok(metrics) => Ok(metrics),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Main identity verification endpoint
async fn verify_identity(
    State(state): State<AppState>,
    Json(request): Json<IdentityVerificationRequest>,
) -> Result<Json<VerificationResult>, StatusCode> {
    match state.engine.verify_identity(request).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            tracing::error!("Verification failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Batch verification endpoint
async fn batch_verify(
    State(state): State<AppState>,
    Json(requests): Json<Vec<IdentityVerificationRequest>>,
) -> Result<Json<Vec<VerificationResult>>, StatusCode> {
    if requests.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    match state.engine.batch_verify(requests).await {
        Ok(results) => Ok(Json(results)),
        Err(e) => {
            tracing::error!("Batch verification failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Get verification status
async fn get_verification_status(
    State(state): State<AppState>,
    Path(request_id): Path<Uuid>,
) -> Result<Json<VerificationStatusResponse>, StatusCode> {
    match state.engine.get_verification_status(request_id).await {
        Some(status) => Ok(Json(VerificationStatusResponse {
            request_id,
            status: format!("{:?}", status),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// Cancel verification
async fn cancel_verification(
    State(state): State<AppState>,
    Path(request_id): Path<Uuid>,
) -> Result<Json<CancelVerificationResponse>, StatusCode> {
    match state.engine.cancel_verification(request_id).await {
        Ok(cancelled) => Ok(Json(CancelVerificationResponse {
            request_id,
            cancelled,
            message: if cancelled {
                "Verification cancelled successfully".to_string()
            } else {
                "Verification not found or already completed".to_string()
            },
        })),
        Err(e) => {
            tracing::error!("Failed to cancel verification: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Get verification history
async fn get_verification_history(
    State(state): State<AppState>,
    Path(citizen_id): Path<String>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<VerificationHistoryResponse>, StatusCode> {
    let limit = params.limit.unwrap_or(50).min(100);
    
    match state.engine.database_manager.get_verification_history(&citizen_id, limit as i32).await {
        Ok(records) => Ok(Json(VerificationHistoryResponse {
            citizen_id,
            total_records: records.len(),
            records,
        })),
        Err(e) => {
            tracing::error!("Failed to get verification history: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Get verification trends
async fn get_verification_trends(
    State(state): State<AppState>,
    Query(params): Query<TrendsParams>,
) -> Result<Json<VerificationTrendsResponse>, StatusCode> {
    let days = params.days.unwrap_or(30).min(365);
    
    match state.engine.database_manager.get_verification_trends(days as i32).await {
        Ok(trends) => Ok(Json(VerificationTrendsResponse {
            period_days: days,
            trends,
        })),
        Err(e) => {
            tracing::error!("Failed to get verification trends: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Clear cache (admin endpoint)
async fn clear_cache(State(state): State<AppState>) -> Result<Json<AdminResponse>, StatusCode> {
    match state.engine.cache_manager.clear().await {
        Ok(_) => Ok(Json(AdminResponse {
            success: true,
            message: "Cache cleared successfully".to_string(),
        })),
        Err(e) => {
            tracing::error!("Failed to clear cache: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Get system status (admin endpoint)
async fn get_system_status(State(state): State<AppState>) -> Result<Json<SystemStatus>, StatusCode> {
    let health = state.engine.health_check().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let metrics = state.engine.get_metrics().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cache_size = state.engine.cache_manager.get_cache_size().await;
    let cache_hit_rate = state.engine.cache_manager.get_hit_rate().await;

    Ok(Json(SystemStatus {
        health,
        metrics,
        cache_size,
        cache_hit_rate,
        uptime_seconds: state.engine.metrics_collector.get_uptime().await,
    }))
}

// Response types
#[derive(Serialize)]
struct VerificationStatusResponse {
    request_id: Uuid,
    status: String,
}

#[derive(Serialize)]
struct CancelVerificationResponse {
    request_id: Uuid,
    cancelled: bool,
    message: String,
}

#[derive(Serialize)]
struct VerificationHistoryResponse {
    citizen_id: String,
    total_records: usize,
    records: Vec<crate::database::VerificationRecord>,
}

#[derive(Serialize)]
struct VerificationTrendsResponse {
    period_days: u32,
    trends: Vec<crate::database::VerificationTrend>,
}

#[derive(Serialize)]
struct AdminResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
struct SystemStatus {
    health: HealthStatus,
    metrics: SystemMetrics,
    cache_size: usize,
    cache_hit_rate: f64,
    uptime_seconds: u64,
}

// Query parameter types
#[derive(Deserialize)]
struct HistoryParams {
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct TrendsParams {
    days: Option<u32>,
}

// Error handling
pub async fn handle_error(err: axum::BoxError) -> impl axum::response::IntoResponse {
    if err.is::<tower::timeout::error::Elapsed>() {
        (StatusCode::REQUEST_TIMEOUT, "Request timeout")
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", err),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use crate::{VerificationType, DataSource, Priority};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_app().await.unwrap();
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_verification_endpoint() {
        let app = create_app().await.unwrap();
        let server = TestServer::new(app).unwrap();

        let request = IdentityVerificationRequest {
            request_id: Uuid::new_v4(),
            citizen_id: "test_citizen_123".to_string(),
            verification_type: VerificationType::BasicIdentity,
            data_sources: vec![DataSource::NHS, DataSource::DVLA],
            priority: Priority::Normal,
            callback_url: None,
            metadata: HashMap::new(),
        };

        let response = server.post("/verify").json(&request).await;
        response.assert_status_ok();
    }
}