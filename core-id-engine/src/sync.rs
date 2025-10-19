use anyhow::Result;
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncEvent {
    IdentityVerified { citizen_id: String, status: String },
    FraudDetected { citizen_id: String, risk_score: f64 },
    WalletUpdated { citizen_id: String, balance: f64 },
    PortalLogin { citizen_id: String, timestamp: chrono::DateTime<chrono::Utc> },
    ConnectorDataReceived { source: String, data: serde_json::Value },
}

pub struct SyncService {
    redis_client: Client,
    connection_manager: ConnectionManager,
    subscribers: Arc<RwLock<Vec<String>>>,
}

impl SyncService {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = Client::open(redis_url)?;
        let connection_manager = ConnectionManager::new(client.clone()).await?;

        Ok(Self {
            redis_client: client,
            connection_manager,
            subscribers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn publish_event(&mut self, event: SyncEvent) -> Result<()> {
        let channel = "id-system-events";
        let message = serde_json::to_string(&event)?;

        let _: () = self.connection_manager.publish(channel, message).await?;
        info!("Published sync event: {:?}", event);

        Ok(())
    }

    pub async fn subscribe_to_events<F>(&mut self, callback: F) -> Result<()>
    where
        F: Fn(SyncEvent) -> Result<()> + Send + Sync + 'static,
    {
        let mut pubsub = self.redis_client.get_async_pubsub().await?;
        pubsub.subscribe("id-system-events").await?;

        let callback = Arc::new(callback);

        tokio::spawn(async move {
            let mut stream = pubsub.on_message();

            while let Some(msg) = stream.next().await {
                let payload: String = msg.get_payload().unwrap_or_default();
                match serde_json::from_str::<SyncEvent>(&payload) {
                    Ok(event) => {
                        if let Err(e) = callback(event.clone()) {
                            error!("Error handling sync event: {:?}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to deserialize sync event: {:?}", e);
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn sync_with_service(&mut self, service_url: &str, data: serde_json::Value) -> Result<()> {
        let client = reqwest::Client::new();
        let response = client
            .post(service_url)
            .json(&data)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Successfully synced data with {}", service_url);
        } else {
            error!("Failed to sync with {}: {:?}", service_url, response.status());
        }

        Ok(())
    }
}