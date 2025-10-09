use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use redis::{Client, Commands, Connection, AsyncCommands};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use tokio::sync::RwLock;
use dashmap::DashMap;
use zstd::encode_all;

pub struct CacheManager {
    redis_client: Client,
    local_cache: Arc<DashMap<String, CacheEntry>>,
    cache_stats: Arc<RwLock<CacheStats>>,
}

#[derive(Clone)]
struct CacheEntry {
    data: Vec<u8>,
    expires_at: std::time::Instant,
    access_count: u32,
    last_accessed: std::time::Instant,
}

#[derive(Debug, Default)]
struct CacheStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    total_requests: u64,
}

impl CacheManager {
    pub async fn new() -> Result<Self> {
        let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
        let redis_client = Client::open(redis_url).context("Failed to create Redis client")?;

        Ok(Self {
            redis_client,
            local_cache: Arc::new(DashMap::new()),
            cache_stats: Arc::new(RwLock::new(CacheStats::default())),
        })
    }

    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let mut stats = self.cache_stats.write().await;
        stats.total_requests += 1;

        // Check local cache first (L1)
        if let Some(entry) = self.local_cache.get(key) {
            if entry.expires_at > std::time::Instant::now() {
                // Update access statistics
                let mut entry_mut = self.local_cache.get_mut(key).unwrap();
                entry_mut.access_count += 1;
                entry_mut.last_accessed = std::time::Instant::now();
                drop(entry_mut);

                stats.hits += 1;
                let decompressed = zstd::decode_all(&entry.data[..]).context("Failed to decompress data")?;
                let result: T = serde_json::from_slice(&decompressed).context("Failed to deserialize data")?;
                return Ok(Some(result));
            } else {
                // Entry expired, remove it
                self.local_cache.remove(key);
                stats.evictions += 1;
            }
        }

        // Check Redis cache (L2)
        match self.get_from_redis(key).await {
            Ok(Some(data)) => {
                stats.hits += 1;
                
                // Store in local cache for faster future access
                let entry = CacheEntry {
                    data: data.clone(),
                    expires_at: std::time::Instant::now() + Duration::from_secs(300), // 5 minutes local TTL
                    access_count: 1,
                    last_accessed: std::time::Instant::now(),
                };
                self.local_cache.insert(key.to_string(), entry);

                let decompressed = zstd::decode_all(&data[..]).context("Failed to decompress data")?;
                let result: T = serde_json::from_slice(&decompressed).context("Failed to deserialize data")?;
                Ok(Some(result))
            }
            Ok(None) => {
                stats.misses += 1;
                Ok(None)
            }
            Err(e) => {
                stats.misses += 1;
                tracing::warn!("Redis cache error for key {}: {}", key, e);
                Ok(None)
            }
        }
    }

    pub async fn set<T: Serialize>(&self, key: &str, value: &T, ttl: Duration) -> Result<()> {
        let serialized = serde_json::to_vec(value).context("Failed to serialize data")?;
        let compressed = encode_all(&serialized[..], 3).context("Failed to compress data")?;

        // Store in Redis (L2) with longer TTL
        if let Err(e) = self.set_in_redis(key, &compressed, ttl).await {
            tracing::warn!("Failed to store in Redis cache: {}", e);
        }

        // Store in local cache (L1) with shorter TTL
        let local_ttl = std::cmp::min(ttl, Duration::from_secs(300)); // Max 5 minutes local
        let entry = CacheEntry {
            data: compressed,
            expires_at: std::time::Instant::now() + local_ttl,
            access_count: 0,
            last_accessed: std::time::Instant::now(),
        };
        self.local_cache.insert(key.to_string(), entry);

        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        // Remove from local cache
        self.local_cache.remove(key);

        // Remove from Redis cache
        if let Err(e) = self.delete_from_redis(key).await {
            tracing::warn!("Failed to delete from Redis cache: {}", e);
        }

        Ok(())
    }

    pub async fn clear(&self) -> Result<()> {
        // Clear local cache
        self.local_cache.clear();

        // Clear Redis cache (flush database)
        if let Err(e) = self.clear_redis().await {
            tracing::warn!("Failed to clear Redis cache: {}", e);
        }

        // Reset statistics
        let mut stats = self.cache_stats.write().await;
        *stats = CacheStats::default();

        Ok(())
    }

    pub async fn get_stats(&self) -> CacheStats {
        let stats = self.cache_stats.read().await;
        CacheStats {
            hits: stats.hits,
            misses: stats.misses,
            evictions: stats.evictions,
            total_requests: stats.total_requests,
        }
    }

    pub async fn get_hit_rate(&self) -> f64 {
        let stats = self.cache_stats.read().await;
        if stats.total_requests == 0 {
            0.0
        } else {
            stats.hits as f64 / stats.total_requests as f64
        }
    }

    pub async fn evict_expired(&self) -> Result<u32> {
        let now = std::time::Instant::now();
        let mut evicted = 0;

        // Collect keys to evict (to avoid holding the map lock during iteration)
        let keys_to_evict: Vec<String> = self.local_cache
            .iter()
            .filter(|entry| entry.expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect();

        // Evict expired entries
        for key in keys_to_evict {
            self.local_cache.remove(&key);
            evicted += 1;
        }

        if evicted > 0 {
            let mut stats = self.cache_stats.write().await;
            stats.evictions += evicted as u64;
        }

        Ok(evicted)
    }

    pub async fn get_cache_size(&self) -> usize {
        self.local_cache.len()
    }

    pub async fn health_check(&self) -> Result<bool> {
        // Test Redis connectivity
        match self.redis_client.get_connection() {
            Ok(mut conn) => {
                let _: Result<String, _> = conn.ping();
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    // Batch operations for better performance
    pub async fn get_multiple<T: DeserializeOwned>(&self, keys: &[String]) -> Result<HashMap<String, T>> {
        let mut results = HashMap::new();
        let mut missing_keys = Vec::new();

        // Check local cache first
        for key in keys {
            if let Some(value) = self.get::<T>(key).await? {
                results.insert(key.clone(), value);
            } else {
                missing_keys.push(key.clone());
            }
        }

        // Get remaining keys from Redis in batch
        if !missing_keys.is_empty() {
            if let Ok(redis_results) = self.get_multiple_from_redis(&missing_keys).await {
                for (key, data) in redis_results {
                    if let Ok(decompressed) = zstd::decode_all(&data[..]) {
                        if let Ok(value) = serde_json::from_slice::<T>(&decompressed) {
                            results.insert(key, value);
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn set_multiple<T: Serialize>(&self, items: HashMap<String, T>, ttl: Duration) -> Result<()> {
        for (key, value) in items {
            self.set(&key, &value, ttl).await?;
        }
        Ok(())
    }

    // LRU eviction for local cache when it gets too large
    pub async fn evict_lru(&self, target_size: usize) -> Result<u32> {
        if self.local_cache.len() <= target_size {
            return Ok(0);
        }

        let mut entries_with_access: Vec<_> = self.local_cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.last_accessed))
            .collect();

        // Sort by last accessed time (oldest first)
        entries_with_access.sort_by_key(|(_, last_accessed)| *last_accessed);

        let to_evict = self.local_cache.len() - target_size;
        let mut evicted = 0;

        for (key, _) in entries_with_access.iter().take(to_evict) {
            self.local_cache.remove(key);
            evicted += 1;
        }

        if evicted > 0 {
            let mut stats = self.cache_stats.write().await;
            stats.evictions += evicted as u64;
        }

        Ok(evicted)
    }

    // Private Redis operations
    async fn get_from_redis(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.redis_client.get_async_connection().await.context("Failed to connect to Redis")?;
        let result: Option<Vec<u8>> = conn.get(key).await.context("Failed to get from Redis")?;
        Ok(result)
    }

    async fn set_in_redis(&self, key: &str, data: &[u8], ttl: Duration) -> Result<()> {
        let mut conn = self.redis_client.get_async_connection().await.context("Failed to connect to Redis")?;
        let ttl_seconds = ttl.as_secs() as u64;
        conn.set_ex(key, data, ttl_seconds).await.context("Failed to set in Redis")?;
        Ok(())
    }

    async fn delete_from_redis(&self, key: &str) -> Result<()> {
        let mut conn = self.redis_client.get_async_connection().await.context("Failed to connect to Redis")?;
        conn.del(key).await.context("Failed to delete from Redis")?;
        Ok(())
    }

    async fn clear_redis(&self) -> Result<()> {
        let mut conn = self.redis_client.get_async_connection().await.context("Failed to connect to Redis")?;
        redis::cmd("FLUSHDB").exec_async(&mut conn).await.context("Failed to flush Redis")?;
        Ok(())
    }

    async fn get_multiple_from_redis(&self, keys: &[String]) -> Result<HashMap<String, Vec<u8>>> {
        let mut conn = self.redis_client.get_async_connection().await.context("Failed to connect to Redis")?;
        let values: Vec<Option<Vec<u8>>> = conn.get(keys).await.context("Failed to get multiple from Redis")?;
        
        let mut results = HashMap::new();
        for (key, value) in keys.iter().zip(values.into_iter()) {
            if let Some(data) = value {
                results.insert(key.clone(), data);
            }
        }
        
        Ok(results)
    }
}

// Background task to periodically clean up expired entries
pub async fn start_cache_cleanup_task(cache_manager: Arc<CacheManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60)); // Run every minute
    
    loop {
        interval.tick().await;
        
        if let Err(e) = cache_manager.evict_expired().await {
            tracing::error!("Cache cleanup failed: {}", e);
        }
        
        // Also perform LRU eviction if cache gets too large
        let cache_size = cache_manager.get_cache_size().await;
        if cache_size > 10000 { // Max 10k entries in local cache
            if let Err(e) = cache_manager.evict_lru(8000).await { // Evict down to 8k
                tracing::error!("LRU eviction failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u32,
        name: String,
    }

    #[tokio::test]
    async fn test_cache_operations() {
        // This test requires Redis to be running
        if std::env::var("REDIS_URL").is_err() {
            return; // Skip test if Redis is not available
        }

        let cache = CacheManager::new().await.unwrap();
        let test_data = TestData {
            id: 1,
            name: "test".to_string(),
        };

        // Test set and get
        cache.set("test_key", &test_data, Duration::from_secs(60)).await.unwrap();
        let retrieved: Option<TestData> = cache.get("test_key").await.unwrap();
        assert_eq!(retrieved, Some(test_data));

        // Test delete
        cache.delete("test_key").await.unwrap();
        let deleted: Option<TestData> = cache.get("test_key").await.unwrap();
        assert_eq!(deleted, None);
    }
}