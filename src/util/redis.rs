use crate::config::RedisConfig;
use redis::{
    AsyncCommands, Client, ErrorKind,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, instrument};
use async_trait::async_trait;

/// Trait for Redis service operations
#[async_trait]
pub trait RedisServiceTrait: Send + Sync {
    async fn set_string(&self, key: &str, value: &str) -> Result<(), RedisError>;
    async fn get_string(&self, key: &str) -> Result<Option<String>, RedisError>;
    async fn set_string_with_expiry(&self, key: &str, value: &str, expiry_secs: u64) -> Result<(), RedisError>;
    async fn delete(&self, key: &str) -> Result<bool, RedisError>;
    async fn exists(&self, key: &str) -> Result<bool, RedisError>;
    async fn set_hash(&self, key: &str, data: &HashMap<String, String>) -> Result<(), RedisError>;
    async fn get_hash(&self, key: &str) -> Result<HashMap<String, String>, RedisError>;
    async fn increment(&self, key: &str) -> Result<i64, RedisError>;
    async fn get_ttl(&self, key: &str) -> Result<i64, RedisError>;
    async fn ping(&self) -> Result<String, RedisError>;
}

#[derive(Clone)]
pub struct RedisService {
    connection_manager: ConnectionManager,
    config: RedisConfig,
}

impl RedisService {
    /// Create a new Redis service instance with connection pooling
    #[instrument(skip(config), fields(host = %config.host, port = config.port, db = config.database))]
    pub async fn new(config: RedisConfig) -> Result<Self, RedisError> {
        info!("Initializing Redis service");
        
        // Validate configuration first
        config.validate().map_err(|e| {
            error!("Redis configuration validation failed: {}", e);
            RedisError::ConfigError(e.to_string())
        })?;

        let connection_url = config.get_connection_url();
        debug!("Creating Redis client with URL: {}", 
            if config.password.is_some() || config.username.is_some() {
                config.get_connection_url().replace(&format!("{}:{}", 
                    config.username.as_deref().unwrap_or(""), 
                    config.password.as_deref().unwrap_or("")), "***:***")
            } else {
                connection_url.clone()
            }
        );

        let client = Client::open(connection_url)
            .map_err(|e| {
                error!("Failed to create Redis client: {}", e);
                RedisError::ConnectionError(format!("Client creation failed: {}", e))
            })?;

        let connection_manager = ConnectionManager::new(client).await
            .map_err(|e| {
                error!("Failed to create Redis connection manager: {}", e);
                RedisError::ConnectionError(format!("Connection manager creation failed: {}", e))
            })?;

        let service = Self {
            connection_manager,
            config,
        };

        // Test the connection
        service.ping().await?;

        info!("Redis service initialized successfully");
        Ok(service)
    }

    /// Test the Redis connection
    #[instrument(skip(self))]
    pub async fn ping(&self) -> Result<(), RedisError> {
        debug!("Pinging Redis server");
        
        let mut conn = self.get_connection().await?;
        let result: String = redis::cmd("PING").query_async(&mut conn).await
            .map_err(|e| {
                error!("Redis ping failed: {}", e);
                RedisError::OperationError(format!("Ping failed: {}", e))
            })?;

        if result == "PONG" {
            debug!("Redis ping successful");
            Ok(())
        } else {
            error!("Unexpected ping response: {}", result);
            Err(RedisError::OperationError(format!("Unexpected ping response: {}", result)))
        }
    }

    /// Get a connection from the pool
    async fn get_connection(&self) -> Result<ConnectionManager, RedisError> {
        Ok(self.connection_manager.clone())
    }

    // ==================== STRING OPERATIONS ====================

    /// Set a key-value pair
    #[instrument(skip(self, value), fields(key = %key))]
    pub async fn set<T>(&self, key: &str, value: T) -> Result<(), RedisError>
    where
        T: Serialize,
    {
        debug!("Setting key: {}", key);
        
        let serialized = serde_json::to_string(&value)
            .map_err(|e| {
                error!("Failed to serialize value for key '{}': {}", key, e);
                RedisError::SerializationError(e.to_string())
            })?;

        let mut conn = self.get_connection().await?;
        let _: () = conn.set(key, serialized).await
            .map_err(|e| {
                error!("Failed to set key '{}': {}", key, e);
                RedisError::OperationError(format!("Set operation failed: {}", e))
            })?;

        debug!("Successfully set key: {}", key);
        Ok(())
    }

    /// Set a key-value pair with expiration
    #[instrument(skip(self, value), fields(key = %key, ttl_secs = ttl_secs))]
    pub async fn setex<T>(&self, key: &str, value: T, ttl_secs: u64) -> Result<(), RedisError>
    where
        T: Serialize,
    {
        debug!("Setting key '{}' with TTL {} seconds", key, ttl_secs);
        
        let serialized = serde_json::to_string(&value)
            .map_err(|e| {
                error!("Failed to serialize value for key '{}': {}", key, e);
                RedisError::SerializationError(e.to_string())
            })?;

        let mut conn = self.get_connection().await?;
        let _: () = redis::cmd("SETEX")
            .arg(key)
            .arg(ttl_secs)
            .arg(serialized)
            .query_async(&mut conn).await
            .map_err(|e| {
                error!("Failed to setex key '{}': {}", key, e);
                RedisError::OperationError(format!("Setex operation failed: {}", e))
            })?;

        debug!("Successfully set key '{}' with TTL", key);
        Ok(())
    }

    /// Get a value by key
    #[instrument(skip(self), fields(key = %key))]
    pub async fn get<T>(&self, key: &str) -> Result<Option<T>, RedisError>
    where
        T: for<'de> Deserialize<'de>,
    {
        debug!("Getting key: {}", key);
        
        let mut conn = self.get_connection().await?;
        let value: redis::RedisResult<String> = conn.get(key).await;
        
        match value {
            Ok(data) => {
                let deserialized = serde_json::from_str(&data)
                    .map_err(|e| {
                        error!("Failed to deserialize value for key '{}': {}", key, e);
                        RedisError::SerializationError(e.to_string())
                    })?;
                debug!("Successfully retrieved and deserialized key: {}", key);
                Ok(Some(deserialized))
            }
            Err(e) => {
                if e.kind() == ErrorKind::TypeError {
                    debug!("Key '{}' not found", key);
                    Ok(None)
                } else {
                    error!("Failed to get key '{}': {}", key, e);
                    Err(RedisError::OperationError(format!("Get operation failed: {}", e)))
                }
            }
        }
    }

    /// Delete a key
    #[instrument(skip(self), fields(key = %key))]
    pub async fn delete(&self, key: &str) -> Result<bool, RedisError> {
        debug!("Deleting key: {}", key);
        
        let mut conn = self.get_connection().await?;
        let deleted: u64 = conn.del(key).await
            .map_err(|e| {
                error!("Failed to delete key '{}': {}", key, e);
                RedisError::OperationError(format!("Delete operation failed: {}", e))
            })?;

        let was_deleted = deleted > 0;
        if was_deleted {
            debug!("Successfully deleted key: {}", key);
        } else {
            debug!("Key '{}' was not found for deletion", key);
        }
        Ok(was_deleted)
    }

    /// Check if a key exists
    #[instrument(skip(self), fields(key = %key))]
    pub async fn exists(&self, key: &str) -> Result<bool, RedisError> {
        debug!("Checking if key exists: {}", key);
        
        let mut conn = self.get_connection().await?;
        let exists: bool = conn.exists(key).await
            .map_err(|e| {
                error!("Failed to check existence of key '{}': {}", key, e);
                RedisError::OperationError(format!("Exists operation failed: {}", e))
            })?;

        debug!("Key '{}' exists: {}", key, exists);
        Ok(exists)
    }

    /// Set expiration for a key
    #[instrument(skip(self), fields(key = %key, ttl_secs = ttl_secs))]
    pub async fn expire(&self, key: &str, ttl_secs: u64) -> Result<bool, RedisError> {
        debug!("Setting expiration for key '{}': {} seconds", key, ttl_secs);
        
        let mut conn = self.get_connection().await?;
        let success: bool = conn.expire(key, ttl_secs as i64).await
            .map_err(|e| {
                error!("Failed to set expiration for key '{}': {}", key, e);
                RedisError::OperationError(format!("Expire operation failed: {}", e))
            })?;

        if success {
            debug!("Successfully set expiration for key: {}", key);
        } else {
            debug!("Failed to set expiration for key '{}' (key may not exist)", key);
        }
        Ok(success)
    }

    /// Get time to live for a key
    #[instrument(skip(self), fields(key = %key))]
    pub async fn ttl(&self, key: &str) -> Result<i64, RedisError> {
        debug!("Getting TTL for key: {}", key);
        
        let mut conn = self.get_connection().await?;
        let ttl: i64 = conn.ttl(key).await
            .map_err(|e| {
                error!("Failed to get TTL for key '{}': {}", key, e);
                RedisError::OperationError(format!("TTL operation failed: {}", e))
            })?;

        debug!("TTL for key '{}': {}", key, ttl);
        Ok(ttl)
    }

    // ==================== HASH OPERATIONS ====================

    /// Set a field in a hash
    #[instrument(skip(self, value), fields(key = %key, field = %field))]
    pub async fn hset<T>(&self, key: &str, field: &str, value: T) -> Result<(), RedisError>
    where
        T: Serialize,
    {
        debug!("Setting hash field '{}' in key '{}'", field, key);
        
        let serialized = serde_json::to_string(&value)
            .map_err(|e| {
                error!("Failed to serialize value for hash field '{}' in key '{}': {}", field, key, e);
                RedisError::SerializationError(e.to_string())
            })?;

        let mut conn = self.get_connection().await?;
        let _: () = conn.hset(key, field, serialized).await
            .map_err(|e| {
                error!("Failed to hset field '{}' in key '{}': {}", field, key, e);
                RedisError::OperationError(format!("Hset operation failed: {}", e))
            })?;

        debug!("Successfully set hash field '{}' in key '{}'", field, key);
        Ok(())
    }

    /// Get a field from a hash
    #[instrument(skip(self), fields(key = %key, field = %field))]
    pub async fn hget<T>(&self, key: &str, field: &str) -> Result<Option<T>, RedisError>
    where
        T: for<'de> Deserialize<'de>,
    {
        debug!("Getting hash field '{}' from key '{}'", field, key);
        
        let mut conn = self.get_connection().await?;
        let value: redis::RedisResult<String> = conn.hget(key, field).await;

        match value {
            Ok(data) => {
                let deserialized = serde_json::from_str(&data)
                    .map_err(|e| {
                        error!("Failed to deserialize hash field '{}' from key '{}': {}", field, key, e);
                        RedisError::SerializationError(e.to_string())
                    })?;
                debug!("Successfully retrieved hash field '{}' from key '{}'", field, key);
                Ok(Some(deserialized))
            }
            Err(e) => {
                if e.kind() == ErrorKind::TypeError {
                    debug!("Hash field '{}' not found in key '{}'", field, key);
                    Ok(None)
                } else {
                    error!("Failed to hget field '{}' from key '{}': {}", field, key, e);
                    Err(RedisError::OperationError(format!("Hget operation failed: {}", e)))
                }
            }
        }
    }

    /// Delete a field from a hash
    #[instrument(skip(self), fields(key = %key, field = %field))]
    pub async fn hdel(&self, key: &str, field: &str) -> Result<bool, RedisError> {
        debug!("Deleting hash field '{}' from key '{}'", field, key);
        
        let mut conn = self.get_connection().await?;
        let deleted: u64 = conn.hdel(key, field).await
            .map_err(|e| {
                error!("Failed to hdel field '{}' from key '{}': {}", field, key, e);
                RedisError::OperationError(format!("Hdel operation failed: {}", e))
            })?;

        let was_deleted = deleted > 0;
        if was_deleted {
            debug!("Successfully deleted hash field '{}' from key '{}'", field, key);
        } else {
            debug!("Hash field '{}' was not found in key '{}'", field, key);
        }
        Ok(was_deleted)
    }

    /// Get all fields and values from a hash
    #[instrument(skip(self), fields(key = %key))]
    pub async fn hgetall(&self, key: &str) -> Result<HashMap<String, String>, RedisError> {
        debug!("Getting all hash fields from key '{}'", key);
        
        let mut conn = self.get_connection().await?;
        let hash: HashMap<String, String> = conn.hgetall(key).await
            .map_err(|e| {
                error!("Failed to hgetall from key '{}': {}", key, e);
                RedisError::OperationError(format!("Hgetall operation failed: {}", e))
            })?;

        debug!("Successfully retrieved {} hash fields from key '{}'", hash.len(), key);
        Ok(hash)
    }

    // ==================== LIST OPERATIONS ====================

    /// Push value to the left of a list
    #[instrument(skip(self, value), fields(key = %key))]
    pub async fn lpush<T>(&self, key: &str, value: T) -> Result<u64, RedisError>
    where
        T: Serialize,
    {
        debug!("Left-pushing value to list '{}'", key);
        
        let serialized = serde_json::to_string(&value)
            .map_err(|e| {
                error!("Failed to serialize value for list '{}': {}", key, e);
                RedisError::SerializationError(e.to_string())
            })?;

        let mut conn = self.get_connection().await?;
        let length: u64 = conn.lpush(key, serialized).await
            .map_err(|e| {
                error!("Failed to lpush to list '{}': {}", key, e);
                RedisError::OperationError(format!("Lpush operation failed: {}", e))
            })?;

        debug!("Successfully pushed to list '{}', new length: {}", key, length);
        Ok(length)
    }

    /// Push value to the right of a list
    #[instrument(skip(self, value), fields(key = %key))]
    pub async fn rpush<T>(&self, key: &str, value: T) -> Result<u64, RedisError>
    where
        T: Serialize,
    {
        debug!("Right-pushing value to list '{}'", key);
        
        let serialized = serde_json::to_string(&value)
            .map_err(|e| {
                error!("Failed to serialize value for list '{}': {}", key, e);
                RedisError::SerializationError(e.to_string())
            })?;

        let mut conn = self.get_connection().await?;
        let length: u64 = conn.rpush(key, serialized).await
            .map_err(|e| {
                error!("Failed to rpush to list '{}': {}", key, e);
                RedisError::OperationError(format!("Rpush operation failed: {}", e))
            })?;

        debug!("Successfully pushed to list '{}', new length: {}", key, length);
        Ok(length)
    }

    /// Pop value from the left of a list
    #[instrument(skip(self), fields(key = %key))]
    pub async fn lpop<T>(&self, key: &str) -> Result<Option<T>, RedisError>
    where
        T: for<'de> Deserialize<'de>,
    {
        debug!("Left-popping value from list '{}'", key);
        
        let mut conn = self.get_connection().await?;
        let value: redis::RedisResult<String> = conn.lpop(key, None).await;

        match value {
            Ok(data) => {
                let deserialized = serde_json::from_str(&data)
                    .map_err(|e| {
                        error!("Failed to deserialize popped value from list '{}': {}", key, e);
                        RedisError::SerializationError(e.to_string())
                    })?;
                debug!("Successfully popped value from list '{}'", key);
                Ok(Some(deserialized))
            }
            Err(e) => {
                if e.kind() == ErrorKind::TypeError {
                    debug!("List '{}' is empty", key);
                    Ok(None)
                } else {
                    error!("Failed to lpop from list '{}': {}", key, e);
                    Err(RedisError::OperationError(format!("Lpop operation failed: {}", e)))
                }
            }
        }
    }

    /// Get length of a list
    #[instrument(skip(self), fields(key = %key))]
    pub async fn llen(&self, key: &str) -> Result<u64, RedisError> {
        debug!("Getting length of list '{}'", key);
        
        let mut conn = self.get_connection().await?;
        let length: u64 = conn.llen(key).await
            .map_err(|e| {
                error!("Failed to get length of list '{}': {}", key, e);
                RedisError::OperationError(format!("Llen operation failed: {}", e))
            })?;

        debug!("Length of list '{}': {}", key, length);
        Ok(length)
    }

    // ==================== SET OPERATIONS ====================

    /// Add member to a set
    #[instrument(skip(self, member), fields(key = %key))]
    pub async fn sadd<T>(&self, key: &str, member: T) -> Result<bool, RedisError>
    where
        T: Serialize,
    {
        debug!("Adding member to set '{}'", key);
        
        let serialized = serde_json::to_string(&member)
            .map_err(|e| {
                error!("Failed to serialize member for set '{}': {}", key, e);
                RedisError::SerializationError(e.to_string())
            })?;

        let mut conn = self.get_connection().await?;
        let added: u64 = conn.sadd(key, serialized).await
            .map_err(|e| {
                error!("Failed to sadd to set '{}': {}", key, e);
                RedisError::OperationError(format!("Sadd operation failed: {}", e))
            })?;

        let was_added = added > 0;
        if was_added {
            debug!("Successfully added member to set '{}'", key);
        } else {
            debug!("Member already exists in set '{}'", key);
        }
        Ok(was_added)
    }

    /// Check if member exists in a set
    #[instrument(skip(self, member), fields(key = %key))]
    pub async fn sismember<T>(&self, key: &str, member: T) -> Result<bool, RedisError>
    where
        T: Serialize,
    {
        debug!("Checking if member exists in set '{}'", key);
        
        let serialized = serde_json::to_string(&member)
            .map_err(|e| {
                error!("Failed to serialize member for set '{}': {}", key, e);
                RedisError::SerializationError(e.to_string())
            })?;

        let mut conn = self.get_connection().await?;
        let is_member: bool = conn.sismember(key, serialized).await
            .map_err(|e| {
                error!("Failed to check member in set '{}': {}", key, e);
                RedisError::OperationError(format!("Sismember operation failed: {}", e))
            })?;

        debug!("Member exists in set '{}': {}", key, is_member);
        Ok(is_member)
    }

    // ==================== UTILITY OPERATIONS ====================

    /// Get the configuration used by this service
    pub fn get_config(&self) -> &RedisConfig {
        &self.config
    }

    /// Increment a numeric value
    #[instrument(skip(self), fields(key = %key, increment = increment))]
    pub async fn incr(&self, key: &str, increment: i64) -> Result<i64, RedisError> {
        debug!("Incrementing key '{}' by {}", key, increment);
        
        let mut conn = self.get_connection().await?;
        let result: i64 = conn.incr(key, increment).await
            .map_err(|e| {
                error!("Failed to increment key '{}': {}", key, e);
                RedisError::OperationError(format!("Increment operation failed: {}", e))
            })?;

        debug!("Successfully incremented key '{}' to {}", key, result);
        Ok(result)
    }
}

// Implement the trait for RedisService
#[async_trait]
impl RedisServiceTrait for RedisService {
    async fn set_string(&self, key: &str, value: &str) -> Result<(), RedisError> {
        self.setex(key, value, 3600).await // Default 1 hour expiry for strings
    }

    async fn get_string(&self, key: &str) -> Result<Option<String>, RedisError> {
        self.get::<String>(key).await
    }

    async fn set_string_with_expiry(&self, key: &str, value: &str, expiry_secs: u64) -> Result<(), RedisError> {
        let serialized = value.to_string();
        self.setex(key, serialized, expiry_secs).await
    }

    async fn delete(&self, key: &str) -> Result<bool, RedisError> {
        self.delete(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool, RedisError> {
        self.exists(key).await
    }

    async fn set_hash(&self, key: &str, data: &HashMap<String, String>) -> Result<(), RedisError> {
        let mut conn = self.get_connection().await?;
        for (field, value) in data {
            let _: () = conn.hset(key, field, value).await
                .map_err(|e| RedisError::OperationError(format!("Hash set operation failed: {}", e)))?;
        }
        Ok(())
    }

    async fn get_hash(&self, key: &str) -> Result<HashMap<String, String>, RedisError> {
        self.hgetall(key).await
    }

    async fn increment(&self, key: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        let result: i64 = conn.incr(key, 1).await
            .map_err(|e| RedisError::OperationError(format!("Increment operation failed: {}", e)))?;
        Ok(result)
    }

    async fn get_ttl(&self, key: &str) -> Result<i64, RedisError> {
        self.ttl(key).await
    }

    async fn ping(&self) -> Result<String, RedisError> {
        self.ping().await?;
        Ok("PONG".to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RedisError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Operation error: {0}")]
    OperationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key not found")]
    KeyNotFound,

    #[error("Timeout error: {0}")]
    TimeoutError(String),
}
