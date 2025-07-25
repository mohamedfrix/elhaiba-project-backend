# Redis Utility Documentation

## Overview

The Redis utility provides a comprehensive async Redis client wrapper for the ElHaiba backend application. It implements connection pooling, error handling, and a wide range of Redis operations including strings, hashes, lists, sets, sorted sets, and advanced operations. The utility is designed for high-performance, scalable applications with extensive logging and monitoring capabilities.

## Purpose and Philosophy

### Design Philosophy

The Redis utility is built around these core principles:

1. **Async-First Design**: All operations are asynchronous for maximum performance
2. **Connection Pooling**: Efficient connection management with automatic failover
3. **Type Safety**: Strong typing with Rust's type system and serde integration
4. **Error Resilience**: Comprehensive error handling with retry mechanisms
5. **Observability**: Extensive logging and metrics for monitoring
6. **Scalability**: Designed to handle high-throughput distributed systems
7. **Developer Experience**: Clean, intuitive API with helpful error messages

### Use Cases

- **Caching Layer**: High-performance caching for frequently accessed data
- **Session Storage**: User session management with automatic expiration
- **Rate Limiting**: Token bucket and sliding window rate limiting implementations
- **Job Queues**: Distributed task queues with Redis lists and streams
- **Real-time Features**: Pub/Sub messaging for real-time notifications
- **Data Structures**: Complex data operations using Redis native types
- **Distributed Locks**: Coordination between distributed services
- **Analytics**: Real-time counters and aggregation

## Architecture

### Core Components

#### 1. RedisService
The main service implementing Redis operations:

```rust
pub struct RedisService {
    connection_manager: ConnectionManager,
    config: RedisConfig,
}
```

#### 2. RedisServiceTrait
Comprehensive trait defining all Redis operations:

```rust
#[async_trait]
pub trait RedisServiceTrait {
    // String operations
    async fn set(&self, key: &str, value: &str) -> Result<(), RedisError>;
    async fn get(&self, key: &str) -> Result<Option<String>, RedisError>;
    async fn setex(&self, key: &str, seconds: u64, value: &str) -> Result<(), RedisError>;
    
    // Hash operations
    async fn hset(&self, key: &str, field: &str, value: &str) -> Result<(), RedisError>;
    async fn hget(&self, key: &str, field: &str) -> Result<Option<String>, RedisError>;
    async fn hgetall(&self, key: &str) -> Result<HashMap<String, String>, RedisError>;
    
    // List operations
    async fn lpush(&self, key: &str, value: &str) -> Result<i64, RedisError>;
    async fn rpush(&self, key: &str, value: &str) -> Result<i64, RedisError>;
    async fn lpop(&self, key: &str) -> Result<Option<String>, RedisError>;
    async fn rpop(&self, key: &str) -> Result<Option<String>, RedisError>;
    
    // Set operations
    async fn sadd(&self, key: &str, member: &str) -> Result<i64, RedisError>;
    async fn srem(&self, key: &str, member: &str) -> Result<i64, RedisError>;
    async fn smembers(&self, key: &str) -> Result<Vec<String>, RedisError>;
    
    // Advanced operations
    async fn incr(&self, key: &str, delta: i64) -> Result<i64, RedisError>;
    async fn expire(&self, key: &str, seconds: u64) -> Result<bool, RedisError>;
    async fn del(&self, key: &str) -> Result<i64, RedisError>;
    async fn exists(&self, key: &str) -> Result<bool, RedisError>;
    
    // Serialization helpers
    async fn set_json<T>(&self, key: &str, value: &T) -> Result<(), RedisError>
    where
        T: Serialize + Send + Sync;
    async fn get_json<T>(&self, key: &str) -> Result<Option<T>, RedisError>
    where
        T: DeserializeOwned + Send + Sync;
}
```

#### 3. RedisConfig
Configuration structure for Redis connection and behavior:

```rust
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub database: u8,
    pub max_connections: u32,
    pub connection_timeout: Duration,
    pub command_timeout: Duration,
    pub retry_attempts: usize,
    pub retry_delay: Duration,
}
```

#### 4. RedisError
Comprehensive error handling:

```rust
#[derive(Debug, Clone)]
pub enum RedisError {
    ConnectionFailed(String),
    OperationFailed(String),
    SerializationError(String),
    DeserializationError(String),
    TimeoutError,
    KeyNotFound,
    InvalidType(String),
}
```

## Implementation Details

### Connection Management

The Redis service uses connection pooling for optimal performance:

```rust
impl RedisService {
    pub async fn new(config: &RedisConfig) -> Result<Self, RedisError> {
        let redis_url = if let Some(password) = &config.password {
            format!("redis://:{}@{}:{}/{}", 
                password, config.host, config.port, config.database)
        } else {
            format!("redis://{}:{}/{}", 
                config.host, config.port, config.database)
        };
        
        let client = redis::Client::open(redis_url)
            .map_err(|e| RedisError::ConnectionFailed(e.to_string()))?;
        
        let connection_manager = ConnectionManager::new(client).await
            .map_err(|e| RedisError::ConnectionFailed(e.to_string()))?;
        
        tracing::info!(
            host = %config.host,
            port = config.port,
            database = config.database,
            "Redis connection established"
        );
        
        Ok(RedisService {
            connection_manager,
            config: config.clone(),
        })
    }
    
    async fn get_connection(&self) -> Result<ConnectionManager, RedisError> {
        // Connection manager handles pooling automatically
        Ok(self.connection_manager.clone())
    }
}
```

### String Operations Implementation

Basic string operations with error handling and logging:

```rust
#[async_trait]
impl RedisServiceTrait for RedisService {
    async fn set(&self, key: &str, value: &str) -> Result<(), RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(()) => {
                tracing::debug!(
                    key = %key,
                    value_length = value.len(),
                    "Set string value"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to set string value"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn get(&self, key: &str) -> Result<Option<String>, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<Option<String>, redis::RedisError> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(value) => {
                tracing::debug!(
                    key = %key,
                    found = value.is_some(),
                    "Retrieved string value"
                );
                Ok(value)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to get string value"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn setex(&self, key: &str, seconds: u64, value: &str) -> Result<(), RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<(), redis::RedisError> = redis::cmd("SETEX")
            .arg(key)
            .arg(seconds)
            .arg(value)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(()) => {
                tracing::debug!(
                    key = %key,
                    ttl_seconds = seconds,
                    value_length = value.len(),
                    "Set string value with expiration"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    ttl_seconds = seconds,
                    error = %e,
                    "Failed to set string value with expiration"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
}
```

### Hash Operations Implementation

Hash operations for complex data structures:

```rust
impl RedisServiceTrait for RedisService {
    async fn hset(&self, key: &str, field: &str, value: &str) -> Result<(), RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("HSET")
            .arg(key)
            .arg(field)
            .arg(value)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(_) => {
                tracing::debug!(
                    key = %key,
                    field = %field,
                    value_length = value.len(),
                    "Set hash field"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    field = %field,
                    error = %e,
                    "Failed to set hash field"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn hget(&self, key: &str, field: &str) -> Result<Option<String>, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<Option<String>, redis::RedisError> = redis::cmd("HGET")
            .arg(key)
            .arg(field)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(value) => {
                tracing::debug!(
                    key = %key,
                    field = %field,
                    found = value.is_some(),
                    "Retrieved hash field"
                );
                Ok(value)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    field = %field,
                    error = %e,
                    "Failed to get hash field"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn hgetall(&self, key: &str) -> Result<HashMap<String, String>, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<HashMap<String, String>, redis::RedisError> = redis::cmd("HGETALL")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(hash_map) => {
                tracing::debug!(
                    key = %key,
                    field_count = hash_map.len(),
                    "Retrieved all hash fields"
                );
                Ok(hash_map)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to get all hash fields"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn hdel(&self, key: &str, field: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("HDEL")
            .arg(key)
            .arg(field)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(count) => {
                tracing::debug!(
                    key = %key,
                    field = %field,
                    deleted_count = count,
                    "Deleted hash field"
                );
                Ok(count)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    field = %field,
                    error = %e,
                    "Failed to delete hash field"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
}

### List Operations Implementation

List operations for queues and stacks:

```rust
impl RedisServiceTrait for RedisService {
    async fn lpush(&self, key: &str, value: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("LPUSH")
            .arg(key)
            .arg(value)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(length) => {
                tracing::debug!(
                    key = %key,
                    new_length = length,
                    "Pushed to list head"
                );
                Ok(length)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to push to list head"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn rpush(&self, key: &str, value: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("RPUSH")
            .arg(key)
            .arg(value)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(length) => {
                tracing::debug!(
                    key = %key,
                    new_length = length,
                    "Pushed to list tail"
                );
                Ok(length)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to push to list tail"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn lpop(&self, key: &str) -> Result<Option<String>, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<Option<String>, redis::RedisError> = redis::cmd("LPOP")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(value) => {
                tracing::debug!(
                    key = %key,
                    found = value.is_some(),
                    "Popped from list head"
                );
                Ok(value)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to pop from list head"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn rpop(&self, key: &str) -> Result<Option<String>, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<Option<String>, redis::RedisError> = redis::cmd("RPOP")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(value) => {
                tracing::debug!(
                    key = %key,
                    found = value.is_some(),
                    "Popped from list tail"
                );
                Ok(value)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to pop from list tail"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn lrange(&self, key: &str, start: i64, stop: i64) -> Result<Vec<String>, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<Vec<String>, redis::RedisError> = redis::cmd("LRANGE")
            .arg(key)
            .arg(start)
            .arg(stop)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(values) => {
                tracing::debug!(
                    key = %key,
                    start = start,
                    stop = stop,
                    count = values.len(),
                    "Retrieved list range"
                );
                Ok(values)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    start = start,
                    stop = stop,
                    error = %e,
                    "Failed to get list range"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
}

### Set Operations Implementation

Set operations for unique collections:

```rust
impl RedisServiceTrait for RedisService {
    async fn sadd(&self, key: &str, member: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("SADD")
            .arg(key)
            .arg(member)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(added_count) => {
                tracing::debug!(
                    key = %key,
                    member = %member,
                    added = added_count > 0,
                    "Added member to set"
                );
                Ok(added_count)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    member = %member,
                    error = %e,
                    "Failed to add member to set"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn srem(&self, key: &str, member: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("SREM")
            .arg(key)
            .arg(member)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(removed_count) => {
                tracing::debug!(
                    key = %key,
                    member = %member,
                    removed = removed_count > 0,
                    "Removed member from set"
                );
                Ok(removed_count)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    member = %member,
                    error = %e,
                    "Failed to remove member from set"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn smembers(&self, key: &str) -> Result<Vec<String>, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<Vec<String>, redis::RedisError> = redis::cmd("SMEMBERS")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(members) => {
                tracing::debug!(
                    key = %key,
                    member_count = members.len(),
                    "Retrieved all set members"
                );
                Ok(members)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to get set members"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn sismember(&self, key: &str, member: &str) -> Result<bool, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("SISMEMBER")
            .arg(key)
            .arg(member)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(is_member) => {
                let exists = is_member == 1;
                tracing::debug!(
                    key = %key,
                    member = %member,
                    exists = exists,
                    "Checked set membership"
                );
                Ok(exists)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    member = %member,
                    error = %e,
                    "Failed to check set membership"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
}

### Advanced Operations Implementation

Advanced Redis operations including atomic operations and utilities:

```rust
impl RedisServiceTrait for RedisService {
    async fn incr(&self, key: &str, delta: i64) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = if delta == 1 {
            redis::cmd("INCR").arg(key).query_async(&mut conn).await
        } else {
            redis::cmd("INCRBY").arg(key).arg(delta).query_async(&mut conn).await
        };
        
        match result {
            Ok(new_value) => {
                tracing::debug!(
                    key = %key,
                    delta = delta,
                    new_value = new_value,
                    "Incremented counter"
                );
                Ok(new_value)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    delta = delta,
                    error = %e,
                    "Failed to increment counter"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn expire(&self, key: &str, seconds: u64) -> Result<bool, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("EXPIRE")
            .arg(key)
            .arg(seconds)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(set_result) => {
                let was_set = set_result == 1;
                tracing::debug!(
                    key = %key,
                    ttl_seconds = seconds,
                    was_set = was_set,
                    "Set key expiration"
                );
                Ok(was_set)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    ttl_seconds = seconds,
                    error = %e,
                    "Failed to set key expiration"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn del(&self, key: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(deleted_count) => {
                tracing::debug!(
                    key = %key,
                    deleted = deleted_count > 0,
                    "Deleted key"
                );
                Ok(deleted_count)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to delete key"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn exists(&self, key: &str) -> Result<bool, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(exists_result) => {
                let exists = exists_result > 0;
                tracing::debug!(
                    key = %key,
                    exists = exists,
                    "Checked key existence"
                );
                Ok(exists)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to check key existence"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
    
    async fn ttl(&self, key: &str) -> Result<i64, RedisError> {
        let mut conn = self.get_connection().await?;
        
        let result: Result<i64, redis::RedisError> = redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await;
        
        match result {
            Ok(ttl_seconds) => {
                tracing::debug!(
                    key = %key,
                    ttl_seconds = ttl_seconds,
                    "Retrieved key TTL"
                );
                Ok(ttl_seconds)
            }
            Err(e) => {
                tracing::error!(
                    key = %key,
                    error = %e,
                    "Failed to get key TTL"
                );
                Err(RedisError::OperationFailed(e.to_string()))
            }
        }
    }
}

### Serialization Helpers Implementation

JSON serialization and deserialization support:

```rust
impl RedisServiceTrait for RedisService {
    async fn set_json<T>(&self, key: &str, value: &T) -> Result<(), RedisError>
    where
        T: Serialize + Send + Sync,
    {
        let serialized = serde_json::to_string(value)
            .map_err(|e| RedisError::SerializationError(e.to_string()))?;
        
        self.set(key, &serialized).await
    }
    
    async fn get_json<T>(&self, key: &str) -> Result<Option<T>, RedisError>
    where
        T: DeserializeOwned + Send + Sync,
    {
        match self.get(key).await? {
            Some(serialized) => {
                let value = serde_json::from_str(&serialized)
                    .map_err(|e| RedisError::DeserializationError(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
    
    async fn setex_json<T>(&self, key: &str, seconds: u64, value: &T) -> Result<(), RedisError>
    where
        T: Serialize + Send + Sync,
    {
        let serialized = serde_json::to_string(value)
            .map_err(|e| RedisError::SerializationError(e.to_string()))?;
        
        self.setex(key, seconds, &serialized).await
    }
    
    async fn hset_json<T>(&self, key: &str, field: &str, value: &T) -> Result<(), RedisError>
    where
        T: Serialize + Send + Sync,
    {
        let serialized = serde_json::to_string(value)
            .map_err(|e| RedisError::SerializationError(e.to_string()))?;
        
        self.hset(key, field, &serialized).await
    }
    
    async fn hget_json<T>(&self, key: &str, field: &str) -> Result<Option<T>, RedisError>
    where
        T: DeserializeOwned + Send + Sync,
    {
        match self.hget(key, field).await? {
            Some(serialized) => {
                let value = serde_json::from_str(&serialized)
                    .map_err(|e| RedisError::DeserializationError(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

## API Reference

### Primary Methods

#### String Operations

##### `set(key: &str, value: &str) -> Result<(), RedisError>`
Sets a string value for the given key.

**Parameters:**
- `key`: The Redis key
- `value`: The string value to store

**Returns:**
- `Ok(())`: Value successfully set
- `Err(RedisError)`: Operation failed

**Example:**
```rust
redis_service.set("user:123:name", "John Doe").await?;
```

##### `get(key: &str) -> Result<Option<String>, RedisError>`
Retrieves a string value for the given key.

**Parameters:**
- `key`: The Redis key

**Returns:**
- `Ok(Some(String))`: Value found and returned
- `Ok(None)`: Key not found
- `Err(RedisError)`: Operation failed

**Example:**
```rust
if let Some(name) = redis_service.get("user:123:name").await? {
    println!("User name: {}", name);
}
```

##### `setex(key: &str, seconds: u64, value: &str) -> Result<(), RedisError>`
Sets a string value with an expiration time.

**Parameters:**
- `key`: The Redis key
- `seconds`: TTL in seconds
- `value`: The string value to store

**Returns:**
- `Ok(())`: Value successfully set with expiration
- `Err(RedisError)`: Operation failed

**Example:**
```rust
// Cache for 1 hour
redis_service.setex("session:abc123", 3600, &session_data).await?;
```

#### Hash Operations

##### `hset(key: &str, field: &str, value: &str) -> Result<(), RedisError>`
Sets a field in a hash.

**Parameters:**
- `key`: The Redis hash key
- `field`: The field name within the hash
- `value`: The string value to store

**Example:**
```rust
redis_service.hset("user:123", "email", "john@example.com").await?;
redis_service.hset("user:123", "age", "30").await?;
```

##### `hget(key: &str, field: &str) -> Result<Option<String>, RedisError>`
Gets a field value from a hash.

**Example:**
```rust
if let Some(email) = redis_service.hget("user:123", "email").await? {
    println!("User email: {}", email);
}
```

##### `hgetall(key: &str) -> Result<HashMap<String, String>, RedisError>`
Gets all fields and values from a hash.

**Example:**
```rust
let user_data = redis_service.hgetall("user:123").await?;
for (field, value) in user_data {
    println!("{}: {}", field, value);
}
```

#### List Operations

##### `lpush(key: &str, value: &str) -> Result<i64, RedisError>`
Pushes a value to the head of a list.

**Returns:**
- `Ok(i64)`: New length of the list
- `Err(RedisError)`: Operation failed

**Example:**
```rust
let new_length = redis_service.lpush("tasks", "urgent_task").await?;
println!("Task queue now has {} items", new_length);
```

##### `rpush(key: &str, value: &str) -> Result<i64, RedisError>`
Pushes a value to the tail of a list.

**Example:**
```rust
redis_service.rpush("logs", "User logged in").await?;
```

##### `lpop(key: &str) -> Result<Option<String>, RedisError>`
Pops a value from the head of a list.

**Example:**
```rust
if let Some(task) = redis_service.lpop("tasks").await? {
    process_task(&task).await;
}
```

#### Set Operations

##### `sadd(key: &str, member: &str) -> Result<i64, RedisError>`
Adds a member to a set.

**Returns:**
- `Ok(1)`: Member was added (new)
- `Ok(0)`: Member already existed
- `Err(RedisError)`: Operation failed

**Example:**
```rust
redis_service.sadd("user:123:permissions", "read").await?;
redis_service.sadd("user:123:permissions", "write").await?;
```

##### `smembers(key: &str) -> Result<Vec<String>, RedisError>`
Gets all members of a set.

**Example:**
```rust
let permissions = redis_service.smembers("user:123:permissions").await?;
```

#### Advanced Operations

##### `incr(key: &str, delta: i64) -> Result<i64, RedisError>`
Increments a counter atomically.

**Example:**
```rust
let view_count = redis_service.incr("page:home:views", 1).await?;
let score = redis_service.incr("user:123:score", 10).await?;
```

##### `expire(key: &str, seconds: u64) -> Result<bool, RedisError>`
Sets expiration time for a key.

**Example:**
```rust
redis_service.expire("temp_data", 300).await?; // 5 minutes
```

#### JSON Serialization Operations

##### `set_json<T>(key: &str, value: &T) -> Result<(), RedisError>`
Stores a serializable object as JSON.

**Example:**
```rust
#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    email: String,
}

let user = User {
    id: "123".to_string(),
    name: "John Doe".to_string(),
    email: "john@example.com".to_string(),
};

redis_service.set_json("user:123", &user).await?;
```

##### `get_json<T>(key: &str) -> Result<Option<T>, RedisError>`
Retrieves and deserializes a JSON object.

**Example:**
```rust
if let Some(user) = redis_service.get_json::<User>("user:123").await? {
    println!("Retrieved user: {} ({})", user.name, user.email);
}
```

## Configuration

### RedisConfig Structure

```rust
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub host: String,                    // Default: "localhost"
    pub port: u16,                       // Default: 6379
    pub password: Option<String>,        // Default: None
    pub database: u8,                    // Default: 0
    pub max_connections: u32,            // Default: 10
    pub connection_timeout: Duration,    // Default: 5 seconds
    pub command_timeout: Duration,       // Default: 2 seconds
    pub retry_attempts: usize,           // Default: 3
    pub retry_delay: Duration,           // Default: 100ms
    pub enable_logging: bool,            // Default: true
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 6379,
            password: None,
            database: 0,
            max_connections: 10,
            connection_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(2),
            retry_attempts: 3,
            retry_delay: Duration::from_millis(100),
            enable_logging: true,
        }
    }
}
```

### Environment Configuration

```rust
impl RedisConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            host: env::var("REDIS_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port: env::var("REDIS_PORT")
                .unwrap_or_else(|_| "6379".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidPort)?,
            password: env::var("REDIS_PASSWORD").ok(),
            database: env::var("REDIS_DATABASE")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidDatabase)?,
            max_connections: env::var("REDIS_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            connection_timeout: Duration::from_secs(
                env::var("REDIS_CONNECTION_TIMEOUT")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or(5)
            ),
            command_timeout: Duration::from_secs(
                env::var("REDIS_COMMAND_TIMEOUT")
                    .unwrap_or_else(|_| "2".to_string())
                    .parse()
                    .unwrap_or(2)
            ),
            retry_attempts: env::var("REDIS_RETRY_ATTEMPTS")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .unwrap_or(3),
            retry_delay: Duration::from_millis(
                env::var("REDIS_RETRY_DELAY_MS")
                    .unwrap_or_else(|_| "100".to_string())
                    .parse()
                    .unwrap_or(100)
            ),
            enable_logging: env::var("REDIS_ENABLE_LOGGING")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        })
    }
}

## Usage Examples

### Caching Layer Implementation

```rust
use elhaiba_backend::util::redis::{RedisService, RedisServiceTrait};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub name: String,
    pub email: String,
    pub last_login: Option<DateTime<Utc>>,
    pub preferences: HashMap<String, String>,
}

pub struct UserCacheService {
    redis: Arc<RedisService>,
    database: Arc<Database>,
}

impl UserCacheService {
    pub async fn get_user_profile(&self, user_id: &str) -> Result<Option<UserProfile>, ServiceError> {
        let cache_key = format!("user_profile:{}", user_id);
        
        // Try cache first
        if let Some(cached_profile) = self.redis.get_json::<UserProfile>(&cache_key).await? {
            tracing::debug!(
                user_id = %user_id,
                "Retrieved user profile from cache"
            );
            return Ok(Some(cached_profile));
        }
        
        // Cache miss - fetch from database
        if let Some(profile) = self.database.get_user_profile(user_id).await? {
            // Cache for 1 hour
            if let Err(e) = self.redis.setex_json(&cache_key, 3600, &profile).await {
                tracing::warn!(
                    user_id = %user_id,
                    error = ?e,
                    "Failed to cache user profile"
                );
            }
            
            tracing::debug!(
                user_id = %user_id,
                "Retrieved user profile from database and cached"
            );
            
            Ok(Some(profile))
        } else {
            Ok(None)
        }
    }
    
    pub async fn update_user_profile(
        &self,
        user_id: &str,
        profile: &UserProfile,
    ) -> Result<(), ServiceError> {
        // Update database
        self.database.update_user_profile(user_id, profile).await?;
        
        // Update cache
        let cache_key = format!("user_profile:{}", user_id);
        if let Err(e) = self.redis.setex_json(&cache_key, 3600, profile).await {
            tracing::warn!(
                user_id = %user_id,
                error = ?e,
                "Failed to update cached user profile"
            );
        }
        
        Ok(())
    }
    
    pub async fn invalidate_user_cache(&self, user_id: &str) -> Result<(), ServiceError> {
        let cache_key = format!("user_profile:{}", user_id);
        self.redis.del(&cache_key).await?;
        
        tracing::debug!(
            user_id = %user_id,
            "Invalidated user profile cache"
        );
        
        Ok(())
    }
}
```

### Session Management

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: String,
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub data: HashMap<String, serde_json::Value>,
}

pub struct SessionService {
    redis: Arc<RedisService>,
    config: SessionConfig,
}

impl SessionService {
    pub async fn create_session(
        &self,
        user_id: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<UserSession, SessionError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let session = UserSession {
            user_id: user_id.to_string(),
            session_id: session_id.clone(),
            created_at: now,
            last_accessed: now,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            data: HashMap::new(),
        };
        
        // Store session with expiration
        let session_key = format!("session:{}", session_id);
        self.redis
            .setex_json(&session_key, self.config.session_ttl_seconds, &session)
            .await
            .map_err(SessionError::RedisError)?;
        
        // Add to user's active sessions
        let user_sessions_key = format!("user_sessions:{}", user_id);
        self.redis
            .sadd(&user_sessions_key, &session_id)
            .await
            .map_err(SessionError::RedisError)?;
        
        // Set expiration on user sessions set
        self.redis
            .expire(&user_sessions_key, self.config.session_ttl_seconds)
            .await
            .map_err(SessionError::RedisError)?;
        
        tracing::info!(
            user_id = %user_id,
            session_id = %session_id,
            ip_address = %ip_address,
            "Created new user session"
        );
        
        Ok(session)
    }
    
    pub async fn get_session(&self, session_id: &str) -> Result<Option<UserSession>, SessionError> {
        let session_key = format!("session:{}", session_id);
        
        match self.redis.get_json::<UserSession>(&session_key).await {
            Ok(Some(mut session)) => {
                // Update last accessed time
                session.last_accessed = Utc::now();
                
                // Refresh expiration
                if let Err(e) = self.redis
                    .setex_json(&session_key, self.config.session_ttl_seconds, &session)
                    .await
                {
                    tracing::warn!(
                        session_id = %session_id,
                        error = ?e,
                        "Failed to refresh session expiration"
                    );
                }
                
                Ok(Some(session))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SessionError::RedisError(e)),
        }
    }
    
    pub async fn delete_session(&self, session_id: &str) -> Result<(), SessionError> {
        // Get session to find user_id
        let session_key = format!("session:{}", session_id);
        if let Some(session) = self.redis.get_json::<UserSession>(&session_key).await? {
            // Remove from user's active sessions
            let user_sessions_key = format!("user_sessions:{}", session.user_id);
            self.redis
                .srem(&user_sessions_key, session_id)
                .await
                .map_err(SessionError::RedisError)?;
        }
        
        // Delete the session
        self.redis
            .del(&session_key)
            .await
            .map_err(SessionError::RedisError)?;
        
        tracing::info!(
            session_id = %session_id,
            "Deleted user session"
        );
        
        Ok(())
    }
    
    pub async fn delete_all_user_sessions(&self, user_id: &str) -> Result<(), SessionError> {
        let user_sessions_key = format!("user_sessions:{}", user_id);
        
        // Get all session IDs for the user
        let session_ids = self.redis
            .smembers(&user_sessions_key)
            .await
            .map_err(SessionError::RedisError)?;
        
        // Delete each session
        for session_id in session_ids {
            let session_key = format!("session:{}", session_id);
            if let Err(e) = self.redis.del(&session_key).await {
                tracing::warn!(
                    session_id = %session_id,
                    error = ?e,
                    "Failed to delete individual session"
                );
            }
        }
        
        // Clear user sessions set
        self.redis
            .del(&user_sessions_key)
            .await
            .map_err(SessionError::RedisError)?;
        
        tracing::info!(
            user_id = %user_id,
            "Deleted all user sessions"
        );
        
        Ok(())
    }
}
```

### Rate Limiting Implementation

```rust
pub struct RateLimiter {
    redis: Arc<RedisService>,
}

impl RateLimiter {
    pub async fn check_rate_limit(
        &self,
        identifier: &str,
        limit: u32,
        window_seconds: u64,
    ) -> Result<RateLimitResult, RateLimitError> {
        let key = format!("rate_limit:{}", identifier);
        
        // Increment counter
        let current_count = self.redis.incr(&key, 1).await
            .map_err(RateLimitError::RedisError)?;
        
        // Set expiration on first request
        if current_count == 1 {
            self.redis.expire(&key, window_seconds).await
                .map_err(RateLimitError::RedisError)?;
        }
        
        let remaining = if current_count <= limit as i64 {
            limit as i64 - current_count
        } else {
            0
        };
        
        let ttl = self.redis.ttl(&key).await
            .map_err(RateLimitError::RedisError)?;
        
        let reset_time = if ttl > 0 {
            Some(Utc::now() + Duration::seconds(ttl))
        } else {
            None
        };
        
        let result = RateLimitResult {
            allowed: current_count <= limit as i64,
            limit,
            remaining: remaining.max(0) as u32,
            reset_time,
        };
        
        tracing::debug!(
            identifier = %identifier,
            current_count = current_count,
            limit = limit,
            allowed = result.allowed,
            "Rate limit check"
        );
        
        Ok(result)
    }
    
    pub async fn sliding_window_rate_limit(
        &self,
        identifier: &str,
        limit: u32,
        window_seconds: u64,
    ) -> Result<RateLimitResult, RateLimitError> {
        let now = Utc::now().timestamp();
        let window_start = now - window_seconds as i64;
        
        let key = format!("sliding_rate_limit:{}", identifier);
        
        // Remove old entries
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(&key)
            .arg("-inf")
            .arg(window_start)
            .query_async(&mut self.redis.get_connection().await?)
            .await
            .map_err(|e| RateLimitError::RedisError(RedisError::OperationFailed(e.to_string())))?;
        
        // Count current entries
        let current_count: i64 = redis::cmd("ZCARD")
            .arg(&key)
            .query_async(&mut self.redis.get_connection().await?)
            .await
            .map_err(|e| RateLimitError::RedisError(RedisError::OperationFailed(e.to_string())))?;
        
        if current_count < limit as i64 {
            // Add current request
            let request_id = uuid::Uuid::new_v4().to_string();
            let _: () = redis::cmd("ZADD")
                .arg(&key)
                .arg(now)
                .arg(&request_id)
                .query_async(&mut self.redis.get_connection().await?)
                .await
                .map_err(|e| RateLimitError::RedisError(RedisError::OperationFailed(e.to_string())))?;
            
            // Set expiration
            self.redis.expire(&key, window_seconds).await
                .map_err(RateLimitError::RedisError)?;
        }
        
        let remaining = (limit as i64 - current_count - 1).max(0) as u32;
        
        Ok(RateLimitResult {
            allowed: current_count < limit as i64,
            limit,
            remaining,
            reset_time: Some(Utc::now() + Duration::seconds(window_seconds as i64)),
        })
    }
}

#[derive(Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: Option<DateTime<Utc>>,
}
```

### Job Queue Implementation

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub job_type: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub attempts: u32,
    pub max_attempts: u32,
    pub retry_delay_seconds: u64,
}

pub struct JobQueue {
    redis: Arc<RedisService>,
    queue_name: String,
}

impl JobQueue {
    pub fn new(redis: Arc<RedisService>, queue_name: String) -> Self {
        Self { redis, queue_name }
    }
    
    pub async fn enqueue_job(&self, job: Job) -> Result<(), JobQueueError> {
        let job_key = format!("job:{}", job.id);
        let queue_key = format!("queue:{}", self.queue_name);
        
        // Store job data
        self.redis
            .set_json(&job_key, &job)
            .await
            .map_err(JobQueueError::RedisError)?;
        
        // Add job ID to queue
        self.redis
            .rpush(&queue_key, &job.id)
            .await
            .map_err(JobQueueError::RedisError)?;
        
        tracing::info!(
            job_id = %job.id,
            job_type = %job.job_type,
            queue = %self.queue_name,
            "Enqueued job"
        );
        
        Ok(())
    }
    
    pub async fn dequeue_job(&self) -> Result<Option<Job>, JobQueueError> {
        let queue_key = format!("queue:{}", self.queue_name);
        
        // Pop job ID from queue
        if let Some(job_id) = self.redis.lpop(&queue_key).await.map_err(JobQueueError::RedisError)? {
            let job_key = format!("job:{}", job_id);
            
            // Get job data
            if let Some(job) = self.redis.get_json::<Job>(&job_key).await.map_err(JobQueueError::RedisError)? {
                tracing::debug!(
                    job_id = %job_id,
                    job_type = %job.job_type,
                    queue = %self.queue_name,
                    "Dequeued job"
                );
                
                Ok(Some(job))
            } else {
                tracing::warn!(
                    job_id = %job_id,
                    queue = %self.queue_name,
                    "Job ID found in queue but job data missing"
                );
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    
    pub async fn complete_job(&self, job_id: &str) -> Result<(), JobQueueError> {
        let job_key = format!("job:{}", job_id);
        
        // Remove job data
        self.redis
            .del(&job_key)
            .await
            .map_err(JobQueueError::RedisError)?;
        
        tracing::info!(
            job_id = %job_id,
            queue = %self.queue_name,
            "Completed job"
        );
        
        Ok(())
    }
    
    pub async fn retry_job(&self, mut job: Job) -> Result<(), JobQueueError> {
        job.attempts += 1;
        
        if job.attempts >= job.max_attempts {
            // Move to dead letter queue
            let dlq_key = format!("dlq:{}", self.queue_name);
            self.redis
                .rpush(&dlq_key, &job.id)
                .await
                .map_err(JobQueueError::RedisError)?;
            
            tracing::warn!(
                job_id = %job.id,
                attempts = job.attempts,
                max_attempts = job.max_attempts,
                "Job exceeded max attempts, moved to dead letter queue"
            );
        } else {
            // Schedule retry
            let retry_key = format!("retry:{}:{}", self.queue_name, job.id);
            self.redis
                .setex_json(&retry_key, job.retry_delay_seconds, &job)
                .await
                .map_err(JobQueueError::RedisError)?;
            
            tracing::info!(
                job_id = %job.id,
                attempts = job.attempts,
                retry_delay = job.retry_delay_seconds,
                "Scheduled job retry"
            );
        }
        
        Ok(())
    }
}
```

### Real-time Notifications with Pub/Sub

```rust
use tokio::sync::broadcast;

pub struct NotificationService {
    redis: Arc<RedisService>,
    publisher: broadcast::Sender<Notification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub user_id: String,
    pub notification_type: NotificationType,
    pub title: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    Info,
    Warning,
    Error,
    Success,
    Message,
}

impl NotificationService {
    pub async fn new(redis: Arc<RedisService>) -> Result<Self, NotificationError> {
        let (publisher, _) = broadcast::channel(1000);
        
        Ok(Self {
            redis,
            publisher,
        })
    }
    
    pub async fn send_notification(&self, notification: Notification) -> Result<(), NotificationError> {
        // Store notification for persistence
        let notification_key = format!("notification:{}", notification.id);
        self.redis
            .setex_json(&notification_key, 86400, &notification) // 24 hours
            .await
            .map_err(NotificationError::RedisError)?;
        
        // Add to user's notification list
        let user_notifications_key = format!("user_notifications:{}", notification.user_id);
        self.redis
            .lpush(&user_notifications_key, &notification.id)
            .await
            .map_err(NotificationError::RedisError)?;
        
        // Publish to channel for real-time delivery
        let channel = format!("notifications:{}", notification.user_id);
        let payload = serde_json::to_string(&notification)
            .map_err(NotificationError::SerializationError)?;
        
        // Use Redis pub/sub
        let mut conn = self.redis.get_connection().await
            .map_err(NotificationError::RedisError)?;
        
        let _: () = redis::cmd("PUBLISH")
            .arg(&channel)
            .arg(&payload)
            .query_async(&mut conn)
            .await
            .map_err(|e| NotificationError::RedisError(
                RedisError::OperationFailed(e.to_string())
            ))?;
        
        // Also send to local subscribers
        if let Err(_) = self.publisher.send(notification.clone()) {
            tracing::debug!("No local subscribers for notification");
        }
        
        tracing::info!(
            notification_id = %notification.id,
            user_id = %notification.user_id,
            notification_type = ?notification.notification_type,
            "Sent notification"
        );
        
        Ok(())
    }
    
    pub async fn get_user_notifications(
        &self,
        user_id: &str,
        limit: usize,
    ) -> Result<Vec<Notification>, NotificationError> {
        let user_notifications_key = format!("user_notifications:{}", user_id);
        
        // Get notification IDs
        let notification_ids = self.redis
            .lrange(&user_notifications_key, 0, limit as i64 - 1)
            .await
            .map_err(NotificationError::RedisError)?;
        
        let mut notifications = Vec::new();
        
        for notification_id in notification_ids {
            let notification_key = format!("notification:{}", notification_id);
            if let Some(notification) = self.redis
                .get_json::<Notification>(&notification_key)
                .await
                .map_err(NotificationError::RedisError)?
            {
                notifications.push(notification);
            }
        }
        
        Ok(notifications)
    }
    
    pub fn subscribe_to_notifications(&self) -> broadcast::Receiver<Notification> {
        self.publisher.subscribe()
    }
}

## Error Handling

### Comprehensive Error Recovery

The Redis utility provides detailed error handling with automatic retry mechanisms:

```rust
impl RedisService {
    async fn execute_with_retry<F, T>(&self, operation: F) -> Result<T, RedisError>
    where
        F: Fn() -> Pin<Box<dyn Future<Output = Result<T, redis::RedisError>> + Send>>,
    {
        let mut attempts = 0;
        
        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) if attempts < self.config.retry_attempts => {
                    attempts += 1;
                    
                    tracing::warn!(
                        attempt = attempts,
                        max_attempts = self.config.retry_attempts,
                        error = %e,
                        "Redis operation failed, retrying"
                    );
                    
                    // Exponential backoff
                    let delay = self.config.retry_delay * 2_u32.pow(attempts as u32 - 1);
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    tracing::error!(
                        attempts = attempts + 1,
                        error = %e,
                        "Redis operation failed after all retry attempts"
                    );
                    return Err(RedisError::OperationFailed(e.to_string()));
                }
            }
        }
    }
}

// Error conversion and handling
impl From<redis::RedisError> for RedisError {
    fn from(err: redis::RedisError) -> Self {
        match err.kind() {
            redis::ErrorKind::IoError => RedisError::ConnectionFailed(err.to_string()),
            redis::ErrorKind::ResponseError => RedisError::OperationFailed(err.to_string()),
            redis::ErrorKind::TypeError => RedisError::InvalidType(err.to_string()),
            _ => RedisError::OperationFailed(err.to_string()),
        }
    }
}

// Application-level error handling
pub async fn handle_redis_error(
    error: RedisError,
    operation_context: &str,
) -> ApiResponse {
    match error {
        RedisError::ConnectionFailed(msg) => {
            tracing::error!(
                operation = %operation_context,
                error = %msg,
                "Redis connection failed"
            );
            ApiResponse::service_unavailable("Cache service temporarily unavailable")
        }
        RedisError::TimeoutError => {
            tracing::warn!(
                operation = %operation_context,
                "Redis operation timed out"
            );
            ApiResponse::timeout("Operation timed out")
        }
        RedisError::KeyNotFound => {
            tracing::debug!(
                operation = %operation_context,
                "Redis key not found"
            );
            ApiResponse::not_found("Resource not found")
        }
        RedisError::SerializationError(msg) => {
            tracing::error!(
                operation = %operation_context,
                error = %msg,
                "Failed to serialize data for Redis"
            );
            ApiResponse::internal_error("Data processing error")
        }
        RedisError::DeserializationError(msg) => {
            tracing::error!(
                operation = %operation_context,
                error = %msg,
                "Failed to deserialize data from Redis"
            );
            ApiResponse::internal_error("Data processing error")
        }
        RedisError::OperationFailed(msg) => {
            tracing::error!(
                operation = %operation_context,
                error = %msg,
                "Redis operation failed"
            );
            ApiResponse::internal_error("Service error")
        }
        RedisError::InvalidType(msg) => {
            tracing::error!(
                operation = %operation_context,
                error = %msg,
                "Redis type mismatch"
            );
            ApiResponse::internal_error("Data type error")
        }
    }
}
```

## Testing

### Unit Tests

The Redis utility includes comprehensive unit tests:

#### Basic Operations Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;
    
    async fn setup_test_redis() -> RedisService {
        let config = RedisConfig {
            host: "localhost".to_string(),
            port: 6379,
            database: 15, // Use test database
            ..Default::default()
        };
        
        RedisService::new(&config).await.expect("Failed to connect to test Redis")
    }
    
    #[tokio::test]
    async fn test_string_operations() {
        let redis = setup_test_redis().await;
        let test_key = "test:string:key";
        let test_value = "test_value";
        
        // Test SET
        redis.set(test_key, test_value).await.unwrap();
        
        // Test GET
        let retrieved = redis.get(test_key).await.unwrap();
        assert_eq!(retrieved, Some(test_value.to_string()));
        
        // Test DEL
        let deleted = redis.del(test_key).await.unwrap();
        assert_eq!(deleted, 1);
        
        // Verify deletion
        let after_delete = redis.get(test_key).await.unwrap();
        assert_eq!(after_delete, None);
    }
    
    #[tokio::test]
    async fn test_expiration() {
        let redis = setup_test_redis().await;
        let test_key = "test:expiration:key";
        let test_value = "expires_soon";
        
        // Set with 1 second expiration
        redis.setex(test_key, 1, test_value).await.unwrap();
        
        // Should exist immediately
        let exists = redis.exists(test_key).await.unwrap();
        assert!(exists);
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Should be expired
        let after_expiry = redis.exists(test_key).await.unwrap();
        assert!(!after_expiry);
    }
    
    #[tokio::test]
    async fn test_hash_operations() {
        let redis = setup_test_redis().await;
        let test_key = "test:hash:key";
        
        // Set multiple fields
        redis.hset(test_key, "field1", "value1").await.unwrap();
        redis.hset(test_key, "field2", "value2").await.unwrap();
        
        // Get individual field
        let field1 = redis.hget(test_key, "field1").await.unwrap();
        assert_eq!(field1, Some("value1".to_string()));
        
        // Get all fields
        let all_fields = redis.hgetall(test_key).await.unwrap();
        assert_eq!(all_fields.len(), 2);
        assert_eq!(all_fields.get("field1"), Some(&"value1".to_string()));
        assert_eq!(all_fields.get("field2"), Some(&"value2".to_string()));
        
        // Clean up
        redis.del(test_key).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_list_operations() {
        let redis = setup_test_redis().await;
        let test_key = "test:list:key";
        
        // Push to head and tail
        let len1 = redis.lpush(test_key, "first").await.unwrap();
        assert_eq!(len1, 1);
        
        let len2 = redis.rpush(test_key, "last").await.unwrap();
        assert_eq!(len2, 2);
        
        // Get range
        let items = redis.lrange(test_key, 0, -1).await.unwrap();
        assert_eq!(items, vec!["first", "last"]);
        
        // Pop from head
        let popped = redis.lpop(test_key).await.unwrap();
        assert_eq!(popped, Some("first".to_string()));
        
        // Clean up
        redis.del(test_key).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_set_operations() {
        let redis = setup_test_redis().await;
        let test_key = "test:set:key";
        
        // Add members
        let added1 = redis.sadd(test_key, "member1").await.unwrap();
        assert_eq!(added1, 1); // New member
        
        let added2 = redis.sadd(test_key, "member1").await.unwrap();
        assert_eq!(added2, 0); // Already exists
        
        redis.sadd(test_key, "member2").await.unwrap();
        
        // Check membership
        let is_member = redis.sismember(test_key, "member1").await.unwrap();
        assert!(is_member);
        
        let not_member = redis.sismember(test_key, "member3").await.unwrap();
        assert!(!not_member);
        
        // Get all members
        let members = redis.smembers(test_key).await.unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&"member1".to_string()));
        assert!(members.contains(&"member2".to_string()));
        
        // Clean up
        redis.del(test_key).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_counter_operations() {
        let redis = setup_test_redis().await;
        let test_key = "test:counter:key";
        
        // Increment by 1
        let count1 = redis.incr(test_key, 1).await.unwrap();
        assert_eq!(count1, 1);
        
        // Increment by 5
        let count2 = redis.incr(test_key, 5).await.unwrap();
        assert_eq!(count2, 6);
        
        // Decrement
        let count3 = redis.incr(test_key, -2).await.unwrap();
        assert_eq!(count3, 4);
        
        // Clean up
        redis.del(test_key).await.unwrap();
    }
}

#[tokio::test]
async fn test_json_serialization() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestData {
        name: String,
        age: u32,
        active: bool,
    }
    
    let redis = setup_test_redis().await;
    let test_key = "test:json:key";
    
    let test_data = TestData {
        name: "John Doe".to_string(),
        age: 30,
        active: true,
    };
    
    // Set JSON
    redis.set_json(test_key, &test_data).await.unwrap();
    
    // Get JSON
    let retrieved: Option<TestData> = redis.get_json(test_key).await.unwrap();
    assert_eq!(retrieved, Some(test_data));
    
    // Clean up
    redis.del(test_key).await.unwrap();
}
```

#### Integration Tests
```rust
#[tokio::test]
async fn test_caching_workflow() {
    let redis = setup_test_redis().await;
    
    // Simulate cache miss
    let cache_key = "user:123:profile";
    let profile = redis.get_json::<UserProfile>(&cache_key).await.unwrap();
    assert!(profile.is_none());
    
    // Cache the data
    let user_profile = UserProfile {
        id: "123".to_string(),
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
        last_login: Some(Utc::now()),
        preferences: HashMap::new(),
    };
    
    redis.setex_json(&cache_key, 3600, &user_profile).await.unwrap();
    
    // Cache hit
    let cached_profile = redis.get_json::<UserProfile>(&cache_key).await.unwrap();
    assert!(cached_profile.is_some());
    
    let cached = cached_profile.unwrap();
    assert_eq!(cached.id, user_profile.id);
    assert_eq!(cached.name, user_profile.name);
    assert_eq!(cached.email, user_profile.email);
}

#[tokio::test]
async fn test_concurrent_operations() {
    let redis = Arc::new(setup_test_redis().await);
    let counter_key = "test:concurrent:counter";
    
    // Initialize counter
    redis.set(&counter_key, "0").await.unwrap();
    
    // Spawn multiple tasks incrementing the counter
    let mut handles = Vec::new();
    for _ in 0..10 {
        let redis_clone = redis.clone();
        let key = counter_key.to_string();
        
        let handle = tokio::spawn(async move {
            for _ in 0..10 {
                redis_clone.incr(&key, 1).await.unwrap();
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Check final count
    let final_count: i64 = redis.get(&counter_key).await.unwrap()
        .unwrap()
        .parse()
        .unwrap();
    
    assert_eq!(final_count, 100);
    
    // Clean up
    redis.del(&counter_key).await.unwrap();
}
```

## Performance Considerations

### Connection Pooling Optimization

```rust
// Optimized connection management
impl RedisService {
    pub async fn with_connection_pool(config: &RedisConfig) -> Result<Self, RedisError> {
        let redis_url = format!(
            "redis://{}:{}@{}:{}/{}",
            config.password.as_deref().unwrap_or(""),
            config.host,
            config.port,
            config.database
        );
        
        let client = redis::Client::open(redis_url)?;
        
        // Create connection manager with pooling
        let connection_manager = ConnectionManager::new(client).await?;
        
        Ok(Self {
            connection_manager,
            config: config.clone(),
        })
    }
    
    pub async fn health_check(&self) -> Result<bool, RedisError> {
        let mut conn = self.get_connection().await?;
        let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(pong == "PONG")
    }
}
```

### Batch Operations

```rust
impl RedisService {
    pub async fn batch_set(
        &self,
        operations: Vec<(String, String)>,
    ) -> Result<(), RedisError> {
        let mut pipe = redis::pipe();
        
        for (key, value) in operations {
            pipe.set(&key, &value);
        }
        
        let mut conn = self.get_connection().await?;
        pipe.query_async(&mut conn).await?;
        
        Ok(())
    }
    
    pub async fn batch_get(
        &self,
        keys: Vec<String>,
    ) -> Result<Vec<Option<String>>, RedisError> {
        let mut pipe = redis::pipe();
        
        for key in &keys {
            pipe.get(key);
        }
        
        let mut conn = self.get_connection().await?;
        let results: Vec<Option<String>> = pipe.query_async(&mut conn).await?;
        
        Ok(results)
    }
}
```

### Memory Management

```rust
// Memory-efficient operations
impl RedisService {
    pub async fn scan_keys(
        &self,
        pattern: &str,
        batch_size: usize,
    ) -> Result<Vec<String>, RedisError> {
        let mut cursor = 0;
        let mut all_keys = Vec::new();
        
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(batch_size)
                .query_async(&mut self.get_connection().await?)
                .await?;
            
            all_keys.extend(keys);
            cursor = next_cursor;
            
            if cursor == 0 {
                break;
            }
        }
        
        Ok(all_keys)
    }
    
    pub async fn cleanup_expired_keys(
        &self,
        pattern: &str,
    ) -> Result<u64, RedisError> {
        let keys = self.scan_keys(pattern, 1000).await?;
        let mut cleaned_count = 0;
        
        for key in keys {
            let ttl = self.ttl(&key).await?;
            if ttl == -1 {
                // Key exists but has no expiration
                continue;
            } else if ttl == -2 {
                // Key doesn't exist
                cleaned_count += 1;
            }
        }
        
        Ok(cleaned_count)
    }
}
```

## Backend Integration Scenarios

### Distributed Caching Service

```rust
pub struct DistributedCacheService {
    redis_primary: Arc<RedisService>,
    redis_replica: Arc<RedisService>,
    config: CacheConfig,
}

impl DistributedCacheService {
    pub async fn get_with_fallback<T>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError>
    where
        T: DeserializeOwned + Send + Sync,
    {
        // Try primary first
        match self.redis_primary.get_json(key).await {
            Ok(result) => Ok(result),
            Err(_) => {
                // Fallback to replica
                self.redis_replica.get_json(key).await
                    .map_err(CacheError::RedisError)
            }
        }
    }
    
    pub async fn set_with_replication<T>(
        &self,
        key: &str,
        value: &T,
        ttl: u64,
    ) -> Result<(), CacheError>
    where
        T: Serialize + Send + Sync,
    {
        // Write to primary
        self.redis_primary.setex_json(key, ttl, value).await?;
        
        // Async replication to replica (best effort)
        let replica = self.redis_replica.clone();
        let key_clone = key.to_string();
        let value_json = serde_json::to_string(value)?;
        
        tokio::spawn(async move {
            if let Err(e) = replica.setex(&key_clone, ttl, &value_json).await {
                tracing::warn!(
                    key = %key_clone,
                    error = ?e,
                    "Failed to replicate cache entry"
                );
            }
        });
        
        Ok(())
    }
}
```

### Application Service Integration

```rust
pub struct ApplicationService {
    redis: Arc<RedisService>,
    database: Arc<Database>,
    cache_service: Arc<UserCacheService>,
    session_service: Arc<SessionService>,
    rate_limiter: Arc<RateLimiter>,
    job_queue: Arc<JobQueue>,
}

impl ApplicationService {
    pub async fn handle_user_request(
        &self,
        user_id: &str,
        request: UserRequest,
    ) -> Result<UserResponse, ServiceError> {
        // Rate limiting
        let rate_limit_result = self.rate_limiter
            .check_rate_limit(&format!("user:{}", user_id), 100, 3600)
            .await?;
        
        if !rate_limit_result.allowed {
            return Err(ServiceError::RateLimited(rate_limit_result));
        }
        
        // Get user from cache
        let user = self.cache_service
            .get_user_profile(user_id)
            .await?
            .ok_or(ServiceError::UserNotFound)?;
        
        // Process request
        let response = match request {
            UserRequest::GetProfile => {
                UserResponse::Profile(user)
            }
            UserRequest::UpdateSettings(settings) => {
                // Queue background job for settings update
                let job = Job {
                    id: uuid::Uuid::new_v4().to_string(),
                    job_type: "update_user_settings".to_string(),
                    payload: serde_json::to_value(&settings)?,
                    created_at: Utc::now(),
                    attempts: 0,
                    max_attempts: 3,
                    retry_delay_seconds: 60,
                };
                
                self.job_queue.enqueue_job(job).await?;
                UserResponse::Accepted
            }
        };
        
        // Update activity metrics
        self.redis.incr(&format!("user:{}:requests", user_id), 1).await?;
        
        Ok(response)
    }
}
```

## Troubleshooting

### Common Issues and Solutions

1. **Connection Pool Exhaustion**:
   ```rust
   // Monitor connection usage
   pub async fn monitor_connections(&self) -> ConnectionMetrics {
       // Implementation depends on Redis client metrics
       ConnectionMetrics {
           active_connections: self.connection_manager.active_count(),
           max_connections: self.config.max_connections,
           utilization: self.connection_manager.utilization(),
       }
   }
   ```

2. **Memory Usage Optimization**:
   ```rust
   // Implement key expiration monitoring
   pub async fn analyze_memory_usage(&self) -> MemoryReport {
       let info: String = redis::cmd("INFO")
           .arg("memory")
           .query_async(&mut self.get_connection().await?)
           .await?;
       
       // Parse memory info and generate report
       MemoryReport::from_redis_info(&info)
   }
   ```

3. **Performance Debugging**:
   ```rust
   // Add operation timing
   pub async fn timed_operation<F, T>(&self, operation_name: &str, operation: F) -> Result<T, RedisError>
   where
       F: Future<Output = Result<T, RedisError>>,
   {
       let start = std::time::Instant::now();
       let result = operation.await;
       let duration = start.elapsed();
       
       tracing::info!(
           operation = %operation_name,
           duration_ms = duration.as_millis(),
           success = result.is_ok(),
           "Redis operation completed"
       );
       
       result
   }
   ```

## Future Enhancements

### Planned Features

1. **Redis Cluster Support**:
   ```rust
   pub struct RedisClusterService {
       cluster_client: ClusterClient,
       config: ClusterConfig,
   }
   ```

2. **Advanced Pub/Sub**:
   ```rust
   pub struct StreamProcessor {
       redis: Arc<RedisService>,
       stream_name: String,
       consumer_group: String,
   }
   ```

3. **Metrics and Monitoring**:
   ```rust
   pub struct RedisMetrics {
       pub operations_per_second: f64,
       pub average_latency: Duration,
       pub error_rate: f64,
       pub memory_usage: u64,
   }
   ```

This comprehensive Redis utility provides a robust, scalable foundation for caching, session management, rate limiting, and real-time features while maintaining high performance and reliability standards.
```
