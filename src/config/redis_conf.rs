use serde::{Deserialize, Serialize};
use std::env;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub database: u8,
    pub pool_max_size: u32,
    pub connection_timeout_secs: u64,
    pub command_timeout_secs: u64,
    pub use_tls: bool,
}

impl RedisConfig {
    /// Load Redis configuration from environment variables
    /// 
    /// Expected environment variables:
    /// - REDIS_HOST: Redis server host (e.g., "localhost")
    /// - REDIS_PORT: Redis server port (defaults to 6379)
    /// - REDIS_USERNAME: Optional username for Redis (Redis 6.0+)
    /// - REDIS_PASSWORD: Optional password for Redis
    /// - REDIS_DATABASE: Database number (defaults to 0)
    /// - REDIS_POOL_MAX_SIZE: Maximum pool size (defaults to 10)
    /// - REDIS_CONNECTION_TIMEOUT: Connection timeout in seconds (defaults to 5)
    /// - REDIS_COMMAND_TIMEOUT: Command timeout in seconds (defaults to 10)
    /// - REDIS_USE_TLS: Whether to use TLS/SSL (defaults to false)
    pub fn from_env() -> Result<Self, ConfigError> {
        info!("Loading Redis configuration from environment variables");
        
        let host = env::var("REDIS_HOST")
            .map_err(|_| {
                error!("REDIS_HOST environment variable not found");
                ConfigError::MissingEnvVar("REDIS_HOST".to_string())
            })?;
        debug!("Redis host: {}", host);

        let port = env::var("REDIS_PORT")
            .unwrap_or_else(|_| {
                warn!("REDIS_PORT not set, using default: 6379");
                "6379".to_string()
            })
            .parse()
            .map_err(|e| {
                error!("Invalid REDIS_PORT value: {}", e);
                ConfigError::ParseError(format!("Invalid port: {}", e))
            })?;
        debug!("Redis port: {}", port);

        let username = env::var("REDIS_USERNAME").ok();
        if username.is_some() {
            debug!("Redis username provided");
        } else {
            debug!("No Redis username provided");
        }

        let password = env::var("REDIS_PASSWORD").ok();
        if password.is_some() {
            debug!("Redis password provided (length: {} chars)", password.as_ref().unwrap().len());
        } else {
            debug!("No Redis password provided");
        }

        let database = env::var("REDIS_DATABASE")
            .unwrap_or_else(|_| {
                warn!("REDIS_DATABASE not set, using default: 0");
                "0".to_string()
            })
            .parse()
            .map_err(|e| {
                error!("Invalid REDIS_DATABASE value: {}", e);
                ConfigError::ParseError(format!("Invalid database: {}", e))
            })?;
        debug!("Redis database: {}", database);

        let pool_max_size = env::var("REDIS_POOL_MAX_SIZE")
            .unwrap_or_else(|_| {
                warn!("REDIS_POOL_MAX_SIZE not set, using default: 10");
                "10".to_string()
            })
            .parse()
            .map_err(|e| {
                error!("Invalid REDIS_POOL_MAX_SIZE value: {}", e);
                ConfigError::ParseError(format!("Invalid pool size: {}", e))
            })?;
        debug!("Redis pool max size: {}", pool_max_size);

        let connection_timeout_secs = env::var("REDIS_CONNECTION_TIMEOUT")
            .unwrap_or_else(|_| {
                warn!("REDIS_CONNECTION_TIMEOUT not set, using default: 5");
                "5".to_string()
            })
            .parse()
            .map_err(|e| {
                error!("Invalid REDIS_CONNECTION_TIMEOUT value: {}", e);
                ConfigError::ParseError(format!("Invalid connection timeout: {}", e))
            })?;
        debug!("Redis connection timeout: {} seconds", connection_timeout_secs);

        let command_timeout_secs = env::var("REDIS_COMMAND_TIMEOUT")
            .unwrap_or_else(|_| {
                warn!("REDIS_COMMAND_TIMEOUT not set, using default: 10");
                "10".to_string()
            })
            .parse()
            .map_err(|e| {
                error!("Invalid REDIS_COMMAND_TIMEOUT value: {}", e);
                ConfigError::ParseError(format!("Invalid command timeout: {}", e))
            })?;
        debug!("Redis command timeout: {} seconds", command_timeout_secs);

        let use_tls = env::var("REDIS_USE_TLS")
            .unwrap_or_else(|_| {
                warn!("REDIS_USE_TLS not set, defaulting to false");
                "false".to_string()
            })
            .parse()
            .unwrap_or_else(|_| {
                warn!("Invalid REDIS_USE_TLS value, defaulting to false");
                false
            });
        debug!("Redis use TLS: {}", use_tls);

        let config = Self {
            host,
            port,
            username,
            password,
            database,
            pool_max_size,
            connection_timeout_secs,
            command_timeout_secs,
            use_tls,
        };

        info!("Redis configuration loaded successfully");
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        info!("Validating Redis configuration");

        if self.host.is_empty() {
            error!("Redis host is empty");
            return Err(ConfigError::InvalidConfig("Host cannot be empty".to_string()));
        }

        if self.port == 0 {
            error!("Redis port is 0");
            return Err(ConfigError::InvalidConfig("Port must be greater than 0".to_string()));
        }

        if self.database > 15 {
            warn!("Redis database number is high: {} (Redis default max is 15)", self.database);
        }

        if self.pool_max_size == 0 {
            error!("Redis pool max size is 0");
            return Err(ConfigError::InvalidConfig("Pool max size must be greater than 0".to_string()));
        }

        if self.pool_max_size > 1000 {
            warn!("Redis pool max size is very high: {}", self.pool_max_size);
        }

        if self.connection_timeout_secs == 0 {
            error!("Redis connection timeout is 0");
            return Err(ConfigError::InvalidConfig("Connection timeout must be greater than 0".to_string()));
        }

        if self.command_timeout_secs == 0 {
            error!("Redis command timeout is 0");
            return Err(ConfigError::InvalidConfig("Command timeout must be greater than 0".to_string()));
        }

        info!("Redis configuration validation successful");
        Ok(())
    }

    /// Get the Redis connection URL
    pub fn get_connection_url(&self) -> String {
        let protocol = if self.use_tls { "rediss" } else { "redis" };
        
        let auth_part = match (&self.username, &self.password) {
            (Some(username), Some(password)) => format!("{}:{}@", username, password),
            (None, Some(password)) => format!(":{}@", password),
            _ => String::new(),
        };

        let url = format!("{}://{}{}:{}/{}", 
            protocol, 
            auth_part, 
            self.host, 
            self.port, 
            self.database
        );
        
        debug!("Generated Redis connection URL: {}", 
            if auth_part.is_empty() { 
                url.as_str()
            } else { 
                "redis://***:***@host:port/db"
            }
        );
        
        url
    }

    /// Get connection URL without database (for connection management)
    pub fn get_base_connection_url(&self) -> String {
        let protocol = if self.use_tls { "rediss" } else { "redis" };
        
        let auth_part = match (&self.username, &self.password) {
            (Some(username), Some(password)) => format!("{}:{}@", username, password),
            (None, Some(password)) => format!(":{}@", password),
            _ => String::new(),
        };

        let url = format!("{}://{}{}:{}", 
            protocol, 
            auth_part, 
            self.host, 
            self.port
        );
        
        debug!("Generated Redis base connection URL: {}", 
            if auth_part.is_empty() { 
                url.as_str()
            } else { 
                "redis://***:***@host:port"
            }
        );
        
        url
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        warn!("Using default Redis configuration - this should only be used for testing");
        Self {
            host: "localhost".to_string(),
            port: 6379,
            username: None,
            password: None,
            database: 0,
            pool_max_size: 10,
            connection_timeout_secs: 5,
            command_timeout_secs: 10,
            use_tls: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Environment variable parse error: {0}")]
    ParseError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    // use std::env;

    #[test]
    fn test_default_config() {
        let config = RedisConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 6379);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
        assert_eq!(config.database, 0);
        assert_eq!(config.pool_max_size, 10);
        assert_eq!(config.connection_timeout_secs, 5);
        assert_eq!(config.command_timeout_secs, 10);
        assert!(!config.use_tls);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = RedisConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_host() {
        let mut config = RedisConfig::default();
        config.host = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_port() {
        let mut config = RedisConfig::default();
        config.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_get_connection_url_no_auth() {
        let config = RedisConfig::default();
        assert_eq!(config.get_connection_url(), "redis://localhost:6379/0");
    }

    #[test]
    fn test_get_connection_url_with_password() {
        let mut config = RedisConfig::default();
        config.password = Some("secret".to_string());
        assert_eq!(config.get_connection_url(), "redis://:secret@localhost:6379/0");
    }

    #[test]
    fn test_get_connection_url_with_username_password() {
        let mut config = RedisConfig::default();
        config.username = Some("user".to_string());
        config.password = Some("secret".to_string());
        assert_eq!(config.get_connection_url(), "redis://user:secret@localhost:6379/0");
    }

    #[test]
    fn test_get_connection_url_tls() {
        let mut config = RedisConfig::default();
        config.use_tls = true;
        assert_eq!(config.get_connection_url(), "rediss://localhost:6379/0");
    }
}
