use serde::{Deserialize, Serialize};
use std::env;
use tracing::{debug, error, info, warn};

use crate::config::ConfigError;

/// MongoDB configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoConfig {
    /// MongoDB connection URI
    pub uri: String,
    /// Database name
    pub database: String,
    /// Username for authentication (optional)
    pub username: Option<String>,
    /// Password for authentication (optional)
    pub password: Option<String>,
    /// Collection name for quotes (optional, for convenience)
    pub quote_collection: Option<String>,
    /// Connection pool size
    pub pool_size: u32,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
}

impl MongoConfig {
    /// Load MongoDB configuration from environment variables
    ///
    /// Expected environment variables:
    /// - MONGO_URI: MongoDB connection URI (required)
    /// - MONGO_DATABASE: Database name (required)
    /// - MONGO_QUOTE_COLLECTION: Collection name for quotes (optional)
    /// - MONGO_POOL_SIZE: Connection pool size (defaults to 10)
    /// - MONGO_CONNECTION_TIMEOUT: Connection timeout in seconds (defaults to 5)
    pub fn from_env() -> Result<Self, ConfigError> {
        info!("Loading MongoDB configuration from environment variables");

        let uri = env::var("MONGO_URI")
            .map_err(|_| {
                error!("MONGO_URI environment variable not found");
                ConfigError::EnvVarNotFound("MONGO_URI".to_string())
            })?;
        debug!("MongoDB URI: {}", uri);

        let database = env::var("MONGO_DATABASE")
            .map_err(|_| {
                error!("MONGO_DATABASE environment variable not found");
                ConfigError::EnvVarNotFound("MONGO_DATABASE".to_string())
            })?;
        debug!("MongoDB database: {}", database);

        let username = env::var("MONGO_USERNAME").ok();
        if let Some(ref user) = username {
            debug!("MongoDB username: {}", user);
        } else {
            debug!("No MongoDB username specified");
        }

        let password = env::var("MONGO_PASSWORD").ok();
        if let Some(_) = password {
            debug!("MongoDB password provided");
        } else {
            debug!("No MongoDB password specified");
        }

        let quote_collection = env::var("MONGO_QUOTE_COLLECTION").ok();
        if let Some(ref coll) = quote_collection {
            debug!("MongoDB quote collection: {}", coll);
        } else {
            debug!("No quote collection specified");
        }

        let pool_size = env::var("MONGO_POOL_SIZE")
            .unwrap_or_else(|_| {
                warn!("MONGO_POOL_SIZE not set, using default: 10");
                "10".to_string()
            })
            .parse::<u32>()
            .map_err(|_| {
                error!("Invalid MONGO_POOL_SIZE value");
                ConfigError::InvalidValue("Invalid MONGO_POOL_SIZE value".to_string())
            })?;
        debug!("MongoDB pool size: {}", pool_size);

        let connection_timeout_secs = env::var("MONGO_CONNECTION_TIMEOUT")
            .unwrap_or_else(|_| {
                warn!("MONGO_CONNECTION_TIMEOUT not set, using default: 5 seconds");
                "5".to_string()
            })
            .parse::<u64>()
            .map_err(|_| {
                error!("Invalid MONGO_CONNECTION_TIMEOUT value");
                ConfigError::InvalidValue("Invalid MONGO_CONNECTION_TIMEOUT value".to_string())
            })?;
        debug!("MongoDB connection timeout: {} seconds", connection_timeout_secs);

        let config = MongoConfig {
            uri,
            database,
            username,
            password,
            quote_collection,
            pool_size,
            connection_timeout_secs,
        };

        config.validate()?;
        info!("MongoDB configuration loaded successfully");
        Ok(config)
    }

    /// Create MongoConfig for testing
    pub fn from_test_env() -> Self {
        MongoConfig {
            uri: "mongodb://localhost:27017".to_string(),
            database: "test_db".to_string(),
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
            quote_collection: Some("test_quotes".to_string()),
            pool_size: 2,
            connection_timeout_secs: 2,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        info!("Validating MongoDB configuration");

        if self.uri.is_empty() {
            error!("MongoDB URI is empty");
            return Err(ConfigError::ValidationError("MongoDB URI cannot be empty".to_string()));
        }

        if self.database.is_empty() {
            error!("MongoDB database is empty");
            return Err(ConfigError::ValidationError("MongoDB database cannot be empty".to_string()));
        }

        if self.pool_size == 0 {
            error!("MongoDB pool size is 0");
            return Err(ConfigError::ValidationError("MongoDB pool size must be greater than 0".to_string()));
        }

        if self.connection_timeout_secs == 0 {
            error!("MongoDB connection timeout is 0");
            return Err(ConfigError::ValidationError("MongoDB connection timeout must be greater than 0".to_string()));
        }

        // Optionally validate username/password if present
        if let Some(ref user) = self.username {
            if user.is_empty() {
                error!("MongoDB username is empty");
                return Err(ConfigError::ValidationError("MongoDB username cannot be empty if set".to_string()));
            }
        }
        if let Some(ref pass) = self.password {
            if pass.is_empty() {
                error!("MongoDB password is empty");
                return Err(ConfigError::ValidationError("MongoDB password cannot be empty if set".to_string()));
            }
        }
        info!("MongoDB configuration validation successful");
        Ok(())
    }

    /// Get the MongoDB connection URI
    pub fn get_uri(&self) -> &str {
        &self.uri
    }

    /// Get the database name
    pub fn get_database(&self) -> &str {
        &self.database
    }

    /// Get the quote collection name (if set)
    pub fn get_quote_collection(&self) -> Option<&str> {
        self.quote_collection.as_deref()
    }
}

impl Default for MongoConfig {
    fn default() -> Self {
        MongoConfig {
            uri: "mongodb://localhost:27017".to_string(),
            database: "elhaiba".to_string(),
            username: None,
            password: None,
            quote_collection: Some("quotes".to_string()),
            pool_size: 10,
            connection_timeout_secs: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MongoConfig::default();
        assert_eq!(config.uri, "mongodb://localhost:27017");
        assert_eq!(config.database, "elhaiba");
        assert_eq!(config.quote_collection, Some("quotes".to_string()));
        assert_eq!(config.pool_size, 10);
        assert_eq!(config.connection_timeout_secs, 5);
    }

    #[test]
    fn test_test_config() {
        let config = MongoConfig::from_test_env();
        assert_eq!(config.uri, "mongodb://localhost:27017");
        assert_eq!(config.database, "test_db");
        assert_eq!(config.quote_collection, Some("test_quotes".to_string()));
        assert_eq!(config.pool_size, 2);
        assert_eq!(config.connection_timeout_secs, 2);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = MongoConfig::from_test_env();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_uri() {
        let mut config = MongoConfig::from_test_env();
        config.uri = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_database() {
        let mut config = MongoConfig::from_test_env();
        config.database = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_pool_size() {
        let mut config = MongoConfig::from_test_env();
        config.pool_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_timeout() {
        let mut config = MongoConfig::from_test_env();
        config.connection_timeout_secs = 0;
        assert!(config.validate().is_err());
    }
}
