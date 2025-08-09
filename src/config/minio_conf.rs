use serde::{Deserialize, Serialize};
use std::env;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinioConfig {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
    pub links_prefix: String,
    pub region: Option<String>,
    pub secure: bool,
}

impl MinioConfig {
    /// Load MinIO configuration from environment variables
    /// 
    /// Expected environment variables:
    /// - MINIO_ENDPOINT: MinIO server endpoint (e.g., "localhost:9000")
    /// - MINIO_ACCESS_KEY: Access key for MinIO
    /// - MINIO_SECRET_KEY: Secret key for MinIO
    /// - MINIO_BUCKET_NAME: Default bucket name
    /// - MINIO_REGION: Optional region (defaults to "us-east-1")
    /// - MINIO_SECURE: Whether to use HTTPS (defaults to false)
    pub fn from_env() -> Result<Self, ConfigError> {
        info!("Loading MinIO configuration from environment variables");
        
        let endpoint = env::var("MINIO_ENDPOINT")
            .map_err(|_| {
                error!("MINIO_ENDPOINT environment variable not found");
                ConfigError::MissingEnvVar("MINIO_ENDPOINT".to_string())
            })?;
        debug!("MinIO endpoint: {}", endpoint);

        let access_key = env::var("MINIO_ACCESS_KEY")
            .map_err(|_| {
                error!("MINIO_ACCESS_KEY environment variable not found");
                ConfigError::MissingEnvVar("MINIO_ACCESS_KEY".to_string())
            })?;
        debug!("MinIO access key loaded (length: {} chars)", access_key.len());

        let secret_key = env::var("MINIO_SECRET_KEY")
            .map_err(|_| {
                error!("MINIO_SECRET_KEY environment variable not found");
                ConfigError::MissingEnvVar("MINIO_SECRET_KEY".to_string())
            })?;
        debug!("MinIO secret key loaded (length: {} chars)", secret_key.len());

        let bucket_name = env::var("MINIO_BUCKET_NAME")
            .map_err(|_| {
                error!("MINIO_BUCKET_NAME environment variable not found");
                ConfigError::MissingEnvVar("MINIO_BUCKET_NAME".to_string())
            })?;
        debug!("MinIO bucket name: {}", bucket_name);

        let region = env::var("MINIO_REGION").ok().or_else(|| {
            warn!("MINIO_REGION not set, using default: us-east-1");
            Some("us-east-1".to_string())
        });
        debug!("MinIO region: {:?}", region);

        let secure = env::var("MINIO_SECURE")
            .unwrap_or_else(|_| {
                warn!("MINIO_SECURE not set, defaulting to false (HTTP)");
                "false".to_string()
            })
            .parse()
            .unwrap_or_else(|_| {
                warn!("Invalid MINIO_SECURE value, defaulting to false");
                false
            });
        debug!("MinIO secure connection: {}", secure);

        let links_prefix = env::var("MINIO_LINKS_PREFIX")
            .unwrap_or_else(|_| {
                warn!("MINIO_LINKS_PREFIX not set, using default: /");
                "127.0.0.1:9000/".to_string()
            });
        debug!("MinIO links prefix: {}", links_prefix);

        let config = Self {
            endpoint,
            access_key,
            secret_key,
            bucket_name,
            links_prefix,
            region,
            secure,
        };

        info!("MinIO configuration loaded successfully");
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        info!("Validating MinIO configuration");

        if self.endpoint.is_empty() {
            error!("MinIO endpoint is empty");
            return Err(ConfigError::InvalidConfig("Endpoint cannot be empty".to_string()));
        }

        if self.access_key.is_empty() {
            error!("MinIO access key is empty");
            return Err(ConfigError::InvalidConfig("Access key cannot be empty".to_string()));
        }

        if self.secret_key.is_empty() {
            error!("MinIO secret key is empty");
            return Err(ConfigError::InvalidConfig("Secret key cannot be empty".to_string()));
        }

        if self.bucket_name.is_empty() {
            error!("MinIO bucket name is empty");
            return Err(ConfigError::InvalidConfig("Bucket name cannot be empty".to_string()));
        }

        // Validate bucket name format (basic validation)
        if !self.bucket_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.') {
            error!("Invalid bucket name format: {}", self.bucket_name);
            return Err(ConfigError::InvalidConfig(
                "Bucket name contains invalid characters".to_string(),
            ));
        }

        if self.bucket_name.len() < 3 || self.bucket_name.len() > 63 {
            error!("Invalid bucket name length: {}", self.bucket_name.len());
            return Err(ConfigError::InvalidConfig(
                "Bucket name must be between 3 and 63 characters".to_string(),
            ));
        }

        info!("MinIO configuration validation successful");
        Ok(())
    }

    /// Get the full endpoint URL with protocol
    pub fn get_endpoint_url(&self) -> String {
        let protocol = if self.secure { "https" } else { "http" };
        let url = format!("{}://{}", protocol, self.endpoint);
        debug!("Generated MinIO endpoint URL: {}", url);
        url
    }
}

impl Default for MinioConfig {
    fn default() -> Self {
        warn!("Using default MinIO configuration - this should only be used for testing");
        Self {
            endpoint: "localhost:9000".to_string(),
            access_key: "minioadmin".to_string(),
            secret_key: "minioadmin".to_string(),
            bucket_name: "default-bucket".to_string(),
            links_prefix: "127.0.0.1:9000/".to_string(),
            region: Some("us-east-1".to_string()),
            secure: false,
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

    #[test]
    fn test_default_config() {
        let config = MinioConfig::default();
        assert_eq!(config.endpoint, "localhost:9000");
        assert_eq!(config.access_key, "minioadmin");
        assert_eq!(config.secret_key, "minioadmin");
        assert_eq!(config.bucket_name, "default-bucket");
        assert_eq!(config.region, Some("us-east-1".to_string()));
        assert!(!config.secure);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = MinioConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_endpoint() {
        let mut config = MinioConfig::default();
        config.endpoint = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_bucket_name() {
        let mut config = MinioConfig::default();
        config.bucket_name = "ab".to_string(); // Too short
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_get_endpoint_url() {
        let mut config = MinioConfig::default();
        assert_eq!(config.get_endpoint_url(), "http://localhost:9000");
        
        config.secure = true;
        assert_eq!(config.get_endpoint_url(), "https://localhost:9000");
    }
}
