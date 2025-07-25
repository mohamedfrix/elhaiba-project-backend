use serde::{Deserialize, Serialize};
use std::env;
use tracing::{debug, error, info, warn};

use crate::config::ConfigError;

/// Configuration for password reset functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetConfig {
    /// Frontend base URL for password reset page
    pub frontend_base_url: String,
    /// Path to the password reset page (e.g., "/reset-password")
    pub reset_path: String,
    /// Token expiration time in seconds
    pub token_expiration_secs: u64,
    /// Token length in characters
    pub token_length: usize,
    /// Redis key prefix for reset tokens
    pub redis_key_prefix: String,
}

impl PasswordResetConfig {
    /// Create PasswordResetConfig from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        info!("Loading password reset configuration from environment variables");

        let frontend_base_url = env::var("FRONTEND_BASE_URL")
            .map_err(|_| {
                error!("FRONTEND_BASE_URL environment variable not found");
                ConfigError::EnvVarNotFound("FRONTEND_BASE_URL".to_string())
            })?;
        debug!("Frontend base URL: {}", frontend_base_url);

        let reset_path = env::var("RESET_PASSWORD_PATH")
            .unwrap_or_else(|_| {
                warn!("RESET_PASSWORD_PATH not set, defaulting to /reset-password");
                "/reset-password".to_string()
            });
        debug!("Reset password path: {}", reset_path);

        let token_expiration_secs = env::var("RESET_TOKEN_EXPIRATION")
            .unwrap_or_else(|_| {
                warn!("RESET_TOKEN_EXPIRATION not set, defaulting to 3600 seconds (1 hour)");
                "3600".to_string()
            })
            .parse::<u64>()
            .map_err(|_| {
                error!("Invalid RESET_TOKEN_EXPIRATION value");
                ConfigError::InvalidValue("Invalid RESET_TOKEN_EXPIRATION value".to_string())
            })?;
        debug!("Token expiration: {} seconds", token_expiration_secs);

        let token_length = env::var("RESET_TOKEN_LENGTH")
            .unwrap_or_else(|_| {
                warn!("RESET_TOKEN_LENGTH not set, defaulting to 32 characters");
                "32".to_string()
            })
            .parse::<usize>()
            .map_err(|_| {
                error!("Invalid RESET_TOKEN_LENGTH value");
                ConfigError::InvalidValue("Invalid RESET_TOKEN_LENGTH value".to_string())
            })?;
        debug!("Token length: {} characters", token_length);

        let redis_key_prefix = env::var("RESET_TOKEN_REDIS_PREFIX")
            .unwrap_or_else(|_| {
                warn!("RESET_TOKEN_REDIS_PREFIX not set, defaulting to reset_token:");
                "reset_token:".to_string()
            });
        debug!("Redis key prefix: {}", redis_key_prefix);

        let config = PasswordResetConfig {
            frontend_base_url,
            reset_path,
            token_expiration_secs,
            token_length,
            redis_key_prefix,
        };

        config.validate()?;
        info!("Password reset configuration loaded successfully");
        Ok(config)
    }

    /// Create PasswordResetConfig for testing
    pub fn from_test_env() -> Self {
        PasswordResetConfig {
            frontend_base_url: "http://localhost:3000".to_string(),
            reset_path: "/reset-password".to_string(),
            token_expiration_secs: 1800, // 30 minutes for testing
            token_length: 16, // Shorter for testing
            redis_key_prefix: "test_reset_token:".to_string(),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        info!("Validating password reset configuration");

        if self.frontend_base_url.is_empty() {
            error!("Frontend base URL is empty");
            return Err(ConfigError::ValidationError("Frontend base URL cannot be empty".to_string()));
        }

        // Basic URL validation
        if !self.frontend_base_url.starts_with("http://") && !self.frontend_base_url.starts_with("https://") {
            error!("Frontend base URL must start with http:// or https://");
            return Err(ConfigError::ValidationError("Frontend base URL must start with http:// or https://".to_string()));
        }

        if self.reset_path.is_empty() {
            error!("Reset path is empty");
            return Err(ConfigError::ValidationError("Reset path cannot be empty".to_string()));
        }

        if !self.reset_path.starts_with('/') {
            error!("Reset path must start with /");
            return Err(ConfigError::ValidationError("Reset path must start with /".to_string()));
        }

        if self.token_expiration_secs == 0 {
            error!("Token expiration is 0");
            return Err(ConfigError::ValidationError("Token expiration cannot be 0".to_string()));
        }

        if self.token_length < 8 {
            error!("Token length is too short");
            return Err(ConfigError::ValidationError("Token length must be at least 8 characters".to_string()));
        }

        if self.redis_key_prefix.is_empty() {
            error!("Redis key prefix is empty");
            return Err(ConfigError::ValidationError("Redis key prefix cannot be empty".to_string()));
        }

        info!("Password reset configuration validation successful");
        Ok(())
    }

    /// Generate the complete reset URL with token
    pub fn generate_reset_url(&self, token: &str) -> String {
        let base_url = self.frontend_base_url.trim_end_matches('/');
        let path = self.reset_path.trim_start_matches('/');
        format!("{}/{}/{}", base_url, path, token)
    }

    /// Get Redis key for a token
    pub fn get_redis_key(&self, token: &str) -> String {
        format!("{}{}", self.redis_key_prefix, token)
    }
}

impl Default for PasswordResetConfig {
    fn default() -> Self {
        PasswordResetConfig {
            frontend_base_url: "https://example.com".to_string(),
            reset_path: "/reset-password".to_string(),
            token_expiration_secs: 3600, // 1 hour
            token_length: 32,
            redis_key_prefix: "reset_token:".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PasswordResetConfig::default();
        assert_eq!(config.frontend_base_url, "https://example.com");
        assert_eq!(config.reset_path, "/reset-password");
        assert_eq!(config.token_expiration_secs, 3600);
        assert_eq!(config.token_length, 32);
    }

    #[test]
    fn test_test_config() {
        let config = PasswordResetConfig::from_test_env();
        assert_eq!(config.frontend_base_url, "http://localhost:3000");
        assert_eq!(config.token_expiration_secs, 1800);
        assert_eq!(config.token_length, 16);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = PasswordResetConfig::from_test_env();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_base_url() {
        let mut config = PasswordResetConfig::from_test_env();
        config.frontend_base_url = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_base_url() {
        let mut config = PasswordResetConfig::from_test_env();
        config.frontend_base_url = "invalid-url".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_reset_path() {
        let mut config = PasswordResetConfig::from_test_env();
        config.reset_path = "no-slash".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_short_token_length() {
        let mut config = PasswordResetConfig::from_test_env();
        config.token_length = 7;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_generate_reset_url() {
        let config = PasswordResetConfig::from_test_env();
        let token = "abc123def456";
        let url = config.generate_reset_url(token);
        assert_eq!(url, "http://localhost:3000/reset-password/abc123def456");
    }

    #[test]
    fn test_generate_reset_url_with_trailing_slash() {
        let mut config = PasswordResetConfig::from_test_env();
        config.frontend_base_url = "http://localhost:3000/".to_string();
        let token = "abc123def456";
        let url = config.generate_reset_url(token);
        assert_eq!(url, "http://localhost:3000/reset-password/abc123def456");
    }

    #[test]
    fn test_get_redis_key() {
        let config = PasswordResetConfig::from_test_env();
        let token = "abc123def456";
        let key = config.get_redis_key(token);
        assert_eq!(key, "test_reset_token:abc123def456");
    }
}
