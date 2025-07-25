use serde::{Deserialize, Serialize};
use std::env;
use tracing::{debug, error, info, warn};

use crate::config::ConfigError;

/// Email configuration for SMTP settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server hostname
    pub smtp_host: String,
    /// SMTP server port
    pub smtp_port: u16,
    /// SMTP username for authentication
    pub smtp_username: String,
    /// SMTP password for authentication
    pub smtp_password: String,
    /// Whether to use TLS encryption
    pub use_tls: bool,
    /// Whether to use STARTTLS
    pub use_starttls: bool,
    /// From email address
    pub from_email: String,
    /// From name (display name)
    pub from_name: String,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
}

impl EmailConfig {
    /// Create EmailConfig from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        info!("Loading email configuration from environment variables");

        let smtp_host = env::var("SMTP_HOST")
            .map_err(|_| {
                error!("SMTP_HOST environment variable not found");
                ConfigError::EnvVarNotFound("SMTP_HOST".to_string())
            })?;
        debug!("SMTP host: {}", smtp_host);

        let smtp_port = env::var("SMTP_PORT")
            .unwrap_or_else(|_| {
                warn!("SMTP_PORT not set, defaulting to 587");
                "587".to_string()
            })
            .parse::<u16>()
            .map_err(|_| {
                error!("Invalid SMTP_PORT value");
                ConfigError::InvalidValue("Invalid SMTP_PORT value".to_string())
            })?;
        debug!("SMTP port: {}", smtp_port);

        let smtp_username = env::var("SMTP_USERNAME")
            .map_err(|_| {
                error!("SMTP_USERNAME environment variable not found");
                ConfigError::EnvVarNotFound("SMTP_USERNAME".to_string())
            })?;
        debug!("SMTP username: {}", smtp_username);

        let smtp_password = env::var("SMTP_PASSWORD")
            .map_err(|_| {
                error!("SMTP_PASSWORD environment variable not found");
                ConfigError::EnvVarNotFound("SMTP_PASSWORD".to_string())
            })?;
        debug!("SMTP password: [REDACTED]");

        let use_tls = env::var("SMTP_USE_TLS")
            .unwrap_or_else(|_| {
                warn!("SMTP_USE_TLS not set, defaulting to true");
                "true".to_string()
            })
            .parse::<bool>()
            .unwrap_or(true);
        debug!("SMTP use TLS: {}", use_tls);

        let use_starttls = env::var("SMTP_USE_STARTTLS")
            .unwrap_or_else(|_| {
                warn!("SMTP_USE_STARTTLS not set, defaulting to true");
                "true".to_string()
            })
            .parse::<bool>()
            .unwrap_or(true);
        debug!("SMTP use STARTTLS: {}", use_starttls);

        let from_email = env::var("SMTP_FROM_EMAIL")
            .map_err(|_| {
                error!("SMTP_FROM_EMAIL environment variable not found");
                ConfigError::EnvVarNotFound("SMTP_FROM_EMAIL".to_string())
            })?;
        debug!("From email: {}", from_email);

        let from_name = env::var("SMTP_FROM_NAME")
            .unwrap_or_else(|_| {
                warn!("SMTP_FROM_NAME not set, using default");
                "ElHaiba App".to_string()
            });
        debug!("From name: {}", from_name);

        let connection_timeout_secs = env::var("SMTP_CONNECTION_TIMEOUT")
            .unwrap_or_else(|_| {
                warn!("SMTP_CONNECTION_TIMEOUT not set, defaulting to 30 seconds");
                "30".to_string()
            })
            .parse::<u64>()
            .unwrap_or(30);
        debug!("Connection timeout: {} seconds", connection_timeout_secs);

        let config = EmailConfig {
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            use_tls,
            use_starttls,
            from_email,
            from_name,
            connection_timeout_secs,
        };

        config.validate()?;
        info!("Email configuration loaded successfully");
        Ok(config)
    }

    /// Create EmailConfig for testing
    pub fn from_test_env() -> Self {
        EmailConfig {
            smtp_host: "localhost".to_string(),
            smtp_port: 1025,
            smtp_username: "test".to_string(),
            smtp_password: "test".to_string(),
            use_tls: false,
            use_starttls: false,
            from_email: "test@example.com".to_string(),
            from_name: "Test App".to_string(),
            connection_timeout_secs: 10,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        info!("Validating email configuration");

        if self.smtp_host.is_empty() {
            error!("SMTP host is empty");
            return Err(ConfigError::ValidationError("SMTP host cannot be empty".to_string()));
        }

        if self.smtp_port == 0 {
            error!("SMTP port is 0");
            return Err(ConfigError::ValidationError("SMTP port cannot be 0".to_string()));
        }

        if self.smtp_username.is_empty() {
            error!("SMTP username is empty");
            return Err(ConfigError::ValidationError("SMTP username cannot be empty".to_string()));
        }

        if self.smtp_password.is_empty() {
            error!("SMTP password is empty");
            return Err(ConfigError::ValidationError("SMTP password cannot be empty".to_string()));
        }

        if self.from_email.is_empty() {
            error!("From email is empty");
            return Err(ConfigError::ValidationError("From email cannot be empty".to_string()));
        }

        // Basic email validation
        if !self.from_email.contains('@') {
            error!("Invalid from email format");
            return Err(ConfigError::ValidationError("Invalid from email format".to_string()));
        }

        if self.connection_timeout_secs == 0 {
            error!("Connection timeout is 0");
            return Err(ConfigError::ValidationError("Connection timeout cannot be 0".to_string()));
        }

        info!("Email configuration validation successful");
        Ok(())
    }

    /// Get SMTP server URL
    pub fn get_smtp_url(&self) -> String {
        format!("{}:{}", self.smtp_host, self.smtp_port)
    }
}

impl Default for EmailConfig {
    fn default() -> Self {
        EmailConfig {
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_username: "".to_string(),
            smtp_password: "".to_string(),
            use_tls: true,
            use_starttls: true,
            from_email: "noreply@example.com".to_string(),
            from_name: "ElHaiba App".to_string(),
            connection_timeout_secs: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EmailConfig::default();
        assert_eq!(config.smtp_host, "smtp.gmail.com");
        assert_eq!(config.smtp_port, 587);
        assert!(config.use_tls);
        assert!(config.use_starttls);
    }

    #[test]
    fn test_test_config() {
        let config = EmailConfig::from_test_env();
        assert_eq!(config.smtp_host, "localhost");
        assert_eq!(config.smtp_port, 1025);
        assert!(!config.use_tls);
        assert!(!config.use_starttls);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = EmailConfig::from_test_env();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_host() {
        let mut config = EmailConfig::from_test_env();
        config.smtp_host = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_port() {
        let mut config = EmailConfig::from_test_env();
        config.smtp_port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_from_email() {
        let mut config = EmailConfig::from_test_env();
        config.from_email = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_email_format() {
        let mut config = EmailConfig::from_test_env();
        config.from_email = "invalid-email".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_get_smtp_url() {
        let config = EmailConfig::from_test_env();
        assert_eq!(config.get_smtp_url(), "localhost:1025");
    }
}
