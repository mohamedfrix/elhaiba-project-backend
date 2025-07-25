use std::env;
use tracing::{debug, error, info, warn};

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),
    #[error("Invalid environment variable value: {0}")]
    InvalidEnvVar(String),
}

/// JWT configuration structure
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// JWT secret key for signing tokens
    pub jwt_secret: String,
    /// Access token expiration time in minutes
    pub access_token_expiration: i64,
    /// Refresh token expiration time in minutes
    pub refresh_token_expiration: i64,
    /// JWT issuer (optional)
    pub jwt_issuer: Option<String>,
    /// JWT audience (optional)
    pub jwt_audience: Option<String>,
}

impl JwtConfig {
    /// Load JWT configuration from environment variables
    /// 
    /// Expected environment variables:
    /// - JWT_SECRET: Secret key for signing JWT tokens (required)
    /// - JWT_ACCESS_TOKEN_EXPIRY: Access token expiration in minutes (defaults to 15)
    /// - JWT_REFRESH_TOKEN_EXPIRY: Refresh token expiration in minutes (defaults to 10080 = 1 week)
    /// - JWT_ISSUER: JWT issuer (optional)
    /// - JWT_AUDIENCE: JWT audience (optional)
    pub fn from_env() -> Result<Self, ConfigError> {
        info!("Loading JWT configuration from environment variables");

        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| {
                error!("JWT_SECRET environment variable not found");
                ConfigError::MissingEnvVar("JWT_SECRET".to_string())
            })?;
        
        // Validate JWT secret length for security
        if jwt_secret.len() < 32 {
            error!("JWT_SECRET is too short (minimum 32 characters required)");
            return Err(ConfigError::InvalidEnvVar("JWT_SECRET must be at least 32 characters long".to_string()));
        }
        debug!("JWT secret loaded (length: {} chars)", jwt_secret.len());

        let access_token_expiration = env::var("JWT_ACCESS_TOKEN_EXPIRY")
            .unwrap_or_else(|_| {
                warn!("JWT_ACCESS_TOKEN_EXPIRY not set, using default: 15 minutes");
                "15".to_string()
            })
            .parse::<i64>()
            .map_err(|e| {
                error!("Invalid JWT_ACCESS_TOKEN_EXPIRY value: {}", e);
                ConfigError::InvalidEnvVar(format!("JWT_ACCESS_TOKEN_EXPIRY: {}", e))
            })?;
        
        if access_token_expiration <= 0 {
            error!("JWT_ACCESS_TOKEN_EXPIRY must be greater than 0");
            return Err(ConfigError::InvalidEnvVar("JWT_ACCESS_TOKEN_EXPIRY must be greater than 0".to_string()));
        }
        debug!("JWT access token expiration: {} minutes", access_token_expiration);

        let refresh_token_expiration = env::var("JWT_REFRESH_TOKEN_EXPIRY")
            .unwrap_or_else(|_| {
                warn!("JWT_REFRESH_TOKEN_EXPIRY not set, using default: 10080 minutes (1 week)");
                "10080".to_string() // 1 week in minutes
            })
            .parse::<i64>()
            .map_err(|e| {
                error!("Invalid JWT_REFRESH_TOKEN_EXPIRY value: {}", e);
                ConfigError::InvalidEnvVar(format!("JWT_REFRESH_TOKEN_EXPIRY: {}", e))
            })?;
        
        if refresh_token_expiration <= 0 {
            error!("JWT_REFRESH_TOKEN_EXPIRY must be greater than 0");
            return Err(ConfigError::InvalidEnvVar("JWT_REFRESH_TOKEN_EXPIRY must be greater than 0".to_string()));
        }
        debug!("JWT refresh token expiration: {} minutes", refresh_token_expiration);

        let jwt_issuer = env::var("JWT_ISSUER").ok();
        if let Some(ref issuer) = jwt_issuer {
            debug!("JWT issuer: {}", issuer);
        } else {
            debug!("No JWT issuer provided");
        }

        let jwt_audience = env::var("JWT_AUDIENCE").ok();
        if let Some(ref audience) = jwt_audience {
            debug!("JWT audience: {}", audience);
        } else {
            debug!("No JWT audience provided");
        }

        let config = JwtConfig {
            jwt_secret,
            access_token_expiration,
            refresh_token_expiration,
            jwt_issuer,
            jwt_audience,
        };

        info!("JWT configuration loaded successfully");
        Ok(config)
    }

    /// Validate the JWT configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        debug!("Validating JWT configuration");

        if self.jwt_secret.is_empty() {
            error!("JWT secret cannot be empty");
            return Err(ConfigError::InvalidEnvVar("JWT secret cannot be empty".to_string()));
        }

        if self.jwt_secret.len() < 32 {
            error!("JWT secret is too short (minimum 32 characters required)");
            return Err(ConfigError::InvalidEnvVar("JWT secret must be at least 32 characters long".to_string()));
        }

        if self.access_token_expiration <= 0 {
            error!("Access token expiration must be greater than 0");
            return Err(ConfigError::InvalidEnvVar("Access token expiration must be greater than 0".to_string()));
        }

        if self.refresh_token_expiration <= 0 {
            error!("Refresh token expiration must be greater than 0");
            return Err(ConfigError::InvalidEnvVar("Refresh token expiration must be greater than 0".to_string()));
        }

        if self.access_token_expiration >= self.refresh_token_expiration {
            warn!("Access token expiration is greater than or equal to refresh token expiration");
        }

        debug!("JWT configuration validation passed");
        Ok(())
    }

    /// Load JWT configuration from environment variables for testing
    /// Uses TEST_ prefixed environment variables
    pub fn from_test_env() -> Result<Self, ConfigError> {
        info!("Loading JWT configuration from test environment variables");

        let jwt_secret = env::var("TEST_JWT_SECRET")
            .map_err(|_| {
                error!("TEST_JWT_SECRET environment variable not found");
                ConfigError::MissingEnvVar("TEST_JWT_SECRET".to_string())
            })?;
        
        // Validate JWT secret length for security
        if jwt_secret.len() < 32 {
            error!("TEST_JWT_SECRET is too short (minimum 32 characters required)");
            return Err(ConfigError::InvalidEnvVar("TEST_JWT_SECRET must be at least 32 characters long".to_string()));
        }
        debug!("Test JWT secret loaded (length: {} chars)", jwt_secret.len());

        let access_token_expiration = env::var("TEST_JWT_ACCESS_TOKEN_EXPIRY")
            .unwrap_or_else(|_| {
                warn!("TEST_JWT_ACCESS_TOKEN_EXPIRY not set, using default: 15 minutes");
                "15".to_string()
            })
            .parse::<i64>()
            .map_err(|e| {
                error!("Invalid TEST_JWT_ACCESS_TOKEN_EXPIRY value: {}", e);
                ConfigError::InvalidEnvVar(format!("TEST_JWT_ACCESS_TOKEN_EXPIRY: {}", e))
            })?;
        debug!("Test JWT access token expiration: {} minutes", access_token_expiration);

        let refresh_token_expiration = env::var("TEST_JWT_REFRESH_TOKEN_EXPIRY")
            .unwrap_or_else(|_| {
                warn!("TEST_JWT_REFRESH_TOKEN_EXPIRY not set, using default: 10080 minutes (1 week)");
                "10080".to_string()
            })
            .parse::<i64>()
            .map_err(|e| {
                error!("Invalid TEST_JWT_REFRESH_TOKEN_EXPIRY value: {}", e);
                ConfigError::InvalidEnvVar(format!("TEST_JWT_REFRESH_TOKEN_EXPIRY: {}", e))
            })?;
        debug!("Test JWT refresh token expiration: {} minutes", refresh_token_expiration);

        let jwt_issuer = env::var("TEST_JWT_ISSUER").ok();
        let jwt_audience = env::var("TEST_JWT_AUDIENCE").ok();

        let config = JwtConfig {
            jwt_secret,
            access_token_expiration,
            refresh_token_expiration,
            jwt_issuer,
            jwt_audience,
        };

        info!("Test JWT configuration loaded successfully");
        Ok(config)
    }
}

/// Create JWT configuration for testing with default values
impl Default for JwtConfig {
    fn default() -> Self {
        JwtConfig {
            jwt_secret: "test_secret_key_for_jwt_testing_should_be_long_enough_for_security_purposes".to_string(),
            access_token_expiration: 15,
            refresh_token_expiration: 10080, // 1 week
            jwt_issuer: Some("elhaiba-backend-test".to_string()),
            jwt_audience: Some("elhaiba-backend-users".to_string()),
        }
    }
}
