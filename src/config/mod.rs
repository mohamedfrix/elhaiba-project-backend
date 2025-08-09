pub mod minio_conf;
pub mod redis_conf;
pub mod jwt_conf;
pub mod email_conf;
pub mod password_reset_conf;
pub mod mongo_conf;
pub mod admin_user_conf;
pub mod app_conf;


pub use minio_conf::MinioConfig;
pub use redis_conf::RedisConfig;
pub use jwt_conf::JwtConfig;
pub use email_conf::EmailConfig;
pub use password_reset_conf::PasswordResetConfig;

/// Common configuration error type
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
    
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
}
