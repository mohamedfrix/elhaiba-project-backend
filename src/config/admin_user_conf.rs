use std::env;
use serde::{Serialize, Deserialize};
use crate::config::ConfigError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUserConfig {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
}

impl AdminUserConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(AdminUserConfig {
            username: env::var("ADMIN_USERNAME").map_err(|_| ConfigError::EnvVarNotFound("ADMIN_USERNAME".to_string()))?,
            first_name: env::var("ADMIN_FIRST_NAME").map_err(|_| ConfigError::EnvVarNotFound("ADMIN_FIRST_NAME".to_string()))?,
            last_name: env::var("ADMIN_LAST_NAME").map_err(|_| ConfigError::EnvVarNotFound("ADMIN_LAST_NAME".to_string()))?,
            email: env::var("ADMIN_EMAIL").map_err(|_| ConfigError::EnvVarNotFound("ADMIN_EMAIL".to_string()))?,
            password: env::var("ADMIN_PASSWORD").map_err(|_| ConfigError::EnvVarNotFound("ADMIN_PASSWORD".to_string()))?,
        })
    }
}
