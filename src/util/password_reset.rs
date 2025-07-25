use rand::{distributions::Alphanumeric, Rng};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};
use async_trait::async_trait;

use crate::config::PasswordResetConfig;
use crate::util::redis::{RedisServiceTrait, RedisError};

/// Password reset utility errors
#[derive(Debug, Error)]
pub enum PasswordResetError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Token generation error: {0}")]
    TokenGenerationError(String),

    #[error("Redis error: {0}")]
    RedisError(#[from] RedisError),

    #[error("Token not found or expired")]
    TokenNotFound,

    #[error("Invalid token format")]
    InvalidToken,

    #[error("Token already used")]
    TokenAlreadyUsed,
}

/// Password reset token information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResetTokenInfo {
    pub user_id: String,
    pub email: String,
    pub created_at: i64, // Unix timestamp
    pub expires_at: i64, // Unix timestamp
    pub used: bool,
}

impl ResetTokenInfo {
    pub fn new(user_id: String, email: String, expiration_secs: u64) -> Self {
        let now = chrono::Utc::now().timestamp();
        ResetTokenInfo {
            user_id,
            email,
            created_at: now,
            expires_at: now + expiration_secs as i64,
            used: false,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() > self.expires_at
    }

    pub fn is_valid(&self) -> bool {
        !self.used && !self.is_expired()
    }
}

/// Password reset utility trait
#[async_trait]
pub trait PasswordResetService {
    async fn generate_reset_token(&self, user_id: &str, email: &str) -> Result<String, PasswordResetError>;
    async fn generate_reset_url(&self, user_id: &str, email: &str) -> Result<String, PasswordResetError>;
    async fn validate_reset_token(&self, token: &str) -> Result<ResetTokenInfo, PasswordResetError>;
    async fn use_reset_token(&self, token: &str) -> Result<ResetTokenInfo, PasswordResetError>;
    async fn revoke_reset_token(&self, token: &str) -> Result<(), PasswordResetError>;
    async fn cleanup_expired_tokens(&self) -> Result<u32, PasswordResetError>;
}

/// Redis-based password reset service implementation
pub struct RedisPasswordResetService {
    config: PasswordResetConfig,
    redis_service: Box<dyn RedisServiceTrait>,
}

impl RedisPasswordResetService {
    /// Create a new Redis password reset service
    pub fn new(config: PasswordResetConfig, redis_service: Box<dyn RedisServiceTrait>) -> Result<Self, PasswordResetError> {
        config.validate().map_err(|e| PasswordResetError::ConfigError(e.to_string()))?;
        Ok(RedisPasswordResetService {
            config,
            redis_service,
        })
    }

    /// Generate a cryptographically secure random token
    fn generate_secure_token(&self) -> Result<String, PasswordResetError> {
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(self.config.token_length)
            .map(char::from)
            .collect();

        if token.len() != self.config.token_length {
            return Err(PasswordResetError::TokenGenerationError(
                "Generated token length mismatch".to_string(),
            ));
        }

        debug!("Generated secure token of length: {}", token.len());
        Ok(token)
    }

    /// Store token information in Redis
    async fn store_token_info(&self, token: &str, token_info: &ResetTokenInfo) -> Result<(), PasswordResetError> {
        let key = self.config.get_redis_key(token);
        let value = serde_json::to_string(token_info)
            .map_err(|e| PasswordResetError::TokenGenerationError(format!("Failed to serialize token info: {}", e)))?;

        self.redis_service
            .set_string_with_expiry(&key, &value, self.config.token_expiration_secs)
            .await?;

        debug!("Stored token info in Redis with key: {}", key);
        Ok(())
    }

    /// Retrieve token information from Redis
    async fn get_token_info(&self, token: &str) -> Result<ResetTokenInfo, PasswordResetError> {
        let key = self.config.get_redis_key(token);
        
        match self.redis_service.get_string(&key).await {
            Ok(Some(value)) => {
                let token_info: ResetTokenInfo = serde_json::from_str(&value)
                    .map_err(|_e| PasswordResetError::InvalidToken)?;
                Ok(token_info)
            }
            Ok(None) => Err(PasswordResetError::TokenNotFound),
            Err(e) => Err(PasswordResetError::RedisError(e)),
        }
    }

    /// Update token information in Redis
    async fn update_token_info(&self, token: &str, token_info: &ResetTokenInfo) -> Result<(), PasswordResetError> {
        let key = self.config.get_redis_key(token);
        let value = serde_json::to_string(token_info)
            .map_err(|e| PasswordResetError::TokenGenerationError(format!("Failed to serialize token info: {}", e)))?;

        // Calculate remaining TTL
        let remaining_ttl = token_info.expires_at - chrono::Utc::now().timestamp();
        if remaining_ttl <= 0 {
            return Err(PasswordResetError::TokenNotFound);
        }

        self.redis_service
            .set_string_with_expiry(&key, &value, remaining_ttl as u64)
            .await?;

        debug!("Updated token info in Redis with key: {}", key);
        Ok(())
    }
}

#[async_trait]
impl PasswordResetService for RedisPasswordResetService {
    #[instrument(skip(self), fields(user_id = %user_id, email = %email))]
    async fn generate_reset_token(&self, user_id: &str, email: &str) -> Result<String, PasswordResetError> {
        info!("Generating reset token for user: {}", user_id);

        if user_id.is_empty() {
            return Err(PasswordResetError::TokenGenerationError(
                "User ID cannot be empty".to_string(),
            ));
        }

        if email.is_empty() {
            return Err(PasswordResetError::TokenGenerationError(
                "Email cannot be empty".to_string(),
            ));
        }

        // Generate secure token
        let token = self.generate_secure_token()?;

        // Create token info
        let token_info = ResetTokenInfo::new(
            user_id.to_string(),
            email.to_string(),
            self.config.token_expiration_secs,
        );

        // Store in Redis
        self.store_token_info(&token, &token_info).await?;

        info!("Reset token generated successfully for user: {}", user_id);
        Ok(token)
    }

    #[instrument(skip(self), fields(user_id = %user_id, email = %email))]
    async fn generate_reset_url(&self, user_id: &str, email: &str) -> Result<String, PasswordResetError> {
        info!("Generating reset URL for user: {}", user_id);

        let token = self.generate_reset_token(user_id, email).await?;
        let url = self.config.generate_reset_url(&token);

        info!("Reset URL generated successfully for user: {}", user_id);
        debug!("Reset URL: {}", url);
        Ok(url)
    }

    #[instrument(skip(self), fields(token_preview = %&token[..std::cmp::min(8, token.len())]))]
    async fn validate_reset_token(&self, token: &str) -> Result<ResetTokenInfo, PasswordResetError> {
        debug!("Validating reset token");

        if token.is_empty() {
            return Err(PasswordResetError::InvalidToken);
        }

        if token.len() != self.config.token_length {
            warn!("Token length mismatch: expected {}, got {}", self.config.token_length, token.len());
            return Err(PasswordResetError::InvalidToken);
        }

        let token_info = self.get_token_info(token).await?;

        if !token_info.is_valid() {
            if token_info.used {
                warn!("Attempted to use already used token");
                return Err(PasswordResetError::TokenAlreadyUsed);
            } else if token_info.is_expired() {
                warn!("Attempted to use expired token");
                return Err(PasswordResetError::TokenNotFound);
            }
        }

        debug!("Reset token validated successfully");
        Ok(token_info)
    }

    #[instrument(skip(self), fields(token_preview = %&token[..std::cmp::min(8, token.len())]))]
    async fn use_reset_token(&self, token: &str) -> Result<ResetTokenInfo, PasswordResetError> {
        info!("Using reset token");

        let mut token_info = self.validate_reset_token(token).await?;

        // Mark as used
        token_info.used = true;

        // Update in Redis
        self.update_token_info(token, &token_info).await?;

        info!("Reset token used successfully for user: {}", token_info.user_id);
        Ok(token_info)
    }

    #[instrument(skip(self), fields(token_preview = %&token[..std::cmp::min(8, token.len())]))]
    async fn revoke_reset_token(&self, token: &str) -> Result<(), PasswordResetError> {
        info!("Revoking reset token");

        let key = self.config.get_redis_key(token);
        
        match self.redis_service.delete(&key).await {
            Ok(_) => {
                info!("Reset token revoked successfully");
                Ok(())
            }
            Err(RedisError::KeyNotFound) => {
                warn!("Attempted to revoke non-existent token");
                Err(PasswordResetError::TokenNotFound)
            }
            Err(e) => Err(PasswordResetError::RedisError(e)),
        }
    }

    #[instrument(skip(self))]
    async fn cleanup_expired_tokens(&self) -> Result<u32, PasswordResetError> {
        info!("Starting cleanup of expired reset tokens");

        // This is a simplified implementation. In a production environment,
        // you might want to use Redis SCAN to iterate through keys
        let _pattern = format!("{}*", self.config.redis_key_prefix);
        
        // For now, we'll return 0 as Redis TTL handles expiration automatically
        // In a real implementation, you could scan for keys and check their expiration
        warn!("Cleanup not fully implemented - Redis TTL handles expiration automatically");
        Ok(0)
    }
}
