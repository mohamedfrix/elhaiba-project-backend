use elhaiba_backend::config::PasswordResetConfig;
use elhaiba_backend::util::password_reset::{PasswordResetService, RedisPasswordResetService, ResetTokenInfo, PasswordResetError};
use elhaiba_backend::util::redis::{RedisServiceTrait, RedisError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;

/// Mock Redis service for testing
#[derive(Clone)]
pub struct MockRedisService {
    data: Arc<Mutex<HashMap<String, String>>>,
}

impl MockRedisService {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl RedisServiceTrait for MockRedisService {
    async fn set_string(&self, key: &str, value: &str) -> Result<(), RedisError> {
        let mut data = self.data.lock().unwrap();
        data.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn get_string(&self, key: &str) -> Result<Option<String>, RedisError> {
        let data = self.data.lock().unwrap();
        Ok(data.get(key).cloned())
    }

    async fn set_string_with_expiry(&self, key: &str, value: &str, _expiry_secs: u64) -> Result<(), RedisError> {
        // For simplicity, ignore expiry in mock
        self.set_string(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<bool, RedisError> {
        let mut data = self.data.lock().unwrap();
        match data.remove(key) {
            Some(_) => Ok(true),
            None => Err(RedisError::KeyNotFound),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, RedisError> {
        let data = self.data.lock().unwrap();
        Ok(data.contains_key(key))
    }

    async fn set_hash(&self, _key: &str, _data: &HashMap<String, String>) -> Result<(), RedisError> {
        // Not needed for password reset tests
        Ok(())
    }

    async fn get_hash(&self, _key: &str) -> Result<HashMap<String, String>, RedisError> {
        // Not needed for password reset tests
        Ok(HashMap::new())
    }

    async fn increment(&self, _key: &str) -> Result<i64, RedisError> {
        // Not needed for password reset tests
        Ok(1)
    }

    async fn get_ttl(&self, _key: &str) -> Result<i64, RedisError> {
        // Not needed for password reset tests
        Ok(-1)
    }

    async fn ping(&self) -> Result<String, RedisError> {
        Ok("PONG".to_string())
    }
}

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();
}

/// Create test password reset config
fn create_test_config() -> PasswordResetConfig {
    PasswordResetConfig::from_test_env()
}

/// Create test password reset service
fn create_test_service() -> RedisPasswordResetService {
    let config = create_test_config();
    let redis_service = Box::new(MockRedisService::new());
    RedisPasswordResetService::new(config, redis_service).expect("Failed to create test service")
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_reset_token_info_creation() {
        let token_info = ResetTokenInfo::new(
            "user123".to_string(),
            "user@example.com".to_string(),
            3600,
        );

        assert_eq!(token_info.user_id, "user123");
        assert_eq!(token_info.email, "user@example.com");
        assert!(!token_info.used);
        assert!(!token_info.is_expired());
        assert!(token_info.is_valid());
        assert!(token_info.created_at > 0);
        assert!(token_info.expires_at > token_info.created_at);
    }

    #[test]
    fn test_reset_token_info_expiration() {
        let mut token_info = ResetTokenInfo::new(
            "user123".to_string(),
            "user@example.com".to_string(),
            3600,
        );

        // Manually set expiration to past
        token_info.expires_at = chrono::Utc::now().timestamp() - 100;

        assert!(token_info.is_expired());
        assert!(!token_info.is_valid());
    }

    #[test]
    fn test_reset_token_info_used() {
        let mut token_info = ResetTokenInfo::new(
            "user123".to_string(),
            "user@example.com".to_string(),
            3600,
        );

        token_info.used = true;

        assert!(!token_info.is_valid());
        assert!(!token_info.is_expired()); // Still not expired, just used
    }

    #[test]
    fn test_password_reset_service_creation() {
        init_tracing();
        let _service = create_test_service();
        // Just test that service creation succeeds
    }

    #[tokio::test]
    async fn test_generate_reset_token() {
        init_tracing();
        let service = create_test_service();
        
        let result = service.generate_reset_token("user123", "user@example.com").await;
        
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.len(), 16); // Test config token length
        assert!(token.chars().all(|c| c.is_alphanumeric()));
    }

    #[tokio::test]
    async fn test_generate_reset_url() {
        init_tracing();
        let service = create_test_service();
        
        let result = service.generate_reset_url("user123", "user@example.com").await;
        
        assert!(result.is_ok());
        let url = result.unwrap();
        assert!(url.starts_with("http://localhost:3000/reset-password/"));
        
        // Extract token from URL
        let token_part = url.split('/').last().unwrap();
        assert_eq!(token_part.len(), 16); // Test config token length
    }

    #[tokio::test]
    async fn test_validate_reset_token() {
        init_tracing();
        let service = create_test_service();
        
        // Generate a token first
        let token = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        
        // Validate it
        let result = service.validate_reset_token(&token).await;
        assert!(result.is_ok());
        
        let token_info = result.unwrap();
        assert_eq!(token_info.user_id, "user123");
        assert_eq!(token_info.email, "user@example.com");
        assert!(!token_info.used);
        assert!(token_info.is_valid());
    }

    #[tokio::test]
    async fn test_use_reset_token() {
        init_tracing();
        let service = create_test_service();
        
        // Generate a token first
        let token = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        
        // Use it
        let result = service.use_reset_token(&token).await;
        assert!(result.is_ok());
        
        let token_info = result.unwrap();
        assert_eq!(token_info.user_id, "user123");
        assert!(token_info.used);
        
        // Try to validate again - should fail
        let validation_result = service.validate_reset_token(&token).await;
        assert!(validation_result.is_err());
        assert!(matches!(validation_result.unwrap_err(), PasswordResetError::TokenAlreadyUsed));
    }

    #[tokio::test]
    async fn test_revoke_reset_token() {
        init_tracing();
        let service = create_test_service();
        
        // Generate a token first
        let token = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        
        // Revoke it
        let result = service.revoke_reset_token(&token).await;
        assert!(result.is_ok());
        
        // Try to validate - should fail
        let validation_result = service.validate_reset_token(&token).await;
        assert!(validation_result.is_err());
        assert!(matches!(validation_result.unwrap_err(), PasswordResetError::TokenNotFound));
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_reset_token_empty_user_id() {
        let service = create_test_service();
        let result = service.generate_reset_token("", "user@example.com").await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordResetError::TokenGenerationError(_)));
    }

    #[tokio::test]
    async fn test_generate_reset_token_empty_email() {
        let service = create_test_service();
        let result = service.generate_reset_token("user123", "").await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordResetError::TokenGenerationError(_)));
    }

    #[tokio::test]
    async fn test_validate_reset_token_invalid_length() {
        let service = create_test_service();
        let result = service.validate_reset_token("short").await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordResetError::InvalidToken));
    }

    #[tokio::test]
    async fn test_validate_reset_token_empty() {
        let service = create_test_service();
        let result = service.validate_reset_token("").await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordResetError::InvalidToken));
    }

    #[tokio::test]
    async fn test_validate_reset_token_not_found() {
        let service = create_test_service();
        
        // Create a token of correct length but not stored
        let fake_token = "a".repeat(16); // Test config token length
        let result = service.validate_reset_token(&fake_token).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordResetError::TokenNotFound));
    }

    #[tokio::test]
    async fn test_revoke_non_existent_token() {
        let service = create_test_service();
        
        let fake_token = "a".repeat(16); // Test config token length
        let result = service.revoke_reset_token(&fake_token).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordResetError::TokenNotFound));
    }

    #[tokio::test]
    async fn test_unicode_in_user_data() {
        let service = create_test_service();
        
        let unicode_user_id = "用户123";
        let unicode_email = "用户@example.com";
        
        let result = service.generate_reset_token(unicode_user_id, unicode_email).await;
        assert!(result.is_ok());
        
        let token = result.unwrap();
        let validation_result = service.validate_reset_token(&token).await;
        assert!(validation_result.is_ok());
        
        let token_info = validation_result.unwrap();
        assert_eq!(token_info.user_id, unicode_user_id);
        assert_eq!(token_info.email, unicode_email);
    }

    #[tokio::test]
    async fn test_very_long_user_data() {
        let service = create_test_service();
        
        let long_user_id = "a".repeat(1000);
        let long_email = format!("{}@example.com", "b".repeat(100));
        
        let result = service.generate_reset_token(&long_user_id, &long_email).await;
        assert!(result.is_ok());
        
        let token = result.unwrap();
        let validation_result = service.validate_reset_token(&token).await;
        assert!(validation_result.is_ok());
        
        let token_info = validation_result.unwrap();
        assert_eq!(token_info.user_id, long_user_id);
        assert_eq!(token_info.email, long_email);
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_config_generate_reset_url() {
        let config = create_test_config();
        let token = "abc123def456";
        let url = config.generate_reset_url(token);
        
        assert_eq!(url, "http://localhost:3000/reset-password/abc123def456");
    }

    #[test]
    fn test_config_generate_reset_url_with_trailing_slash() {
        let mut config = create_test_config();
        config.frontend_base_url = "http://localhost:3000/".to_string();
        
        let token = "abc123def456";
        let url = config.generate_reset_url(token);
        
        assert_eq!(url, "http://localhost:3000/reset-password/abc123def456");
    }

    #[test]
    fn test_config_get_redis_key() {
        let config = create_test_config();
        let token = "abc123def456";
        let key = config.get_redis_key(token);
        
        assert_eq!(key, "test_reset_token:abc123def456");
    }

    #[test]
    fn test_config_validation() {
        let config = create_test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_empty_base_url() {
        let mut config = create_test_config();
        config.frontend_base_url = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_base_url() {
        let mut config = create_test_config();
        config.frontend_base_url = "invalid-url".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_reset_path() {
        let mut config = create_test_config();
        config.reset_path = "no-slash".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_short_token_length() {
        let mut config = create_test_config();
        config.token_length = 7;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_expiration() {
        let mut config = create_test_config();
        config.token_expiration_secs = 0;
        assert!(config.validate().is_err());
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_password_reset_error_types() {
        let errors = vec![
            PasswordResetError::ConfigError("Config error".to_string()),
            PasswordResetError::TokenGenerationError("Token error".to_string()),
            PasswordResetError::TokenNotFound,
            PasswordResetError::InvalidToken,
            PasswordResetError::TokenAlreadyUsed,
        ];

        for error in errors {
            let display = format!("{}", error);
            let debug = format!("{:?}", error);
            
            assert!(!display.is_empty());
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_invalid_config_creation() {
        let mut config = create_test_config();
        config.frontend_base_url = "".to_string();
        
        let redis_service = Box::new(MockRedisService::new());
        let result = RedisPasswordResetService::new(config, redis_service);
        
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, PasswordResetError::ConfigError(_)));
        }
    }
}

#[cfg(test)]
mod workflow_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_password_reset_workflow() {
        init_tracing();
        let service = create_test_service();
        
        // Step 1: Generate reset URL
        let reset_url = service.generate_reset_url("user123", "user@example.com").await.unwrap();
        assert!(reset_url.contains("http://localhost:3000/reset-password/"));
        
        // Step 2: Extract token from URL
        let token = reset_url.split('/').last().unwrap();
        
        // Step 3: Validate token
        let token_info = service.validate_reset_token(token).await.unwrap();
        assert_eq!(token_info.user_id, "user123");
        assert_eq!(token_info.email, "user@example.com");
        assert!(token_info.is_valid());
        
        // Step 4: Use token (simulate password reset)
        let used_token_info = service.use_reset_token(token).await.unwrap();
        assert!(used_token_info.used);
        
        // Step 5: Verify token cannot be used again
        let reuse_result = service.validate_reset_token(token).await;
        assert!(reuse_result.is_err());
        assert!(matches!(reuse_result.unwrap_err(), PasswordResetError::TokenAlreadyUsed));
    }

    #[tokio::test]
    async fn test_multiple_tokens_for_same_user() {
        init_tracing();
        let service = create_test_service();
        
        // Generate multiple tokens for the same user
        let token1 = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        let token2 = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        let token3 = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        
        // All tokens should be different
        assert_ne!(token1, token2);
        assert_ne!(token2, token3);
        assert_ne!(token1, token3);
        
        // All tokens should be valid
        assert!(service.validate_reset_token(&token1).await.is_ok());
        assert!(service.validate_reset_token(&token2).await.is_ok());
        assert!(service.validate_reset_token(&token3).await.is_ok());
        
        // Use one token
        assert!(service.use_reset_token(&token1).await.is_ok());
        
        // Other tokens should still be valid
        assert!(service.validate_reset_token(&token2).await.is_ok());
        assert!(service.validate_reset_token(&token3).await.is_ok());
        
        // Used token should not be valid
        assert!(service.validate_reset_token(&token1).await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_and_regenerate_workflow() {
        init_tracing();
        let service = create_test_service();
        
        // Generate initial token
        let token1 = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        assert!(service.validate_reset_token(&token1).await.is_ok());
        
        // Revoke token (e.g., user requests new reset)
        assert!(service.revoke_reset_token(&token1).await.is_ok());
        
        // Generate new token
        let token2 = service.generate_reset_token("user123", "user@example.com").await.unwrap();
        
        // Old token should not be valid
        assert!(service.validate_reset_token(&token1).await.is_err());
        
        // New token should be valid
        assert!(service.validate_reset_token(&token2).await.is_ok());
    }
}
