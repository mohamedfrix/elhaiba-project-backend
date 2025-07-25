# Password Reset Utility Documentation

## Overview

The Password Reset utility provides a secure, Redis-backed token management system for handling password reset requests in the ElHaiba backend application. It implements time-limited tokens, secure generation, validation, and comprehensive lifecycle management with Redis storage for scalability and persistence.

## Purpose and Philosophy

### Design Philosophy

The Password Reset utility is built around these core security principles:

1. **Time-Limited Security**: All reset tokens have configurable expiration times
2. **Single-Use Tokens**: Tokens are invalidated after successful use
3. **Cryptographic Randomness**: Uses secure random generation for unpredictable tokens
4. **Auditability**: Complete token lifecycle logging and tracking
5. **Scalable Storage**: Redis-backed for distributed systems and high availability
6. **Revocation Support**: Administrative ability to revoke tokens
7. **Rate Limiting Ready**: Designed to integrate with rate limiting systems

### Use Cases

- **Password Reset Flows**: Secure token generation for email-based password resets
- **Account Recovery**: Multi-step account recovery processes
- **Administrative Resets**: Admin-initiated password resets with tracking
- **Security Incident Response**: Bulk token revocation during security events
- **Token Lifecycle Management**: Automated cleanup and expiration handling
- **Audit and Compliance**: Complete reset request tracking and reporting

## Architecture

### Core Components

#### 1. PasswordResetService
The main service implementing token management operations:

```rust
pub struct PasswordResetService {
    redis_service: Arc<RedisService>,
    config: PasswordResetConfig,
}
```

#### 2. PasswordResetTrait
Defines the interface for password reset operations:

```rust
#[async_trait]
pub trait PasswordResetTrait {
    async fn generate_reset_token(&self, user_id: &str) -> Result<String, PasswordResetError>;
    async fn validate_reset_token(&self, token: &str) -> Result<ResetTokenInfo, PasswordResetError>;
    async fn use_reset_token(&self, token: &str) -> Result<String, PasswordResetError>;
    async fn revoke_reset_token(&self, token: &str) -> Result<(), PasswordResetError>;
    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<(), PasswordResetError>;
    async fn cleanup_expired_tokens(&self) -> Result<u64, PasswordResetError>;
}
```

#### 3. ResetTokenInfo
Comprehensive token metadata structure:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetTokenInfo {
    pub user_id: String,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub request_ip: Option<String>,
    pub user_agent: Option<String>,
}
```

#### 4. PasswordResetError
Comprehensive error handling for reset operations:

```rust
#[derive(Debug, Clone)]
pub enum PasswordResetError {
    TokenGenerationFailed(String),
    TokenNotFound,
    TokenExpired,
    TokenAlreadyUsed,
    TokenRevoked,
    RedisError(String),
    SerializationError(String),
    InvalidTokenFormat,
}
```

## Implementation Details

### Token Generation Process

Secure token generation with metadata tracking:

```rust
async fn generate_reset_token(&self, user_id: &str) -> Result<String, PasswordResetError> {
    // Generate cryptographically secure random token
    let token = generate_secure_token(32);
    
    let now = Utc::now();
    let expires_at = now + Duration::seconds(self.config.token_expiry_seconds);
    
    let token_info = ResetTokenInfo {
        user_id: user_id.to_string(),
        token: token.clone(),
        created_at: now,
        expires_at,
        used: false,
        used_at: None,
        revoked: false,
        revoked_at: None,
        request_ip: None,
        user_agent: None,
    };
    
    // Store in Redis with expiration
    let key = format!("password_reset_token:{}", token);
    let serialized = serde_json::to_string(&token_info)
        .map_err(|e| PasswordResetError::SerializationError(e.to_string()))?;
    
    self.redis_service
        .setex(&key, self.config.token_expiry_seconds as u64, &serialized)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    // Also maintain user -> tokens mapping for bulk operations
    let user_tokens_key = format!("user_reset_tokens:{}", user_id);
    self.redis_service
        .sadd(&user_tokens_key, &token)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    // Set expiration on user tokens set
    self.redis_service
        .expire(&user_tokens_key, self.config.token_expiry_seconds as u64)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    tracing::info!(
        user_id = %user_id,
        token_length = token.len(),
        expires_at = %expires_at,
        "Generated password reset token"
    );
    
    Ok(token)
}

fn generate_secure_token(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
```

### Token Validation Process

Comprehensive validation with state checking:

```rust
async fn validate_reset_token(&self, token: &str) -> Result<ResetTokenInfo, PasswordResetError> {
    let key = format!("password_reset_token:{}", token);
    
    // Retrieve token info from Redis
    let serialized_info = self.redis_service
        .get(&key)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?
        .ok_or(PasswordResetError::TokenNotFound)?;
    
    let mut token_info: ResetTokenInfo = serde_json::from_str(&serialized_info)
        .map_err(|e| PasswordResetError::SerializationError(e.to_string()))?;
    
    let now = Utc::now();
    
    // Check if token is expired
    if now > token_info.expires_at {
        tracing::warn!(
            token = %token,
            user_id = %token_info.user_id,
            expired_at = %token_info.expires_at,
            "Attempted to validate expired reset token"
        );
        return Err(PasswordResetError::TokenExpired);
    }
    
    // Check if token is already used
    if token_info.used {
        tracing::warn!(
            token = %token,
            user_id = %token_info.user_id,
            used_at = ?token_info.used_at,
            "Attempted to validate already used reset token"
        );
        return Err(PasswordResetError::TokenAlreadyUsed);
    }
    
    // Check if token is revoked
    if token_info.revoked {
        tracing::warn!(
            token = %token,
            user_id = %token_info.user_id,
            revoked_at = ?token_info.revoked_at,
            "Attempted to validate revoked reset token"
        );
        return Err(PasswordResetError::TokenRevoked);
    }
    
    tracing::info!(
        token = %token,
        user_id = %token_info.user_id,
        "Successfully validated reset token"
    );
    
    Ok(token_info)
}
```

### Token Usage Process

Secure token consumption with atomic operations:

```rust
async fn use_reset_token(&self, token: &str) -> Result<String, PasswordResetError> {
    // First validate the token
    let mut token_info = self.validate_reset_token(token).await?;
    
    // Mark token as used
    token_info.used = true;
    token_info.used_at = Some(Utc::now());
    
    // Update in Redis
    let key = format!("password_reset_token:{}", token);
    let serialized = serde_json::to_string(&token_info)
        .map_err(|e| PasswordResetError::SerializationError(e.to_string()))?;
    
    // Use a short expiration to keep used tokens briefly for audit purposes
    let audit_retention_seconds = 3600; // 1 hour
    self.redis_service
        .setex(&key, audit_retention_seconds, &serialized)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    // Remove from user's active tokens set
    let user_tokens_key = format!("user_reset_tokens:{}", token_info.user_id);
    self.redis_service
        .srem(&user_tokens_key, token)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    tracing::info!(
        token = %token,
        user_id = %token_info.user_id,
        used_at = %token_info.used_at.unwrap(),
        "Password reset token used successfully"
    );
    
    Ok(token_info.user_id)
}
```

### Token Revocation Process

Administrative token revocation with bulk operations:

```rust
async fn revoke_reset_token(&self, token: &str) -> Result<(), PasswordResetError> {
    let key = format!("password_reset_token:{}", token);
    
    let serialized_info = self.redis_service
        .get(&key)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?
        .ok_or(PasswordResetError::TokenNotFound)?;
    
    let mut token_info: ResetTokenInfo = serde_json::from_str(&serialized_info)
        .map_err(|e| PasswordResetError::SerializationError(e.to_string()))?;
    
    // Mark as revoked
    token_info.revoked = true;
    token_info.revoked_at = Some(Utc::now());
    
    // Update in Redis with short retention for audit
    let serialized = serde_json::to_string(&token_info)
        .map_err(|e| PasswordResetError::SerializationError(e.to_string()))?;
    
    let audit_retention_seconds = 3600; // 1 hour
    self.redis_service
        .setex(&key, audit_retention_seconds, &serialized)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    // Remove from user's active tokens
    let user_tokens_key = format!("user_reset_tokens:{}", token_info.user_id);
    self.redis_service
        .srem(&user_tokens_key, token)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    tracing::warn!(
        token = %token,
        user_id = %token_info.user_id,
        revoked_at = %token_info.revoked_at.unwrap(),
        "Password reset token revoked"
    );
    
    Ok(())
}

async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<(), PasswordResetError> {
    let user_tokens_key = format!("user_reset_tokens:{}", user_id);
    
    // Get all tokens for this user
    let tokens: Vec<String> = self.redis_service
        .smembers(&user_tokens_key)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    let mut revoked_count = 0;
    
    for token in tokens {
        match self.revoke_reset_token(&token).await {
            Ok(()) => revoked_count += 1,
            Err(PasswordResetError::TokenNotFound) => {
                // Token already cleaned up, that's okay
                continue;
            }
            Err(e) => {
                tracing::error!(
                    token = %token,
                    user_id = %user_id,
                    error = ?e,
                    "Failed to revoke user token during bulk revocation"
                );
            }
        }
    }
    
    // Clear the user tokens set
    self.redis_service
        .del(&user_tokens_key)
        .await
        .map_err(|e| PasswordResetError::RedisError(e.to_string()))?;
    
    tracing::warn!(
        user_id = %user_id,
        revoked_count = revoked_count,
        "Revoked all reset tokens for user"
    );
    
    Ok(())
}
```

## API Reference

### Primary Methods

#### `generate_reset_token(user_id: &str) -> Result<String, PasswordResetError>`
Generates a new password reset token for a user.

**Parameters:**
- `user_id`: The unique identifier of the user requesting password reset

**Returns:**
- `Ok(String)`: The generated reset token
- `Err(PasswordResetError)`: Token generation failed

**Example:**
```rust
let token = password_reset_service.generate_reset_token("user_123").await?;
// token: "AbC123DeF456GhI789JkL012MnO345PqR"
```

#### `validate_reset_token(token: &str) -> Result<ResetTokenInfo, PasswordResetError>`
Validates a reset token and returns its information.

**Parameters:**
- `token`: The reset token to validate

**Returns:**
- `Ok(ResetTokenInfo)`: Token is valid with full metadata
- `Err(PasswordResetError)`: Token is invalid, expired, used, or revoked

**Example:**
```rust
match password_reset_service.validate_reset_token(&token).await {
    Ok(token_info) => {
        println!("Token valid for user: {}", token_info.user_id);
        println!("Expires at: {}", token_info.expires_at);
    },
    Err(PasswordResetError::TokenExpired) => {
        return Err("Reset link has expired");
    },
    Err(PasswordResetError::TokenAlreadyUsed) => {
        return Err("Reset link has already been used");
    },
    Err(_) => {
        return Err("Invalid reset link");
    }
}
```

#### `use_reset_token(token: &str) -> Result<String, PasswordResetError>`
Consumes a reset token and returns the associated user ID.

**Parameters:**
- `token`: The reset token to consume

**Returns:**
- `Ok(String)`: The user ID associated with the token
- `Err(PasswordResetError)`: Token cannot be used

**Example:**
```rust
let user_id = password_reset_service.use_reset_token(&token).await?;
// Now proceed with password reset for user_id
```

#### `revoke_reset_token(token: &str) -> Result<(), PasswordResetError>`
Revokes a specific reset token.

**Parameters:**
- `token`: The reset token to revoke

**Returns:**
- `Ok(())`: Token successfully revoked
- `Err(PasswordResetError)`: Revocation failed

**Example:**
```rust
password_reset_service.revoke_reset_token(&suspicious_token).await?;
```

#### `revoke_all_user_tokens(user_id: &str) -> Result<(), PasswordResetError>`
Revokes all active reset tokens for a specific user.

**Parameters:**
- `user_id`: The user whose tokens should be revoked

**Returns:**
- `Ok(())`: All tokens successfully revoked
- `Err(PasswordResetError)`: Bulk revocation failed

**Example:**
```rust
// During security incident or password change
password_reset_service.revoke_all_user_tokens("user_123").await?;
```

#### `cleanup_expired_tokens() -> Result<u64, PasswordResetError>`
Removes expired tokens from storage (maintenance operation).

**Returns:**
- `Ok(u64)`: Number of tokens cleaned up
- `Err(PasswordResetError)`: Cleanup operation failed

**Example:**
```rust
let cleaned_count = password_reset_service.cleanup_expired_tokens().await?;
println!("Cleaned up {} expired tokens", cleaned_count);
```

## Configuration

### PasswordResetConfig Structure

```rust
#[derive(Debug, Clone)]
pub struct PasswordResetConfig {
    pub token_expiry_seconds: i64,        // Default: 3600 (1 hour)
    pub token_length: usize,              // Default: 32 characters
    pub max_tokens_per_user: usize,       // Default: 5
    pub cleanup_interval_seconds: u64,    // Default: 3600 (1 hour)
    pub audit_retention_seconds: u64,     // Default: 86400 (24 hours)
    pub rate_limit_window_seconds: u64,   // Default: 300 (5 minutes)
    pub rate_limit_max_requests: usize,   // Default: 3
}

impl Default for PasswordResetConfig {
    fn default() -> Self {
        Self {
            token_expiry_seconds: 3600,        // 1 hour
            token_length: 32,
            max_tokens_per_user: 5,
            cleanup_interval_seconds: 3600,
            audit_retention_seconds: 86400,    // 24 hours
            rate_limit_window_seconds: 300,    // 5 minutes
            rate_limit_max_requests: 3,
        }
    }
}
```

### Redis Key Structure

The service uses these Redis key patterns:

```rust
// Individual token storage
"password_reset_token:{token}" -> ResetTokenInfo (JSON)

// User's active tokens set
"user_reset_tokens:{user_id}" -> Set<String>

// Rate limiting (if implemented)
"reset_rate_limit:{identifier}" -> Counter with expiration

// Cleanup tracking
"reset_cleanup_last_run" -> Timestamp
```

## Usage Examples

### Complete Password Reset Flow

```rust
use elhaiba_backend::util::password_reset::{PasswordResetService, PasswordResetTrait};
use elhaiba_backend::util::email::{EmailService, EmailTrait};

pub struct PasswordResetHandler {
    reset_service: Arc<PasswordResetService>,
    email_service: Arc<EmailService>,
    user_service: Arc<UserService>,
}

impl PasswordResetHandler {
    pub async fn initiate_password_reset(
        &self,
        email: &str,
        request_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), ResetError> {
        // Find user by email
        let user = self.user_service.find_by_email(email).await
            .ok_or(ResetError::UserNotFound)?;
        
        // Check rate limiting
        if self.is_rate_limited(&user.id).await? {
            return Err(ResetError::RateLimited);
        }
        
        // Generate reset token
        let token = self.reset_service.generate_reset_token(&user.id).await
            .map_err(ResetError::TokenGenerationFailed)?;
        
        // Create reset URL
        let reset_url = format!("https://yourdomain.com/reset-password?token={}", token);
        
        // Send email
        self.email_service.send_password_reset_email(
            &user.email,
            &user.name.unwrap_or_else(|| "User".to_string()),
            &reset_url,
        ).await.map_err(ResetError::EmailSendFailed)?;
        
        tracing::info!(
            user_id = %user.id,
            email = %user.email,
            request_ip = ?request_ip,
            "Password reset initiated"
        );
        
        Ok(())
    }
    
    pub async fn complete_password_reset(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<(), ResetError> {
        // Validate new password strength
        if let Err(errors) = PasswordUtilsImpl::validate_password_strength(new_password) {
            return Err(ResetError::WeakPassword(errors));
        }
        
        // Use the reset token (this validates and consumes it)
        let user_id = self.reset_service.use_reset_token(token).await
            .map_err(|e| match e {
                PasswordResetError::TokenNotFound => ResetError::InvalidToken,
                PasswordResetError::TokenExpired => ResetError::ExpiredToken,
                PasswordResetError::TokenAlreadyUsed => ResetError::TokenAlreadyUsed,
                PasswordResetError::TokenRevoked => ResetError::TokenRevoked,
                _ => ResetError::TokenValidationFailed(e),
            })?;
        
        // Hash the new password
        let new_password_hash = PasswordUtilsImpl::hash_password(new_password)
            .map_err(ResetError::PasswordHashingFailed)?;
        
        // Update user password
        self.user_service.update_password(&user_id, &new_password_hash).await
            .map_err(ResetError::PasswordUpdateFailed)?;
        
        // Revoke any other active reset tokens for this user
        if let Err(e) = self.reset_service.revoke_all_user_tokens(&user_id).await {
            tracing::warn!(
                user_id = %user_id,
                error = ?e,
                "Failed to revoke other tokens after successful password reset"
            );
        }
        
        tracing::info!(
            user_id = %user_id,
            "Password reset completed successfully"
        );
        
        Ok(())
    }
    
    async fn is_rate_limited(&self, user_id: &str) -> Result<bool, ResetError> {
        // Simple rate limiting implementation
        let key = format!("reset_rate_limit:{}", user_id);
        let current_count: i64 = self.reset_service.redis_service
            .incr(&key, 1)
            .await
            .map_err(ResetError::RateLimitCheckFailed)?;
        
        if current_count == 1 {
            // Set expiration for the first request
            self.reset_service.redis_service
                .expire(&key, 300) // 5 minutes
                .await
                .map_err(ResetError::RateLimitCheckFailed)?;
        }
        
        Ok(current_count > 3) // Max 3 requests per 5 minutes
    }
}
```

### Administrative Token Management

```rust
pub struct PasswordResetAdminService {
    reset_service: Arc<PasswordResetService>,
    audit_service: Arc<AuditService>,
}

impl PasswordResetAdminService {
    pub async fn revoke_user_tokens(
        &self,
        admin_user_id: &str,
        target_user_id: &str,
        reason: &str,
    ) -> Result<(), AdminError> {
        // Log the administrative action
        self.audit_service.log_admin_action(
            admin_user_id,
            "revoke_reset_tokens",
            &json!({
                "target_user_id": target_user_id,
                "reason": reason,
            }),
        ).await?;
        
        // Revoke all tokens
        self.reset_service.revoke_all_user_tokens(target_user_id).await
            .map_err(AdminError::TokenRevocationFailed)?;
        
        tracing::warn!(
            admin_user_id = %admin_user_id,
            target_user_id = %target_user_id,
            reason = %reason,
            "Admin revoked all reset tokens for user"
        );
        
        Ok(())
    }
    
    pub async fn get_user_reset_tokens(
        &self,
        user_id: &str,
    ) -> Result<Vec<ResetTokenInfo>, AdminError> {
        let user_tokens_key = format!("user_reset_tokens:{}", user_id);
        
        let tokens: Vec<String> = self.reset_service.redis_service
            .smembers(&user_tokens_key)
            .await
            .map_err(AdminError::RedisError)?;
        
        let mut token_infos = Vec::new();
        
        for token in tokens {
            match self.reset_service.validate_reset_token(&token).await {
                Ok(token_info) => token_infos.push(token_info),
                Err(_) => {
                    // Token might be expired or invalid, skip it
                    continue;
                }
            }
        }
        
        Ok(token_infos)
    }
    
    pub async fn bulk_cleanup_expired_tokens(&self) -> Result<CleanupReport, AdminError> {
        let start_time = std::time::Instant::now();
        
        let cleaned_count = self.reset_service.cleanup_expired_tokens().await
            .map_err(AdminError::CleanupFailed)?;
        
        let duration = start_time.elapsed();
        
        let report = CleanupReport {
            tokens_cleaned: cleaned_count,
            duration_ms: duration.as_millis() as u64,
            completed_at: Utc::now(),
        };
        
        tracing::info!(
            cleaned_count = cleaned_count,
            duration_ms = duration.as_millis(),
            "Completed bulk cleanup of expired reset tokens"
        );
        
        Ok(report)
    }
}

#[derive(Debug, Serialize)]
pub struct CleanupReport {
    pub tokens_cleaned: u64,
    pub duration_ms: u64,
    pub completed_at: DateTime<Utc>,
}
```

### API Integration

```rust
use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::Json as ResponseJson,
    Extension,
};

#[derive(serde::Deserialize)]
pub struct InitiateResetRequest {
    pub email: String,
}

#[derive(serde::Deserialize)]
pub struct CompleteResetRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(serde::Deserialize)]
pub struct ValidateTokenQuery {
    pub token: String,
}

#[derive(serde::Serialize)]
pub struct ResetResponse {
    pub message: String,
    pub success: bool,
}

#[derive(serde::Serialize)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub user_id: Option<String>,
}

pub async fn initiate_password_reset(
    Extension(reset_handler): Extension<Arc<PasswordResetHandler>>,
    Extension(request_info): Extension<RequestInfo>,
    Json(request): Json<InitiateResetRequest>,
) -> Result<ResponseJson<ResetResponse>, StatusCode> {
    match reset_handler.initiate_password_reset(
        &request.email,
        request_info.client_ip,
        request_info.user_agent,
    ).await {
        Ok(()) => Ok(ResponseJson(ResetResponse {
            message: "If an account with that email exists, a password reset link has been sent.".to_string(),
            success: true,
        })),
        Err(ResetError::RateLimited) => Ok(ResponseJson(ResetResponse {
            message: "Too many reset requests. Please try again later.".to_string(),
            success: false,
        })),
        Err(_) => {
            // Don't reveal whether the email exists or not
            Ok(ResponseJson(ResetResponse {
                message: "If an account with that email exists, a password reset link has been sent.".to_string(),
                success: true,
            }))
        }
    }
}

pub async fn validate_reset_token(
    Extension(reset_service): Extension<Arc<PasswordResetService>>,
    Query(query): Query<ValidateTokenQuery>,
) -> Result<ResponseJson<TokenValidationResponse>, StatusCode> {
    match reset_service.validate_reset_token(&query.token).await {
        Ok(token_info) => Ok(ResponseJson(TokenValidationResponse {
            valid: true,
            expires_at: Some(token_info.expires_at),
            user_id: Some(token_info.user_id),
        })),
        Err(_) => Ok(ResponseJson(TokenValidationResponse {
            valid: false,
            expires_at: None,
            user_id: None,
        })),
    }
}

pub async fn complete_password_reset(
    Extension(reset_handler): Extension<Arc<PasswordResetHandler>>,
    Json(request): Json<CompleteResetRequest>,
) -> Result<ResponseJson<ResetResponse>, StatusCode> {
    match reset_handler.complete_password_reset(&request.token, &request.new_password).await {
        Ok(()) => Ok(ResponseJson(ResetResponse {
            message: "Password has been reset successfully.".to_string(),
            success: true,
        })),
        Err(ResetError::InvalidToken) => Ok(ResponseJson(ResetResponse {
            message: "Invalid reset token.".to_string(),
            success: false,
        })),
        Err(ResetError::ExpiredToken) => Ok(ResponseJson(ResetResponse {
            message: "Reset token has expired. Please request a new one.".to_string(),
            success: false,
        })),
        Err(ResetError::TokenAlreadyUsed) => Ok(ResponseJson(ResetResponse {
            message: "Reset token has already been used.".to_string(),
            success: false,
        })),
        Err(ResetError::WeakPassword(errors)) => Ok(ResponseJson(ResetResponse {
            message: format!("Password requirements not met: {}", errors.join(", ")),
            success: false,
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
```

### Scheduled Maintenance

```rust
use tokio_cron_scheduler::{JobScheduler, Job};

pub async fn setup_reset_token_maintenance(
    reset_service: Arc<PasswordResetService>,
) -> Result<(), SchedulerError> {
    let scheduler = JobScheduler::new().await?;
    
    // Cleanup expired tokens every hour
    let cleanup_service = reset_service.clone();
    let cleanup_job = Job::new_async("0 0 * * * *", move |_uuid, _l| {
        let service = cleanup_service.clone();
        Box::pin(async move {
            match service.cleanup_expired_tokens().await {
                Ok(count) => {
                    tracing::info!(
                        cleaned_count = count,
                        "Scheduled cleanup of expired reset tokens completed"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = ?e,
                        "Scheduled cleanup of expired reset tokens failed"
                    );
                }
            }
        })
    })?;
    
    scheduler.add(cleanup_job).await?;
    scheduler.start().await?;
    
    Ok(())
}
```

## Error Handling

### Comprehensive Error Recovery

```rust
impl From<redis::RedisError> for PasswordResetError {
    fn from(err: redis::RedisError) -> Self {
        PasswordResetError::RedisError(err.to_string())
    }
}

impl From<serde_json::Error> for PasswordResetError {
    fn from(err: serde_json::Error) -> Self {
        PasswordResetError::SerializationError(err.to_string())
    }
}

// Error handling in application layer
pub async fn handle_reset_error(
    error: PasswordResetError,
    user_context: &UserContext,
) -> ApiResponse {
    match error {
        PasswordResetError::TokenNotFound => {
            tracing::warn!(
                user_id = ?user_context.user_id,
                "User attempted to use non-existent reset token"
            );
            ApiResponse::error("Invalid or expired reset token")
        },
        PasswordResetError::TokenExpired => {
            tracing::info!(
                user_id = ?user_context.user_id,
                "User attempted to use expired reset token"
            );
            ApiResponse::error("Reset token has expired. Please request a new one.")
        },
        PasswordResetError::TokenAlreadyUsed => {
            tracing::warn!(
                user_id = ?user_context.user_id,
                "User attempted to reuse reset token"
            );
            ApiResponse::error("Reset token has already been used")
        },
        PasswordResetError::TokenRevoked => {
            tracing::warn!(
                user_id = ?user_context.user_id,
                "User attempted to use revoked reset token"
            );
            ApiResponse::error("Reset token has been revoked")
        },
        PasswordResetError::RedisError(msg) => {
            tracing::error!(
                error = %msg,
                user_id = ?user_context.user_id,
                "Redis error during password reset operation"
            );
            ApiResponse::internal_error("Service temporarily unavailable")
        },
        PasswordResetError::SerializationError(msg) => {
            tracing::error!(
                error = %msg,
                user_id = ?user_context.user_id,
                "Serialization error during password reset operation"
            );
            ApiResponse::internal_error("Service temporarily unavailable")
        },
        PasswordResetError::TokenGenerationFailed(msg) => {
            tracing::error!(
                error = %msg,
                user_id = ?user_context.user_id,
                "Failed to generate reset token"
            );
            ApiResponse::internal_error("Unable to generate reset token")
        },
        PasswordResetError::InvalidTokenFormat => {
            tracing::warn!(
                user_id = ?user_context.user_id,
                "User provided malformed reset token"
            );
            ApiResponse::error("Invalid token format")
        },
    }
}
```

## Testing

### Unit Tests

The Password Reset utility includes comprehensive unit tests:

#### Token Generation Tests
```rust
#[tokio::test]
async fn test_generate_reset_token_success() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    let token = service.generate_reset_token(user_id).await.unwrap();
    
    // Token should not be empty
    assert!(!token.is_empty());
    
    // Token should have expected length
    assert_eq!(token.len(), 32);
    
    // Token should contain only alphanumeric characters
    assert!(token.chars().all(|c| c.is_alphanumeric()));
}

#[tokio::test]
async fn test_generate_multiple_tokens_unique() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    let mut tokens = std::collections::HashSet::new();
    
    // Generate multiple tokens and ensure uniqueness
    for _ in 0..100 {
        let token = service.generate_reset_token(user_id).await.unwrap();
        assert!(tokens.insert(token), "All generated tokens should be unique");
    }
}
```

#### Token Validation Tests
```rust
#[tokio::test]
async fn test_validate_reset_token_success() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    let token = service.generate_reset_token(user_id).await.unwrap();
    
    let token_info = service.validate_reset_token(&token).await.unwrap();
    
    assert_eq!(token_info.user_id, user_id);
    assert_eq!(token_info.token, token);
    assert!(!token_info.used);
    assert!(!token_info.revoked);
    assert!(token_info.expires_at > Utc::now());
}

#[tokio::test]
async fn test_validate_nonexistent_token() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let result = service.validate_reset_token("nonexistent_token").await;
    
    assert!(matches!(result, Err(PasswordResetError::TokenNotFound)));
}
```

#### Token Usage Tests
```rust
#[tokio::test]
async fn test_use_reset_token_success() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    let token = service.generate_reset_token(user_id).await.unwrap();
    
    let returned_user_id = service.use_reset_token(&token).await.unwrap();
    assert_eq!(returned_user_id, user_id);
    
    // Token should now be marked as used
    let result = service.validate_reset_token(&token).await;
    assert!(matches!(result, Err(PasswordResetError::TokenAlreadyUsed)));
}

#[tokio::test]
async fn test_use_token_twice_fails() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    let token = service.generate_reset_token(user_id).await.unwrap();
    
    // First use should succeed
    service.use_reset_token(&token).await.unwrap();
    
    // Second use should fail
    let result = service.use_reset_token(&token).await;
    assert!(matches!(result, Err(PasswordResetError::TokenAlreadyUsed)));
}
```

#### Token Revocation Tests
```rust
#[tokio::test]
async fn test_revoke_reset_token() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    let token = service.generate_reset_token(user_id).await.unwrap();
    
    // Revoke the token
    service.revoke_reset_token(&token).await.unwrap();
    
    // Token should now be revoked
    let result = service.validate_reset_token(&token).await;
    assert!(matches!(result, Err(PasswordResetError::TokenRevoked)));
}

#[tokio::test]
async fn test_revoke_all_user_tokens() {
    let redis_service = Arc::new(MockRedisService::new());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    
    // Generate multiple tokens for the user
    let mut tokens = Vec::new();
    for _ in 0..3 {
        let token = service.generate_reset_token(user_id).await.unwrap();
        tokens.push(token);
    }
    
    // Revoke all tokens for the user
    service.revoke_all_user_tokens(user_id).await.unwrap();
    
    // All tokens should now be revoked
    for token in tokens {
        let result = service.validate_reset_token(&token).await;
        assert!(matches!(result, Err(PasswordResetError::TokenRevoked)));
    }
}
```

#### Expiration Tests
```rust
#[tokio::test]
async fn test_token_expiration() {
    let redis_service = Arc::new(MockRedisService::new());
    let mut config = PasswordResetConfig::default();
    config.token_expiry_seconds = 1; // 1 second expiry for testing
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "test_user_123";
    let token = service.generate_reset_token(user_id).await.unwrap();
    
    // Token should be valid initially
    service.validate_reset_token(&token).await.unwrap();
    
    // Wait for expiration
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Token should now be expired
    let result = service.validate_reset_token(&token).await;
    assert!(matches!(result, Err(PasswordResetError::TokenExpired)));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_complete_password_reset_flow() {
    let redis_service = Arc::new(RedisService::new(&redis_config).await.unwrap());
    let config = PasswordResetConfig::default();
    let service = PasswordResetService::new(redis_service, config);
    
    let user_id = "integration_test_user";
    
    // Step 1: Generate token
    let token = service.generate_reset_token(user_id).await.unwrap();
    
    // Step 2: Validate token
    let token_info = service.validate_reset_token(&token).await.unwrap();
    assert_eq!(token_info.user_id, user_id);
    
    // Step 3: Use token
    let returned_user_id = service.use_reset_token(&token).await.unwrap();
    assert_eq!(returned_user_id, user_id);
    
    // Step 4: Verify token cannot be used again
    let result = service.validate_reset_token(&token).await;
    assert!(matches!(result, Err(PasswordResetError::TokenAlreadyUsed)));
}

#[tokio::test]
async fn test_concurrent_token_operations() {
    let redis_service = Arc::new(RedisService::new(&redis_config).await.unwrap());
    let config = PasswordResetConfig::default();
    let service = Arc::new(PasswordResetService::new(redis_service, config));
    
    let user_id = "concurrent_test_user";
    
    // Generate multiple tokens concurrently
    let token_tasks: Vec<_> = (0..10)
        .map(|_| {
            let service = service.clone();
            let user_id = user_id.to_string();
            tokio::spawn(async move {
                service.generate_reset_token(&user_id).await
            })
        })
        .collect();
    
    let tokens: Vec<String> = futures::future::join_all(token_tasks)
        .await
        .into_iter()
        .map(|result| result.unwrap().unwrap())
        .collect();
    
    // All tokens should be unique
    let unique_tokens: std::collections::HashSet<_> = tokens.iter().collect();
    assert_eq!(unique_tokens.len(), tokens.len());
    
    // All tokens should be valid
    for token in &tokens {
        service.validate_reset_token(token).await.unwrap();
    }
}
```

## Security Considerations

### Token Security

1. **Cryptographic Randomness**:
   ```rust
   // Uses thread_rng() which is cryptographically secure
   let mut rng = rand::thread_rng();
   ```

2. **Unpredictable Tokens**:
   ```rust
   // 32-character alphanumeric tokens provide ~190 bits of entropy
   // Making brute force attacks computationally infeasible
   ```

3. **Time-Limited Exposure**:
   ```rust
   // Default 1-hour expiration limits exposure window
   // Tokens are automatically cleaned up after expiration
   ```

### Rate Limiting

```rust
pub struct ResetRateLimiter {
    redis_service: Arc<RedisService>,
    config: RateLimitConfig,
}

impl ResetRateLimiter {
    pub async fn check_rate_limit(&self, identifier: &str) -> Result<bool, RateLimitError> {
        let key = format!("reset_rate_limit:{}", identifier);
        
        // Use Redis atomic operations for thread-safe rate limiting
        let current_count: i64 = self.redis_service
            .incr(&key, 1)
            .await?;
        
        if current_count == 1 {
            // Set expiration on first request in window
            self.redis_service
                .expire(&key, self.config.window_seconds)
                .await?;
        }
        
        Ok(current_count > self.config.max_requests)
    }
}
```

### Audit Logging

```rust
pub struct ResetAuditLogger {
    database: Arc<Database>,
}

impl ResetAuditLogger {
    pub async fn log_token_generation(
        &self,
        user_id: &str,
        token_hash: &str, // Never log the actual token
        request_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), AuditError> {
        let event = AuditEvent {
            event_type: "password_reset_token_generated".to_string(),
            user_id: user_id.to_string(),
            timestamp: Utc::now(),
            metadata: json!({
                "token_hash": token_hash,
                "request_ip": request_ip,
                "user_agent": user_agent,
            }),
        };
        
        self.database.save_audit_event(&event).await?;
        Ok(())
    }
    
    pub async fn log_token_usage(
        &self,
        user_id: &str,
        token_hash: &str,
        success: bool,
    ) -> Result<(), AuditError> {
        let event = AuditEvent {
            event_type: "password_reset_token_used".to_string(),
            user_id: user_id.to_string(),
            timestamp: Utc::now(),
            metadata: json!({
                "token_hash": token_hash,
                "success": success,
            }),
        };
        
        self.database.save_audit_event(&event).await?;
        Ok(())
    }
}
```

## Performance Considerations

### Redis Optimization

1. **Efficient Key Design**:
   ```rust
   // Use hierarchical keys for better Redis performance
   "password_reset_token:{token}"     // Individual tokens
   "user_reset_tokens:{user_id}"      // User token sets
   "reset_stats:{date}"               // Daily statistics
   ```

2. **Memory Management**:
   ```rust
   // Automatic expiration prevents memory leaks
   redis.setex(key, expiry_seconds, value).await?;
   ```

3. **Bulk Operations**:
   ```rust
   // Use Redis pipelines for bulk operations
   let mut pipe = redis::pipe();
   for token in tokens_to_revoke {
       pipe.del(format!("password_reset_token:{}", token));
   }
   pipe.query_async(&mut connection).await?;
   ```

### Scalability Patterns

```rust
pub struct DistributedResetService {
    redis_cluster: Arc<RedisCluster>,
    config: PasswordResetConfig,
}

impl DistributedResetService {
    pub async fn generate_reset_token_distributed(
        &self,
        user_id: &str,
        shard_key: &str,
    ) -> Result<String, PasswordResetError> {
        // Use consistent hashing for token distribution
        let shard = self.redis_cluster.get_shard(shard_key).await?;
        
        // Generate token with shard-specific prefix for debugging
        let token = format!("{}_{}", 
            self.get_shard_prefix(shard_key),
            generate_secure_token(28)
        );
        
        // Store in the appropriate shard
        shard.setex(
            &format!("password_reset_token:{}", token),
            self.config.token_expiry_seconds as u64,
            &serde_json::to_string(&token_info)?,
        ).await?;
        
        Ok(token)
    }
}
```

## Backend Integration Scenarios

### Complete Authentication Service Integration

```rust
pub struct AuthenticationService {
    user_service: Arc<UserService>,
    password_utils: PhantomData<PasswordUtilsImpl>,
    reset_service: Arc<PasswordResetService>,
    email_service: Arc<EmailService>,
    jwt_service: Arc<JwtService>,
}

impl AuthenticationService {
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        request_info: RequestInfo,
    ) -> Result<LoginResponse, AuthError> {
        // Find user
        let user = self.user_service.find_by_email(email).await
            .ok_or(AuthError::InvalidCredentials)?;
        
        // Verify password
        let is_valid = PasswordUtilsImpl::verify_password(password, &user.password_hash)
            .map_err(AuthError::PasswordVerificationFailed)?;
        
        if !is_valid {
            // Log failed attempt
            self.audit_service.log_failed_login(&user.id, &request_info).await?;
            return Err(AuthError::InvalidCredentials);
        }
        
        // Generate JWT tokens
        let token_pair = self.jwt_service.generate_token_pair(&user).await?;
        
        Ok(LoginResponse {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            user: user.into(),
        })
    }
    
    pub async fn initiate_password_reset(
        &self,
        email: &str,
        request_info: RequestInfo,
    ) -> Result<(), AuthError> {
        // Rate limiting
        if self.is_reset_rate_limited(&email, &request_info).await? {
            return Err(AuthError::RateLimited);
        }
        
        // Find user (but don't reveal if email exists)
        if let Some(user) = self.user_service.find_by_email(email).await {
            // Generate reset token
            let token = self.reset_service.generate_reset_token(&user.id).await?;
            
            // Send reset email
            let reset_url = format!("{}/reset-password?token={}", 
                self.config.frontend_url, token);
            
            self.email_service.send_password_reset_email(
                &user.email,
                &user.name.unwrap_or_else(|| "User".to_string()),
                &reset_url,
            ).await?;
        }
        
        // Always return success to prevent email enumeration
        Ok(())
    }
    
    pub async fn complete_password_reset(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        // Validate password strength
        PasswordUtilsImpl::validate_password_strength(new_password)
            .map_err(AuthError::WeakPassword)?;
        
        // Use reset token
        let user_id = self.reset_service.use_reset_token(token).await
            .map_err(AuthError::InvalidResetToken)?;
        
        // Hash new password
        let password_hash = PasswordUtilsImpl::hash_password(new_password)
            .map_err(AuthError::PasswordHashingFailed)?;
        
        // Update password
        self.user_service.update_password(&user_id, &password_hash).await?;
        
        // Revoke all other reset tokens
        self.reset_service.revoke_all_user_tokens(&user_id).await?;
        
        // Invalidate existing JWT tokens
        self.jwt_service.revoke_all_user_tokens(&user_id).await?;
        
        Ok(())
    }
}
```

### Microservice Architecture Integration

```rust
// Reset service as a standalone microservice
pub struct ResetServiceAPI {
    reset_service: Arc<PasswordResetService>,
}

#[derive(Serialize, Deserialize)]
pub struct GenerateTokenRequest {
    pub user_id: String,
    pub metadata: Option<TokenMetadata>,
}

#[derive(Serialize, Deserialize)]
pub struct TokenMetadata {
    pub request_ip: Option<String>,
    pub user_agent: Option<String>,
    pub requested_by: Option<String>, // Admin user ID
}

impl ResetServiceAPI {
    pub async fn generate_token_endpoint(
        &self,
        request: GenerateTokenRequest,
    ) -> Result<ApiResponse<String>, ApiError> {
        let token = self.reset_service.generate_reset_token(&request.user_id).await
            .map_err(ApiError::from)?;
        
        Ok(ApiResponse::success(token))
    }
    
    pub async fn validate_token_endpoint(
        &self,
        token: String,
    ) -> Result<ApiResponse<ResetTokenInfo>, ApiError> {
        let token_info = self.reset_service.validate_reset_token(&token).await
            .map_err(ApiError::from)?;
        
        Ok(ApiResponse::success(token_info))
    }
    
    pub async fn consume_token_endpoint(
        &self,
        token: String,
    ) -> Result<ApiResponse<String>, ApiError> {
        let user_id = self.reset_service.use_reset_token(&token).await
            .map_err(ApiError::from)?;
        
        Ok(ApiResponse::success(user_id))
    }
}

// gRPC service definition
#[tonic::async_trait]
impl ResetTokenService for ResetServiceAPI {
    async fn generate_token(
        &self,
        request: Request<GenerateTokenRequest>,
    ) -> Result<Response<GenerateTokenResponse>, Status> {
        let req = request.into_inner();
        
        match self.reset_service.generate_reset_token(&req.user_id).await {
            Ok(token) => Ok(Response::new(GenerateTokenResponse { token })),
            Err(e) => Err(Status::internal(format!("Token generation failed: {}", e))),
        }
    }
    
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let req = request.into_inner();
        
        match self.reset_service.validate_reset_token(&req.token).await {
            Ok(token_info) => Ok(Response::new(ValidateTokenResponse {
                valid: true,
                user_id: token_info.user_id,
                expires_at: Some(token_info.expires_at.timestamp()),
            })),
            Err(_) => Ok(Response::new(ValidateTokenResponse {
                valid: false,
                user_id: String::new(),
                expires_at: None,
            })),
        }
    }
}
```

## Troubleshooting

### Common Issues and Solutions

1. **Redis Connection Issues**:
   ```rust
   // Implement connection retry logic
   pub async fn with_redis_retry<F, T>(
       operation: F,
       max_retries: usize,
   ) -> Result<T, PasswordResetError>
   where
       F: Fn() -> Pin<Box<dyn Future<Output = Result<T, redis::RedisError>> + Send>>,
   {
       let mut attempts = 0;
       loop {
           match operation().await {
               Ok(result) => return Ok(result),
               Err(e) if attempts < max_retries => {
                   attempts += 1;
                   let delay = Duration::from_millis(100 * 2_u64.pow(attempts as u32));
                   tokio::time::sleep(delay).await;
               }
               Err(e) => return Err(PasswordResetError::RedisError(e.to_string())),
           }
       }
   }
   ```

2. **Token Cleanup Performance**:
   ```rust
   // Implement incremental cleanup
   pub async fn incremental_cleanup(
       &self,
       batch_size: usize,
   ) -> Result<u64, PasswordResetError> {
       let mut total_cleaned = 0;
       let mut cursor = 0;
       
       loop {
           let (next_cursor, keys): (u64, Vec<String>) = self.redis_service
               .scan(cursor, "password_reset_token:*", batch_size)
               .await?;
           
           for key in keys {
               if self.is_token_expired(&key).await? {
                   self.redis_service.del(&key).await?;
                   total_cleaned += 1;
               }
           }
           
           cursor = next_cursor;
           if cursor == 0 {
               break;
           }
           
           // Small delay to prevent overwhelming Redis
           tokio::time::sleep(Duration::from_millis(10)).await;
       }
       
       Ok(total_cleaned)
   }
   ```

3. **Memory Usage Optimization**:
   ```rust
   // Use more compact token representation
   #[derive(Serialize, Deserialize)]
   pub struct CompactTokenInfo {
       pub uid: String,        // user_id
       pub exp: i64,          // expires_at timestamp
       pub crt: i64,          // created_at timestamp
       pub usd: bool,         // used flag
       pub rev: bool,         // revoked flag
   }
   ```

## Future Enhancements

### Planned Features

1. **Multi-Step Reset Process**:
   ```rust
   pub enum ResetStep {
       EmailVerification(String),    // token
       IdentityConfirmation(String), // secondary token
       PasswordChange(String),       // final token
   }
   ```

2. **Token Families**:
   ```rust
   pub struct TokenFamily {
       pub family_id: String,
       pub tokens: Vec<String>,
       pub max_concurrent: usize,
   }
   ```

3. **Geographic Validation**:
   ```rust
   pub struct GeoValidation {
       pub allowed_countries: Vec<String>,
       pub suspicious_login_protection: bool,
   }
   ```

This comprehensive password reset utility provides a secure, scalable foundation for user account recovery while maintaining strict security standards and extensive auditability.
