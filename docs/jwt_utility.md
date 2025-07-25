# JWT (JSON Web Token) Utility Documentation

## Overview

The JWT utility provides a comprehensive token-based authentication system for the ElHaiba backend application. It implements secure token generation, validation, and management using the industry-standard JWT format with Argon2 encryption. The utility supports both access and refresh tokens with role-based access control.

## Purpose and Philosophy

### Design Philosophy

The JWT utility is built around these core principles:

1. **Security by Design**: Uses cryptographically secure token generation with proper expiration handling
2. **Stateless Authentication**: No server-side session storage required, enabling horizontal scaling
3. **Role-Based Access Control**: Built-in support for user roles and permissions
4. **Token Lifecycle Management**: Proper handling of token generation, validation, and expiration
5. **Audit Trail**: Every token includes unique identifiers (JTI) for tracking and potential revocation
6. **Flexibility**: Configurable expiration times and support for different token types

### Use Cases

- **User Authentication**: Primary authentication mechanism for API access
- **Session Management**: Maintaining user sessions across requests
- **Authorization**: Role-based access control for different application features
- **API Security**: Securing REST API endpoints and GraphQL resolvers
- **Mobile Authentication**: Token-based auth suitable for mobile applications
- **Microservices**: Stateless authentication across distributed services

## Architecture

### Core Components

#### 1. JwtTokenUtilsImpl
The main implementation struct providing all JWT operations:

```rust
pub struct JwtTokenUtilsImpl {
    pub jwt_config: JwtConfig,
}
```

#### 2. Claims Structure
The JWT payload containing user information and metadata:

```rust
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub email: String,      // User email
    pub role: String,       // User role (admin, user, etc.)
    pub iat: i64,          // Issued at timestamp
    pub exp: i64,          // Expiration timestamp
    pub token_type: String, // Token type (access/refresh)
    pub jti: String,       // JWT ID (unique identifier)
}
```

#### 3. TokenPair
Container for access and refresh token pairs:

```rust
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: String,
}
```

#### 4. Token Types
Enum defining different token purposes:

```rust
pub enum TokenType {
    Access,  // Short-lived tokens for API access
    Refresh, // Long-lived tokens for refreshing access tokens
}
```

## Implementation Details

### Token Generation Algorithm

The JWT utility uses the HS256 (HMAC-SHA256) algorithm for token signing:

```rust
fn generate_token(
    &self,
    user_id: &str,
    email: &str,
    role: &str,
    token_type: TokenType,
    expires_in_minutes: i64,
) -> Result<String, JwtError> {
    let secret = self.jwt_config.jwt_secret.as_str();
    let now = Utc::now();
    let expiration = now + Duration::minutes(expires_in_minutes);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        iat: now.timestamp(),
        exp: expiration.timestamp(),
        token_type: token_type.as_str().to_string(),
        jti: Uuid::new_v4().to_string(), // Unique token identifier
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret.as_ref());
    
    encode(&header, &claims, &encoding_key)
        .map_err(|err| JwtError::EncodingFailed(err.to_string()))
}
```

### Token Validation Process

Token validation includes multiple security checks:

```rust
pub fn validate_token(
    &self,
    token: &str,
    expected_token_type: Option<TokenType>
) -> Result<Claims, JwtError> {
    let secret = self.jwt_config.jwt_secret.as_str();
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    // Decode and validate signature
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    let claims = token_data.claims;
    
    // Check expiration
    let now = Utc::now().timestamp();
    if claims.exp < now {
        return Err(JwtError::TokenExpired);
    }

    // Validate token type if specified
    if let Some(expected_type) = expected_token_type {
        if claims.token_type != expected_type.as_str() {
            return Err(JwtError::InvalidTokenType {
                expected: expected_type.as_str().to_string(),
                actual: claims.token_type.clone(),
            });
        }
    }

    Ok(claims)
}
```

### Role-Based Access Control

The utility implements a hierarchical role system:

```rust
fn check_role_permission(&self, user_role: &str, required_role: &str) -> bool {
    match (user_role, required_role) {
        // Admin has access to everything
        ("admin", _) => true,
        // User only has access to user resources
        ("user", "user") => true,
        // No other combinations are allowed
        _ => false,
    }
}
```

### Token Pair Generation

Access and refresh tokens are generated together for complete authentication flow:

```rust
fn generate_token_pair(
    &self,
    user_id: &str,
    email: &str,
    role: &str
) -> Result<TokenPair, JwtError> {
    let access_token = self.generate_access_token(user_id, email, role)?;
    let refresh_token = self.generate_refresh_token(user_id, email, role)?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        expires_in: self.jwt_config.access_token_expiration * 60, // Convert to seconds
        token_type: "Bearer".to_string(),
    })
}
```

## API Reference

### Primary Methods

#### `new(jwt_config: JwtConfig) -> Self`
Creates a new JWT utility instance with the provided configuration.

**Parameters:**
- `jwt_config`: Configuration containing secret, expiration times, etc.

**Returns:**
- `JwtTokenUtilsImpl`: Configured JWT utility instance

#### `from_env() -> Result<Self, JwtError>`
Creates JWT utility from environment variables.

**Returns:**
- `Ok(JwtTokenUtilsImpl)`: Successfully configured from environment
- `Err(JwtError::MissingSecret)`: Missing or invalid environment configuration

#### `generate_access_token(&self, user_id: &str, email: &str, role: &str) -> Result<String, JwtError>`
Generates a short-lived access token for API authentication.

**Parameters:**
- `user_id`: Unique user identifier
- `email`: User's email address
- `role`: User's role in the system

**Returns:**
- `Ok(String)`: Generated JWT access token
- `Err(JwtError)`: Token generation failure

#### `generate_refresh_token(&self, user_id: &str, email: &str, role: &str) -> Result<String, JwtError>`
Generates a long-lived refresh token for obtaining new access tokens.

**Parameters:**
- `user_id`: Unique user identifier
- `email`: User's email address
- `role`: User's role in the system

**Returns:**
- `Ok(String)`: Generated JWT refresh token
- `Err(JwtError)`: Token generation failure

#### `generate_token_pair(&self, user_id: &str, email: &str, role: &str) -> Result<TokenPair, JwtError>`
Generates both access and refresh tokens together.

**Parameters:**
- `user_id`: Unique user identifier
- `email`: User's email address
- `role`: User's role in the system

**Returns:**
- `Ok(TokenPair)`: Container with both tokens and metadata
- `Err(JwtError)`: Token generation failure

#### `validate_access_token(&self, token: &str) -> Result<Claims, JwtError>`
Validates an access token and returns the claims.

**Parameters:**
- `token`: JWT token to validate

**Returns:**
- `Ok(Claims)`: Valid token claims
- `Err(JwtError)`: Invalid token or validation failure

#### `validate_refresh_token(&self, token: &str) -> Result<Claims, JwtError>`
Validates a refresh token and returns the claims.

**Parameters:**
- `token`: Refresh token to validate

**Returns:**
- `Ok(Claims)`: Valid token claims
- `Err(JwtError)`: Invalid token or validation failure

#### `extract_token_from_header(&self, auth_header: &str) -> Result<String, JwtError>`
Extracts JWT token from Authorization header.

**Parameters:**
- `auth_header`: HTTP Authorization header value (e.g., "Bearer token")

**Returns:**
- `Ok(String)`: Extracted token
- `Err(JwtError::InvalidToken)`: Malformed authorization header

#### `get_user_id_from_token(&self, token: &str) -> Result<String, JwtError>`
Extracts user ID from a valid token.

**Parameters:**
- `token`: JWT token

**Returns:**
- `Ok(String)`: User ID from token subject
- `Err(JwtError)`: Invalid token

#### `check_role_permission(&self, user_role: &str, required_role: &str) -> bool`
Checks if a user role has permission for a required role.

**Parameters:**
- `user_role`: User's actual role
- `required_role`: Required role for the operation

**Returns:**
- `bool`: True if permission granted, false otherwise

## Configuration

### JwtConfig Structure

```rust
pub struct JwtConfig {
    pub jwt_secret: String,                // Secret key for token signing
    pub access_token_expiration: i64,      // Access token expiration (minutes)
    pub refresh_token_expiration: i64,     // Refresh token expiration (minutes)
    pub jwt_issuer: Option<String>,        // Token issuer (optional)
    pub jwt_audience: Option<String>,      // Token audience (optional)
}
```

### Configuration Examples

#### Development Configuration
```rust
JwtConfig {
    jwt_secret: "development_secret_key_that_is_very_long_for_security".to_string(),
    access_token_expiration: 15,    // 15 minutes
    refresh_token_expiration: 10080, // 1 week
    jwt_issuer: Some("elhaiba-dev".to_string()),
    jwt_audience: Some("elhaiba-users".to_string()),
}
```

#### Production Configuration
```rust
JwtConfig {
    jwt_secret: std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
    access_token_expiration: 15,     // 15 minutes
    refresh_token_expiration: 10080, // 1 week
    jwt_issuer: Some("elhaiba.com".to_string()),
    jwt_audience: Some("elhaiba-api".to_string()),
}
```

### Environment Variables

```bash
# Required
JWT_SECRET=your_very_long_and_secure_secret_key_here

# Optional (defaults will be used if not set)
JWT_ACCESS_TOKEN_EXPIRATION_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRATION_MINUTES=10080
JWT_ISSUER=elhaiba.com
JWT_AUDIENCE=elhaiba-api
```

## Usage Examples

### Basic Authentication Flow

```rust
use elhaiba_backend::util::jwt::{JwtTokenUtilsImpl, JwtTokenUtils};
use elhaiba_backend::config::JwtConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize JWT utility
    let jwt_utils = JwtTokenUtilsImpl::from_env()?;
    
    // Generate token pair for user login
    let token_pair = jwt_utils.generate_token_pair(
        "user123",
        "user@example.com",
        "user"
    )?;
    
    println!("Access Token: {}", token_pair.access_token);
    println!("Refresh Token: {}", token_pair.refresh_token);
    println!("Expires in: {} seconds", token_pair.expires_in);
    
    Ok(())
}
```

### API Middleware Integration

```rust
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

pub async fn auth_middleware(
    State(jwt_utils): State<Arc<JwtTokenUtilsImpl>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    // Extract token from header
    let token = jwt_utils
        .extract_token_from_header(auth_header)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Validate token
    let claims = jwt_utils
        .validate_access_token(&token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Add user info to request
    request.extensions_mut().insert(claims);
    
    Ok(next.run(request).await)
}
```

### Role-Based Route Protection

```rust
use axum::{
    extract::Extension,
    http::StatusCode,
    Json,
};

pub async fn admin_only_endpoint(
    Extension(claims): Extension<Claims>,
    State(jwt_utils): State<Arc<JwtTokenUtilsImpl>>,
) -> Result<Json<AdminData>, StatusCode> {
    // Check if user has admin role
    if !jwt_utils.check_role_permission(&claims.role, "admin") {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // User is admin, proceed with admin operations
    let admin_data = get_admin_data().await;
    Ok(Json(admin_data))
}

pub async fn user_endpoint(
    Extension(claims): Extension<Claims>,
    State(jwt_utils): State<Arc<JwtTokenUtilsImpl>>,
) -> Result<Json<UserData>, StatusCode> {
    // Check if user has at least user role
    if !jwt_utils.check_role_permission(&claims.role, "user") {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get user-specific data
    let user_data = get_user_data(&claims.sub).await;
    Ok(Json(user_data))
}
```

### Token Refresh Flow

```rust
pub async fn refresh_token_endpoint(
    State(jwt_utils): State<Arc<JwtTokenUtilsImpl>>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<Json<TokenPair>, StatusCode> {
    // Validate refresh token
    let claims = jwt_utils
        .validate_refresh_token(&request.refresh_token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Generate new token pair
    let new_token_pair = jwt_utils
        .generate_token_pair(&claims.sub, &claims.email, &claims.role)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(new_token_pair))
}
```

### Login Handler

```rust
pub async fn login_handler(
    State(jwt_utils): State<Arc<JwtTokenUtilsImpl>>,
    State(password_utils): State<Arc<PasswordUtilsImpl>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Authenticate user
    let user = authenticate_user(&login_request.email, &login_request.password).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Generate token pair
    let token_pair = jwt_utils
        .generate_token_pair(&user.id, &user.email, &user.role)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(LoginResponse {
        user: user.into(),
        tokens: token_pair,
    }))
}
```

## Error Handling

### Error Types

The JWT utility provides detailed error information:

```rust
pub enum JwtError {
    EncodingFailed(String),         // Token generation failed
    DecodingFailed(String),         // Token parsing failed
    TokenExpired,                   // Token has expired
    InvalidToken,                   // Malformed token
    MissingSecret,                  // JWT secret not configured
    InvalidTokenType {              // Wrong token type used
        expected: String,
        actual: String,
    },
}
```

### Error Recovery Strategies

```rust
async fn handle_jwt_error(error: JwtError) -> Result<Response, StatusCode> {
    match error {
        JwtError::TokenExpired => {
            // Suggest token refresh
            Err(StatusCode::UNAUTHORIZED)
        },
        JwtError::InvalidTokenType { expected, actual } => {
            // Log security concern
            tracing::warn!("Wrong token type used: expected {}, got {}", expected, actual);
            Err(StatusCode::UNAUTHORIZED)
        },
        JwtError::DecodingFailed(_) | JwtError::InvalidToken => {
            // Possible tampering attempt
            tracing::warn!("Invalid token received");
            Err(StatusCode::UNAUTHORIZED)
        },
        JwtError::EncodingFailed(_) | JwtError::MissingSecret => {
            // Server configuration issue
            tracing::error!("JWT configuration error: {}", error);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        },
    }
}
```

## Testing

### Unit Tests

The JWT utility includes comprehensive unit tests:

#### Token Generation Tests
```rust
#[test]
fn test_generate_access_token_success() {
    let jwt_utils = create_test_jwt_utils();
    let user = TestUser::new_user();

    let result = jwt_utils.generate_access_token(&user.id, &user.email, &user.role);
    assert!(result.is_ok());

    let token = result.unwrap();
    assert!(!token.is_empty());
    
    // Verify the token can be validated
    let claims_result = jwt_utils.validate_access_token(&token);
    assert!(claims_result.is_ok());
    
    let claims = claims_result.unwrap();
    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.email, user.email);
    assert_eq!(claims.role, user.role);
    assert_eq!(claims.token_type, "access");
}
```

#### Token Validation Tests
```rust
#[test]
fn test_validate_access_token_wrong_type() {
    let jwt_utils = create_test_jwt_utils();
    let user = TestUser::new_user();
    let refresh_token = jwt_utils.generate_refresh_token(&user.id, &user.email, &user.role).unwrap();

    let result = jwt_utils.validate_access_token(&refresh_token);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        JwtError::InvalidTokenType { expected, actual } => {
            assert_eq!(expected, "access");
            assert_eq!(actual, "refresh");
        }
        _ => panic!("Expected InvalidTokenType error"),
    }
}
```

#### Security Tests
```rust
#[test]
fn test_jwt_token_tamper_detection() {
    let jwt_utils = create_test_jwt_utils();
    let user = TestUser::new_user();
    
    let token = jwt_utils.generate_access_token(&user.id, &user.email, &user.role).unwrap();
    
    // Test various tampering attempts
    let tampered_tokens = vec![
        token[..token.len()-1].to_string(),           // Remove last character
        format!("{}x", token),                        // Add character at end
        token.replace('.', "_"),                      // Replace JWT separators
    ];
    
    for tampered_token in tampered_tokens {
        let result = jwt_utils.validate_access_token(&tampered_token);
        assert!(result.is_err(), "Tampered token should be invalid");
    }
}
```

#### Role Permission Tests
```rust
#[test]
fn test_check_role_permission_comprehensive() {
    let jwt_utils = create_test_jwt_utils();
    
    let role_tests = vec![
        ("admin", "admin", true),       // Admin accessing admin resource
        ("admin", "user", true),        // Admin accessing user resource
        ("user", "user", true),         // User accessing user resource
        ("user", "admin", false),       // User trying to access admin resource
        ("guest", "user", false),       // Guest trying to access user resource
    ];
    
    for (user_role, required_role, should_have_access) in role_tests {
        let has_access = jwt_utils.check_role_permission(user_role, required_role);
        assert_eq!(has_access, should_have_access);
    }
}
```

### Integration Tests

```rust
#[test]
fn test_authentication_flow() {
    let jwt_utils = create_test_jwt_utils();
    let user = TestUser::new_user();

    // 1. Generate token pair for login
    let token_pair = jwt_utils.generate_token_pair(&user.id, &user.email, &user.role).unwrap();

    // 2. Extract access token from authorization header
    let auth_header = format!("Bearer {}", token_pair.access_token);
    let extracted_token = jwt_utils.extract_token_from_header(&auth_header).unwrap();

    // 3. Validate access token
    let access_claims = jwt_utils.validate_access_token(&extracted_token).unwrap();
    assert_eq!(access_claims.sub, user.id);

    // 4. Check role permissions
    assert!(jwt_utils.check_role_permission(&access_claims.role, "user"));
    assert!(!jwt_utils.check_role_permission(&access_claims.role, "admin"));

    // 5. Use refresh token
    let refresh_claims = jwt_utils.validate_refresh_token(&token_pair.refresh_token).unwrap();
    assert_eq!(refresh_claims.sub, user.id);
}
```

## Security Considerations

### Token Security

1. **Secret Management**:
   ```rust
   // Use environment variables for secrets
   let jwt_secret = std::env::var("JWT_SECRET")
       .expect("JWT_SECRET environment variable must be set");
   
   // Ensure minimum length
   if jwt_secret.len() < 32 {
       panic!("JWT secret must be at least 32 characters long");
   }
   ```

2. **Token Expiration**:
   - Access tokens: 15 minutes (short-lived)
   - Refresh tokens: 1 week (longer-lived)
   - Configurable based on security requirements

3. **Algorithm Selection**:
   - Uses HS256 (HMAC-SHA256) for simplicity and performance
   - Consider RS256 for distributed systems with public key verification

### Best Practices

1. **Secure Storage**:
   ```rust
   // Client-side: Store refresh tokens securely (HttpOnly cookies)
   // Access tokens can be stored in memory or sessionStorage
   ```

2. **Token Rotation**:
   ```rust
   // Implement token rotation on refresh
   pub async fn refresh_with_rotation(
       &self,
       refresh_token: &str,
       revocation_service: &TokenRevocationService,
   ) -> Result<TokenPair, JwtError> {
       let claims = self.validate_refresh_token(refresh_token)?;
       
       // Revoke old refresh token
       revocation_service.revoke_token(&claims.jti).await?;
       
       // Generate new token pair
       self.generate_token_pair(&claims.sub, &claims.email, &claims.role)
   }
   ```

3. **Rate Limiting**:
   ```rust
   // Implement rate limiting for token generation
   pub struct TokenRateLimiter {
       // Implementation for preventing token abuse
   }
   ```

## Performance Considerations

### Token Generation Performance
- HS256 is fast for token generation and validation
- Consider caching user data to avoid database lookups during validation
- Use async operations to prevent blocking

### Memory Usage
```rust
// Tokens are relatively small (typically < 1KB)
// Claims struct is lightweight
// No server-side session storage required
```

### Scalability
```rust
// Stateless design enables horizontal scaling
// No shared state between application instances
// Can validate tokens without database access
```

## Backend Integration Scenarios

### API Gateway Integration

```rust
pub async fn api_gateway_auth(
    jwt_utils: Arc<JwtTokenUtilsImpl>,
    request: Request,
) -> Result<AuthenticatedRequest, AuthError> {
    let auth_header = extract_auth_header(&request)?;
    let token = jwt_utils.extract_token_from_header(&auth_header)?;
    let claims = jwt_utils.validate_access_token(&token)?;
    
    Ok(AuthenticatedRequest {
        request,
        user_id: claims.sub,
        email: claims.email,
        role: claims.role,
    })
}
```

### WebSocket Authentication

```rust
pub async fn websocket_auth(
    jwt_utils: Arc<JwtTokenUtilsImpl>,
    token: String,
) -> Result<WebSocketUser, JwtError> {
    let claims = jwt_utils.validate_access_token(&token)?;
    
    Ok(WebSocketUser {
        id: claims.sub,
        email: claims.email,
        role: claims.role,
        connected_at: Utc::now(),
    })
}
```

### Background Job Authentication

```rust
pub async fn background_job_auth(
    jwt_utils: Arc<JwtTokenUtilsImpl>,
    job_token: String,
) -> Result<JobContext, JwtError> {
    let claims = jwt_utils.validate_access_token(&job_token)?;
    
    // Verify job permissions
    if !jwt_utils.check_role_permission(&claims.role, "admin") {
        return Err(JwtError::InvalidToken);
    }
    
    Ok(JobContext {
        initiated_by: claims.sub,
        permissions: claims.role,
    })
}
```

### Multi-Tenant Support

```rust
pub struct TenantAwareJwtUtils {
    jwt_utils: JwtTokenUtilsImpl,
    tenant_service: TenantService,
}

impl TenantAwareJwtUtils {
    pub async fn validate_tenant_token(
        &self,
        token: &str,
        tenant_id: &str,
    ) -> Result<Claims, JwtError> {
        let claims = self.jwt_utils.validate_access_token(token)?;
        
        // Verify user belongs to tenant
        self.tenant_service
            .verify_user_in_tenant(&claims.sub, tenant_id)
            .await?;
        
        Ok(claims)
    }
}
```

## Troubleshooting

### Common Issues

1. **Token Expired Errors**:
   ```rust
   // Check token expiration times
   let claims = jwt_utils.validate_access_token(token);
   match claims {
       Err(JwtError::TokenExpired) => {
           // Implement automatic refresh logic
           refresh_token_automatically().await?;
       }
       Ok(claims) => { /* use claims */ }
       Err(e) => return Err(e),
   }
   ```

2. **Invalid Secret Errors**:
   ```bash
   # Verify environment variable
   echo $JWT_SECRET
   
   # Check secret length
   echo $JWT_SECRET | wc -c  # Should be >= 32 characters
   ```

3. **Token Type Mismatches**:
   ```rust
   // Ensure correct token type is used
   let access_claims = jwt_utils.validate_access_token(token)?;  // For API access
   let refresh_claims = jwt_utils.validate_refresh_token(token)?; // For token refresh
   ```

### Debugging

Enable detailed logging:
```rust
use tracing::{debug, error, info, warn};

// The JWT utility includes comprehensive logging
debug!("Generating {} token for user: {}", token_type.as_str(), user_id);
info!("Successfully generated token pair for user: {}", user_id);
warn!("Token has expired for user: {}", claims.sub);
error!("Failed to decode JWT token: {}", err);
```

## Future Enhancements

### Planned Features

1. **Token Revocation**:
   ```rust
   pub trait TokenRevocationService {
       async fn revoke_token(&self, jti: &str) -> Result<(), RevocationError>;
       async fn is_token_revoked(&self, jti: &str) -> Result<bool, RevocationError>;
   }
   ```

2. **Advanced Claims**:
   ```rust
   pub struct ExtendedClaims {
       // Standard claims
       pub sub: String,
       pub email: String,
       pub role: String,
       // Extended claims
       pub permissions: Vec<String>,
       pub tenant_id: Option<String>,
       pub device_id: Option<String>,
       pub scope: Vec<String>,
   }
   ```

3. **Algorithm Flexibility**:
   ```rust
   pub enum JwtAlgorithm {
       HS256,  // Symmetric
       RS256,  // Asymmetric
       ES256,  // Elliptic Curve
   }
   ```

4. **Token Encryption**:
   ```rust
   // JWE (JSON Web Encryption) support for sensitive data
   pub struct EncryptedJwtUtils {
       encryption_key: String,
       signing_key: String,
   }
   ```

### Extensibility

The JWT utility supports extension through traits:

```rust
pub trait JwtService: Send + Sync {
    async fn generate_token_pair(&self, user_id: &str, email: &str, role: &str) -> Result<TokenPair, JwtError>;
    async fn validate_access_token(&self, token: &str) -> Result<Claims, JwtError>;
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, JwtError>;
}

// Different implementations for different requirements
pub struct RedisJwtService; // With Redis-based revocation
pub struct DatabaseJwtService; // With database session tracking
pub struct DistributedJwtService; // For microservices
```

This design allows for easy extension and customization based on specific application requirements while maintaining a consistent interface.
