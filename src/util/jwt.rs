use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use crate::config::JwtConfig;

/// JWT token claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// User email
    pub email: String,
    /// User role (admin, mentor, participant)
    pub role: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Token type (access or refresh)
    pub token_type: String,
    /// JWT ID (unique identifier for the token)
    pub jti: String,
}

/// Token pair containing access and refresh tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

/// JWT token types
#[derive(Debug, Clone)]
pub enum TokenType {
    Access,
    Refresh,
}

impl TokenType {
    pub fn as_str(&self) -> &str {
        match self {
            TokenType::Access => "access",
            TokenType::Refresh => "refresh",
        }
    }
}

/// Error types for JWT operations
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Failed to encode JWT token: {0}")]
    EncodingFailed(String),
    #[error("Failed to decode JWT token: {0}")]
    DecodingFailed(String),
    #[error("Token has expired")]
    TokenExpired,
    #[error("Invalid token format")]
    InvalidToken,
    #[error("Missing JWT secret")]
    MissingSecret,
    #[error("Invalid token type: expected {expected}, got {actual}")]
    InvalidTokenType { expected: String, actual: String },
}


pub trait JwtTokenUtils {
    fn generate_access_token(&self, user_id: &str, email: &str, role: &str) -> Result<String, JwtError>;
    fn generate_refresh_token(&self, user_id: &str, email: &str, role: &str) -> Result<String, JwtError>;
    fn generate_token_pair(&self, user_id: &str, email: &str, role: &str) -> Result<TokenPair, JwtError>;
    fn validate_access_token(&self, token: &str) -> Result<Claims, JwtError>;
    fn validate_refresh_token(&self, token: &str) -> Result<Claims, JwtError>;
    fn extract_token_from_header(&self, auth_header: &str) -> Result<String, JwtError>;
    fn get_user_id_from_token(&self, token: &str) -> Result<String, JwtError>;
    fn check_role_permission(&self, user_role: &str, required_role: &str) -> bool;
}

#[derive(Debug, Clone)]
pub struct JwtTokenUtilsImpl{
    pub jwt_config: JwtConfig,
}

impl JwtTokenUtilsImpl {

    pub fn new(jwt_config: JwtConfig) -> Self {
        JwtTokenUtilsImpl {
            jwt_config,
        }
    }

    /// Create JWT utils from environment variables
    pub fn from_env() -> Result<Self, JwtError> {
        let jwt_config = JwtConfig::from_env()
            .map_err(|_| JwtError::MissingSecret)?;
        
        jwt_config.validate()
            .map_err(|_| JwtError::MissingSecret)?;
            
        Ok(JwtTokenUtilsImpl::new(jwt_config))
    }

    /// Create JWT utils from test environment variables
    pub fn from_test_env() -> Result<Self, JwtError> {
        let jwt_config = JwtConfig::from_test_env()
            .map_err(|_| JwtError::MissingSecret)?;
        
        jwt_config.validate()
            .map_err(|_| JwtError::MissingSecret)?;
            
        Ok(JwtTokenUtilsImpl::new(jwt_config))
    }

    fn generate_token(&self, user_id: &str, email: &str, role: &str, token_type: TokenType, expires_in_minutes: i64,) -> Result<String, JwtError> {
        debug!(
        "Generating {} token for user: {} with role: {}",
        token_type.as_str(),
        user_id,
        role
        );

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
            jti: Uuid::new_v4().to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(secret.as_ref());

        match encode(&header, &claims, &encoding_key) {
            Ok(token) => {
                info!(
                    "Successfully generated {} token for user: {}",
                    token_type.as_str(),
                    user_id
                );
                Ok(token)
            }
            Err(err) => {
                error!("Failed to encode JWT token: {}", err);
                Err(JwtError::EncodingFailed(err.to_string()))
            }
        }
    }

    pub fn validate_token(&self, token: &str, expected_token_type: Option<TokenType>) -> Result<Claims, JwtError> {
         debug!("Validating JWT token");

        let secret = self.jwt_config.jwt_secret.as_str();
        let decoding_key = DecodingKey::from_secret(secret.as_ref());
        let validation = Validation::new(Algorithm::HS256);

        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;
                
                // Check if token has expired
                let now = Utc::now().timestamp();
                if claims.exp < now {
                    warn!("Token has expired for user: {}", claims.sub);
                    return Err(JwtError::TokenExpired);
                }

                // Validate token type if specified
                if let Some(expected_type) = expected_token_type {
                    if claims.token_type != expected_type.as_str() {
                        error!(
                            "Invalid token type: expected {}, got {}",
                            expected_type.as_str(),
                            claims.token_type
                        );
                        return Err(JwtError::InvalidTokenType {
                            expected: expected_type.as_str().to_string(),
                            actual: claims.token_type.clone(),
                        });
                    }
                }

                debug!("Token validation successful for user: {}", claims.sub);
                Ok(claims)
            }
            Err(err) => {
                error!("Failed to decode JWT token: {}", err);
                Err(JwtError::DecodingFailed(err.to_string()))
            }
        }
    }

}

impl JwtTokenUtils for JwtTokenUtilsImpl {

    fn generate_access_token(&self, user_id: &str, email: &str, role: &str) -> Result<String, JwtError> {
        self.generate_token(user_id, email, role, TokenType::Access, self.jwt_config.access_token_expiration)
    }

    fn generate_refresh_token(&self, user_id: &str, email: &str, role: &str) -> Result<String, JwtError> {
        self.generate_token(user_id, email, role, TokenType::Refresh, self.jwt_config.refresh_token_expiration)
    }
    
    fn generate_token_pair(&self, user_id: &str, email: &str, role: &str) -> Result<TokenPair, JwtError> {
        debug!("Generating token pair for user: {}", user_id);

        let access_token = self.generate_access_token(user_id, email, role)?;
        let refresh_token = self.generate_refresh_token(user_id, email, role)?;

        let token_pair = TokenPair {
            access_token,
            refresh_token,
            expires_in: self.jwt_config.access_token_expiration * 60, // convert minutes to seconds
            token_type: "Bearer".to_string(),
        };

        info!("Successfully generated token pair for user: {}", user_id);
        Ok(token_pair)
    }

    fn validate_access_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, Some(TokenType::Access))
    }

    fn validate_refresh_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, Some(TokenType::Refresh))
    }

    fn extract_token_from_header(&self, auth_header: &str) -> Result<String, JwtError> {
        debug!("Extracting token from authorization header");

        if !auth_header.starts_with("Bearer ") {
            error!("Invalid authorization header format");
            return Err(JwtError::InvalidToken);
        }

        let token = auth_header.trim_start_matches("Bearer ").trim();
        
        if token.is_empty() {
            error!("Empty token in authorization header");
            return Err(JwtError::InvalidToken);
        }

        debug!("Successfully extracted token from header");
        Ok(token.to_string())
    }
    
    fn get_user_id_from_token(&self, token: &str) -> Result<String, JwtError> {
        let claims = self.validate_token(token, None)?;
        Ok(claims.sub)
    }
    
    fn check_role_permission(&self, user_role: &str, required_role: &str) -> bool {
        match (user_role, required_role) {
            // Admin has access to everything
            ("admin", _) => true,
            // Participant only has access to participant resources
            ("user", "user") => true,
            // No other combinations are allowed
            _ => false,
        }
    }

}