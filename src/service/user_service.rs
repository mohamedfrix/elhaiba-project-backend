use tracing::{info, error, instrument};
use crate::repository::user_repo::{UserRepository, UserRepositoryImpl};
use crate::util::jwt::{JwtTokenUtils, JwtTokenUtilsImpl};
use crate::util::password_reset::PasswordResetService;
use std::sync::Arc;
use crate::util::password::{PasswordUtilsImpl, PasswordUtils};


use crate::model::user::User;
use crate::util::error::ServiceError;
use async_trait::async_trait;
use bson::oid::ObjectId;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserAuthResponse {
    pub user: UserWithoutPassword,
    pub tokens: AuthTokens,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserWithoutPassword {
    pub id: Option<ObjectId>,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[async_trait]
pub trait UserService: Send + Sync {
    async fn register(&self, user: User, password: String) -> Result<UserAuthResponse, ServiceError>;
    async fn login(&self, email: String, password: String) -> Result<UserAuthResponse, ServiceError>;
    async fn refresh_token(&self, refresh_token: String) -> Result<AuthTokens, ServiceError>;
    async fn generate_reset_token(&self, email: String) -> Result<String, ServiceError>;
    async fn validate_reset_token(&self, token: String) -> Result<(), ServiceError>;
    async fn reset_password(&self, token: String, new_password: String) -> Result<(), ServiceError>;
}



pub struct UserServiceImpl {
    pub user_repo: Arc<UserRepositoryImpl>,
    pub jwt_utils: Arc<JwtTokenUtilsImpl>,
    pub password_reset: Arc<dyn PasswordResetService + Send + Sync>,
}

impl UserServiceImpl {
    pub fn new(
        user_repo: Arc<UserRepositoryImpl>,
        jwt_utils: Arc<JwtTokenUtilsImpl>,
        password_reset: Arc<dyn PasswordResetService + Send + Sync>,
    ) -> Self {
        Self { user_repo, jwt_utils, password_reset }
    }
}

#[async_trait]
impl UserService for UserServiceImpl {
    #[instrument(skip(self, user, password), fields(username = %user.username, email = %user.email))]
    async fn register(&self, mut user: User, password: String) -> Result<UserAuthResponse, ServiceError> {
        info!("Registering new user");
        let hash = PasswordUtilsImpl::hash_password(&password)
            .map_err(|e| ServiceError::InvalidInput(format!("Password hash error: {}", e)))?;
        user.password_hash = hash;
        let inserted = self.user_repo.insert(user.clone()).await;
        match &inserted {
            Ok(_) => info!("User inserted successfully"),
            Err(e) => error!("Failed to insert user: {e}"),
        }
        let inserted = inserted?;
        let tokens = self.jwt_utils.generate_token_pair(
            &inserted.id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
            &inserted.email,
            &inserted.role
        ).map_err(|e| ServiceError::InternalError(format!("JWT error: {}", e)))?;
        let user_no_pw = UserWithoutPassword {
            id: inserted.id,
            username: inserted.username,
            first_name: inserted.first_name,
            last_name: inserted.last_name,
            email: inserted.email,
            created_at: inserted.created_at,
            updated_at: inserted.updated_at,
        };
        Ok(UserAuthResponse { user: user_no_pw, tokens: AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            token_type: tokens.token_type,
        }})
    }

    #[instrument(skip(self, password), fields(email = %email))]
    async fn login(&self, email: String, password: String) -> Result<UserAuthResponse, ServiceError> {
        info!("User login attempt");
        let user_opt = self.user_repo.find_by_email(&email).await;
        match &user_opt {
            Ok(Some(_)) => info!("User found for login"),
            Ok(None) => error!("User not found for login"),
            Err(e) => error!("Failed to fetch user for login: {e}"),
        }
        let user = user_opt?.ok_or(ServiceError::NotFound("User not found".to_string()))?;
        let valid = PasswordUtilsImpl::verify_password(&password, &user.password_hash)
            .map_err(|e| ServiceError::InvalidInput(format!("Password verify error: {}", e)))?;
        if !valid {
            error!("Invalid credentials for user: {}", email);
            return Err(ServiceError::InvalidInput("Invalid credentials".to_string()));
        }
        let tokens = self.jwt_utils.generate_token_pair(
            &user.id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
            &user.email,
            &user.role
        ).map_err(|e| ServiceError::InternalError(format!("JWT error: {}", e)))?;
        let user_no_pw = UserWithoutPassword {
            id: user.id,
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            created_at: user.created_at,
            updated_at: user.updated_at,
        };
        info!("User logged in successfully");
        Ok(UserAuthResponse { user: user_no_pw, tokens: AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            token_type: tokens.token_type,
        }})
    }

    #[instrument(skip(self, refresh_token))]
    async fn refresh_token(&self, refresh_token: String) -> Result<AuthTokens, ServiceError> {
        info!("Refreshing token");
        let claims = self.jwt_utils.validate_refresh_token(&refresh_token)
            .map_err(|e| ServiceError::InvalidInput(format!("Invalid refresh token: {}", e)))?;
        let tokens = self.jwt_utils.generate_token_pair(
            &claims.sub,
            &claims.email,
            &claims.role
        ).map_err(|e| ServiceError::InternalError(format!("JWT error: {}", e)))?;
        info!("Token refreshed successfully");
        Ok(AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            token_type: tokens.token_type,
        })
    }

    #[instrument(skip(self), fields(email = %email))]
    async fn generate_reset_token(&self, email: String) -> Result<String, ServiceError> {
        info!("Generating password reset token");
        let user_opt = self.user_repo.find_by_email(&email).await;
        match &user_opt {
            Ok(Some(_)) => info!("User found for reset token"),
            Ok(None) => error!("User not found for reset token"),
            Err(e) => error!("Failed to fetch user for reset token: {e}"),
        }
        let user = user_opt?.ok_or(ServiceError::NotFound("User not found".to_string()))?;
        let token = self.password_reset.generate_reset_token(
            &user.id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
            &user.email
        ).await.map_err(|e| ServiceError::InternalError(format!("Reset token error: {}", e)))?;
        info!("Reset token generated successfully");
        Ok(token)
    }

    #[instrument(skip(self, token))]
    async fn validate_reset_token(&self, token: String) -> Result<(), ServiceError> {
        info!("Validating reset token");
        let res = self.password_reset.validate_reset_token(&token).await;
        match &res {
            Ok(_) => info!("Reset token is valid"),
            Err(e) => error!("Invalid reset token: {e}"),
        }
        res.map(|_| ()).map_err(|e| ServiceError::InvalidInput(format!("Invalid reset token: {}", e)))
    }

    #[instrument(skip(self, token, new_password))]
    async fn reset_password(&self, token: String, new_password: String) -> Result<(), ServiceError> {
        info!("Resetting user password");
        let token_info = self.password_reset.use_reset_token(&token).await;
        match &token_info {
            Ok(_) => info!("Reset token used successfully"),
            Err(e) => error!("Invalid or used reset token: {e}"),
        }
        let token_info = token_info.map_err(|e| ServiceError::InvalidInput(format!("Invalid or used reset token: {}", e)))?;
        let user_id = bson::oid::ObjectId::parse_str(&token_info.user_id)
            .map_err(|e| ServiceError::InvalidInput(format!("Invalid user id in token: {}", e)))?;
        let user_opt = self.user_repo.find_by_id(&user_id).await;
        match &user_opt {
            Ok(Some(_)) => info!("User found for password reset"),
            Ok(None) => error!("User not found for password reset"),
            Err(e) => error!("Failed to fetch user for password reset: {e}"),
        }
        let mut user = user_opt?.ok_or(ServiceError::NotFound("User not found".to_string()))?;
        let hash = PasswordUtilsImpl::hash_password(&new_password)
            .map_err(|e| ServiceError::InvalidInput(format!("Password hash error: {}", e)))?;
        user.password_hash = hash;
        self.user_repo.update(user_id, user).await?;
        info!("Password reset successfully");
        Ok(())
    }
}