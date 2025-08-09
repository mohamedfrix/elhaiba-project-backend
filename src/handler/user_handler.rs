use axum::{extract::{State, Json}, response::IntoResponse};
use crate::service::user_service::{UserServiceImpl, UserService};
use crate::model::user::User;
use std::sync::Arc;
use crate::util::error::{HandlerError, HandlerErrorKind};
use serde::Deserialize;
use validator::Validate;


#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 32))]
    pub username: String,
    #[validate(length(min = 2, max = 32))]
    pub first_name: String,
    #[validate(length(min = 2, max = 32))]
    pub last_name: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 10))]
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 10))]
    pub token: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct EmailRequest {
    #[validate(email)]
    pub email: String,
}


// Register
pub async fn register_handler(
    State(service): State<Arc<UserServiceImpl>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    let user = User {
        id: None,
        username: payload.username,
        first_name: payload.first_name,
        last_name: payload.last_name,
        email: payload.email.clone(),
        password_hash: String::new(),
        role: "user".to_string(),
        created_at: None,
        updated_at: None,
    };
    let res = service.register(user, payload.password).await.map_err(|e| HandlerError {
        error: HandlerErrorKind::Internal,
        message: e.to_string(),
        details: None,
    })?;
    Ok(Json(res))
}


// Login
pub async fn login_handler(
    State(service): State<Arc<UserServiceImpl>>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    let res = service.login(payload.email, payload.password).await.map_err(|e| HandlerError {
        error: HandlerErrorKind::Internal,
        message: e.to_string(),
        details: None,
    })?;
    Ok(Json(res))
}


// Refresh Token
pub async fn refresh_token_handler(
    State(service): State<Arc<UserServiceImpl>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    let res = service.refresh_token(payload.refresh_token).await.map_err(|e| HandlerError {
        error: HandlerErrorKind::Internal,
        message: e.to_string(),
        details: None,
    })?;
    Ok(Json(res))
}


// Generate Reset Token
pub async fn generate_reset_token_handler(
    State(service): State<Arc<UserServiceImpl>>,
    Json(payload): Json<EmailRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    let res = service.generate_reset_token(payload.email).await.map_err(|e| HandlerError {
        error: HandlerErrorKind::Internal,
        message: e.to_string(),
        details: None,
    })?;
    Ok(Json(res))
}


// Validate Reset Token
pub async fn validate_reset_token_handler(
    State(service): State<Arc<UserServiceImpl>>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    service.validate_reset_token(payload.token).await.map_err(|e| HandlerError {
        error: HandlerErrorKind::Internal,
        message: e.to_string(),
        details: None,
    })?;
    Ok(Json("Token valid"))
}


// Reset Password
pub async fn reset_password_handler(
    State(service): State<Arc<UserServiceImpl>>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    service.reset_password(payload.token, payload.new_password).await.map_err(|e| HandlerError {
        error: HandlerErrorKind::Internal,
        message: e.to_string(),
        details: None,
    })?;
    Ok(Json("Password reset successful"))
}
