use axum::{response::{IntoResponse, Response}, http::StatusCode};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum HandlerErrorKind {
    NotFound,
    Validation,
    Internal,
    Unauthorized,
    Forbidden,
    Conflict,
    BadRequest,
    // Add more as needed
}

impl std::fmt::Display for HandlerErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HandlerErrorKind::NotFound => "NotFound",
            HandlerErrorKind::Validation => "Validation",
            HandlerErrorKind::Internal => "Internal",
            HandlerErrorKind::Unauthorized => "Unauthorized",
            HandlerErrorKind::Forbidden => "Forbidden",
            HandlerErrorKind::Conflict => "Conflict",
            HandlerErrorKind::BadRequest => "BadRequest",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Serialize)]
pub struct HandlerError {
    pub error: HandlerErrorKind,
    pub message: String,
    pub details: Option<String>,
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

impl std::error::Error for HandlerError {}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let status = match self.error {
            HandlerErrorKind::NotFound => StatusCode::NOT_FOUND,
            HandlerErrorKind::Validation | HandlerErrorKind::BadRequest => StatusCode::BAD_REQUEST,
            HandlerErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
            HandlerErrorKind::Forbidden => StatusCode::FORBIDDEN,
            HandlerErrorKind::Conflict => StatusCode::CONFLICT,
            HandlerErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = axum::Json(self);
        (status, body).into_response()
    }
}


#[derive(Debug, Clone)]
pub enum ServiceError {
    NotFound(String),
    InvalidInput(String),
    InternalError(String),
    Conflict(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::NotFound(msg) => write!(f, "Not Found: {}", msg),
            ServiceError::InvalidInput(msg) => write!(f, "Invalid Input: {}", msg),
            ServiceError::InternalError(msg) => write!(f, "Internal Error: {}", msg),
            ServiceError::Conflict(msg) => write!(f, "Conflict: {}", msg),
        }
    }
}
impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

// Allow conversion from RepositoryError to ServiceError
impl From<crate::repository::repository_error::RepositoryError> for ServiceError {
    fn from(err: crate::repository::repository_error::RepositoryError) -> Self {
        use crate::repository::repository_error::RepositoryError;
        match err {
            RepositoryError::NotFound(msg) => ServiceError::NotFound(msg),
            RepositoryError::ValidationError(msg) => ServiceError::InvalidInput(msg),
            RepositoryError::AlreadyExists(msg) => ServiceError::Conflict(msg),
            RepositoryError::DatabaseError(msg) => ServiceError::InternalError(msg),
            RepositoryError::ConnectionError(msg) => ServiceError::InternalError(msg),
            RepositoryError::SerializationError(msg) => ServiceError::InternalError(msg),
            RepositoryError::Generic(e) => ServiceError::InternalError(e.to_string()),
        }
    }
}


