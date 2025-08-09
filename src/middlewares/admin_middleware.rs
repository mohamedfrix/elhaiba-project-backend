use axum::{http::Request, middleware::Next, response::Response, extract::State, body::Body};
use axum::http::StatusCode;
use std::sync::Arc;
use crate::util::jwt::{JwtTokenUtilsImpl, JwtTokenUtils};
use crate::service::user_service::UserServiceImpl;

pub struct AdminAuthState {
    pub jwt_utils: Arc<JwtTokenUtilsImpl>,
    pub user_service: Arc<UserServiceImpl>,
}

pub async fn admin_auth(
    State(state): State<Arc<AdminAuthState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract the Authorization header
    let auth_header = req.headers().get("authorization").and_then(|v| v.to_str().ok());
    if auth_header.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let auth_header = auth_header.unwrap();

    // Extract and validate the token
    let token = match state.jwt_utils.extract_token_from_header(auth_header) {
        Ok(t) => t,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };
    let claims = match state.jwt_utils.validate_access_token(&token) {
        Ok(c) => c,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    // Check for admin role
    if claims.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    // Optionally, you can attach user info to request extensions here
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}
