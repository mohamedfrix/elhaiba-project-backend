use axum::{Router, routing::{post}, middleware};
use crate::handler::user_handler::{
    login_handler,
    refresh_token_handler,
    generate_reset_token_handler,
    validate_reset_token_handler,
    reset_password_handler,
};
use std::sync::Arc;
use crate::service::user_service::UserServiceImpl;
use crate::middlewares::admin_middleware::{admin_auth, AdminAuthState};

pub fn user_router(service: Arc<UserServiceImpl>, admin_auth_state: Arc<AdminAuthState>) -> Router {
    // Public login route
    let public = Router::new()
        .route("/users/login", post(login_handler));

    // Public refresh-token route
    let public = public
        .route("/users/refresh-token", post(refresh_token_handler));

    // Admin-protected user routes (except login and refresh-token)
    let admin = Router::new()
        .route("/users/generate-reset-token", post(generate_reset_token_handler))
        .route("/users/validate-reset-token", post(validate_reset_token_handler))
        .route("/users/reset-password", post(reset_password_handler))
        .route_layer(middleware::from_fn_with_state(admin_auth_state.clone(), admin_auth));

    public
        .merge(admin)
        .with_state(service)
}
