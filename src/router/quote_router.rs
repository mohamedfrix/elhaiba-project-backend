
use axum::{Router, routing::{post, get, put}, middleware};
use crate::handler::quote_handler::{
    create_quote_handler,
    list_quotes_handler,
    update_quote_status_handler,
    get_quote_handler,
    add_quote_note_handler,
    get_quote_note_handler,
    list_quote_notes_handler,
};
use std::sync::Arc;
use crate::service::quote_service::QuoteServiceImpl;
use crate::middlewares::admin_middleware::{admin_auth, AdminAuthState};


pub fn quote_router(service: Arc<QuoteServiceImpl>, admin_auth_state: Arc<AdminAuthState>) -> Router {
    // Public route
    let public = Router::new()
        .route("/quotes", post(create_quote_handler));

    // Admin-protected routes
    let admin = Router::new()
        .route("/quotes", get(list_quotes_handler))
        .route("/quotes/{id}/status", put(update_quote_status_handler))
        .route("/quotes/{id}", get(get_quote_handler))
        .route("/quotes/notes", post(add_quote_note_handler))
        .route("/quotes/notes/{id}", get(get_quote_note_handler))
        .route("/quotes/{quote_id}/notes", get(list_quote_notes_handler))
        .route_layer(middleware::from_fn_with_state(admin_auth_state.clone(), admin_auth));

    public
        .merge(admin)
        .with_state(service)
}
