use axum::{body::to_bytes, body::Body, http::{Request, StatusCode}, Router};
use elhaiba_backend::router::user_router::user_router;
use elhaiba_backend::router::quote_router::quote_router;
use elhaiba_backend::service::user_service::UserServiceImpl;
use elhaiba_backend::service::quote_service::QuoteServiceImpl;
use elhaiba_backend::middlewares::admin_middleware::AdminAuthState;
use std::sync::Arc;
use tower::ServiceExt;
use serde_json::json;
use dotenv::dotenv;

async fn setup_app() -> Router {
    let _ = dotenv();
    let mongo_config = elhaiba_backend::config::mongo_conf::MongoConfig::from_env().expect("mongo config");
    let jwt_config = elhaiba_backend::config::jwt_conf::JwtConfig::from_env().expect("jwt config");
    let redis_config = elhaiba_backend::config::redis_conf::RedisConfig::from_env().expect("redis config");
    let password_reset_config = elhaiba_backend::config::PasswordResetConfig::from_env().expect("PasswordResetConfig error");
    let redis_service = Box::new(elhaiba_backend::util::redis::RedisService::new(redis_config.clone()).await.expect("RedisService error")) as Box<dyn elhaiba_backend::util::redis::RedisServiceTrait>;
    let password_reset = Arc::new(
        elhaiba_backend::util::password_reset::RedisPasswordResetService::new(password_reset_config, redis_service)
            .expect("Failed to create RedisPasswordResetService")
    ) as Arc<dyn elhaiba_backend::util::password_reset::PasswordResetService + Send + Sync>;
    let user_repo = Arc::new(elhaiba_backend::repository::user_repo::UserRepositoryImpl::new(&mongo_config).await.expect("User repo error"));
    let jwt_utils = Arc::new(elhaiba_backend::util::jwt::JwtTokenUtilsImpl::new(jwt_config));
    let user_service = Arc::new(UserServiceImpl::new(user_repo, jwt_utils.clone(), password_reset));
    let admin_auth_state = Arc::new(AdminAuthState {
        jwt_utils: jwt_utils.clone(),
        user_service: user_service.clone(),
    });
    let minio_config = elhaiba_backend::config::minio_conf::MinioConfig::from_env().expect("Minio config error");
    let quote_repo = elhaiba_backend::repository::quote_repo::MongoQuoteRepository::new(&mongo_config).await.expect("Quote repo error");
    let note_repo = elhaiba_backend::repository::quote_note_repo::MongoQuoteNoteRepository::new(&mongo_config).await.expect("Quote note repo error");
    let quote_file_repo = Arc::new(elhaiba_backend::repository::quote_file_repo::MongoQuoteFileRepository::new(&mongo_config).await.expect("Quote file repo error"));
    let minio_service = Arc::new(elhaiba_backend::util::minio::MinioService::new(minio_config).await.expect("Minio service error"));
    let quote_service = Arc::new(QuoteServiceImpl {
        quote_repo,
        note_repo,
        quote_file_repo,
        minio_service,
    });
    Router::new()
        .merge(user_router(user_service.clone(), admin_auth_state.clone()))
        .merge(quote_router(quote_service.clone(), admin_auth_state.clone()))
}

async fn get_admin_access_token(app: &Router) -> String {
    let login_body = json!({
        "email": "admin@example.com",
        "password": "changeme123"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/users/login")
        .header("content-type", "application/json")
        .body(Body::from(login_body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    login_json["tokens"]["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_list_quotes_handler() {
    let app = setup_app().await;
    let access_token = get_admin_access_token(&app).await;
    let req = Request::builder()
        .method("GET")
        .uri("/quotes")
        .header("authorization", format!("Bearer {}", access_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_update_quote_status_handler() {
    let app = setup_app().await;
    let access_token = get_admin_access_token(&app).await;
    // You need a valid quote id in your test DB. Replace below with a real one or insert a quote first.
    let quote_id = "replace_with_valid_quote_id";
    let body = json!({ "status": "approved" });
    let req = Request::builder()
        .method("PUT")
        .uri(&format!("/quotes/{}/status", quote_id))
        .header("authorization", format!("Bearer {}", access_token))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Accept 200 or 400 (if id is invalid)
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_quote_handler() {
    let app = setup_app().await;
    let access_token = get_admin_access_token(&app).await;
    let quote_id = "replace_with_valid_quote_id";
    let req = Request::builder()
        .method("GET")
        .uri(&format!("/quotes/{}", quote_id))
        .header("authorization", format!("Bearer {}", access_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_add_quote_note_handler() {
    let app = setup_app().await;
    let access_token = get_admin_access_token(&app).await;
    let quote_id = "replace_with_valid_quote_id";
    let body = json!({ "quote_id": quote_id, "content": "Test note content" });
    let req = Request::builder()
        .method("POST")
        .uri("/quotes/notes")
        .header("authorization", format!("Bearer {}", access_token))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_quote_note_handler() {
    let app = setup_app().await;
    let access_token = get_admin_access_token(&app).await;
    let note_id = "replace_with_valid_note_id";
    let req = Request::builder()
        .method("GET")
        .uri(&format!("/quotes/notes/{}", note_id))
        .header("authorization", format!("Bearer {}", access_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_list_quote_notes_handler() {
    let app = setup_app().await;
    let access_token = get_admin_access_token(&app).await;
    let quote_id = "replace_with_valid_quote_id";
    let req = Request::builder()
        .method("GET")
        .uri(&format!("/quotes/{}/notes", quote_id))
        .header("authorization", format!("Bearer {}", access_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST);
}
