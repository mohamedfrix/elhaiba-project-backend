use axum::body::to_bytes;
use axum::{body::Body, http::{Request, StatusCode}, Router};
use elhaiba_backend::router::user_router::user_router;
use elhaiba_backend::service::user_service::UserServiceImpl;
use elhaiba_backend::middlewares::admin_middleware::{admin_auth, AdminAuthState};
use std::sync::Arc;
use tower::ServiceExt; // for .oneshot()
use serde_json::json;
use dotenv::dotenv;

#[tokio::test]
async fn test_login_handler() {
    let _ = dotenv();
    // Setup: create a test service (mock or real, depending on your infra)
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
    let app = Router::new().merge(user_router(user_service.clone(), admin_auth_state.clone()));

    // Prepare login body (assuming a user with this email/password exists)
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
    println!("Response: {:?}", resp);
    assert_eq!(resp.status(), StatusCode::OK);
    // Optionally, check the response body for expected fields
   
}

// Add similar tests for refresh_token, generate_reset_token, validate_reset_token, reset_password
// You can use the same pattern as above, adjusting the endpoint, method, and body as needed.

#[tokio::test]
async fn test_refresh_token_handler() {
    let _ = dotenv();
    // Setup: create a test service (mock or real, depending on your infra)
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
    let app = Router::new().merge(user_router(user_service.clone(), admin_auth_state.clone()));

    // First, login to get a refresh token
    let login_body = json!({
        "email": "admin@example.com",
        "password": "changeme123"
    });
    let login_req = Request::builder()
        .method("POST")
        .uri("/users/login")
        .header("content-type", "application/json")
        .body(Body::from(login_body.to_string()))
        .unwrap();
    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(login_resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(login_resp.into_body(), 1024 * 1024).await.unwrap(); // 1 MB limit
    let login_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let access_token = login_json["tokens"]["access_token"].as_str().expect("access_token missing");
    let refresh_token = login_json["tokens"]["refresh_token"].as_str().expect("refresh_token missing");
    println!("Access Token: {}", access_token);
    println!("Refresh Token: {}", refresh_token);

    // Now, call refresh_token endpoint
    let refresh_body = json!({
        "refresh_token": refresh_token
    });
    let refresh_req = Request::builder()
        .method("POST")
        .uri("/users/refresh-token")
        .header("content-type", "application/json")
        .body(Body::from(refresh_body.to_string()))
        .unwrap();
    let refresh_resp = app.clone().oneshot(refresh_req).await.unwrap();
    println!("Refresh request body: {}", refresh_body.to_string());
    println!("Refresh Response: {:?}", refresh_resp);
    let refresh_status = refresh_resp.status();
    let refresh_body_bytes = to_bytes(refresh_resp.into_body(), 1024 * 1024).await.unwrap();
    let refresh_body_str = String::from_utf8_lossy(&refresh_body_bytes);
    println!("Refresh Response Body: {}", refresh_body_str);
    assert_eq!(refresh_status, StatusCode::OK);
    // Optionally, check the response body for expected fields
}