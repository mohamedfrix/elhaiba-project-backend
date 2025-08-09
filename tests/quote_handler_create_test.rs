use axum::{body::Body, http::{Request, StatusCode}, Router};
use http_body_util::BodyExt;
use elhaiba_backend::router::quote_router::quote_router;
use elhaiba_backend::service::quote_service::QuoteServiceImpl;
use std::sync::Arc;
use tower::ServiceExt; // for .oneshot()
use serde_json::json;
use bytes::Bytes;
use dotenv::dotenv;

use elhaiba_backend::util::jwt::JwtTokenUtilsImpl;
use elhaiba_backend::service::user_service::UserServiceImpl;
use elhaiba_backend::repository::user_repo::UserRepositoryImpl;
use elhaiba_backend::util::password_reset::RedisPasswordResetService;
use elhaiba_backend::util::redis::RedisService;
use elhaiba_backend::config::{PasswordResetConfig, JwtConfig, RedisConfig};
use elhaiba_backend::util::minio::MinioService;
use elhaiba_backend::config::mongo_conf::MongoConfig;


#[tokio::test]
async fn test_create_quote_with_file() {
    let _ = dotenv::dotenv();
    // Setup: create a test service (mock or real, depending on your infra)
    // Here we assume a real service, but you can mock QuoteServiceImpl if needed
    let mongo_config = elhaiba_backend::config::mongo_conf::MongoConfig::from_env().expect("mongo config");
    let minio_config = elhaiba_backend::config::minio_conf::MinioConfig::from_env().expect("minio config");
    let quote_service = Arc::new(QuoteServiceImpl::new(&mongo_config, &minio_config).await.expect("service"));


    let jwt_config = JwtConfig::from_env().expect("JWT config error");
    let mongo_config = MongoConfig::from_env().expect("Mongo config error");
    let redis_config = RedisConfig::from_env().expect("Redis config error");
    let password_reset_config = PasswordResetConfig::from_env().expect("PasswordResetConfig error");
    let redis_service = Box::new(RedisService::new(redis_config.clone()).await.expect("RedisService error")) as Box<dyn elhaiba_backend::util::redis::RedisServiceTrait>;
    let password_reset = Arc::new(
        RedisPasswordResetService::new(password_reset_config, redis_service)
            .expect("Failed to create RedisPasswordResetService")
    ) as Arc<dyn elhaiba_backend::util::password_reset::PasswordResetService + Send + Sync>;
    let user_repo = Arc::new(UserRepositoryImpl::new(&mongo_config).await.expect("User repo error"));
    let jwt_utils = Arc::new(JwtTokenUtilsImpl::new(jwt_config));
    let user_service = Arc::new(UserServiceImpl::new(user_repo, jwt_utils.clone(), password_reset));
    use elhaiba_backend::middlewares::admin_middleware::AdminAuthState;
        let admin_auth_state = Arc::new(AdminAuthState {
            jwt_utils: jwt_utils.clone(),
            user_service: user_service.clone(),
        });

    let app = Router::new().merge(quote_router(quote_service.clone(), admin_auth_state.clone()));

    // Prepare multipart body
    let quote_json = json!({
        "fullName": "Test User",
        "phone": "+213770000000",
        "email": "test@elhaiba.com",
        "country": "Algeria",
        "wilaya": "Algiers",
        "address": "123 Main St",
        "spaceType": "Residential",
        "spaceTypeOther": null,
        "projectState": "Planned",
        "area": 120.5,
        "floorsNumber": 2,
        "vacantLand": true,
        "serviceType": "Architecture",
        "serviceTypeOther": null,
        "haveFiles": true,
        "files": null,
        "startDate": "2025-10-01",
        "note": "Test quote",
        "firstTime": true,
        "hearAboutUs": "Instagram",
        "status": null,
        "createdAt": null,
        "updatedAt": null
    });
    let quote_json_str = serde_json::to_string(&quote_json).unwrap();

    let file_bytes = Bytes::from_static(b"dummy file content");
    let boundary = "X-BOUNDARY";
    let mut body = Vec::new();
    // Add json part
    body.extend(format!("--{}\r\nContent-Disposition: form-data; name=\"json\"\r\n\r\n{}\r\n", boundary, quote_json_str).as_bytes());
    // Add file part
    body.extend(format!("--{}\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\n", boundary).as_bytes());
    body.extend(&file_bytes);
    body.extend(b"\r\n");
    // End boundary
    body.extend(format!("--{}--\r\n", boundary).as_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/quotes")
        .header("content-type", format!("multipart/form-data; boundary={}", boundary))
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    println!("Response body: {}", String::from_utf8_lossy(&body_bytes));
    assert_eq!(status, StatusCode::OK);
    // Optionally, check the response body for expected fields
}
