#![feature(test)]
extern crate test;

use test::Bencher;
use elhaiba_backend::util::jwt::{JwtTokenUtilsImpl, JwtTokenUtils};

/// Helper function to create JWT utils for benchmarking
fn create_bench_jwt_utils() -> JwtTokenUtilsImpl {
    JwtTokenUtilsImpl::new(
        "bench_secret_key_for_testing_purposes_only_very_long_key_that_ensures_security",
        3600,  // 1 hour access token expiration
        86400, // 24 hour refresh token expiration
    )
}

/// Benchmark: Generate access token
/// Tests the performance of creating JWT access tokens
#[bench]
fn bench_generate_access_token(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    b.iter(|| {
        jwt_utils.generate_access_token("user123", "user@example.com", "user")
    });
}

/// Benchmark: Generate refresh token
/// Tests the performance of creating JWT refresh tokens
#[bench]
fn bench_generate_refresh_token(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    b.iter(|| {
        jwt_utils.generate_refresh_token("user123", "user@example.com", "user")
    });
}

/// Benchmark: Generate token pair
/// Tests the performance of creating both access and refresh tokens together
#[bench]
fn bench_generate_token_pair(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    b.iter(|| {
        jwt_utils.generate_token_pair("user123", "user@example.com", "user")
    });
}

/// Benchmark: Validate access token
/// Tests the performance of JWT token validation
#[bench]
fn bench_validate_access_token(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    let token = jwt_utils.generate_access_token("user123", "user@example.com", "user").unwrap();
    
    b.iter(|| {
        jwt_utils.validate_access_token(&token)
    });
}

/// Benchmark: Validate refresh token
/// Tests the performance of JWT refresh token validation
#[bench]
fn bench_validate_refresh_token(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    let token = jwt_utils.generate_refresh_token("user123", "user@example.com", "user").unwrap();
    
    b.iter(|| {
        jwt_utils.validate_refresh_token(&token)
    });
}

/// Benchmark: Extract token from header
/// Tests the performance of extracting JWT from Authorization header
#[bench]
fn bench_extract_token_from_header(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    let token = jwt_utils.generate_access_token("user123", "user@example.com", "user").unwrap();
    let header = format!("Bearer {}", token);
    
    b.iter(|| {
        jwt_utils.extract_token_from_header(&header)
    });
}

/// Benchmark: Get user ID from token
/// Tests the performance of extracting user ID from JWT claims
#[bench]
fn bench_get_user_id_from_token(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    let token = jwt_utils.generate_access_token("user123", "user@example.com", "user").unwrap();
    
    b.iter(|| {
        jwt_utils.get_user_id_from_token(&token)
    });
}

/// Benchmark: Check role permission
/// Tests the performance of role-based access control checks
#[bench]
fn bench_check_role_permission(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    
    b.iter(|| {
        jwt_utils.check_role_permission("admin", "user")
    });
}

/// Benchmark: Complete token validation flow
/// Tests the performance of a complete token validation workflow:
/// Extract from header -> Validate token -> Get user ID
#[bench]
fn bench_complete_token_validation_flow(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    let token = jwt_utils.generate_access_token("user123", "user@example.com", "admin").unwrap();
    let header = format!("Bearer {}", token);
    
    b.iter(|| {
        // Extract token from header
        let extracted_token = jwt_utils.extract_token_from_header(&header).unwrap();
        // Validate the token
        let _claims = jwt_utils.validate_access_token(&extracted_token).unwrap();
        // Get user ID from token
        jwt_utils.get_user_id_from_token(&extracted_token).unwrap()
    });
}

/// Benchmark: Token generation under different roles
/// Tests if token generation performance varies by role
#[bench]
fn bench_token_generation_different_roles(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    let roles = ["user", "admin", "moderator", "guest"];
    let mut role_index = 0;
    
    b.iter(|| {
        let role = roles[role_index % roles.len()];
        role_index += 1;
        jwt_utils.generate_access_token("user123", "user@example.com", role)
    });
}

/// Benchmark: Concurrent token validation simulation
/// Tests token validation performance under simulated concurrent load
#[bench]
fn bench_concurrent_token_validation(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    
    // Pre-generate multiple tokens to simulate different users
    let tokens: Vec<String> = (0..10)
        .map(|i| {
            jwt_utils.generate_access_token(
                &format!("user{}", i), 
                &format!("user{}@example.com", i), 
                "user"
            ).unwrap()
        })
        .collect();
    
    let mut token_index = 0;
    
    b.iter(|| {
        let token = &tokens[token_index % tokens.len()];
        token_index += 1;
        jwt_utils.validate_access_token(token)
    });
}

/// Benchmark: Token serialization/deserialization
/// Tests the performance of token pair serialization
#[bench]
fn bench_token_serialization(b: &mut Bencher) {
    let jwt_utils = create_bench_jwt_utils();
    let token_pair = jwt_utils.generate_token_pair("user123", "user@example.com", "user").unwrap();
    
    b.iter(|| {
        // Serialize to JSON
        let serialized = serde_json::to_string(&token_pair).unwrap();
        // Deserialize back
        let _deserialized: elhaiba_backend::util::jwt::TokenPair = 
            serde_json::from_str(&serialized).unwrap();
    });
}
