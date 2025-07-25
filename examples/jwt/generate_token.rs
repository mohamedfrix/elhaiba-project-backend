use elhaiba_backend::{util::{jwt::{JwtTokenUtils, JwtTokenUtilsImpl}, logger::Logger}};
use tracing::{error, info, debug, warn};
use uuid::Uuid;
use dotenv::dotenv;

#[tokio::main]
async fn main () -> Result<(), Box<dyn std::error::Error>> {

    let logger = Logger::new()?;
    let _guards = logger.guards;

    match dotenv() {
        Ok(_) => info!("✅ Successfully loaded .env file"),
        Err(e) => warn!("⚠️ Failed to load .env file: {} (using system env vars)", e),
    }



    let jwt_util = match JwtTokenUtilsImpl::from_env(){
        Ok(util) => {
            info!("JWT utils created successfully");
            util
        },
        Err(e) => {
            error!("Failed to create JWT utils Missing Config: {}", e);
            return Err(Box::<dyn std::error::Error>::from(e));
        }
    };

    let user_id = Uuid::new_v4(); // Or use an existing UUID
    let email = "user@example.com";
    let role = "user";

    debug!(
        user_id = %user_id,
        email = %email,
        role = %role,
        "Generating JWT token pair for user"
    );

    let token_pairs = match jwt_util.generate_token_pair(user_id.to_string().as_str(), email, role){
        Ok(pairs) => {
            info!("Successfully generated JWT token pair for user: {}", user_id);
            pairs
        },
        Err(e) => {
            error!("Failed to generate JWT token pair: {}", e);
            return Err(Box::<dyn std::error::Error>::from(e));
        }
    };

    debug!(
        access_token = %token_pairs.access_token,
        refresh_token = %token_pairs.refresh_token,
        "Generated JWT token pair"
    );

    // Validate access token
    let claims = match jwt_util.validate_access_token(&token_pairs.access_token) {
        Ok(claims) => {
            info!("Access token validated successfully for user: {}", claims.sub);
            claims
        },
        Err(e) => {
            error!("Failed to validate access token: {}", e);
            return Err(Box::<dyn std::error::Error>::from(e));
        }
    };

    debug!(
        claims = ?claims,
        "Access token claims"
    );

    // Validate refresh token
    let refresh_claims = match jwt_util.validate_refresh_token(&token_pairs.refresh_token) {
        Ok(claims) => {
            info!("Refresh token validates successfully for user: {}", claims.sub);
            claims
        },
        Err(e) => {
            error!("Failed to validate refresh token: {}", e);
            return Err(Box::<dyn std::error::Error>::from(e));
        }
    };

    debug!(
        claims = ?refresh_claims,
        "Refresh token claims"
    );

    match jwt_util.check_role_permission(&claims.role, "admin") {
        true => {
            info!(
                user_id = &claims.sub,
                role = &claims.role,
                user_email = &claims.email,
                "User have required role: {}", &claims.role
            )
        }
        false => {
            error!(
                user_id = &claims.sub,
                role = &claims.role,
                user_email = &claims.email,
                "User does not have required role admin, current role: {}", &claims.role
            );
            return Err(Box::<dyn std::error::Error>::from (format!("User does not have required role admin, current role: {}", &claims.role)));
        }
    };


    Ok(())
}