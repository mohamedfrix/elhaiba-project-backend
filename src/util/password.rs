//! Password hashing and verification utilities
//! 
//! This module provides secure password hashing using Argon2 algorithm
//! and password verification functions for authentication.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;
use tracing::{debug, error, info};

/// Error types for password operations
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("Failed to hash password: {0}")]
    HashingFailed(String),
    #[error("Failed to verify password: {0}")]
    VerificationFailed(String),
    #[error("Invalid password hash format")]
    InvalidHashFormat,
}

pub trait PasswordUtils {
    /// Hashes the given password using Argon2id algorithm
    fn hash_password(password: &str) -> Result<String, PasswordError>;

    /// Verifies the given password against the stored hash
    fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError>;

    /// Generates a random password of specified length
    fn generate_random_password(length: usize) -> String;

    /// Validates the strength of the given password
    fn validate_password_strength(password: &str) -> Result<(), Vec<String>>;
}

pub struct PasswordUtilsImpl;

impl PasswordUtils for PasswordUtilsImpl {

    fn hash_password(password: &str) -> Result<String, PasswordError> {
        debug!("Hashing password");
        
        // Generate a random salt using OsRng 
        let salt = SaltString::generate(OsRng);
        
        // Hash the password with Argon2id
        let argon2 = Argon2::default();
        
        match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(password_hash) => {
                info!("Password successfully hashed");
                Ok(password_hash.to_string())
            }
            Err(err) => {
                error!("Failed to hash password: {}", err);
                Err(PasswordError::HashingFailed(err.to_string()))
            }
        }
    }

    fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
        debug!("Verifying password against hash");
        debug!("Input password length: {}", password.len());
        debug!("Input password first 3 chars: {}", &password[..std::cmp::min(3, password.len())]);
        debug!("Hash format: {}", &hash[..std::cmp::min(50, hash.len())]);
        
        // Parse the stored hash
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(hash) => hash,
            Err(err) => {
                error!("Invalid password hash format: {}", err);
                return Err(PasswordError::InvalidHashFormat);
            }
        };
        
        // Verify the password
        let argon2 = Argon2::default();
        
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => {
                debug!("Password verification successful");
                Ok(true)
            }
            Err(argon2::password_hash::Error::Password) => {
                debug!("Password verification failed - invalid password");
                Ok(false)
            }
            Err(err) => {
                error!("Password verification error: {}", err);
                Err(PasswordError::VerificationFailed(err.to_string()))
            }
        }
    }

    fn generate_random_password(length: usize) -> String {
        use rand::Rng;
        
        let length = length.max(8); // Ensure minimum length of 8
        debug!("Generating random password of length {}", length);
        
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789";
        let mut rng = rand::thread_rng();
        
        let password: String = (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        
        info!("Random password generated successfully");
        password
    }

    fn validate_password_strength(password: &str) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        
        // Check minimum length
        if password.len() < 8 {
            errors.push("Password must be at least 8 characters long".to_string());
        }
        
        // Check for uppercase letter
        if !password.chars().any(|c| c.is_uppercase()) {
            errors.push("Password must contain at least one uppercase letter".to_string());
        }
        
        // Check for lowercase letter
        if !password.chars().any(|c| c.is_lowercase()) {
            errors.push("Password must contain at least one lowercase letter".to_string());
        }
        
        // Check for digit
        if !password.chars().any(|c| c.is_ascii_digit()) {
            errors.push("Password must contain at least one digit".to_string());
        }
        
        // Check for special character
        if !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
            errors.push("Password must contain at least one special character".to_string());
        }
        
        if errors.is_empty() {
            debug!("Password strength validation passed");
            Ok(())
        } else {
            debug!("Password strength validation failed: {:?}", errors);
            Err(errors)
        }
    }
}
