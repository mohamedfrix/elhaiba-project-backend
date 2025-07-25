# Password Utility Documentation

## Overview

The Password utility provides a comprehensive password management system for the ElHaiba backend application. It implements secure password hashing using the Argon2id algorithm, password verification, strength validation, and random password generation. The utility is designed with security-first principles and follows modern cryptographic best practices.

## Purpose and Philosophy

### Design Philosophy

The Password utility is built around these core security principles:

1. **Security by Default**: Uses the most secure algorithms and configurations available
2. **Cryptographic Strength**: Implements Argon2id, the winner of the Password Hashing Competition
3. **Zero-Knowledge Design**: Passwords are never stored in plaintext or recoverable formats
4. **Strength Enforcement**: Configurable password complexity requirements
5. **Timing Attack Resistance**: Constant-time operations where possible
6. **Auditability**: Clear logging and error reporting for security monitoring

### Use Cases

- **User Registration**: Secure password hashing during account creation
- **Authentication**: Password verification during login
- **Password Policy Enforcement**: Validating password strength requirements
- **Password Reset**: Generating secure temporary passwords
- **Security Auditing**: Ensuring password compliance across the system
- **Administrative Functions**: Bulk password operations and security assessments

## Architecture

### Core Components

#### 1. PasswordUtilsImpl
The main implementation struct providing all password operations:

```rust
pub struct PasswordUtilsImpl;
```

#### 2. PasswordUtils Trait
Defines the interface for password operations:

```rust
pub trait PasswordUtils {
    fn hash_password(password: &str) -> Result<String, PasswordError>;
    fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError>;
    fn generate_random_password(length: usize) -> String;
    fn validate_password_strength(password: &str) -> Result<(), Vec<String>>;
}
```

#### 3. PasswordError
Comprehensive error handling for password operations:

```rust
pub enum PasswordError {
    HashingFailed(String),
    VerificationFailed(String),
    InvalidHashFormat,
}
```

## Implementation Details

### Argon2id Password Hashing

The utility uses Argon2id, the recommended password hashing algorithm:

```rust
fn hash_password(password: &str) -> Result<String, PasswordError> {
    // Generate a cryptographically secure random salt
    let salt = SaltString::generate(OsRng);
    
    // Use Argon2id with default secure parameters
    let argon2 = Argon2::default();
    
    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(err) => Err(PasswordError::HashingFailed(err.to_string())),
    }
}
```

#### Why Argon2id?

1. **Memory-Hard Function**: Resistant to GPU and ASIC attacks
2. **Time-Memory Tradeoff**: Configurable memory and time costs
3. **Side-Channel Resistance**: Designed to resist timing attacks
4. **Proven Security**: Winner of the Password Hashing Competition
5. **Future-Proof**: Actively maintained and updated

### Password Verification Process

Verification ensures constant-time comparison and proper error handling:

```rust
fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    // Parse the stored hash with validation
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(hash) => hash,
        Err(err) => return Err(PasswordError::InvalidHashFormat),
    };
    
    let argon2 = Argon2::default();
    
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(err) => Err(PasswordError::VerificationFailed(err.to_string())),
    }
}
```

### Password Strength Validation

Comprehensive strength validation with configurable rules:

```rust
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
        Ok(())
    } else {
        Err(errors)
    }
}
```

### Secure Random Password Generation

Cryptographically secure password generation:

```rust
fn generate_random_password(length: usize) -> String {
    use rand::Rng;
    
    let length = length.max(8); // Ensure minimum length
    
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
    
    password
}
```

## API Reference

### Primary Methods

#### `hash_password(password: &str) -> Result<String, PasswordError>`
Securely hashes a password using Argon2id algorithm.

**Parameters:**
- `password`: The plaintext password to hash

**Returns:**
- `Ok(String)`: Argon2id hash string suitable for storage
- `Err(PasswordError::HashingFailed)`: Hashing operation failed

**Example:**
```rust
let password = "user_password_123";
let hash = PasswordUtilsImpl::hash_password(password)?;
// hash: "$argon2id$v=19$m=65536,t=2,p=1$..."
```

#### `verify_password(password: &str, hash: &str) -> Result<bool, PasswordError>`
Verifies a password against its stored hash.

**Parameters:**
- `password`: The plaintext password to verify
- `hash`: The stored Argon2id hash string

**Returns:**
- `Ok(true)`: Password matches the hash
- `Ok(false)`: Password does not match the hash
- `Err(PasswordError)`: Verification operation failed

**Example:**
```rust
let password = "user_password_123";
let stored_hash = "$argon2id$v=19$m=65536,t=2,p=1$...";
let is_valid = PasswordUtilsImpl::verify_password(password, stored_hash)?;
```

#### `generate_random_password(length: usize) -> String`
Generates a cryptographically secure random password.

**Parameters:**
- `length`: Desired password length (minimum 8 characters)

**Returns:**
- `String`: Randomly generated password containing alphanumeric characters

**Example:**
```rust
let random_password = PasswordUtilsImpl::generate_random_password(16);
// Example output: "Kj8mN3qR2wE5tY9p"
```

#### `validate_password_strength(password: &str) -> Result<(), Vec<String>>`
Validates password against strength requirements.

**Parameters:**
- `password`: The password to validate

**Returns:**
- `Ok(())`: Password meets all strength requirements
- `Err(Vec<String>)`: List of validation errors

**Example:**
```rust
let password = "weak";
match PasswordUtilsImpl::validate_password_strength(password) {
    Ok(()) => println!("Password is strong"),
    Err(errors) => {
        for error in errors {
            println!("Validation error: {}", error);
        }
    }
}
```

## Configuration

### Default Password Requirements

The utility enforces these password strength requirements by default:

```rust
pub struct PasswordPolicy {
    pub min_length: usize,              // Minimum 8 characters
    pub require_uppercase: bool,        // At least one uppercase letter
    pub require_lowercase: bool,        // At least one lowercase letter
    pub require_digit: bool,            // At least one digit
    pub require_special_char: bool,     // At least one special character
    pub forbidden_patterns: Vec<String>, // Optional: Common weak patterns
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special_char: true,
            forbidden_patterns: vec![
                "password".to_string(),
                "123456".to_string(),
                "qwerty".to_string(),
            ],
        }
    }
}
```

### Special Characters

The following special characters are accepted:
```
!@#$%^&*()_+-=[]{}|;:,.<>?
```

### Argon2id Parameters

The utility uses Argon2's default parameters, which are:

```rust
// Argon2::default() uses these secure parameters:
// - Memory cost: 65536 KB (64 MB)
// - Time cost: 2 iterations
// - Parallelism: 1 thread
// - Algorithm: Argon2id (hybrid of Argon2i and Argon2d)
```

## Usage Examples

### User Registration

```rust
use elhaiba_backend::util::password::{PasswordUtilsImpl, PasswordUtils};

async fn register_user(
    email: String,
    password: String,
) -> Result<User, RegistrationError> {
    // Validate password strength
    if let Err(errors) = PasswordUtilsImpl::validate_password_strength(&password) {
        return Err(RegistrationError::WeakPassword(errors));
    }
    
    // Hash the password
    let password_hash = PasswordUtilsImpl::hash_password(&password)
        .map_err(RegistrationError::HashingFailed)?;
    
    // Store user with hashed password
    let user = User {
        id: generate_user_id(),
        email,
        password_hash,
        created_at: Utc::now(),
    };
    
    save_user_to_database(&user).await?;
    
    Ok(user)
}
```

### User Authentication

```rust
async fn authenticate_user(
    email: &str,
    password: &str,
) -> Result<User, AuthenticationError> {
    // Retrieve user from database
    let user = find_user_by_email(email).await
        .ok_or(AuthenticationError::UserNotFound)?;
    
    // Verify password
    let is_valid = PasswordUtilsImpl::verify_password(password, &user.password_hash)
        .map_err(AuthenticationError::VerificationFailed)?;
    
    if !is_valid {
        return Err(AuthenticationError::InvalidPassword);
    }
    
    Ok(user)
}
```

### Password Reset with Temporary Password

```rust
async fn generate_temporary_password(user_id: &str) -> Result<String, PasswordResetError> {
    // Generate secure temporary password
    let temp_password = PasswordUtilsImpl::generate_random_password(12);
    
    // Hash for storage
    let temp_hash = PasswordUtilsImpl::hash_password(&temp_password)
        .map_err(PasswordResetError::HashingFailed)?;
    
    // Store temporary password hash (with expiration)
    store_temporary_password(user_id, &temp_hash, Duration::hours(1)).await?;
    
    // Return plaintext password for email (only time it's in plaintext)
    Ok(temp_password)
}
```

### Password Change

```rust
async fn change_password(
    user_id: &str,
    current_password: &str,
    new_password: &str,
) -> Result<(), PasswordChangeError> {
    // Get current user
    let user = find_user_by_id(user_id).await
        .ok_or(PasswordChangeError::UserNotFound)?;
    
    // Verify current password
    let is_current_valid = PasswordUtilsImpl::verify_password(current_password, &user.password_hash)
        .map_err(PasswordChangeError::VerificationFailed)?;
    
    if !is_current_valid {
        return Err(PasswordChangeError::InvalidCurrentPassword);
    }
    
    // Validate new password strength
    if let Err(errors) = PasswordUtilsImpl::validate_password_strength(new_password) {
        return Err(PasswordChangeError::WeakPassword(errors));
    }
    
    // Hash new password
    let new_hash = PasswordUtilsImpl::hash_password(new_password)
        .map_err(PasswordChangeError::HashingFailed)?;
    
    // Update in database
    update_user_password(user_id, &new_hash).await?;
    
    Ok(())
}
```

### Bulk Password Validation

```rust
async fn validate_user_passwords() -> Result<PasswordAuditReport, AuditError> {
    let mut report = PasswordAuditReport::new();
    let users = get_all_users().await?;
    
    for user in users {
        // Check if user needs to update password based on creation date
        let password_age = Utc::now() - user.created_at;
        
        if password_age > Duration::days(90) {
            report.add_expired_password(user.id.clone());
        }
        
        // Note: We cannot validate actual password strength from hashes
        // This would need to be done during password creation/change
    }
    
    Ok(report)
}

pub struct PasswordAuditReport {
    pub expired_passwords: Vec<String>,
    pub total_users: usize,
    pub compliance_rate: f64,
}
```

### API Integration

```rust
use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
};

#[derive(serde::Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(serde::Serialize)]
pub struct PasswordValidationResponse {
    pub is_valid: bool,
    pub errors: Vec<String>,
}

pub async fn validate_password_endpoint(
    Json(request): Json<ValidatePasswordRequest>,
) -> Result<ResponseJson<PasswordValidationResponse>, StatusCode> {
    match PasswordUtilsImpl::validate_password_strength(&request.password) {
        Ok(()) => Ok(ResponseJson(PasswordValidationResponse {
            is_valid: true,
            errors: vec![],
        })),
        Err(errors) => Ok(ResponseJson(PasswordValidationResponse {
            is_valid: false,
            errors,
        })),
    }
}

pub async fn change_password_endpoint(
    Extension(user_claims): Extension<Claims>,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    match change_password(
        &user_claims.sub,
        &request.current_password,
        &request.new_password,
    ).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(PasswordChangeError::InvalidCurrentPassword) => Err(StatusCode::UNAUTHORIZED),
        Err(PasswordChangeError::WeakPassword(_)) => Err(StatusCode::BAD_REQUEST),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
```

## Error Handling

### Error Types and Recovery

The Password utility provides detailed error information:

```rust
match PasswordUtilsImpl::hash_password(password) {
    Ok(hash) => {
        // Store hash securely
        store_password_hash(&user_id, &hash).await?;
    },
    Err(PasswordError::HashingFailed(msg)) => {
        eprintln!("Password hashing failed: {}", msg);
        // Log security incident and retry with different parameters
    },
}

match PasswordUtilsImpl::verify_password(password, stored_hash) {
    Ok(true) => {
        // Authentication successful
        proceed_with_login().await?;
    },
    Ok(false) => {
        // Invalid password - log failed attempt
        log_failed_login_attempt(&user_id).await;
        return Err(AuthError::InvalidCredentials);
    },
    Err(PasswordError::VerificationFailed(msg)) => {
        eprintln!("Password verification error: {}", msg);
        return Err(AuthError::SystemError);
    },
    Err(PasswordError::InvalidHashFormat) => {
        eprintln!("Corrupted password hash detected");
        // This is a serious issue - hash may be corrupted
        return Err(AuthError::DataCorruption);
    },
}
```

### Password Strength Error Handling

```rust
fn handle_password_validation_errors(errors: Vec<String>) -> UserFriendlyResponse {
    let formatted_errors: Vec<String> = errors.into_iter()
        .map(|error| {
            match error.as_str() {
                msg if msg.contains("8 characters") => "Choose a longer password (at least 8 characters)".to_string(),
                msg if msg.contains("uppercase") => "Include at least one capital letter".to_string(),
                msg if msg.contains("lowercase") => "Include at least one lowercase letter".to_string(),
                msg if msg.contains("digit") => "Include at least one number".to_string(),
                msg if msg.contains("special") => "Include at least one special character (!@#$%^&*...)".to_string(),
                _ => error,
            }
        })
        .collect();
    
    UserFriendlyResponse {
        message: "Please strengthen your password",
        suggestions: formatted_errors,
        help_url: "https://example.com/password-help",
    }
}
```

## Testing

### Unit Tests

The Password utility includes comprehensive unit tests:

#### Hash and Verify Tests
```rust
#[test]
fn test_hash_password_success() {
    let password = "test_password_123";
    let result = PasswordUtilsImpl::hash_password(password);
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Hash should not be empty
    assert!(!hash.is_empty());
    
    // Hash should not equal the original password
    assert_ne!(hash, password);
    
    // Hash should contain Argon2 format components
    assert!(hash.starts_with("$argon2"));
    
    // Hash should have the expected number of components
    let parts: Vec<&str> = hash.split('$').collect();
    assert!(parts.len() >= 5);
}

#[test]
fn test_verify_password_correct() {
    let password = "correct_password_123";
    let hash = PasswordUtilsImpl::hash_password(password).unwrap();
    
    let result = PasswordUtilsImpl::verify_password(password, &hash);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_verify_password_incorrect() {
    let correct_password = "correct_password_123";
    let wrong_password = "wrong_password_456";
    let hash = PasswordUtilsImpl::hash_password(correct_password).unwrap();
    
    let result = PasswordUtilsImpl::verify_password(wrong_password, &hash);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
```

#### Password Strength Tests
```rust
#[test]
fn test_validate_password_strength_comprehensive() {
    let test_cases = vec![
        ("ValidPass123!", true),        // Valid password
        ("weak", false),                // Too short, missing requirements
        ("nouppercase123!", false),     // Missing uppercase
        ("NOLOWERCASE123!", false),     // Missing lowercase  
        ("NoDigitsHere!", false),       // Missing digits
        ("NoSpecialChars123", false),   // Missing special chars
        ("Short1!", false),             // Too short
        ("AnotherValidOne456@", true),  // Valid password
    ];
    
    for (password, should_be_valid) in test_cases {
        let result = PasswordUtilsImpl::validate_password_strength(password);
        
        if should_be_valid {
            assert!(result.is_ok(), "Password '{}' should be valid", password);
        } else {
            assert!(result.is_err(), "Password '{}' should be invalid", password);
        }
    }
}
```

#### Random Password Generation Tests
```rust
#[test]
fn test_generate_random_password_uniqueness() {
    let mut passwords = std::collections::HashSet::new();
    
    // Generate 100 passwords and ensure they're all unique
    for _ in 0..100 {
        let password = PasswordUtilsImpl::generate_random_password(16);
        assert!(passwords.insert(password.clone()), "Generated password should be unique: {}", password);
    }
}

#[test]
fn test_generate_random_password_character_distribution() {
    let password = PasswordUtilsImpl::generate_random_password(100);
    
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    
    // With 100 characters, it's extremely likely to have all types
    assert!(has_uppercase, "Generated password should contain uppercase letters");
    assert!(has_lowercase, "Generated password should contain lowercase letters");
    assert!(has_digit, "Generated password should contain digits");
}
```

#### Security Tests
```rust
#[test]
fn test_password_hash_format_consistency() {
    let passwords = vec![
        "SimplePass123!".to_string(),
        "ComplexP@ssw0rd2024".to_string(),
        "🔒Unicode🔑Emoji🛡️".to_string(),
        "a".repeat(200), // Very long password
    ];
    
    for password in passwords {
        let hash = PasswordUtilsImpl::hash_password(&password).unwrap();
        
        // All hashes should follow Argon2 format
        assert!(hash.starts_with("$argon2"), "Hash should start with $argon2: {}", hash);
        
        // Should have the correct number of parts
        let parts: Vec<&str> = hash.split('$').collect();
        assert!(parts.len() >= 5, "Hash should have at least 5 parts: {}", hash);
        
        // Should be able to verify with the original password
        let verify_result = PasswordUtilsImpl::verify_password(&password, &hash);
        assert!(verify_result.is_ok() && verify_result.unwrap());
    }
}
```

### Integration Tests

```rust
#[test]
fn test_password_workflow_integration() {
    // Test the complete workflow: generate -> validate -> hash -> verify
    let generated_password = PasswordUtilsImpl::generate_random_password(16);
    
    // Create a password that will definitely be valid
    let test_password = format!("{}A1!", generated_password.chars().take(12).collect::<String>());
    
    // Validate strength
    let validation_result = PasswordUtilsImpl::validate_password_strength(&test_password);
    assert!(validation_result.is_ok());
    
    // Hash the password
    let hash_result = PasswordUtilsImpl::hash_password(&test_password);
    assert!(hash_result.is_ok());
    
    let hash = hash_result.unwrap();
    
    // Verify the password
    let verify_result = PasswordUtilsImpl::verify_password(&test_password, &hash);
    assert!(verify_result.is_ok());
    assert!(verify_result.unwrap());
    
    // Verify wrong password fails
    let wrong_password = "WrongPassword123!";
    let verify_wrong_result = PasswordUtilsImpl::verify_password(wrong_password, &hash);
    assert!(verify_wrong_result.is_ok());
    assert!(!verify_wrong_result.unwrap());
}
```

## Security Considerations

### Cryptographic Security

1. **Salt Generation**:
   ```rust
   // Uses cryptographically secure random number generator
   let salt = SaltString::generate(OsRng);
   ```

2. **Hash Parameters**:
   ```rust
   // Argon2::default() uses secure parameters:
   // - Memory: 64 MB (resistant to parallel attacks)
   // - Time: 2 iterations (balanced security/performance)
   // - Parallelism: 1 (simple, secure default)
   ```

3. **Constant-Time Operations**:
   - Argon2 verification is designed to be timing-attack resistant
   - Password comparison happens within the Argon2 library

### Best Practices Implementation

1. **Never Store Plaintext**:
   ```rust
   // ❌ Never do this
   let user = User {
       password: plaintext_password, // NEVER!
   };
   
   // ✅ Always hash first
   let user = User {
       password_hash: PasswordUtilsImpl::hash_password(&plaintext_password)?,
   };
   ```

2. **Secure Memory Handling**:
   ```rust
   // Password strings are automatically zeroed when dropped
   // Rust's ownership system helps prevent accidental copies
   ```

3. **Error Information Leakage**:
   ```rust
   // Don't leak information about why authentication failed
   match authenticate_user(email, password).await {
       Ok(user) => proceed_with_login(user),
       Err(_) => return_generic_error("Invalid credentials"), // Don't specify what failed
   }
   ```

### Rate Limiting Integration

```rust
use std::collections::HashMap;
use tokio::time::Instant;

pub struct LoginAttemptTracker {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window_duration: Duration,
}

impl LoginAttemptTracker {
    pub fn is_rate_limited(&mut self, identifier: &str) -> bool {
        let now = Instant::now();
        let attempts = self.attempts.entry(identifier.to_string()).or_insert(Vec::new());
        
        // Remove old attempts outside the window
        attempts.retain(|&attempt_time| now.duration_since(attempt_time) <= self.window_duration);
        
        // Check if rate limited
        attempts.len() >= self.max_attempts
    }
    
    pub fn record_attempt(&mut self, identifier: &str) {
        let attempts = self.attempts.entry(identifier.to_string()).or_insert(Vec::new());
        attempts.push(Instant::now());
    }
}
```

## Performance Considerations

### Hashing Performance

Argon2id is intentionally slow to resist brute-force attacks:

```rust
// Typical performance on modern hardware:
// - Hashing: ~100-500ms per password
// - Verification: Same as hashing
// This is intentional and provides security
```

### Optimization Strategies

1. **Async Operations**:
   ```rust
   use tokio::task::spawn_blocking;
   
   pub async fn hash_password_async(password: String) -> Result<String, PasswordError> {
       spawn_blocking(move || {
           PasswordUtilsImpl::hash_password(&password)
       }).await.unwrap()
   }
   ```

2. **Caching Considerations**:
   ```rust
   // ❌ Never cache password hashes in memory
   // ❌ Never cache verification results
   // ✅ Only cache non-sensitive user data
   ```

3. **Batch Operations**:
   ```rust
   pub async fn hash_multiple_passwords(
       passwords: Vec<String>
   ) -> Vec<Result<String, PasswordError>> {
       let tasks: Vec<_> = passwords.into_iter()
           .map(|password| spawn_blocking(move || PasswordUtilsImpl::hash_password(&password)))
           .collect();
       
       let results = futures::future::join_all(tasks).await;
       results.into_iter().map(|r| r.unwrap()).collect()
   }
   ```

## Backend Integration Scenarios

### User Management Service

```rust
pub struct UserService {
    database: Arc<Database>,
    password_utils: PhantomData<PasswordUtilsImpl>,
}

impl UserService {
    pub async fn create_user(
        &self,
        email: String,
        password: String,
        role: UserRole,
    ) -> Result<User, UserCreationError> {
        // Validate password strength
        PasswordUtilsImpl::validate_password_strength(&password)
            .map_err(UserCreationError::WeakPassword)?;
        
        // Hash password
        let password_hash = PasswordUtilsImpl::hash_password(&password)
            .map_err(UserCreationError::HashingFailed)?;
        
        // Create user
        let user = User {
            id: Uuid::new_v4().to_string(),
            email,
            password_hash,
            role,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        // Save to database
        self.database.save_user(&user).await?;
        
        Ok(user)
    }
    
    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
    ) -> Result<User, AuthenticationError> {
        let user = self.database.find_user_by_email(email).await
            .ok_or(AuthenticationError::UserNotFound)?;
        
        let is_valid = PasswordUtilsImpl::verify_password(password, &user.password_hash)
            .map_err(AuthenticationError::VerificationError)?;
        
        if !is_valid {
            return Err(AuthenticationError::InvalidPassword);
        }
        
        Ok(user)
    }
}
```

### Password Policy Service

```rust
pub struct PasswordPolicyService {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digit: bool,
    require_special: bool,
    forbidden_patterns: Vec<String>,
}

impl PasswordPolicyService {
    pub fn new(config: PasswordPolicyConfig) -> Self {
        Self {
            min_length: config.min_length,
            require_uppercase: config.require_uppercase,
            require_lowercase: config.require_lowercase,
            require_digit: config.require_digit,
            require_special: config.require_special,
            forbidden_patterns: config.forbidden_patterns,
        }
    }
    
    pub fn validate_password(&self, password: &str) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        
        // Use the base validation
        if let Err(base_errors) = PasswordUtilsImpl::validate_password_strength(password) {
            errors.extend(base_errors);
        }
        
        // Additional custom validations
        for pattern in &self.forbidden_patterns {
            if password.to_lowercase().contains(&pattern.to_lowercase()) {
                errors.push(format!("Password cannot contain '{}'", pattern));
            }
        }
        
        // Check against common passwords database
        if self.is_common_password(password) {
            errors.push("Password is too common".to_string());
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    
    fn is_common_password(&self, password: &str) -> bool {
        // Check against a database of common passwords
        // This could be implemented with a bloom filter for efficiency
        let common_passwords = vec!["password", "123456", "qwerty", "admin"];
        common_passwords.contains(&password.to_lowercase().as_str())
    }
}
```

### Audit and Compliance Service

```rust
pub struct PasswordAuditService {
    database: Arc<Database>,
}

impl PasswordAuditService {
    pub async fn audit_password_compliance(&self) -> Result<ComplianceReport, AuditError> {
        let mut report = ComplianceReport::new();
        
        // Get users with old passwords
        let users_with_old_passwords = self.database
            .find_users_with_passwords_older_than(Duration::days(90))
            .await?;
        
        report.users_needing_password_change = users_with_old_passwords.len();
        
        // Check for users without recent password changes
        let total_users = self.database.count_users().await?;
        report.total_users = total_users;
        report.compliance_rate = 1.0 - (report.users_needing_password_change as f64 / total_users as f64);
        
        // Generate recommendations
        if report.compliance_rate < 0.8 {
            report.recommendations.push("Consider implementing forced password rotation".to_string());
        }
        
        if report.users_needing_password_change > 100 {
            report.recommendations.push("Send bulk password update notifications".to_string());
        }
        
        Ok(report)
    }
    
    pub async fn generate_security_report(&self) -> Result<SecurityReport, AuditError> {
        let mut report = SecurityReport::new();
        
        // Analyze recent authentication attempts
        let failed_attempts = self.database.count_failed_login_attempts_last_24h().await?;
        let successful_attempts = self.database.count_successful_login_attempts_last_24h().await?;
        
        report.failed_login_rate = failed_attempts as f64 / (failed_attempts + successful_attempts) as f64;
        
        if report.failed_login_rate > 0.1 {
            report.alerts.push("High failed login rate detected".to_string());
        }
        
        Ok(report)
    }
}

#[derive(Debug)]
pub struct ComplianceReport {
    pub total_users: usize,
    pub users_needing_password_change: usize,
    pub compliance_rate: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug)]
pub struct SecurityReport {
    pub failed_login_rate: f64,
    pub alerts: Vec<String>,
    pub generated_at: DateTime<Utc>,
}
```

## Troubleshooting

### Common Issues

1. **Slow Performance**:
   ```rust
   // Expected behavior - Argon2id is intentionally slow
   // If too slow, consider:
   // - Running hashing operations in background tasks
   // - Using async wrappers
   // - Adjusting Argon2 parameters (carefully!)
   ```

2. **Hash Verification Failures**:
   ```rust
   // Check for common issues:
   match PasswordUtilsImpl::verify_password(password, hash) {
       Err(PasswordError::InvalidHashFormat) => {
           eprintln!("Hash format is corrupted or invalid");
           // May need to reset user password
       },
       Err(PasswordError::VerificationFailed(msg)) => {
           eprintln!("Verification error: {}", msg);
           // System error - check logs
       },
       Ok(false) => {
           eprintln!("Password is incorrect");
           // Normal failed authentication
       },
       Ok(true) => {
           // Success
       },
   }
   ```

3. **Memory Usage**:
   ```rust
   // Argon2id uses significant memory by design (64MB default)
   // This is intentional for security
   // Monitor system memory usage under load
   ```

### Debugging

Enable detailed logging:
```rust
use tracing::{debug, error, info, warn};

// The password utility includes logging
debug!("Hashing password for user authentication");
info!("Password successfully hashed");
warn!("Password validation failed with {} errors", errors.len());
error!("Failed to hash password: {}", err);
```

## Future Enhancements

### Planned Features

1. **Configurable Parameters**:
   ```rust
   pub struct Argon2Config {
       pub memory_cost: u32,
       pub time_cost: u32,
       pub parallelism: u32,
   }
   ```

2. **Multiple Algorithm Support**:
   ```rust
   pub enum HashingAlgorithm {
       Argon2id(Argon2Config),
       Scrypt(ScryptConfig),
       Bcrypt(BcryptConfig),
   }
   ```

3. **Password History**:
   ```rust
   pub trait PasswordHistoryService {
       async fn check_password_history(&self, user_id: &str, new_password: &str) -> Result<bool, HistoryError>;
       async fn add_to_history(&self, user_id: &str, password_hash: &str) -> Result<(), HistoryError>;
   }
   ```

4. **Breach Detection**:
   ```rust
   pub trait BreachDetectionService {
       async fn check_password_breach(&self, password: &str) -> Result<bool, BreachError>;
   }
   ```

### Extensibility

The password utility supports extension:

```rust
pub trait PasswordService: Send + Sync {
    async fn hash_password(&self, password: &str) -> Result<String, PasswordError>;
    async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, PasswordError>;
    async fn validate_strength(&self, password: &str) -> Result<(), Vec<String>>;
}

// Alternative implementations
pub struct BcryptPasswordService;
pub struct ScryptPasswordService;
pub struct CustomPasswordService;
```

This design enables easy migration between password hashing algorithms while maintaining backward compatibility.
