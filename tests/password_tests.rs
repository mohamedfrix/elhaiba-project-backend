use elhaiba_backend::util::password::*;
use std::collections::HashSet;

// Helper function for generating test passwords with different strengths
fn get_test_passwords() -> Vec<(&'static str, bool)> {
    vec![
        ("ValidPass123!", true),        // Valid password
        ("weak", false),                // Too short, missing requirements
        ("nouppercase123!", false),     // Missing uppercase
        ("NOLOWERCASE123!", false),     // Missing lowercase  
        ("NoDigitsHere!", false),       // Missing digits
        ("NoSpecialChars123", false),   // Missing special chars
        ("Short1!", false),             // Too short
        ("AnotherValidOne456@", true),  // Valid password
        ("ComplexP@ssw0rd2024", true),  // Valid complex password
        ("", false),                    // Empty password
        ("1234567890", false),          // Only digits
        ("abcdefghijk", false),         // Only lowercase
        ("ABCDEFGHIJK", false),         // Only uppercase
        ("!@#$%^&*()", false),          // Only special chars
        ("Aa1!", false),                // Too short but has all requirements
        ("VeryLongPasswordButNoDigitsOrSpecialChars", false), // Long but missing requirements
    ]
}

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
    
    // Hash should contain the expected number of components
    let parts: Vec<&str> = hash.split('$').collect();
    assert!(parts.len() >= 5, "Hash should have at least 5 parts separated by $");
}

#[test]
fn test_hash_password_empty_password() {
    let password = "";
    let result = PasswordUtilsImpl::hash_password(password);
    
    // Should still work - empty passwords are hashed but should be caught by validation
    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(hash.starts_with("$argon2"));
}

#[test]
fn test_hash_password_very_long_password() {
    let password = "a".repeat(1000); // Very long password
    let result = PasswordUtilsImpl::hash_password(password.as_str());
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(hash.starts_with("$argon2"));
}

#[test]
fn test_hash_password_unicode_characters() {
    let password = "Pássw0rd123!🔒"; // Password with unicode characters
    let result = PasswordUtilsImpl::hash_password(password);
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(hash.starts_with("$argon2"));
}

#[test]
fn test_hash_password_different_results() {
    let password = "same_password";
    
    let hash1 = PasswordUtilsImpl::hash_password(password).unwrap();
    let hash2 = PasswordUtilsImpl::hash_password(password).unwrap();
    
    // Same password should produce different hashes due to random salt
    assert_ne!(hash1, hash2);
    
    // But both should be valid hashes
    assert!(hash1.starts_with("$argon2"));
    assert!(hash2.starts_with("$argon2"));
}

#[test]
fn test_hash_password_consistent_length_range() {
    let passwords = vec!["short", "medium_length_password", "very_very_very_long_password_that_goes_on_and_on"];
    let mut hash_lengths = HashSet::new();
    
    for password in passwords {
        let hash = PasswordUtilsImpl::hash_password(password).unwrap();
        hash_lengths.insert(hash.len());
    }
    
    // All hashes should be roughly the same length (Argon2 produces fixed-length output)
    // Allow for small variations due to base64 encoding
    assert!(hash_lengths.len() <= 2, "Hash lengths should be consistent");
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
fn test_verify_password_case_sensitive() {
    let password = "CaseSensitive123!";
    let hash = PasswordUtilsImpl::hash_password(password).unwrap();
    
    // Test with different cases
    let wrong_cases = vec!["casesensitive123!", "CASESENSITIVE123!", "cASEsENSITIVE123!"];
    
    for wrong_case in wrong_cases {
        let result = PasswordUtilsImpl::verify_password(wrong_case, &hash);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Password verification should be case-sensitive");
    }
}

#[test]
fn test_verify_password_unicode() {
    let password = "Unicøde🔐Pássw0rd!";
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

#[test]
fn test_verify_password_empty_password() {
    let password = "test_password";
    let hash = PasswordUtilsImpl::hash_password(password).unwrap();
    
    let result = PasswordUtilsImpl::verify_password("", &hash);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_verify_password_empty_hash() {
    let password = "test_password";
    let result = PasswordUtilsImpl::verify_password(password, "");
    assert!(result.is_err());
}

#[test]
fn test_verify_password_invalid_hash_format() {
    let password = "test_password";
    let invalid_hashes = vec![
        "invalid_hash_format",
        "not_a_hash",
        "plaintext_password",
        "$bcrypt$10$invalidhash", // Different algorithm
    ];
    
    for invalid_hash in invalid_hashes {
        let result = PasswordUtilsImpl::verify_password(password, invalid_hash);
        assert!(result.is_err(), "Should fail for invalid hash: {}", invalid_hash);
        
        match result.unwrap_err() {
            PasswordError::InvalidHashFormat | PasswordError::VerificationFailed(_) => (),
            _ => panic!("Expected InvalidHashFormat or VerificationFailed error for hash: {}", invalid_hash),
        }
    }
    
    // Test malformed Argon2 hashes separately - these might not all fail
    // depending on how the Argon2 library handles them
    let malformed_argon2_hashes = vec![
        "$argon2id$invalid$hash$format",
    ];
    
    for invalid_hash in malformed_argon2_hashes {
        let result = PasswordUtilsImpl::verify_password(password, invalid_hash);
        // Note: Some malformed hashes might be handled gracefully by the library
        // so we just ensure they don't panic and return a reasonable result
        match result {
            Ok(false) => (), // Library handled it gracefully and returned false
            Err(_) => (),    // Library returned an error, which is also fine
            Ok(true) => panic!("Malformed hash should not verify as correct: {}", invalid_hash),
        }
    }
}

#[test]
fn test_verify_password_malformed_argon2_hash() {
    let password = "test_password";
    let malformed_hash = "$argon2id$invalid$hash$format";
    
    let result = PasswordUtilsImpl::verify_password(password, malformed_hash);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        PasswordError::InvalidHashFormat | PasswordError::VerificationFailed(_) => (),
        _ => panic!("Expected InvalidHashFormat or VerificationFailed error"),
    }
}

#[test]
fn test_validate_password_strength_comprehensive() {
    let test_cases = get_test_passwords();
    
    for (password, should_be_valid) in test_cases {
        let result = PasswordUtilsImpl::validate_password_strength(password);
        
        if should_be_valid {
            assert!(result.is_ok(), "Password '{}' should be valid but got errors: {:?}", 
                    password, result.err());
        } else {
            assert!(result.is_err(), "Password '{}' should be invalid but passed validation", password);
            let errors = result.unwrap_err();
            assert!(!errors.is_empty(), "Invalid password should have error messages");
        }
    }
}

#[test]
fn test_validate_password_strength_specific_errors() {
    // Test specific error messages
    let test_cases = vec![
        ("short", vec!["at least 8 characters", "uppercase", "digit", "special"]),
        ("toolongbutnouppercaseordigitsorspecial", vec!["uppercase", "digit", "special"]),
        ("NOLOWERCASE123!", vec!["lowercase"]),  // Fixed: all caps
        ("nouppercase123!", vec!["uppercase"]),
        ("NoDigitsHere!", vec!["digit"]),
        ("NoSpecialChars123", vec!["special"]),
    ];
    
    for (password, expected_error_keywords) in test_cases {
        let result = PasswordUtilsImpl::validate_password_strength(password);
        assert!(result.is_err(), "Password '{}' should be invalid", password);
        
        let errors = result.unwrap_err();
        let errors_text = errors.join(" ").to_lowercase();
        
        for keyword in expected_error_keywords {
            assert!(errors_text.contains(keyword), 
                    "Password '{}' should have error containing '{}'. Got: {:?}", 
                    password, keyword, errors);
        }
    }
}

#[test]
fn test_validate_password_strength_edge_cases() {
    // Test edge cases
    let edge_cases = vec![
        ("", false),                          // Empty password
        ("1234567", false),                   // 7 chars (too short)
        ("12345678", false),                  // 8 digits only
        ("Aa1!", false),                      // 4 chars with all requirements
        ("Aa1!bcde", true),                   // Minimum valid password
        ("🔒Password123!", true),             // With emoji
        ("Pássw0rd!", true),                  // With accented characters
    ];
    
    for (password, should_be_valid) in edge_cases {
        let result = PasswordUtilsImpl::validate_password_strength(password);
        
        if should_be_valid {
            assert!(result.is_ok(), "Edge case password '{}' should be valid but got: {:?}", 
                    password, result.err());
        } else {
            assert!(result.is_err(), "Edge case password '{}' should be invalid", password);
        }
    }
    
    // Test very long password separately
    let very_long_password = format!("{}a1!", "A".repeat(100));
    let result = PasswordUtilsImpl::validate_password_strength(&very_long_password);
    assert!(result.is_ok(), "Very long password should be valid");
}

#[test]
fn test_generate_random_password_basic() {
    let password = PasswordUtilsImpl::generate_random_password(12);
    
    assert_eq!(password.len(), 12);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn test_generate_random_password_minimum_length() {
    // Test that minimum length is enforced
    let password = PasswordUtilsImpl::generate_random_password(5); // Less than 8
    assert!(password.len() >= 8, "Generated password should be at least 8 characters");
}

#[test]
fn test_generate_random_password_various_lengths() {
    let lengths = vec![8, 12, 16, 20, 32, 64];
    
    for length in lengths {
        let password = PasswordUtilsImpl::generate_random_password(length);
        assert_eq!(password.len(), length, "Generated password should have requested length");
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}

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

#[test]
fn test_password_workflow_integration() {
    // Test the complete workflow: generate -> validate -> hash -> verify
    let generated_password = PasswordUtilsImpl::generate_random_password(16);
    
    // Generated password should be valid (though it might not have special chars)
    // Let's create a password that will definitely be valid
    let test_password = format!("{}A1!", generated_password.chars().take(12).collect::<String>());
    
    // Validate strength
    let validation_result = PasswordUtilsImpl::validate_password_strength(&test_password);
    assert!(validation_result.is_ok(), "Generated and modified password should be valid");
    
    // Hash the password
    let hash_result = PasswordUtilsImpl::hash_password(&test_password);
    assert!(hash_result.is_ok(), "Should be able to hash the generated password");
    
    let hash = hash_result.unwrap();
    
    // Verify the password
    let verify_result = PasswordUtilsImpl::verify_password(&test_password, &hash);
    assert!(verify_result.is_ok(), "Verification should succeed");
    assert!(verify_result.unwrap(), "Password should verify correctly");
    
    // Verify wrong password fails
    let wrong_password = "WrongPassword123!";
    let verify_wrong_result = PasswordUtilsImpl::verify_password(wrong_password, &hash);
    assert!(verify_wrong_result.is_ok(), "Verification call should succeed");
    assert!(!verify_wrong_result.unwrap(), "Wrong password should not verify");
}

#[test]
fn test_password_timing_attack_resistance() {
    // This test ensures that password verification takes similar time regardless of correctness
    // Note: This is more of a conceptual test since timing attacks are hard to test reliably in unit tests
    
    let correct_password = "CorrectPassword123!";
    let hash = PasswordUtilsImpl::hash_password(correct_password).unwrap();
    
    let test_passwords = vec![
        correct_password,                    // Correct password
        "WrongPassword123!",                 // Wrong password, same length
        "Short!1",                          // Wrong password, shorter
        "VeryLongWrongPasswordWithManyCharacters123!", // Wrong password, longer
        "",                                 // Empty password
    ];
    
    // All verifications should complete successfully (though with different results)
    for password in test_passwords {
        let result = PasswordUtilsImpl::verify_password(password, &hash);
        assert!(result.is_ok(), "Verification should not fail due to timing issues");
    }
}

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
        assert!(verify_result.is_ok() && verify_result.unwrap(), 
                "Should be able to verify password: {}", password);
    }
}

#[test]
fn test_generate_random_password_default_length() {
    let length = 12;
    let password = PasswordUtilsImpl::generate_random_password(length);
    
    assert_eq!(password.len(), length);
    assert!(password.chars().all(|c| c.is_alphanumeric()));
}

#[test]
fn test_generate_random_password_different_results() {
    let length = 16;
    let password1 = PasswordUtilsImpl::generate_random_password(length);
    let password2 = PasswordUtilsImpl::generate_random_password(length);
    
    // Generated passwords should be different
    assert_ne!(password1, password2);
    assert_eq!(password1.len(), length);
    assert_eq!(password2.len(), length);
}

#[test]
fn test_generate_random_password_large_length() {
    let length = 100;
    let password = PasswordUtilsImpl::generate_random_password(length);
    
    assert_eq!(password.len(), length);
    assert!(password.chars().all(|c| c.is_alphanumeric()));
}

#[test]
fn test_validate_password_strength_with_test_data() {
    let test_passwords = get_test_passwords();
    
    for (password, should_be_valid) in test_passwords {
        let result = PasswordUtilsImpl::validate_password_strength(password);
        
        if should_be_valid {
            assert!(result.is_ok(), "Password '{}' should be valid but got errors: {:?}", 
                   password, result.err());
        } else {
            assert!(result.is_err(), "Password '{}' should be invalid but was accepted", password);
        }
    }
}

#[test]
fn test_validate_password_strength_valid_password() {
    let strong_password = "StrongPass123!";
    let result = PasswordUtilsImpl::validate_password_strength(strong_password);
    
    assert!(result.is_ok());
}

#[test]
fn test_validate_password_strength_too_short() {
    let short_password = "Sh0rt!";
    let result = PasswordUtilsImpl::validate_password_strength(short_password);
    
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.contains(&"Password must be at least 8 characters long".to_string()));
}

#[test]
fn test_validate_password_strength_no_uppercase() {
    let password = "lowercase123!";
    let result = PasswordUtilsImpl::validate_password_strength(password);
    
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.contains(&"Password must contain at least one uppercase letter".to_string()));
}

#[test]
fn test_validate_password_strength_no_lowercase() {
    let password = "UPPERCASE123!";
    let result = PasswordUtilsImpl::validate_password_strength(password);
    
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.contains(&"Password must contain at least one lowercase letter".to_string()));
}

#[test]
fn test_validate_password_strength_no_digit() {
    let password = "NoDigitsHere!";
    let result = PasswordUtilsImpl::validate_password_strength(password);
    
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.contains(&"Password must contain at least one digit".to_string()));
}

#[test]
fn test_validate_password_strength_no_special_char() {
    let password = "NoSpecialChars123";
    let result = PasswordUtilsImpl::validate_password_strength(password);
    
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.contains(&"Password must contain at least one special character".to_string()));
}

#[test]
fn test_validate_password_strength_multiple_errors() {
    let weak_password = "weak";
    let result = PasswordUtilsImpl::validate_password_strength(weak_password);
    
    assert!(result.is_err());
    let errors = result.unwrap_err();
    
    // Should contain multiple validation errors
    assert!(errors.len() > 1);
    assert!(errors.contains(&"Password must be at least 8 characters long".to_string()));
    assert!(errors.contains(&"Password must contain at least one uppercase letter".to_string()));
    assert!(errors.contains(&"Password must contain at least one digit".to_string()));
    assert!(errors.contains(&"Password must contain at least one special character".to_string()));
}

#[test]
fn test_validate_password_strength_all_special_chars() {
    // Test with different special characters
    let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    for special_char in special_chars.chars() {
        let password = format!("Valid123{}", special_char);
        let result = PasswordUtilsImpl::validate_password_strength(&password);
        assert!(result.is_ok(), "Failed for special character: {}", special_char);
    }
}

#[test]
fn test_password_error_display() {
    let hash_error = PasswordError::HashingFailed("test error".to_string());
    assert_eq!(hash_error.to_string(), "Failed to hash password: test error");

    let verify_error = PasswordError::VerificationFailed("test error".to_string());
    assert_eq!(verify_error.to_string(), "Failed to verify password: test error");

    let format_error = PasswordError::InvalidHashFormat;
    assert_eq!(format_error.to_string(), "Invalid password hash format");
}

// Integration test for complete password workflow
#[test]
fn test_password_workflow() {
    let password = "TestPassword123!";
    
    // 1. Validate password strength
    let validation_result = PasswordUtilsImpl::validate_password_strength(password);
    assert!(validation_result.is_ok());
    
    // 2. Hash the password
    let hash_result = PasswordUtilsImpl::hash_password(password);
    assert!(hash_result.is_ok());
    let hash = hash_result.unwrap();
    
    // 3. Verify correct password
    let verify_correct = PasswordUtilsImpl::verify_password(password, &hash);
    assert!(verify_correct.is_ok());
    assert!(verify_correct.unwrap());
    
    // 4. Verify incorrect password
    let verify_incorrect = PasswordUtilsImpl::verify_password("WrongPassword123!", &hash);
    assert!(verify_incorrect.is_ok());
    assert!(!verify_incorrect.unwrap());
}

// Test for consistent hashing behavior
#[test]
fn test_hash_verification_consistency() {
    let passwords = vec![
        "SimplePass123!",
        "ComplexPassword456@",
        "AnotherOne789#",
        "ShortP1!",
        "VeryLongPasswordWithLotsOfCharacters123!@#",
    ];

    for password in passwords {
        let hash = PasswordUtilsImpl::hash_password(password).unwrap();
        
        // Verify the password multiple times to ensure consistency
        for _ in 0..5 {
            let verify_result = PasswordUtilsImpl::verify_password(password, &hash);
            assert!(verify_result.is_ok());
            assert!(verify_result.unwrap());
        }
    }
}

// Test boundary conditions
#[test]
fn test_boundary_conditions() {
    // Test minimum valid password
    let min_valid = "Ab1!abcd"; // 8 chars, all requirements met
    assert!(PasswordUtilsImpl::validate_password_strength(min_valid).is_ok());
    
    // Test 7 character password (should fail)
    let too_short = "Ab1!abc"; // 7 chars
    assert!(PasswordUtilsImpl::validate_password_strength(too_short).is_err());
    
    // Test password with unicode characters
    let unicode_password = "Pässwörd123!";
    let hash_result = PasswordUtilsImpl::hash_password(unicode_password);
    assert!(hash_result.is_ok());
    
    let hash = hash_result.unwrap();
    let verify_result = PasswordUtilsImpl::verify_password(unicode_password, &hash);
    assert!(verify_result.is_ok());
    assert!(verify_result.unwrap());
}

// Test trait implementation
#[test]
fn test_trait_implementation() {
    // Test that we can use the trait methods through the trait interface
    fn test_with_trait<T: PasswordUtils>() {
        let password = "TraitTest123!";
        let hash = T::hash_password(password).unwrap();
        let is_valid = T::verify_password(password, &hash).unwrap();
        assert!(is_valid);
        
        let random_pass = T::generate_random_password(12);
        assert_eq!(random_pass.len(), 12);
        
        let validation = T::validate_password_strength("ValidPass123!");
        assert!(validation.is_ok());
    }
    
    test_with_trait::<PasswordUtilsImpl>();
}

// Stress test for random password generation
#[test]
fn test_random_password_uniqueness() {
    let mut generated_passwords = std::collections::HashSet::new();
    let count = 1000;
    
    for _ in 0..count {
        let password = PasswordUtilsImpl::generate_random_password(16);
        assert!(!generated_passwords.contains(&password), "Duplicate password generated");
        generated_passwords.insert(password);
    }
    
    assert_eq!(generated_passwords.len(), count);
}

// Test empty and whitespace passwords
#[test]
fn test_edge_case_passwords() {
    // Empty password
    let empty_hash_result = PasswordUtilsImpl::hash_password("");
    assert!(empty_hash_result.is_ok()); // Empty passwords can be hashed
    
    let empty_hash = empty_hash_result.unwrap();
    let verify_empty = PasswordUtilsImpl::verify_password("", &empty_hash);
    assert!(verify_empty.is_ok());
    assert!(verify_empty.unwrap());
    
    // Whitespace password
    let whitespace_password = "   \t\n   ";
    let whitespace_hash = PasswordUtilsImpl::hash_password(whitespace_password).unwrap();
    let verify_whitespace = PasswordUtilsImpl::verify_password(whitespace_password, &whitespace_hash);
    assert!(verify_whitespace.is_ok());
    assert!(verify_whitespace.unwrap());
    
    // But whitespace should not verify against a different whitespace pattern
    let verify_different_whitespace = PasswordUtilsImpl::verify_password("    ", &whitespace_hash);
    assert!(verify_different_whitespace.is_ok());
    assert!(!verify_different_whitespace.unwrap());
}
