#![feature(test)]
extern crate test;

use test::Bencher;
use elhaiba_backend::util::password::{PasswordUtilsImpl, PasswordUtils};

/// Benchmark: Hash password with Argon2
/// Tests the performance of password hashing (intentionally slow for security)
#[bench]
fn bench_hash_password(b: &mut Bencher) {
    let password = "TestPassword123!@#";
    b.iter(|| {
        PasswordUtilsImpl::hash_password(password)
    });
}

/// Benchmark: Verify password
/// Tests the performance of password verification against hash
#[bench]
fn bench_verify_password(b: &mut Bencher) {
    let password = "TestPassword123!@#";
    let hash = PasswordUtilsImpl::hash_password(password).unwrap();
    
    b.iter(|| {
        PasswordUtilsImpl::verify_password(password, &hash)
    });
}

/// Benchmark: Generate random password
/// Tests the performance of secure random password generation
#[bench]
fn bench_generate_random_password(b: &mut Bencher) {
    b.iter(|| {
        PasswordUtilsImpl::generate_random_password(16)
    });
}

/// Benchmark: Generate long random password
/// Tests performance with longer passwords (32 characters)
#[bench]
fn bench_generate_long_random_password(b: &mut Bencher) {
    b.iter(|| {
        PasswordUtilsImpl::generate_random_password(32)
    });
}

/// Benchmark: Validate password strength
/// Tests the performance of password strength validation
#[bench]
fn bench_validate_password_strength(b: &mut Bencher) {
    let password = "ComplexPassword123!@#$%^&*()";
    b.iter(|| {
        PasswordUtilsImpl::validate_password_strength(password)
    });
}

/// Benchmark: Validate weak password strength
/// Tests validation performance on passwords that fail multiple criteria
#[bench]
fn bench_validate_weak_password_strength(b: &mut Bencher) {
    let weak_password = "weak";
    b.iter(|| {
        PasswordUtilsImpl::validate_password_strength(weak_password)
    });
}

/// Benchmark: Multiple password strength validations
/// Tests batch validation of different password strengths
#[bench]
fn bench_multiple_password_validations(b: &mut Bencher) {
    let passwords = [
        "short",
        "nouppercase123!",
        "NOLOWERCASE123!",
        "NoDigitsHere!",
        "NoSpecialChars123",
        "ValidPassword123!",
        "AnotherValidOne456@",
        "VeryLongButValidPassword789#",
    ];
    let mut password_index = 0;
    
    b.iter(|| {
        let password = passwords[password_index % passwords.len()];
        password_index += 1;
        PasswordUtilsImpl::validate_password_strength(password)
    });
}

/// Benchmark: Hash different password lengths
/// Tests if hashing performance varies with password length
#[bench]
fn bench_hash_different_lengths(b: &mut Bencher) {
    let passwords = [
        "Short1!",
        "MediumLength123!",
        "VeryLongPasswordWithManyCharacters123!@#$%",
        "ExtremelyLongPasswordThatSimulatesUserBehaviorWithVeryLongPassphrases123!@#$%^&*()",
    ];
    let mut password_index = 0;
    
    b.iter(|| {
        let password = passwords[password_index % passwords.len()];
        password_index += 1;
        PasswordUtilsImpl::hash_password(password)
    });
}

/// Benchmark: Verify correct vs incorrect passwords
/// Tests verification performance for both correct and incorrect passwords
#[bench]
fn bench_verify_correct_vs_incorrect(b: &mut Bencher) {
    let correct_password = "CorrectPassword123!";
    let incorrect_password = "IncorrectPassword456@";
    let hash = PasswordUtilsImpl::hash_password(correct_password).unwrap();
    let mut use_correct = true;
    
    b.iter(|| {
        let password = if use_correct { correct_password } else { incorrect_password };
        use_correct = !use_correct;
        PasswordUtilsImpl::verify_password(password, &hash)
    });
}

/// Benchmark: Complete password workflow
/// Tests the complete workflow: Generate -> Hash -> Verify
#[bench]
fn bench_complete_password_workflow(b: &mut Bencher) {
    b.iter(|| {
        // Generate a random password
        let password = PasswordUtilsImpl::generate_random_password(16);
        
        // Validate its strength
        let _strength_result = PasswordUtilsImpl::validate_password_strength(&password);
        
        // Hash the password
        let hash = PasswordUtilsImpl::hash_password(&password).unwrap();
        
        // Verify the password
        PasswordUtilsImpl::verify_password(&password, &hash).unwrap()
    });
}

/// Benchmark: Random password uniqueness check
/// Generates multiple passwords and measures performance
#[bench]
fn bench_random_password_uniqueness(b: &mut Bencher) {
    b.iter(|| {
        // Generate multiple passwords to test randomness performance
        let passwords: Vec<String> = (0..5)
            .map(|_| PasswordUtilsImpl::generate_random_password(12))
            .collect();
        
        // Verify they're all different (simple uniqueness check)
        for i in 0..passwords.len() {
            for j in i+1..passwords.len() {
                assert_ne!(passwords[i], passwords[j]);
            }
        }
    });
}

/// Benchmark: Password hashing under concurrent simulation
/// Simulates multiple users registering simultaneously
#[bench]
fn bench_concurrent_password_hashing(b: &mut Bencher) {
    let passwords = [
        "UserPassword1!",
        "UserPassword2@",
        "UserPassword3#",
        "UserPassword4$",
        "UserPassword5%",
    ];
    let mut password_index = 0;
    
    b.iter(|| {
        let password = passwords[password_index % passwords.len()];
        password_index += 1;
        PasswordUtilsImpl::hash_password(password)
    });
}

/// Benchmark: Unicode password handling
/// Tests performance with international characters
#[bench]
fn bench_unicode_password_handling(b: &mut Bencher) {
    let unicode_passwords = [
        "Пароль123!",           // Cyrillic
        "パスワード123!",         // Japanese
        "密码123!",             // Chinese
        "Contraseña123!",       // Spanish
        "Mot2Passe123!",        // French with accents (simplified for demo)
        "Καλός123!",            // Greek
    ];
    let mut password_index = 0;
    
    b.iter(|| {
        let password = unicode_passwords[password_index % unicode_passwords.len()];
        password_index += 1;
        
        // Test strength validation with unicode
        let _strength = PasswordUtilsImpl::validate_password_strength(password);
        
        // Test hashing with unicode
        PasswordUtilsImpl::hash_password(password)
    });
}

/// Benchmark: Memory-intensive password operations
/// Tests performance with very long passwords (stress test)
#[bench]
fn bench_memory_intensive_operations(b: &mut Bencher) {
    // Generate a very long password (1KB)
    let long_password = "A".repeat(500) + "123!" + &"b".repeat(495);
    
    b.iter(|| {
        // Test strength validation on long password
        let _strength = PasswordUtilsImpl::validate_password_strength(&long_password);
        
        // Note: We don't hash the very long password in the benchmark 
        // as it would be too slow and unrealistic
        // Instead, test with a reasonably long but realistic password
        let realistic_long = "MyVeryLongButRealisticPassphrase123!@#";
        PasswordUtilsImpl::hash_password(realistic_long)
    });
}
