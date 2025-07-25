# Rust Testing Guide with Cargo

This guide provides comprehensive information about testing in Rust using Cargo, specifically for the Elhaiba Backend project.

## Table of Contents

1. [Introduction to Rust Testing](#introduction-to-rust-testing)
2. [Basic Test Commands](#basic-test-commands)
3. [Running Specific Tests](#running-specific-tests)
4. [Test Organization](#test-organization)
5. [Advanced Testing Features](#advanced-testing-features)
6. [Test Configuration](#test-configuration)
7. [Performance and Benchmarking](#performance-and-benchmarking)
8. [Testing Best Practices](#testing-best-practices)
9. [Project-Specific Tests](#project-specific-tests)

## Introduction to Rust Testing

Rust has built-in support for testing through the `cargo test` command. Tests are written as regular Rust functions annotated with `#[test]`. The testing framework is integrated directly into the language and build system.

### Test Types

- **Unit Tests**: Test individual functions or modules in isolation
- **Integration Tests**: Test how multiple parts work together
- **Documentation Tests**: Test code examples in documentation comments

## Basic Test Commands

### Run All Tests
```bash
cargo test
```
This runs all tests in your project, including unit tests, integration tests, and doc tests.

### Run Tests with Output
```bash
cargo test -- --nocapture
```
Shows `println!` output from tests (normally hidden on successful tests).

### Run Tests in Single Thread
```bash
cargo test -- --test-threads=1
```
Useful when tests share resources or for debugging race conditions.

### Show Test Names Only
```bash
cargo test -- --list
```
Lists all available tests without running them.

## Running Specific Tests

### Run Tests by Name Pattern
```bash
# Run all tests containing "jwt" in the name
cargo test jwt

# Run all tests containing "password" in the name  
cargo test password

# Run a specific test function
cargo test test_generate_access_token_success
```

### Run Tests by Module
```bash
# Run all tests in the jwt_tests module
cargo test jwt_tests

# Run all tests in the password_tests module
cargo test password_tests
```

### Run Tests in Specific Files
```bash
# Run tests in a specific file (integration tests)
cargo test --test integration_tests

# Run only unit tests (exclude integration and doc tests)
cargo test --lib
```

### Run Ignored Tests
```bash
# Run only ignored tests
cargo test -- --ignored

# Run both ignored and non-ignored tests
cargo test -- --include-ignored
```

## Test Organization

### Unit Tests
Located in the same file as the code being tested or in separate test modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function() {
        // Test code here
    }
}
```

### Integration Tests
Located in `tests/` directory at the project root. Each `.rs` file in the `tests/` directory is compiled as a separate integration test crate:

```
project_root/
├── src/
│   └── util/
│       ├── jwt.rs
│       ├── password.rs
│       └── mod.rs
├── tests/
│   ├── jwt_tests.rs           # JWT utility integration tests
│   ├── password_tests.rs      # Password utility integration tests
│   └── integration_tests.rs   # Cross-module integration tests
└── Cargo.toml
```

### Our Project Test Structure
```
elhaiba-backend/
├── src/
│   ├── main.rs
│   └── util/
│       ├── jwt.rs          # JWT utility implementation
│       ├── password.rs     # Password utility implementation
│       └── mod.rs          # Module declarations
├── tests/
│   ├── jwt_tests.rs        # Comprehensive JWT tests
│   ├── password_tests.rs   # Comprehensive password tests
│   └── integration_tests.rs # End-to-end authentication flow tests
└── Cargo.toml
```

## Performance Testing and Benchmarking

### Rust Nightly and Benchmarking

**What is Rust Nightly?**
Rust has three release channels:
- **Stable**: Main release channel (default)
- **Beta**: Pre-release testing version  
- **Nightly**: Experimental features, updated daily

Benchmarking requires Rust nightly because the `test` crate and `#[bench]` attribute are unstable features.

### Installing Rust Nightly

```bash
# Install Rust nightly toolchain
rustup toolchain install nightly

# Check available toolchains
rustup toolchain list

# Use nightly for current project
rustup override set nightly

# Or run commands with nightly temporarily
cargo +nightly bench
```

### Running Benchmarks

Our project includes comprehensive benchmarks in `benches/auth_benchmarks.rs`:

```bash
# Run all benchmarks (requires nightly)
cargo +nightly bench

# Run specific benchmark pattern
cargo +nightly bench bench_generate

# Run benchmarks with more iterations for accuracy
cargo +nightly bench -- --exact bench_hash_password

# Save benchmark results to file
cargo +nightly bench > benchmark_results.txt
```

### Benchmark Results Interpretation

Example output from our authentication benchmarks:
```
test bench_complete_authentication_flow ... bench:  26,746,551.10 ns/iter (+/- 6,562,563.10)
test bench_extract_token_from_header    ... bench:         103.30 ns/iter (+/- 34.27)
test bench_generate_access_token        ... bench:       4,055.25 ns/iter (+/- 871.50)
test bench_generate_random_password     ... bench:         139.88 ns/iter (+/- 30.21)
test bench_generate_refresh_token       ... bench:       4,380.21 ns/iter (+/- 1,124.96)
test bench_hash_password                ... bench:  25,975,988.70 ns/iter (+/- 4,012,866.67)
test bench_token_validation_flow        ... bench:       3,893.20 ns/iter (+/- 1,929.64)
test bench_validate_password_strength   ... bench:         204.11 ns/iter (+/- 32.42)
test bench_validate_token               ... bench:       3,702.16 ns/iter (+/- 872.61)
test bench_verify_password              ... bench:  25,833,171.50 ns/iter (+/- 3,039,574.95)
```

**Key Insights:**
- Password hashing takes ~26ms (intentionally slow for security)
- Token generation takes ~4μs (very fast)
- Token validation takes ~4μs (very fast)
- Complete auth flow takes ~27ms (dominated by password operations)

### Performance Testing in Regular Tests

You can also measure performance in regular tests:

```rust
#[test]
fn test_performance_benchmark() {
    let start = std::time::Instant::now();
    
    // Your code to benchmark
    let result = expensive_operation();
    
    let duration = start.elapsed();
    println!("Operation took: {:?}", duration);
    
    // Assert performance requirements
    assert!(duration.as_millis() < 1000, "Operation too slow");
}
```

### Test Attributes

```rust
#[test]
fn normal_test() { }

#[test]
#[ignore]
fn expensive_test() { }

#[test]
#[should_panic]
fn test_that_should_panic() { }

#[test]
#[should_panic(expected = "specific error message")]
fn test_with_expected_panic() { }

#[cfg(test)]
#[tokio::test]
async fn async_test() { }
```

### Custom Test Harness
```bash
# Run tests with custom test runner
cargo test --test-threads=1 -- --format=json
```

### Environment Variables
```bash
# Set environment variables for tests
RUST_TEST_THREADS=1 cargo test

# Show more verbose output
RUST_LOG=debug cargo test

# Run tests with backtrace on panic
RUST_BACKTRACE=1 cargo test
```

## Test Configuration

### Cargo.toml Test Configuration
```toml
[package]
name = "elhaiba-backend"

# Test-specific dependencies
[dev-dependencies]
tokio-test = "0.4"
mockall = "0.12"
tempfile = "3.0"

# Custom test configuration
[[test]]
name = "integration"
path = "tests/integration.rs"
```

### Test Profiles
```toml
[profile.test]
opt-level = 0
debug = true
overflow-checks = true
```

## Performance and Benchmarking

### Running Tests with Timing
```bash
# Show test execution time
cargo test -- --report-time

# Run tests with release optimizations
cargo test --release
```

### Benchmark Tests (Nightly Rust)
```rust
#![feature(test)]
extern crate test;

#[cfg(test)]
mod benches {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_hash_password(b: &mut Bencher) {
        b.iter(|| {
            PasswordUtilsImpl::hash_password("test_password")
        });
    }
}
```

Run benchmarks:
```bash
cargo +nightly bench
```

### Using Criterion for Stable Rust Benchmarks
Add to `Cargo.toml`:
```toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "password_bench"
harness = false
```

## Testing Best Practices

### 1. Test Organization and Folder Structure

**✅ Recommended Approach (Used in this project):**
- Place integration tests in the `tests/` directory at project root
- Each `.rs` file in `tests/` is a separate integration test crate
- Use descriptive filenames: `jwt_tests.rs`, `password_tests.rs`, `integration_tests.rs`
- Import your library with `use your_crate_name::module::*`

**❌ Avoid:**
- Mixing test files with source code in `src/`
- Using complex nested folder structures in `tests/`
- Having too many small test files (group related tests)

**Why this structure is better:**
- Clean separation of concerns
- Each test file can have its own helper functions and constants
- Tests run as integration tests, testing the public API
- Easier to manage and organize as the project grows
- Better CI/CD pipeline organization

### 2. Test Naming Convention
- Use descriptive names: `test_generate_access_token_success`
- Follow pattern: `test_[function]_[scenario]_[expected_result]`

### 3. Test Data Management
### 3. Test Data Management
```rust
// Use constants for test data
const TEST_SECRET: &str = "test_secret_key";

// Create helper functions for common setup
fn create_test_jwt_utils() -> JwtTokenUtilsImpl {
    JwtTokenUtilsImpl::new(TEST_SECRET, 15, 60 * 24 * 7)
}

// Create test data structures
struct TestUser {
    id: String,
    email: String,
    role: String,
}
```

### 4. Testing Error Conditions
```rust
#[test]
fn test_invalid_token() {
    let result = validate_token("invalid");
    assert!(result.is_err());
    
    match result.unwrap_err() {
        JwtError::DecodingFailed(_) => (),
        _ => panic!("Expected DecodingFailed error"),
    }
}
```

### 5. Property-Based Testing
```rust
// Test with multiple inputs
#[test]
fn test_password_hashing_consistency() {
    let passwords = vec!["pass1", "pass2", "pass3"];
    for password in passwords {
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
    }
}
```

## Test Filtering and Selection

### Filter by Test Name Patterns
```bash
# Run tests matching multiple patterns
cargo test "jwt|password"

# Run tests NOT matching a pattern
cargo test -- --skip slow_test

# Run exact test name
cargo test test_generate_access_token_success --exact
```

### Filter by Test Type
```bash
# Unit tests only
cargo test --lib

# Integration tests only  
cargo test --test ""

# Documentation tests only
cargo test --doc

# Binary tests
cargo test --bin binary_name
```

### Parallel vs Sequential Execution
```bash
# Run tests sequentially
cargo test -- --test-threads=1

# Limit parallel threads
cargo test -- --test-threads=4
```

## Project-Specific Tests

### JWT Utility Tests
```bash
# Run all JWT tests
cargo test jwt

# Run specific JWT test categories
cargo test test_generate_access_token
cargo test test_validate_token
cargo test test_extract_token_from_header
```

### Password Utility Tests  
```bash
# Run all password tests
cargo test password

# Run specific password test categories
cargo test test_hash_password
cargo test test_verify_password
cargo test test_validate_password_strength
```

### Running Integration Flows
```bash
# Run authentication flow tests
cargo test test_authentication_flow

# Run workflow tests
cargo test test_password_workflow
```

## Debugging Tests

### Verbose Output
```bash
# Show all output including successful tests
cargo test -- --nocapture

# Show test execution details
cargo test -- --nocapture --test-threads=1

# Environment variable approach
RUST_TEST_NOCAPTURE=1 cargo test
```

### Debugging Failed Tests
```bash
# Run with backtrace
RUST_BACKTRACE=1 cargo test test_name

# Run specific failing test
cargo test test_failing_function -- --exact --nocapture
```

### Test Coverage
```bash
# Install cargo-tarpaulin for coverage
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html

# Coverage for specific tests
cargo tarpaulin --test jwt_tests
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run tests
        run: cargo test --verbose
      - name: Run ignored tests  
        run: cargo test -- --ignored
```

### Test Scripts
Create a `test.sh` script:
```bash
#!/bin/bash
set -e

echo "Running unit tests..."
cargo test --lib

echo "Running integration tests..."
cargo test --test integration

echo "Running doc tests..."
cargo test --doc

echo "Checking test coverage..."
cargo tarpaulin --out Stdout
```

## Summary of Key Commands

| Command | Description |
|---------|-------------|
| `cargo test` | Run all tests |
| `cargo test jwt` | Run tests matching "jwt" |
| `cargo test -- --nocapture` | Show test output |
| `cargo test -- --ignored` | Run ignored tests |
| `cargo test --lib` | Unit tests only |
| `cargo test --test integration` | Integration tests only |
| `cargo test -- --test-threads=1` | Sequential execution |
| `cargo test -- --list` | List all tests |
| `RUST_BACKTRACE=1 cargo test` | Run with backtrace |

## Examples from Our Project

### Running JWT Tests
```bash
# All JWT-related tests
cargo test jwt_tests

# Specific JWT functionality
cargo test test_generate_token_pair
cargo test test_validate_access_token
cargo test test_authentication_flow
```

### Running Password Tests
```bash
# All password-related tests  
cargo test password_tests

# Specific password functionality
cargo test test_hash_password
cargo test test_validate_password_strength
cargo test test_password_workflow
```

### Development Workflow
```bash
# Quick test while developing
cargo test test_function_name -- --nocapture

# Full test suite before commit
cargo test

# Performance testing
cargo test --release
```

This comprehensive guide covers all the essential aspects of testing in Rust with Cargo. The tests created for your JWT and password utilities follow these best practices and demonstrate various testing techniques and patterns.
