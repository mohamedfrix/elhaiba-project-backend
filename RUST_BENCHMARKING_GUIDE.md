# Rust Benchmarking Complete Guide

## Table of Contents

1. [Introduction to Rust Benchmarking](#introduction-to-rust-benchmarking)
2. [Why Benchmarking Matters](#why-benchmarking-matters)
3. [Setting Up Benchmarks](#setting-up-benchmarks)
4. [Cargo.toml Configuration](#cargotoml-configuration)
5. [Writing Benchmark Functions](#writing-benchmark-functions)
6. [Benchmark Attributes and Features](#benchmark-attributes-and-features)
7. [Running Benchmarks](#running-benchmarks)
8. [Understanding Benchmark Output](#understanding-benchmark-output)
9. [Advanced Benchmarking Techniques](#advanced-benchmarking-techniques)
10. [Best Practices](#best-practices)
11. [Common Pitfalls and How to Avoid Them](#common-pitfalls-and-how-to-avoid-them)
12. [Benchmark Analysis and Optimization](#benchmark-analysis-and-optimization)
13. [Our Project Examples](#our-project-examples)

---

## Introduction to Rust Benchmarking

Rust benchmarking is a powerful feature that allows you to measure the performance of your code with high precision. Unlike simple timing measurements, Rust's built-in benchmarking framework provides statistical analysis, handles warmup periods, and accounts for system noise to give you reliable performance metrics.

### Key Features:
- **Statistical Analysis**: Multiple iterations with statistical confidence intervals
- **Automatic Warmup**: Code is warmed up before measurement begins
- **Noise Reduction**: Handles system-level interference
- **Precise Timing**: Nanosecond-level precision
- **Regression Detection**: Easy to spot performance regressions

### Why Rust Nightly?
Benchmarking requires **Rust Nightly** because:
- The `test` crate is an unstable feature
- The `#[bench]` attribute is experimental
- Performance measurement APIs are still evolving

---

## Why Benchmarking Matters

### 🎯 **Performance Optimization**
```rust
// Before optimization
test bench_slow_function ... bench: 1,000,000 ns/iter (+/- 50,000)

// After optimization  
test bench_fast_function ... bench:   10,000 ns/iter (+/- 1,000)
// 100x improvement!
```

### 📊 **Regression Detection**
Benchmarks help catch performance regressions during development:
```bash
# Last week
test bench_hash_password ... bench: 25,000,000 ns/iter (+/- 1,000,000)

# This week (regression!)
test bench_hash_password ... bench: 50,000,000 ns/iter (+/- 2,000,000)
```

### 🔍 **Algorithm Comparison**
Compare different implementations:
```rust
#[bench] fn bench_bubble_sort(b: &mut Bencher) { /* ... */ }
#[bench] fn bench_quick_sort(b: &mut Bencher) { /* ... */ }
#[bench] fn bench_merge_sort(b: &mut Bencher) { /* ... */ }
```

---

## Setting Up Benchmarks

### 1. **Install Rust Nightly**
```bash
# Install nightly toolchain
rustup toolchain install nightly

# Check installation
rustup toolchain list

# Use nightly for current project
rustup override set nightly

# Or use temporarily
cargo +nightly bench
```

### 2. **Create Benchmark Directory**
```
your-project/
├── src/
│   ├── lib.rs
│   └── main.rs
├── tests/
│   └── integration_tests.rs
├── benches/           ← Create this directory
│   ├── jwt_benchmarks.rs
│   └── password_benchmarks.rs
├── Cargo.toml
└── README.md
```

### 3. **Basic Benchmark File Structure**
```rust
#![feature(test)]        // Enable unstable test features
extern crate test;       // Import test crate

use test::Bencher;       // Import the Bencher type
use your_crate::module;  // Import your code to benchmark

#[bench]
fn bench_your_function(b: &mut Bencher) {
    b.iter(|| {
        // Code to benchmark goes here
        your_function()
    });
}
```

---

## Cargo.toml Configuration

### Understanding the `[[bench]]` Section

The `[[bench]]` section in Cargo.toml tells Cargo about your benchmark files:

```toml
[package]
name = "your-project"
version = "0.1.0"
edition = "2021"

[dependencies]
# Your regular dependencies

[dev-dependencies]
# Dependencies only used in tests/benchmarks

# Benchmark configuration
[[bench]]
name = "jwt_benchmarks"         # Must match filename (without .rs)

[[bench]]
name = "password_benchmarks"    # Must match filename (without .rs)

# Optional: Add more benchmarks
[[bench]]
name = "database_benchmarks"

[[bench]]
name = "network_benchmarks"
```

### Why Multiple `[[bench]]` Sections?

Each `[[bench]]` section defines a separate benchmark binary:

1. **Modular Organization**: Keep related benchmarks together
   ```
   benches/
   ├── jwt_benchmarks.rs      ← JWT-related benchmarks
   ├── password_benchmarks.rs ← Password-related benchmarks
   └── database_benchmarks.rs ← Database-related benchmarks
   ```

2. **Selective Running**: Run specific benchmark suites
   ```bash
   cargo +nightly bench --bench jwt_benchmarks      # Only JWT benchmarks
   cargo +nightly bench --bench password_benchmarks # Only password benchmarks
   ```

3. **Independent Compilation**: Each benchmark file is compiled separately

### Additional Configuration Options

```toml
[[bench]]
name = "my_benchmarks"
path = "benchmarks/custom_path.rs"  # Custom file path
required-features = ["benchmark-feature"]  # Only build with certain features

[[bench]]
name = "integration_benchmarks"
test = false                         # Don't run as test
bench = true                        # This is a benchmark (default: true)
```

---

## Writing Benchmark Functions

### Basic Benchmark Function

```rust
#[bench]
fn bench_simple_function(b: &mut Bencher) {
    b.iter(|| {
        // This code will be run many times and measured
        expensive_computation()
    });
}
```

### Benchmark with Setup

```rust
#[bench]
fn bench_with_setup(b: &mut Bencher) {
    // Setup code (not measured)
    let data = prepare_test_data();
    
    b.iter(|| {
        // Only this code is measured
        process_data(&data)
    });
}
```

### Preventing Compiler Optimizations

```rust
#[bench]
fn bench_prevent_optimization(b: &mut Bencher) {
    let input = generate_input();
    
    b.iter(|| {
        let result = compute_something(input);
        test::black_box(result)  // Prevents compiler from optimizing away
    });
}
```

### Benchmarking with Different Inputs

```rust
#[bench]
fn bench_varying_inputs(b: &mut Bencher) {
    let inputs = vec![1, 10, 100, 1000, 10000];
    let mut index = 0;
    
    b.iter(|| {
        let input = inputs[index % inputs.len()];
        index += 1;
        process_input(input)
    });
}
```

---

## Benchmark Attributes and Features

### Core Attributes

```rust
#[bench]                    // Mark function as benchmark
#[ignore]                   // Skip this benchmark (like tests)
#[should_panic]             // Benchmark should panic (rare)
```

### Advanced Bencher Methods

```rust
#[bench]
fn advanced_benchmark(b: &mut Bencher) {
    // Measure bytes processed per iteration
    b.bytes = 1024;  // If processing 1KB per iteration
    
    b.iter(|| {
        process_1kb_data()
    });
}
```

### Custom Iteration Control

```rust
#[bench]
fn custom_iterations(b: &mut Bencher) {
    // For very slow operations, control iteration count
    b.iter_with_large_drop(|| {
        expensive_operation_with_large_cleanup()
    });
}
```

---

## Running Benchmarks

### Basic Commands

```bash
# Run all benchmarks
cargo +nightly bench

# Run specific benchmark file
cargo +nightly bench --bench jwt_benchmarks

# Run benchmarks matching pattern
cargo +nightly bench password

# Run single benchmark function
cargo +nightly bench --bench jwt_benchmarks bench_generate_token
```

### Advanced Options

```bash
# Save output to file
cargo +nightly bench > benchmark_results.txt

# Run with specific number of iterations
cargo +nightly bench -- --exact bench_slow_function

# Show benchmark output (like println!)
cargo +nightly bench -- --nocapture

# Run benchmarks in single thread
cargo +nightly bench -- --test-threads=1

# List all available benchmarks without running
cargo +nightly bench -- --list
```

### Filtering and Selection

```bash
# Run only benchmarks containing "hash"
cargo +nightly bench hash

# Exclude benchmarks containing "slow"
cargo +nightly bench -- --skip slow

# Run benchmarks exactly matching name
cargo +nightly bench -- --exact bench_generate_access_token
```

---

## Understanding Benchmark Output

### Reading the Results

```
test bench_generate_access_token ... bench:   4,055.25 ns/iter (+/- 871.50)
```

**Breakdown:**
- `bench_generate_access_token`: Function name
- `4,055.25 ns/iter`: Average time per iteration in nanoseconds
- `(+/- 871.50)`: Standard deviation (confidence interval)

### Time Units

```
1 second = 1,000,000,000 nanoseconds (ns)
1 millisecond = 1,000,000 nanoseconds
1 microsecond = 1,000 nanoseconds

Examples:
- 100 ns = 0.0001 milliseconds (very fast)
- 1,000 ns = 0.001 milliseconds (fast)
- 1,000,000 ns = 1 millisecond (moderate)
- 1,000,000,000 ns = 1 second (slow)
```

### Interpreting Performance

```
test bench_token_validation     ... bench:     3,702.16 ns/iter (+/- 872.61)
test bench_password_hashing     ... bench: 25,975,988.70 ns/iter (+/- 4,012,866.67)
```

**Analysis:**
- Token validation: ~3.7 microseconds (very fast)
- Password hashing: ~26 milliseconds (intentionally slow for security)

### Statistical Significance

The `(+/- value)` represents the standard deviation:
```
4,055.25 ns/iter (+/- 871.50)
```
- Most runs were between 3,183.75 ns and 4,926.75 ns
- Smaller deviation = more consistent performance
- Large deviation might indicate system noise or measurement issues

---

## Advanced Benchmarking Techniques

### 1. **Memory Allocation Tracking**

```rust
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

// Custom allocator to track allocations
struct CountingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        if !ret.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[bench]
fn bench_with_allocation_tracking(b: &mut Bencher) {
    b.iter(|| {
        let before = ALLOCATED.load(Ordering::SeqCst);
        let result = allocating_function();
        let after = ALLOCATED.load(Ordering::SeqCst);
        println!("Allocated {} bytes", after - before);
        test::black_box(result)
    });
}
```

### 2. **Throughput Measurement**

```rust
#[bench]
fn bench_throughput(b: &mut Bencher) {
    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    b.bytes = data.len() as u64;
    
    b.iter(|| {
        process_data(&data)
    });
}
// Output will show MB/s throughput
```

### 3. **Comparative Benchmarking**

```rust
// Benchmark different algorithms
#[bench] fn bench_algorithm_a(b: &mut Bencher) { /* ... */ }
#[bench] fn bench_algorithm_b(b: &mut Bencher) { /* ... */ }
#[bench] fn bench_algorithm_c(b: &mut Bencher) { /* ... */ }

// Results will be easy to compare:
// bench_algorithm_a ... bench: 1,000 ns/iter
// bench_algorithm_b ... bench: 2,000 ns/iter  (2x slower)
// bench_algorithm_c ... bench:   500 ns/iter  (2x faster)
```

### 4. **Setup and Teardown**

```rust
#[bench]
fn bench_with_setup_teardown(b: &mut Bencher) {
    b.iter(|| {
        // Setup (included in measurement)
        let mut data = setup_expensive_data();
        
        // Core operation
        let result = process_data(&mut data);
        
        // Teardown (included in measurement)
        cleanup_data(data);
        
        result
    });
}
```

---

## Best Practices

### 🎯 **1. Choose Representative Workloads**

```rust
// ❌ Bad: Unrealistic input
#[bench]
fn bench_unrealistic(b: &mut Bencher) {
    b.iter(|| process_string("a"));  // Too simple
}

// ✅ Good: Realistic input
#[bench]
fn bench_realistic(b: &mut Bencher) {
    let realistic_data = "A realistic user input with normal length and content";
    b.iter(|| process_string(realistic_data));
}
```

### 🔥 **2. Avoid Cold Start Effects**

```rust
// ❌ Bad: Cold caches
#[bench]
fn bench_cold_start(b: &mut Bencher) {
    b.iter(|| {
        let fresh_data = create_large_dataset();  // Cold every time
        process_data(fresh_data)
    });
}

// ✅ Good: Warm caches
#[bench]
fn bench_warm_cache(b: &mut Bencher) {
    let reused_data = create_large_dataset();  // Created once
    b.iter(|| {
        process_data(&reused_data)  // Reuse warm data
    });
}
```

### 🛡️ **3. Prevent Compiler Optimizations**

```rust
// ❌ Bad: Compiler might optimize away
#[bench]
fn bench_optimized_away(b: &mut Bencher) {
    b.iter(|| {
        expensive_computation()  // Result unused!
    });
}

// ✅ Good: Use black_box to prevent optimization
#[bench]
fn bench_proper(b: &mut Bencher) {
    b.iter(|| {
        let result = expensive_computation();
        test::black_box(result)  // Prevents optimization
    });
}
```

### 📊 **4. Measure What Matters**

```rust
// ✅ Good: Separate concerns
#[bench] fn bench_setup_only(b: &mut Bencher) { /* Setup costs */ }
#[bench] fn bench_core_logic(b: &mut Bencher) { /* Core algorithm */ }
#[bench] fn bench_cleanup_only(b: &mut Bencher) { /* Cleanup costs */ }
#[bench] fn bench_end_to_end(b: &mut Bencher) { /* Complete workflow */ }
```

### 🔄 **5. Test Multiple Scenarios**

```rust
#[bench] fn bench_small_input(b: &mut Bencher) { /* 10 items */ }
#[bench] fn bench_medium_input(b: &mut Bencher) { /* 1,000 items */ }
#[bench] fn bench_large_input(b: &mut Bencher) { /* 100,000 items */ }

#[bench] fn bench_best_case(b: &mut Bencher) { /* Optimal conditions */ }
#[bench] fn bench_worst_case(b: &mut Bencher) { /* Worst conditions */ }
#[bench] fn bench_average_case(b: &mut Bencher) { /* Typical conditions */ }
```

---

## Common Pitfalls and How to Avoid Them

### 🚫 **Pitfall 1: Measuring Setup Code**

```rust
// ❌ Problem: Setup included in measurement
#[bench]
fn bench_wrong_measurement(b: &mut Bencher) {
    b.iter(|| {
        let expensive_setup = create_large_data();  // This is measured!
        process_data(expensive_setup)
    });
}

// ✅ Solution: Move setup outside
#[bench]
fn bench_correct_measurement(b: &mut Bencher) {
    let data = create_large_data();  // Setup outside measurement
    b.iter(|| {
        process_data(&data)  // Only this is measured
    });
}
```

### 🚫 **Pitfall 2: System Noise**

```rust
// ❌ Problem: Inconsistent results due to system activity
// Run other programs while benchmarking

// ✅ Solutions:
// 1. Close other applications
// 2. Run multiple times and compare
// 3. Use dedicated benchmark machine
// 4. Check standard deviation in results
```

### 🚫 **Pitfall 3: Compiler Dead Code Elimination**

```rust
// ❌ Problem: Compiler removes "unused" code
#[bench]
fn bench_dead_code(b: &mut Bencher) {
    b.iter(|| {
        let result = compute_value();
        // Result not used - might be optimized away!
    });
}

// ✅ Solution: Use the result
#[bench]
fn bench_with_usage(b: &mut Bencher) {
    b.iter(|| {
        let result = compute_value();
        test::black_box(result)  // Forces compiler to keep it
    });
}
```

### 🚫 **Pitfall 4: Insufficient Iterations**

```rust
// ❌ Problem: Very fast functions need many iterations
#[bench]
fn bench_tiny_function(b: &mut Bencher) {
    b.iter(|| {
        1 + 1  // Too fast to measure accurately
    });
}

// ✅ Solution: Do more work per iteration
#[bench]
fn bench_batched_operations(b: &mut Bencher) {
    b.iter(|| {
        for _ in 0..1000 {
            test::black_box(1 + 1);
        }
    });
}
```

---

## Benchmark Analysis and Optimization

### 📈 **Performance Trending**

```bash
# Save results to compare over time
echo "$(date): $(cargo +nightly bench | grep 'bench_')" >> performance_history.txt

# Track regressions
git bisect start
git bisect bad  # Current slow commit
git bisect good HEAD~10  # Known fast commit
# Git will help find the regression
```

### 🔍 **Profiling Integration**

```rust
// Use benchmarks with profilers like perf
#[bench]
fn bench_for_profiling(b: &mut Bencher) {
    b.iter(|| {
        // This will show up clearly in profiler output
        expensive_function_to_profile()
    });
}
```

```bash
# Profile the benchmark
perf record --call-graph dwarf cargo +nightly bench bench_for_profiling
perf report
```

### 📊 **Statistical Analysis**

```rust
// Collect custom metrics
static mut ITERATIONS: usize = 0;
static mut TOTAL_TIME: u64 = 0;

#[bench]
fn bench_with_custom_metrics(b: &mut Bencher) {
    b.iter(|| {
        let start = std::time::Instant::now();
        let result = timed_operation();
        let duration = start.elapsed();
        
        unsafe {
            ITERATIONS += 1;
            TOTAL_TIME += duration.as_nanos() as u64;
        }
        
        result
    });
    
    unsafe {
        println!("Average: {} ns/iter", TOTAL_TIME / ITERATIONS as u64);
    }
}
```

---

## Our Project Examples

### JWT Benchmarks Overview

```rust
// Our JWT benchmarks cover:
bench_generate_access_token              // Token creation speed
bench_generate_refresh_token             // Refresh token speed  
bench_validate_access_token              // Validation speed
bench_extract_token_from_header          // Header parsing speed
bench_complete_token_validation_flow     // End-to-end workflow
bench_concurrent_token_validation        // Concurrent performance
```

### Password Benchmarks Overview

```rust
// Our password benchmarks cover:
bench_hash_password                      // Argon2 hashing (intentionally slow)
bench_verify_password                    // Verification speed
bench_generate_random_password           // Random generation speed
bench_validate_password_strength         // Strength validation speed
bench_complete_password_workflow         // End-to-end workflow
bench_unicode_password_handling          // International character support
```

### Running Our Benchmarks

```bash
# All benchmarks
cargo +nightly bench

# JWT only
cargo +nightly bench --bench jwt_benchmarks

# Password only  
cargo +nightly bench --bench password_benchmarks

# Specific patterns
cargo +nightly bench generate      # All generation benchmarks
cargo +nightly bench validate     # All validation benchmarks
cargo +nightly bench complete     # All end-to-end workflows
```

### Expected Performance Characteristics

```
JWT Operations (very fast):
- Token generation: ~4,000 ns (4 microseconds)
- Token validation: ~3,700 ns (3.7 microseconds)  
- Header extraction: ~100 ns (0.1 microseconds)

Password Operations (intentionally slower for security):
- Password hashing: ~26,000,000 ns (26 milliseconds)
- Password verification: ~26,000,000 ns (26 milliseconds)
- Strength validation: ~200 ns (0.2 microseconds)
- Random generation: ~140 ns (0.14 microseconds)
```

---

## Conclusion

Rust benchmarking is a powerful tool for:
- **Performance Optimization**: Find and fix bottlenecks
- **Regression Detection**: Catch performance issues early  
- **Algorithm Comparison**: Choose the best implementation
- **Capacity Planning**: Understand system limits

### Next Steps:
1. Run benchmarks regularly as part of CI/CD
2. Set performance budgets and alerts
3. Profile slow benchmarks to find optimization opportunities
4. Document performance characteristics for your team

### Key Takeaways:
- Always use Rust nightly for benchmarking
- Configure Cargo.toml with `[[bench]]` sections
- Use `test::black_box()` to prevent optimizations
- Measure realistic workloads
- Track performance over time
- Understand the statistical output

Happy benchmarking! 🚀
