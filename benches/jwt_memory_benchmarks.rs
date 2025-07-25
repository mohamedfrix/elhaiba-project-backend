#![feature(test)]
extern crate test;

use test::Bencher;
use elhaiba_backend::util::jwt::{JwtTokenUtilsImpl, JwtTokenUtils};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

// Helper function to format numbers with comma separators
fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().rev().collect();
    
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    
    result.chars().rev().collect()
}

// Memory tracking allocator
struct MemoryTracker;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_MEMORY: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for MemoryTracker {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = unsafe { System.alloc(layout) };
        if !ret.is_null() {
            let old_allocated = ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
            let current_usage = old_allocated + layout.size() - DEALLOCATED.load(Ordering::SeqCst);
            
            // Update peak memory usage
            let mut peak = PEAK_MEMORY.load(Ordering::SeqCst);
            while current_usage > peak {
                match PEAK_MEMORY.compare_exchange_weak(peak, current_usage, Ordering::SeqCst, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(x) => peak = x,
                }
            }
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        DEALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
    }
}

// Enable memory tracking globally for this benchmark file
#[global_allocator]
static GLOBAL: MemoryTracker = MemoryTracker;

// Helper functions for memory tracking
fn reset_memory_counters() {
    ALLOCATED.store(0, Ordering::SeqCst);
    DEALLOCATED.store(0, Ordering::SeqCst);
    PEAK_MEMORY.store(0, Ordering::SeqCst);
}

fn get_memory_stats() -> (usize, usize, usize) {
    let allocated = ALLOCATED.load(Ordering::SeqCst);
    let deallocated = DEALLOCATED.load(Ordering::SeqCst);
    let peak = PEAK_MEMORY.load(Ordering::SeqCst);
    (allocated, deallocated, peak)
}

#[derive(Debug)]
struct MemoryUsage {
    allocated: usize,
    deallocated: usize,
    peak: usize,
    net_usage: usize,
}

fn analyze_memory_usage(function_name: &str, stats: &[MemoryUsage]) {
    if stats.is_empty() { return; }
    
    let samples = stats.len();
    let avg_allocated: f64 = stats.iter().map(|s| s.allocated as f64).sum::<f64>() / stats.len() as f64;
    let avg_peak: f64 = stats.iter().map(|s| s.peak as f64).sum::<f64>() / stats.len() as f64;
    let max_allocated = stats.iter().map(|s| s.allocated).max().unwrap();
    let max_peak = stats.iter().map(|s| s.peak).max().unwrap();
    let min_allocated = stats.iter().map(|s| s.allocated).min().unwrap();
    
    // Calculate standard deviation
    let variance: f64 = stats.iter()
        .map(|s| (s.allocated as f64 - avg_allocated).powi(2))
        .sum::<f64>() / stats.len() as f64;
    let std_dev = variance.sqrt();
    
    // Calculate memory efficiency score
    let efficiency = if avg_peak > 0.0 { avg_allocated / avg_peak } else { 0.0 };
    
    // Determine consistency rating
    let consistency = if std_dev < 50.0 {
        "Excellent"
    } else if std_dev < 200.0 {
        "Good"
    } else {
        "Poor"
    };
    
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║          Memory Analysis: {:^15} ║", function_name);
    println!("╠═══════════════════════════════════════════════════╣");
    println!("║ Samples analyzed:                       {:>8} ║", format_number(samples));
    println!("║ Average allocated:                {:>12} bytes ║", format_number(avg_allocated as usize));
    println!("║ Average peak:                     {:>12} bytes ║", format_number(avg_peak as usize));
    println!("║ Max allocated:                    {:>12} bytes ║", format_number(max_allocated));
    println!("║ Min allocated:                    {:>12} bytes ║", format_number(min_allocated));
    println!("║ Max peak:                         {:>12} bytes ║", format_number(max_peak));
    println!("║ Memory efficiency:                {:12.6} ║", efficiency);
    println!("║ Standard deviation:               {:>12} bytes ║", format_number(std_dev as usize));
    println!("║ Memory consistency:                {:>10} ║", consistency);
    println!("╚═══════════════════════════════════════════════════╝");
}

/// Helper function to create JWT utils for memory benchmarking
fn create_memory_jwt_utils() -> JwtTokenUtilsImpl {
    JwtTokenUtilsImpl::new(
        "memory_bench_secret_key_for_testing_purposes_only_very_long_key_that_ensures_security",
        3600,  // 1 hour access token expiration
        86400, // 24 hour refresh token expiration
    )
}

/// Memory Benchmark: Generate access token
/// Measures memory allocation during JWT access token generation
#[bench]
fn bench_memory_generate_access_token(b: &mut Bencher) {
    let jwt_utils = create_memory_jwt_utils();
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = jwt_utils.generate_access_token("user123", "user@example.com", "user");
        
        let memory_after = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        let (allocated, deallocated, peak) = get_memory_stats();
        
        memory_stats.push(MemoryUsage {
            allocated,
            deallocated,
            peak,
            net_usage: memory_after.saturating_sub(memory_before),
        });
        
        test::black_box(result)
    });
    
    analyze_memory_usage("generate_access_token", &memory_stats);
}

/// Memory Benchmark: Generate refresh token  
/// Measures memory allocation during JWT refresh token generation
#[bench]
fn bench_memory_generate_refresh_token(b: &mut Bencher) {
    let jwt_utils = create_memory_jwt_utils();
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = jwt_utils.generate_refresh_token("user123", "user@example.com", "user");
        
        let memory_after = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        let (allocated, deallocated, peak) = get_memory_stats();
        
        memory_stats.push(MemoryUsage {
            allocated,
            deallocated,
            peak,
            net_usage: memory_after.saturating_sub(memory_before),
        });
        
        test::black_box(result)
    });
    
    analyze_memory_usage("generate_refresh_token", &memory_stats);
}

/// Memory Benchmark: Validate access token
/// Measures memory allocation during JWT token validation
#[bench]
fn bench_memory_validate_access_token(b: &mut Bencher) {
    let jwt_utils = create_memory_jwt_utils();
    let token = jwt_utils.generate_access_token("user123", "user@example.com", "user").unwrap();
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = jwt_utils.validate_access_token(&token);
        
        let memory_after = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        let (allocated, deallocated, peak) = get_memory_stats();
        
        memory_stats.push(MemoryUsage {
            allocated,
            deallocated,
            peak,
            net_usage: memory_after.saturating_sub(memory_before),
        });
        
        test::black_box(result)
    });
    
    analyze_memory_usage("validate_access_token", &memory_stats);
}

/// Memory Benchmark: Token pair generation
/// Measures memory allocation during complete token pair generation
#[bench]
fn bench_memory_generate_token_pair(b: &mut Bencher) {
    let jwt_utils = create_memory_jwt_utils();
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = jwt_utils.generate_token_pair("user123", "user@example.com", "user");
        
        let memory_after = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        let (allocated, deallocated, peak) = get_memory_stats();
        
        memory_stats.push(MemoryUsage {
            allocated,
            deallocated,
            peak,
            net_usage: memory_after.saturating_sub(memory_before),
        });
        
        test::black_box(result)
    });
    
    analyze_memory_usage("generate_token_pair", &memory_stats);
}

/// Memory Benchmark: Complete validation flow
/// Measures memory during extract -> validate -> get_user_id workflow
#[bench]
fn bench_memory_complete_validation_flow(b: &mut Bencher) {
    let jwt_utils = create_memory_jwt_utils();
    let token = jwt_utils.generate_access_token("user123", "user@example.com", "admin").unwrap();
    let header = format!("Bearer {}", token);
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        // Complete workflow
        let extracted_token = jwt_utils.extract_token_from_header(&header).unwrap();
        let _claims = jwt_utils.validate_access_token(&extracted_token).unwrap();
        let result = jwt_utils.get_user_id_from_token(&extracted_token).unwrap();
        
        let memory_after = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        let (allocated, deallocated, peak) = get_memory_stats();
        
        memory_stats.push(MemoryUsage {
            allocated,
            deallocated,
            peak,
            net_usage: memory_after.saturating_sub(memory_before),
        });
        
        test::black_box(result)
    });
    
    analyze_memory_usage("complete_validation_flow", &memory_stats);
}

/// Memory Benchmark: Token serialization
/// Measures memory during token pair serialization/deserialization
#[bench]
fn bench_memory_token_serialization(b: &mut Bencher) {
    let jwt_utils = create_memory_jwt_utils();
    let token_pair = jwt_utils.generate_token_pair("user123", "user@example.com", "user").unwrap();
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&token_pair).unwrap();
        // Deserialize back
        let _deserialized: elhaiba_backend::util::jwt::TokenPair = 
            serde_json::from_str(&serialized).unwrap();
        
        let memory_after = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        let (allocated, deallocated, peak) = get_memory_stats();
        
        memory_stats.push(MemoryUsage {
            allocated,
            deallocated,
            peak,
            net_usage: memory_after.saturating_sub(memory_before),
        });
        
        test::black_box(serialized)
    });
    
    analyze_memory_usage("token_serialization", &memory_stats);
}
