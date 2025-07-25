#![feature(test)]
extern crate test;

use test::Bencher;
use elhaiba_backend::util::password::{PasswordUtilsImpl, PasswordUtils};
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

#[derive(Debug)]
struct MemoryAnalysis {
    function_name: String,
    avg_allocated: f64,
    avg_peak: f64,
    max_allocated: usize,
    min_allocated: usize,
    max_peak: usize,
    samples: usize,
    memory_efficiency_score: f64,
}

fn analyze_memory_usage(function_name: &str, stats: &[MemoryUsage]) -> MemoryAnalysis {
    if stats.is_empty() { 
        return MemoryAnalysis {
            function_name: function_name.to_string(),
            avg_allocated: 0.0,
            avg_peak: 0.0,
            max_allocated: 0,
            min_allocated: 0,
            max_peak: 0,
            samples: 0,
            memory_efficiency_score: 0.0,
        };
    }
    
    let avg_allocated: f64 = stats.iter().map(|s| s.allocated as f64).sum::<f64>() / stats.len() as f64;
    let avg_peak: f64 = stats.iter().map(|s| s.peak as f64).sum::<f64>() / stats.len() as f64;
    let max_allocated = stats.iter().map(|s| s.allocated).max().unwrap();
    let max_peak = stats.iter().map(|s| s.peak).max().unwrap();
    let min_allocated = stats.iter().map(|s| s.allocated).min().unwrap();
    
    // Memory efficiency: lower is better (less memory per operation)
    let memory_efficiency_score = avg_allocated / stats.len() as f64;
    
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║          Memory Analysis: {:^17} ║", function_name);
    println!("╠═══════════════════════════════════════════════════╣");
    println!("║ Samples analyzed: {:>30} ║", format_number(stats.len()));
    println!("║ Average allocated: {:>25} bytes ║", format_number(avg_allocated as usize));
    println!("║ Average peak: {:>30} bytes ║", format_number(avg_peak as usize));
    println!("║ Max allocated: {:>29} bytes ║", format_number(max_allocated));
    println!("║ Min allocated: {:>29} bytes ║", format_number(min_allocated));
    println!("║ Max peak: {:>34} bytes ║", format_number(max_peak));
    println!("║ Memory efficiency: {:>25.6} ║", memory_efficiency_score);
    
    // Memory pattern analysis
    let variance = stats.iter()
        .map(|s| (s.allocated as f64 - avg_allocated).powi(2))
        .sum::<f64>() / stats.len() as f64;
    let std_dev = variance.sqrt();
    
    println!("║ Standard deviation: {:>24} bytes ║", format_number(std_dev as usize));
    
    // Memory consistency rating
    let consistency = if std_dev < avg_allocated * 0.1 {
        "Excellent"
    } else if std_dev < avg_allocated * 0.25 {
        "Good"
    } else if std_dev < avg_allocated * 0.5 {
        "Fair"
    } else {
        "Poor"
    };
    
    println!("║ Memory consistency: {:>26} ║", consistency);
    println!("╚═══════════════════════════════════════════════════╝");
    
    MemoryAnalysis {
        function_name: function_name.to_string(),
        avg_allocated,
        avg_peak,
        max_allocated,
        min_allocated,
        max_peak,
        samples: stats.len(),
        memory_efficiency_score,
    }
}

/// Memory Benchmark: Hash password with Argon2
/// Measures memory allocation during password hashing (this will be high due to Argon2's design)
#[bench]
fn bench_memory_hash_password(b: &mut Bencher) {
    let password = "TestPassword123!@#";
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = PasswordUtilsImpl::hash_password(password);
        
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
    
    analyze_memory_usage("hash_password", &memory_stats);
}

/// Memory Benchmark: Verify password
/// Measures memory allocation during password verification against hash
#[bench]
fn bench_memory_verify_password(b: &mut Bencher) {
    let password = "TestPassword123!@#";
    let hash = PasswordUtilsImpl::hash_password(password).unwrap();
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = PasswordUtilsImpl::verify_password(password, &hash);
        
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
    
    analyze_memory_usage("verify_password", &memory_stats);
}

/// Memory Benchmark: Generate random password
/// Measures memory allocation during secure random password generation
#[bench]
fn bench_memory_generate_random_password(b: &mut Bencher) {
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = PasswordUtilsImpl::generate_random_password(16);
        
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
    
    analyze_memory_usage("generate_random_password", &memory_stats);
}

/// Memory Benchmark: Validate password strength
/// Measures memory allocation during password strength validation
#[bench]
fn bench_memory_validate_password_strength(b: &mut Bencher) {
    let password = "ComplexPassword123!@#$%^&*()";
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let result = PasswordUtilsImpl::validate_password_strength(password);
        
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
    
    analyze_memory_usage("validate_password_strength", &memory_stats);
}

/// Memory Benchmark: Complete password workflow
/// Measures memory during generate -> validate -> hash -> verify workflow
#[bench]
fn bench_memory_complete_password_workflow(b: &mut Bencher) {
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        // Complete workflow
        let password = PasswordUtilsImpl::generate_random_password(16);
        let _strength_result = PasswordUtilsImpl::validate_password_strength(&password);
        let hash = PasswordUtilsImpl::hash_password(&password).unwrap();
        let result = PasswordUtilsImpl::verify_password(&password, &hash).unwrap();
        
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
    
    analyze_memory_usage("complete_password_workflow", &memory_stats);
}

/// Memory Benchmark: Unicode password handling
/// Measures memory allocation with international characters
#[bench]
fn bench_memory_unicode_password_handling(b: &mut Bencher) {
    let unicode_passwords = [
        "Пароль123!",           // Cyrillic
        "パスワード123!",         // Japanese
        "密码123!",             // Chinese
        "Contraseña123!",       // Spanish
        "Mot2Passe123!",        // French
        "Καλός123!",            // Greek
    ];
    let mut memory_stats = Vec::new();
    let mut password_index = 0;
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let password = unicode_passwords[password_index % unicode_passwords.len()];
        password_index += 1;
        
        // Test strength validation with unicode
        let _strength = PasswordUtilsImpl::validate_password_strength(password);
        
        // Test hashing with unicode
        let result = PasswordUtilsImpl::hash_password(password);
        
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
    
    analyze_memory_usage("unicode_password_handling", &memory_stats);
}

/// Memory Benchmark: Password hashing with different lengths
/// Measures how memory usage scales with password length
#[bench]
fn bench_memory_hash_different_lengths(b: &mut Bencher) {
    let passwords = [
        "Short1!",
        "MediumLength123!",
        "VeryLongPasswordWithManyCharacters123!@#$%",
        "ExtremelyLongPasswordThatSimulatesUserBehaviorWithVeryLongPassphrases123!@#$%^&*()",
    ];
    let mut memory_stats = Vec::new();
    let mut password_index = 0;
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        let password = passwords[password_index % passwords.len()];
        password_index += 1;
        let result = PasswordUtilsImpl::hash_password(password);
        
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
    
    analyze_memory_usage("hash_different_lengths", &memory_stats);
}

/// Memory Benchmark: Memory efficiency comparison
/// Compares memory usage of different password operations
#[bench]
fn bench_memory_efficiency_comparison(b: &mut Bencher) {
    let password = "TestPassword123!";
    let hash = PasswordUtilsImpl::hash_password(password).unwrap();
    let mut memory_stats = Vec::new();
    
    b.iter(|| {
        reset_memory_counters();
        let memory_before = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        
        // Test multiple operations in sequence to see cumulative memory usage
        let random_pwd = PasswordUtilsImpl::generate_random_password(12);
        let _strength1 = PasswordUtilsImpl::validate_password_strength(&random_pwd);
        let _strength2 = PasswordUtilsImpl::validate_password_strength(password);
        let _verify_result = PasswordUtilsImpl::verify_password(password, &hash);
        
        let memory_after = ALLOCATED.load(Ordering::SeqCst) - DEALLOCATED.load(Ordering::SeqCst);
        let (allocated, deallocated, peak) = get_memory_stats();
        
        memory_stats.push(MemoryUsage {
            allocated,
            deallocated,
            peak,
            net_usage: memory_after.saturating_sub(memory_before),
        });
        
        test::black_box(random_pwd)
    });
    
    analyze_memory_usage("efficiency_comparison", &memory_stats);
}
