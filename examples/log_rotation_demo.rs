use std::thread;
use std::time::Duration;
use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Log Rotation Demo - Different Rotation Strategies\n");

    // Demo 1: Daily Rotation (what you currently have)
    demo_daily_rotation()?;
    
    // Demo 2: Hourly Rotation (more frequent)
    demo_hourly_rotation()?;
    
    // Demo 3: Size-based Rotation (not time-based)
    demo_size_rotation()?;

    Ok(())
}

fn demo_daily_rotation() -> Result<(), Box<dyn std::error::Error>> {
    println!("📅 DAILY ROTATION DEMO:");
    println!("- Creates one file per day: app.log.YYYY-MM-DD");
    println!("- Rotates at midnight (00:00:00)");
    println!("- File pattern: logs/daily/app.log.2025-07-22\n");

    // Create daily rotating appender
    let file_appender = tracing_appender::rolling::daily("logs/daily", "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
        );

    subscriber.init();

    // Generate some logs
    info!("This goes to today's file: logs/daily/app.log.{}", chrono::Utc::now().format("%Y-%m-%d"));
    warn!("If you run this tomorrow, it will go to a new file!");
    error!("Files accumulate over time - you need to clean them up manually");

    // Reset for next demo
    drop(_guard);
    Ok(())
}

fn demo_hourly_rotation() -> Result<(), Box<dyn std::error::Error>> {
    println!("⏰ HOURLY ROTATION DEMO:");
    println!("- Creates one file per hour: app.log.YYYY-MM-DD-HH");
    println!("- Rotates every hour at minute 00");
    println!("- File pattern: logs/hourly/app.log.2025-07-22-23\n");

    // Create hourly rotating appender
    let file_appender = tracing_appender::rolling::hourly("logs/hourly", "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Note: We need to reset the global subscriber, so this is just demonstration
    println!("Hourly rotation would create: logs/hourly/app.log.{}", 
             chrono::Utc::now().format("%Y-%m-%d-%H"));

    drop(_guard);
    Ok(())
}

fn demo_size_rotation() -> Result<(), Box<dyn std::error::Error>> {
    println!("📊 SIZE-BASED ROTATION (Alternative approach):");
    println!("- Not directly supported by tracing-appender");
    println!("- Would need external log management (logrotate, etc.)");
    println!("- Or use different crates like 'file-rotate'\n");

    Ok(())
}
