use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use tracing_appender::{non_blocking, rolling};


pub struct Logger {
    pub guards: Vec<tracing_appender::non_blocking::WorkerGuard>,
}

impl Logger {
    pub fn new () -> Result<Self, Box<dyn std::error::Error>> {
        let guards = Self::setup_logging()?;
        Ok(Logger { guards })
    }


    pub fn setup_logging() -> Result<Vec<tracing_appender::non_blocking::WorkerGuard>, Box<dyn std::error::Error>> {
        // Create logs directory
        std::fs::create_dir_all("logs")?;
        


        let console_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("debug,elhaiba_backend=debug"));

        let file_log_level = std::env::var("FILE_LOG_LEVEL").unwrap_or_else(|_| "debug".to_string());

        let error_file_log_level = std::env::var("ERROR_FILE_LOG_LEVEL").unwrap_or_else(|_| "error".to_string());
        
        // File appenders
        let general_file = rolling::daily("logs", "elhaiba-backend.log");
        let (non_blocking_general, guard1) = non_blocking(general_file);

        let error_file = rolling::daily("logs/error", "elhaiba-backend-error.log");
        let (non_blocking_error, _guard2) = non_blocking(error_file);

        let general_json_file = rolling::daily("logs/json", "elhaiba-backend.json");
        let (non_blocking_json, _guard3) = non_blocking(general_json_file);

        let error_json_file = rolling::daily("logs/error/json", "elhaiba-backend-error.json");
        let (non_blocking_error_json, _guard4) = non_blocking(error_json_file);


        
        tracing_subscriber::registry()
            .with(
                // Console output - pretty format for development
                fmt::layer()
                    .pretty()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_ansi(true)
                    .with_filter(console_filter)
                    
            )
            .with(
                // General log file - all logs
                fmt::layer()
                    .with_writer(non_blocking_general)
                    .with_ansi(false)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(EnvFilter::new(file_log_level.clone()))
            )
                
            .with(
                // Error log file 
                fmt::layer()
                    .with_writer(non_blocking_error)
                    .with_ansi(false)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(EnvFilter::new(error_file_log_level.clone()))
            )
            .with(
                // General log json file - all logs
                fmt::layer()
                    .json()
                    .with_writer(non_blocking_json)
                    .with_ansi(false)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(EnvFilter::new(file_log_level.clone()))
            )
            .with(
                // Error json log file
                fmt::layer()
                    .json()
                    .with_writer(non_blocking_error_json)
                    .with_ansi(false)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(EnvFilter::new(error_file_log_level.clone()))
            )
            .init();
        
        // Return guards to keep background threads alive
        Ok(vec![guard1, _guard2, _guard3, _guard4])
    }
}