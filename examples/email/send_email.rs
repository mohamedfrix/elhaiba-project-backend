use elhaiba_backend::{config::EmailConfig, util::email::{EmailError, EmailMessage, SmtpEmailService}, util::logger::Logger};
use tracing::{error, info, warn};
use dotenv::dotenv;


#[tokio::main]
async fn main () -> Result<(), Box<dyn std::error::Error>> {
    
    // Initialize logging with file output
    // let _guards = setup_logging()?;

    let logger = Logger::new()?;
    let _guards = logger.guards;
    
    info!("🚀 Starting Elhaiba Backend Email Test Application");

    // Load environment variables from .env file
    match dotenv() {
        Ok(_) => info!("✅ Successfully loaded .env file"),
        Err(e) => warn!("⚠️ Failed to load .env file: {} (using system env vars)", e),
    }

    // Load email configuration
    let email_config = match EmailConfig::from_env() {
        Ok(config) => {
            info!("Email configuration loaded successfully");
            config
        },
        Err(e) => {
            error!("Failed to load email configuration: {}", e);
            return Err(Box::<dyn std::error::Error>::from(e));
        }
    };


    let email_service = match SmtpEmailService::new(email_config) {
        Ok(service) => {
            info!("Email service created successfully");
            service
        },
        Err(EmailError::ConfigError(e)) => {
            error!("Email service configuration error: {}", e);
            return Err(Box::<dyn std::error::Error>::from(e));
        },
        Err(e) => {
            error!("Failed to create email service: {}", e);
            return Err(Box::<dyn std::error::Error>::from(e));
        }
    };

    let message = EmailMessage::new(
        "frihaouimohamed@gmail.com".to_string(),
        "Test Email".to_string(),
    ).with_html_body("<h1 color=\"red\">Hello, World!</h1>".to_string());


    match email_service.send_email(message).await {
        Ok(_) => info!("Email sent successfully"),
        Err(e) => {
            error!("Failed to send email: {}", e);
            return Err(Box::new(e) as Box<dyn std::error::Error>);
        }
    }
    Ok(())
}
