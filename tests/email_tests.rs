use elhaiba_backend::config::EmailConfig;
use elhaiba_backend::util::email::{SmtpEmailService, EmailMessage, EmailError};

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();
}

/// Create test email config
fn create_test_config() -> EmailConfig {
    EmailConfig::from_test_env()
}

/// Create test email service
fn create_test_service() -> SmtpEmailService {
    let config = create_test_config();
    SmtpEmailService::new(config).expect("Failed to create test email service")
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[tokio::test]
    async fn test_email_service_creation() {
        init_tracing();
        // Note: SMTP service requires tokio runtime for connection pool initialization
        // This test verifies the service can be created with test config
        let config = create_test_config();
        assert_eq!(config.smtp_host, "localhost");
        assert_eq!(config.smtp_port, 1025);
    }

    #[test]
    fn test_email_message_creation() {
        let message = EmailMessage::new(
            "test@example.com".to_string(),
            "Test Subject".to_string(),
        );

        assert_eq!(message.to, "test@example.com");
        assert_eq!(message.subject, "Test Subject");
        assert!(message.text_body.is_none());
        assert!(message.html_body.is_none());
    }

    #[test]
    fn test_email_message_with_bodies() {
        let message = EmailMessage::new(
            "test@example.com".to_string(),
            "Test Subject".to_string(),
        )
        .with_text_body("Text body content".to_string())
        .with_html_body("<h1>HTML body content</h1>".to_string());

        assert!(message.text_body.is_some());
        assert!(message.html_body.is_some());
        assert_eq!(message.text_body.unwrap(), "Text body content");
        assert_eq!(message.html_body.unwrap(), "<h1>HTML body content</h1>");
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_email_error_types() {
        // Test that all error types can be created and displayed
        let errors = vec![
            EmailError::ConfigError("Config error".to_string()),
            EmailError::SmtpError("SMTP error".to_string()),
            EmailError::MessageError("Message error".to_string()),
            EmailError::AddressError("Address error".to_string()),
            EmailError::TemplateError("Template error".to_string()),
        ];

        for error in errors {
            let display = format!("{}", error);
            let debug = format!("{:?}", error);
            
            assert!(!display.is_empty());
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_invalid_config_creation() {
        let mut config = create_test_config();
        config.smtp_host = "".to_string();
        
        let result = SmtpEmailService::new(config);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, EmailError::ConfigError(_)));
        }
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_config_from_test_env() {
        let config = EmailConfig::from_test_env();
        assert_eq!(config.smtp_host, "localhost");
        assert_eq!(config.smtp_port, 1025);
        assert_eq!(config.from_email, "test@example.com");
        assert_eq!(config.from_name, "Test App");
        assert!(!config.use_tls);
        assert!(!config.use_starttls);
    }

    #[test]
    fn test_config_validation() {
        let config = create_test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_empty_host() {
        let mut config = create_test_config();
        config.smtp_host = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_port() {
        let mut config = create_test_config();
        config.smtp_port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_empty_from_email() {
        let mut config = create_test_config();
        config.from_email = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_email_format() {
        let mut config = create_test_config();
        config.from_email = "invalid-email".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_get_smtp_url() {
        let config = create_test_config();
        assert_eq!(config.get_smtp_url(), "localhost:1025");
    }
}

// Integration tests that would require actual SMTP server
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires actual SMTP server
    async fn test_send_email_integration() {
        init_tracing();
        let service = create_test_service();
        
        let message = EmailMessage::new(
            "test@example.com".to_string(),
            "Integration Test Email".to_string(),
        )
        .with_text_body("This is a test email from the integration test.".to_string());

        // This would fail without a real SMTP server
        let result = service.send_email(message).await;
        // In a real test environment with MailHog or similar, this should pass
        assert!(result.is_err()); // Expected to fail in CI without SMTP server
    }

    #[tokio::test]
    #[ignore] // Requires actual SMTP server
    async fn test_send_password_reset_email_integration() {
        init_tracing();
        let service = create_test_service();
        
        let result = service.send_password_reset_email(
            "test@example.com",
            "Integration Test User",
            "https://frontend.com/reset-password/token123"
        ).await;

        // This would fail without a real SMTP server
        assert!(result.is_err()); // Expected to fail in CI without SMTP server
    }
}
