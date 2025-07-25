# Email Utility Documentation

## Overview

The Email utility provides a comprehensive SMTP-based email service for the ElHaiba backend application. It's designed to handle secure email sending with support for both text and HTML formats, password reset emails, and various SMTP configurations including TLS/STARTTLS encryption.

## Purpose and Philosophy

### Design Philosophy

The email utility is built with the following principles in mind:

1. **Security First**: All communications are encrypted when possible, with configurable TLS/STARTTLS support
2. **Flexibility**: Support for multiple email formats (text, HTML, multipart)
3. **Reliability**: Comprehensive error handling and logging for debugging
4. **Testability**: Clean separation of concerns with mockable components
5. **Production Ready**: Proper timeout handling, connection pooling, and configuration validation

### Use Cases

- **User Authentication**: Sending password reset emails with secure tokens
- **Notifications**: Sending system notifications to users and administrators
- **Welcome Emails**: Onboarding new users with formatted welcome messages
- **Security Alerts**: Notifying users of important account activities
- **Marketing**: Sending promotional content and newsletters (when applicable)

## Architecture

### Core Components

#### 1. SmtpEmailService
The main service struct that encapsulates SMTP functionality:

```rust
pub struct SmtpEmailService {
    pub config: EmailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}
```

#### 2. EmailMessage
A builder pattern for constructing email messages:

```rust
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}
```

#### 3. EmailError
Comprehensive error handling for all email operations:

```rust
pub enum EmailError {
    ConfigError(String),
    SmtpError(String),
    MessageError(String),
    AddressError(String),
    TemplateError(String),
}
```

## Implementation Details

### Email Service Creation

The service is initialized with an `EmailConfig` that undergoes validation:

```rust
impl SmtpEmailService {
    pub fn new(config: EmailConfig) -> Result<Self, EmailError> {
        // Validates configuration
        config.validate().map_err(EmailError::from)?;
        
        // Creates SMTP transport with TLS settings
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
            .port(config.smtp_port)
            .timeout(Some(std::time::Duration::from_secs(config.connection_timeout_secs)))
            // Configure TLS and authentication
            .build();
            
        Ok(Self { config, transport })
    }
}
```

### TLS Configuration Logic

The service supports multiple TLS configurations:

1. **No TLS**: Plain text connection (development only)
2. **TLS Wrapper**: Direct TLS connection (implicit TLS)
3. **STARTTLS**: Upgrade to TLS after initial connection (explicit TLS)

```rust
if config.use_tls {
    let tls_parameters = TlsParameters::new(config.smtp_host.clone())?;
    
    if config.use_starttls {
        transport_builder = transport_builder.tls(Tls::Required(tls_parameters));
    } else {
        transport_builder = transport_builder.tls(Tls::Wrapper(tls_parameters));
    }
} else {
    transport_builder = transport_builder.tls(Tls::None);
}
```

### Email Message Building

The service builds messages using the `lettre` library with proper MIME handling:

```rust
fn build_message(&self, email_message: EmailMessage) -> Result<Message, EmailError> {
    match (email_message.text_body, email_message.html_body) {
        (Some(text), Some(html)) => {
            // Multipart alternative with both text and HTML
            message_builder.multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(text))
                    .singlepart(SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html))
            )
        }
        // Handle other combinations...
    }
}
```

### Password Reset Email Templates

The service includes built-in templates for password reset emails:

#### Text Template
```text
Hello {user_name},

We received a request to reset your password for your ElHaiba account.

To reset your password, please click on the following link:
{reset_url}

This link will expire in 1 hour for security reasons.
```

#### HTML Template
The HTML template includes:
- Responsive design with proper viewport meta tags
- Professional styling with CSS
- Security warnings and branding
- Proper escaping of user data to prevent XSS

### Email Address Validation

Basic email validation is performed:

```rust
fn validate_email_address(&self, email: &str) -> Result<(), EmailError> {
    if email.is_empty() {
        return Err(EmailError::AddressError("Email address cannot be empty".to_string()));
    }

    if !email.contains('@') {
        return Err(EmailError::AddressError("Invalid email format".to_string()));
    }

    // Additional validation logic...
}
```

## API Reference

### Primary Methods

#### `new(config: EmailConfig) -> Result<Self, EmailError>`
Creates a new email service instance with the provided configuration.

**Parameters:**
- `config`: EmailConfig struct containing SMTP settings

**Returns:**
- `Ok(SmtpEmailService)`: Successfully configured service
- `Err(EmailError)`: Configuration or connection error

#### `send_email(&self, message: EmailMessage) -> Result<(), EmailError>`
Sends a generic email message.

**Parameters:**
- `message`: EmailMessage with recipient, subject, and body content

**Returns:**
- `Ok(())`: Email sent successfully
- `Err(EmailError)`: Failed to send email

#### `send_password_reset_email(&self, to: &str, user_name: &str, reset_url: &str) -> Result<(), EmailError>`
Sends a pre-formatted password reset email.

**Parameters:**
- `to`: Recipient email address
- `user_name`: Display name for personalization
- `reset_url`: Complete URL for password reset

**Returns:**
- `Ok(())`: Password reset email sent successfully
- `Err(EmailError)`: Failed to send email

### Helper Methods

#### EmailMessage Builder Pattern

```rust
let message = EmailMessage::new("user@example.com", "Subject")
    .with_text_body("Plain text content")
    .with_html_body("<h1>HTML content</h1>");
```

## Configuration

### EmailConfig Structure

```rust
pub struct EmailConfig {
    pub smtp_host: String,              // SMTP server hostname
    pub smtp_port: u16,                 // SMTP server port
    pub smtp_username: String,          // Authentication username
    pub smtp_password: String,          // Authentication password
    pub from_email: String,             // From address
    pub from_name: String,              // From display name
    pub use_tls: bool,                  // Enable TLS
    pub use_starttls: bool,             // Use STARTTLS instead of direct TLS
    pub connection_timeout_secs: u64,   // Connection timeout
}
```

### Configuration Examples

#### Development (MailHog)
```rust
EmailConfig {
    smtp_host: "localhost".to_string(),
    smtp_port: 1025,
    smtp_username: "".to_string(),
    smtp_password: "".to_string(),
    from_email: "noreply@localhost".to_string(),
    from_name: "ElHaiba Dev".to_string(),
    use_tls: false,
    use_starttls: false,
    connection_timeout_secs: 30,
}
```

#### Production (Gmail SMTP)
```rust
EmailConfig {
    smtp_host: "smtp.gmail.com".to_string(),
    smtp_port: 587,
    smtp_username: "your-email@gmail.com".to_string(),
    smtp_password: "app-password".to_string(),
    from_email: "noreply@yourdomain.com".to_string(),
    from_name: "ElHaiba".to_string(),
    use_tls: true,
    use_starttls: true,
    connection_timeout_secs: 30,
}
```

## Usage Examples

### Basic Email Sending

```rust
use elhaiba_backend::config::EmailConfig;
use elhaiba_backend::util::email::{SmtpEmailService, EmailMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create email service
    let config = EmailConfig::from_env()?;
    let email_service = SmtpEmailService::new(config)?;
    
    // Send simple text email
    let message = EmailMessage::new(
        "user@example.com".to_string(),
        "Welcome to ElHaiba!".to_string(),
    ).with_text_body(
        "Welcome to our platform! We're excited to have you aboard.".to_string()
    );
    
    email_service.send_email(message).await?;
    
    Ok(())
}
```

### Sending HTML Email

```rust
async fn send_welcome_email(
    email_service: &SmtpEmailService,
    user_email: &str,
    user_name: &str,
) -> Result<(), EmailError> {
    let html_body = format!(
        r#"
        <html>
        <body>
            <h1>Welcome, {}!</h1>
            <p>Thank you for joining ElHaiba. We're excited to have you aboard!</p>
            <p>Get started by exploring our features:</p>
            <ul>
                <li>Create your profile</li>
                <li>Join discussions</li>
                <li>Connect with mentors</li>
            </ul>
        </body>
        </html>
        "#,
        user_name
    );
    
    let text_body = format!(
        "Welcome, {}!\n\nThank you for joining ElHaiba...",
        user_name
    );
    
    let message = EmailMessage::new(
        user_email.to_string(),
        "Welcome to ElHaiba!".to_string(),
    )
    .with_text_body(text_body)
    .with_html_body(html_body);
    
    email_service.send_email(message).await
}
```

### Password Reset Email

```rust
async fn handle_password_reset_request(
    email_service: &SmtpEmailService,
    user_email: &str,
    user_name: &str,
    reset_token: &str,
) -> Result<(), EmailError> {
    let reset_url = format!("https://yourdomain.com/reset-password/{}", reset_token);
    
    email_service.send_password_reset_email(
        user_email,
        user_name,
        &reset_url,
    ).await
}
```

## Error Handling

### Error Types and Recovery

The email utility provides detailed error information for different failure scenarios:

```rust
match email_service.send_email(message).await {
    Ok(()) => println!("Email sent successfully"),
    Err(EmailError::ConfigError(msg)) => {
        eprintln!("Configuration error: {}", msg);
        // Reconfigure and retry
    },
    Err(EmailError::SmtpError(msg)) => {
        eprintln!("SMTP error: {}", msg);
        // Check network connectivity, SMTP server status
    },
    Err(EmailError::AddressError(msg)) => {
        eprintln!("Invalid email address: {}", msg);
        // Validate and sanitize email addresses
    },
    Err(EmailError::MessageError(msg)) => {
        eprintln!("Message building error: {}", msg);
        // Check message content and format
    },
    Err(EmailError::TemplateError(msg)) => {
        eprintln!("Template error: {}", msg);
        // Check template syntax and variables
    },
}
```

### Common Error Scenarios

1. **Authentication Failures**: Wrong username/password
2. **Network Issues**: SMTP server unreachable
3. **Rate Limiting**: Too many emails sent in short period
4. **Invalid Recipients**: Malformed email addresses
5. **Content Issues**: Oversized attachments, blocked content

## Testing

### Unit Tests

The email utility includes comprehensive unit tests covering:

#### Configuration Tests
```rust
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
```

#### Message Building Tests
```rust
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
}
```

### Integration Tests

Integration tests require a running SMTP server (like MailHog for development):

```rust
#[tokio::test]
#[ignore] // Requires actual SMTP server
async fn test_send_email_integration() {
    let service = create_test_service();
    
    let message = EmailMessage::new(
        "test@example.com".to_string(),
        "Integration Test Email".to_string(),
    )
    .with_text_body("This is a test email from the integration test.".to_string());

    let result = service.send_email(message).await;
    assert!(result.is_ok());
}
```

### Test Environment Setup

For local development testing:

1. **Install MailHog**: `docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog`
2. **Configure test environment**: Use localhost:1025 as SMTP server
3. **View emails**: Open http://localhost:8025 to see sent emails

## Performance Considerations

### Connection Pooling
The service uses async SMTP transport with connection pooling to handle multiple concurrent email sending operations efficiently.

### Memory Usage
- Email templates are generated on-demand to avoid memory overhead
- Large attachments should be streamed rather than loaded into memory
- Connection timeouts prevent resource leaks

### Rate Limiting
Consider implementing rate limiting at the application level:

```rust
use tokio::time::{sleep, Duration};

async fn send_bulk_emails(
    email_service: &SmtpEmailService,
    messages: Vec<EmailMessage>,
) -> Result<(), EmailError> {
    for message in messages {
        email_service.send_email(message).await?;
        
        // Rate limiting: wait between emails
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}
```

## Security Considerations

### Data Sanitization
- All user input in email templates is properly escaped to prevent injection attacks
- Email addresses are validated before use
- Sensitive information is not logged

### TLS Configuration
```rust
// Always use TLS in production
if config.use_tls {
    // Verify certificates in production
    let tls_parameters = TlsParameters::new(config.smtp_host.clone())
        .map_err(|e| EmailError::ConfigError(format!("TLS configuration error: {}", e)))?;
}
```

### Credential Management
- SMTP credentials should be stored in environment variables
- Use app-specific passwords for email providers
- Rotate credentials regularly

## Backend Integration Scenarios

### User Registration Flow
```rust
pub async fn register_user(
    user_data: RegisterRequest,
    email_service: Arc<SmtpEmailService>,
) -> Result<UserResponse, AppError> {
    // Create user account
    let user = create_user_account(user_data).await?;
    
    // Send welcome email
    tokio::spawn(async move {
        let welcome_message = EmailMessage::new(
            user.email.clone(),
            "Welcome to ElHaiba!".to_string(),
        ).with_html_body(generate_welcome_email_html(&user.name));
        
        if let Err(e) = email_service.send_email(welcome_message).await {
            eprintln!("Failed to send welcome email: {}", e);
        }
    });
    
    Ok(user.into())
}
```

### Password Reset Flow
```rust
pub async fn request_password_reset(
    email: String,
    email_service: Arc<SmtpEmailService>,
    reset_service: Arc<PasswordResetService>,
) -> Result<(), AppError> {
    let user = find_user_by_email(&email).await?;
    let reset_url = reset_service.generate_reset_url(&user.id, &email).await?;
    
    email_service.send_password_reset_email(
        &email,
        &user.name,
        &reset_url,
    ).await?;
    
    Ok(())
}
```

### Notification System
```rust
pub async fn send_notification(
    notification: Notification,
    email_service: Arc<SmtpEmailService>,
) -> Result<(), AppError> {
    let recipients = get_notification_recipients(&notification).await?;
    
    for recipient in recipients {
        let message = EmailMessage::new(
            recipient.email,
            notification.subject.clone(),
        )
        .with_text_body(notification.text_content.clone())
        .with_html_body(notification.html_content.clone());
        
        // Send asynchronously to avoid blocking
        let email_service = Arc::clone(&email_service);
        tokio::spawn(async move {
            if let Err(e) = email_service.send_email(message).await {
                eprintln!("Failed to send notification: {}", e);
            }
        });
    }
    
    Ok(())
}
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify SMTP credentials
   - Check if app-specific passwords are required
   - Ensure account allows SMTP access

2. **Connection Timeouts**
   - Check network connectivity
   - Verify SMTP server hostname and port
   - Adjust timeout settings

3. **TLS/SSL Issues**
   - Verify TLS configuration matches server requirements
   - Check certificate validity
   - Try different TLS modes (STARTTLS vs direct TLS)

4. **Rate Limiting**
   - Implement exponential backoff
   - Reduce sending frequency
   - Consider using email queues

### Debugging

Enable detailed logging:
```rust
use tracing::{info, error, debug};

// Service includes comprehensive tracing
#[instrument(skip(self, message), fields(to = %message.to, subject = %message.subject))]
pub async fn send_email(&self, message: EmailMessage) -> Result<(), EmailError> {
    info!("Sending email to: {}", message.to);
    // Implementation with debug logging...
}
```

## Future Enhancements

### Planned Features
1. **Email Templates**: Template engine for dynamic content
2. **Attachments**: Support for file attachments
3. **Email Queues**: Background processing with retry logic
4. **Analytics**: Email delivery tracking and statistics
5. **Bulk Operations**: Optimized batch email sending
6. **Email Validation**: Advanced email address validation

### Extensibility
The email utility is designed to be extended:

```rust
pub trait EmailService {
    async fn send_email(&self, message: EmailMessage) -> Result<(), EmailError>;
    async fn send_bulk_emails(&self, messages: Vec<EmailMessage>) -> Result<Vec<Result<(), EmailError>>, EmailError>;
}

impl EmailService for SmtpEmailService {
    // Implementation...
}
```

This allows for alternative implementations (e.g., SendGrid, AWS SES) while maintaining the same interface.
