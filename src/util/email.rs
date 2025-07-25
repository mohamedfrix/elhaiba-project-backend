use crate::config::{EmailConfig, ConfigError};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{header::ContentType, Mailbox},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};
use tracing::{error, info, instrument};

/// Email service errors
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("SMTP error: {0}")]
    SmtpError(String),
    
    #[error("Message building error: {0}")]
    MessageError(String),
    
    #[error("Address error: {0}")]
    AddressError(String),
    
    #[error("Template error: {0}")]
    TemplateError(String),
}

impl From<ConfigError> for EmailError {
    fn from(err: ConfigError) -> Self {
        EmailError::ConfigError(err.to_string())
    }
}

/// Email message builder
#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

impl EmailMessage {
    pub fn new(to: String, subject: String) -> Self {
        Self {
            to,
            subject,
            text_body: None,
            html_body: None,
        }
    }

    pub fn with_text_body(mut self, body: String) -> Self {
        self.text_body = Some(body);
        self
    }

    pub fn with_html_body(mut self, body: String) -> Self {
        self.html_body = Some(body);
        self
    }
}

/// SMTP email service implementation
pub struct SmtpEmailService {
    pub config: EmailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpEmailService {
    /// Create a new SMTP email service
    #[instrument(skip(config), fields(host = %config.smtp_host, port = config.smtp_port))]
    pub fn new(config: EmailConfig) -> Result<Self, EmailError> {
        info!("Initializing SMTP email service");
        
        config.validate().map_err(EmailError::from)?;

        let mut transport_builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
            .port(config.smtp_port)
            .timeout(Some(std::time::Duration::from_secs(config.connection_timeout_secs)));

        // Configure TLS settings
        if config.use_tls {
            let tls_parameters = TlsParameters::new(config.smtp_host.clone())
                .map_err(|e| EmailError::ConfigError(format!("TLS configuration error: {}", e)))?;
            
            if config.use_starttls {
                transport_builder = transport_builder.tls(Tls::Required(tls_parameters));
            } else {
                transport_builder = transport_builder.tls(Tls::Wrapper(tls_parameters));
            }
        } else {
            transport_builder = transport_builder.tls(Tls::None);
        }

        // Configure authentication if credentials are provided
        if !config.smtp_username.is_empty() && !config.smtp_password.is_empty() {
            let credentials = Credentials::new(
                config.smtp_username.clone(),
                config.smtp_password.clone(),
            );
            transport_builder = transport_builder.credentials(credentials);
        }

        let transport = transport_builder.build();

        info!("SMTP email service initialized successfully");
        Ok(Self { config, transport })
    }

    /// Send an email message
    #[instrument(skip(self, message), fields(to = %message.to, subject = %message.subject))]
    pub async fn send_email(&self, message: EmailMessage) -> Result<(), EmailError> {
        info!("Sending email to: {}", message.to);
        
        self.validate_email_address(&message.to)?;
        
        let email_message = self.build_message(message)?;
        
        self.transport
            .send(email_message)
            .await
            .map_err(|e| {
                error!("Failed to send email: {}", e);
                EmailError::SmtpError(format!("Failed to send email: {}", e))
            })?;

        info!("Email sent successfully");
        Ok(())
    }

    /// Send a password reset email
    #[instrument(skip(self), fields(to = %to, user_name = %user_name))]
    pub async fn send_password_reset_email(
        &self,
        to: &str,
        user_name: &str,
        reset_url: &str,
    ) -> Result<(), EmailError> {
        info!("Sending password reset email to: {}", to);
        
        let (text_body, html_body) = self.generate_password_reset_template(to, user_name, reset_url)?;
        
        let message = EmailMessage::new(
            to.to_string(),
            "Password Reset Request - ElHaiba".to_string(),
        )
        .with_text_body(text_body)
        .with_html_body(html_body);

        self.send_email(message).await?;
        
        info!("Password reset email sent successfully");
        Ok(())
    }

    /// Generate password reset email templates
    fn generate_password_reset_template(
        &self,
        _email: &str,
        user_name: &str,
        reset_url: &str,
    ) -> Result<(String, String), EmailError> {
        let text_body = self.generate_password_reset_text(reset_url, user_name);
        let html_body = self.generate_password_reset_html(reset_url, user_name);
        
        Ok((text_body, html_body))
    }

    /// Generate password reset text template
    fn generate_password_reset_text(&self, reset_url: &str, user_name: &str) -> String {
        format!(
            r#"Hello {user_name},

We received a request to reset your password for your ElHaiba account.

To reset your password, please click on the following link or copy and paste it into your browser:

{reset_url}

This link will expire in 1 hour for security reasons.

If you did not request a password reset, please ignore this email. Your password will remain unchanged.

For security reasons:
- Never share this link with anyone
- Our team will never ask for your password via email
- If you have any concerns, please contact our support team

Best regards,
The ElHaiba Team

---
This is an automated message. Please do not reply to this email."#,
            user_name = user_name,
            reset_url = reset_url
        )
    }

    /// Generate password reset HTML template
    fn generate_password_reset_html(&self, reset_url: &str, user_name: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Request</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }}
        .content {{
            background-color: #ffffff;
            padding: 30px;
            border: 1px solid #dee2e6;
        }}
        .button {{
            display: inline-block;
            padding: 12px 24px;
            background-color: #007bff;
            color: #ffffff;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            margin: 20px 0;
        }}
        .footer {{
            background-color: #f8f9fa;
            padding: 15px;
            text-align: center;
            font-size: 12px;
            color: #6c757d;
            border-radius: 0 0 8px 8px;
        }}
        .warning {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ElHaiba</h1>
        <h2>Password Reset Request</h2>
    </div>
    
    <div class="content">
        <p>Hello {user_name},</p>
        
        <p>We received a request to reset your password for your ElHaiba account.</p>
        
        <p>To reset your password, please click the button below:</p>
        
        <div style="text-align: center;">
            <a href="{reset_url}" class="button">Reset Password</a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 4px;">
            {reset_url}
        </p>
        
        <div class="warning">
            <strong>⚠️ Security Notice:</strong>
            <ul>
                <li>This link will expire in 1 hour</li>
                <li>Never share this link with anyone</li>
                <li>If you didn't request this reset, please ignore this email</li>
            </ul>
        </div>
        
        <p>If you have any questions or concerns, please contact our support team.</p>
        
        <p>Best regards,<br>The ElHaiba Team</p>
    </div>
    
    <div class="footer">
        <p>This is an automated message. Please do not reply to this email.</p>
        <p>&copy; 2024 ElHaiba. All rights reserved.</p>
    </div>
</body>
</html>"#,
            user_name = html_escape::encode_text(user_name),
            reset_url = html_escape::encode_text(reset_url)
        )
    }

    /// Build a lettre Message from EmailMessage
    fn build_message(&self, email_message: EmailMessage) -> Result<Message, EmailError> {
        let from_mailbox: Mailbox = format!("{} <{}>", self.config.from_name, self.config.from_email)
            .parse()
            .map_err(|e| EmailError::AddressError(format!("Invalid from address: {}", e)))?;

        let to_mailbox: Mailbox = email_message.to
            .parse()
            .map_err(|e| EmailError::AddressError(format!("Invalid to address: {}", e)))?;

        let message_builder = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(&email_message.subject);

        match (email_message.text_body, email_message.html_body) {
            (Some(text), Some(html)) => {
                // Multipart message with both text and HTML
                let message = message_builder
                    .multipart(
                        lettre::message::MultiPart::alternative()
                            .singlepart(
                                lettre::message::SinglePart::builder()
                                    .header(ContentType::TEXT_PLAIN)
                                    .body(text),
                            )
                            .singlepart(
                                lettre::message::SinglePart::builder()
                                    .header(ContentType::TEXT_HTML)
                                    .body(html),
                            ),
                    )
                    .map_err(|e| EmailError::MessageError(format!("Failed to build multipart message: {}", e)))?;
                return Ok(message);
            }
            (Some(text), None) => {
                // Text-only message
                let message = message_builder
                    .body(text)
                    .map_err(|e| EmailError::MessageError(format!("Failed to build text message: {}", e)))?;
                return Ok(message);
            }
            (None, Some(html)) => {
                // HTML-only message
                let message = message_builder
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    )
                    .map_err(|e| EmailError::MessageError(format!("Failed to build HTML message: {}", e)))?;
                return Ok(message);
            }
            (None, None) => {
                Err(EmailError::MessageError("No message body provided".to_string()))
            }
        }
    }

    /// Validate email address format
    fn validate_email_address(&self, email: &str) -> Result<(), EmailError> {
        if email.is_empty() {
            return Err(EmailError::AddressError("Email address cannot be empty".to_string()));
        }

        if !email.contains('@') {
            return Err(EmailError::AddressError("Invalid email format".to_string()));
        }

        // Basic email validation
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(EmailError::AddressError("Invalid email format".to_string()));
        }

        Ok(())
    }
}
