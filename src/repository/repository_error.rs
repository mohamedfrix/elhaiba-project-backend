use std::fmt;

#[derive(Debug)]
pub enum RepositoryError {
    NotFound(String),
    AlreadyExists(String),
    ValidationError(String),
    DatabaseError(String),
    ConnectionError(String),
    SerializationError(String),
    /// Generic error that wraps any error implementing std::error::Error
    Generic(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepositoryError::NotFound(msg) => write!(f, "Not Found: {}", msg),
            RepositoryError::AlreadyExists(msg) => write!(f, "Already Exists: {}", msg),
            RepositoryError::ValidationError(msg) => write!(f, "Validation Error: {}", msg),
            RepositoryError::DatabaseError(msg) => write!(f, "Database Error: {}", msg),
            RepositoryError::ConnectionError(msg) => write!(f, "Connection Error: {}", msg),
            RepositoryError::SerializationError(msg) => write!(f, "Serialization Error: {}", msg),
            RepositoryError::Generic(err) => write!(f, "Repository Error: {}", err),
        }
    }
}

impl std::error::Error for RepositoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RepositoryError::Generic(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

// Convenient constructors
impl RepositoryError {
    pub fn not_found<T: Into<String>>(msg: T) -> Self {
        RepositoryError::NotFound(msg.into())
    }

    pub fn already_exists<T: Into<String>>(msg: T) -> Self {
        RepositoryError::AlreadyExists(msg.into())
    }

    pub fn validation<T: Into<String>>(msg: T) -> Self {
        RepositoryError::ValidationError(msg.into())
    }

    pub fn database<T: Into<String>>(msg: T) -> Self {
        RepositoryError::DatabaseError(msg.into())
    }

    pub fn connection<T: Into<String>>(msg: T) -> Self {
        RepositoryError::ConnectionError(msg.into())
    }

    pub fn serialization<T: Into<String>>(msg: T) -> Self {
        RepositoryError::SerializationError(msg.into())
    }

    pub fn generic<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        RepositoryError::Generic(Box::new(err))
    }
}

// MongoDB-specific conversions
impl From<mongodb::error::Error> for RepositoryError {
    fn from(err: mongodb::error::Error) -> Self {
        use mongodb::error::ErrorKind;
        
        match err.kind.as_ref() {
                ErrorKind::Write(_) => {
                    // Check for duplicate key error (E11000) using error message
                    let err_msg = err.to_string();
                    if err_msg.contains("E11000") {
                        RepositoryError::AlreadyExists(format!("Duplicate key: {}", err))
                    } else {
                        RepositoryError::DatabaseError(format!("Write error: {}", err))
                    }
                }
            ErrorKind::Authentication { .. } => {
                RepositoryError::ConnectionError(format!("Authentication failed: {}", err))
            }
            ErrorKind::InvalidArgument { .. } => {
                RepositoryError::ValidationError(format!("Invalid argument: {}", err))
            }
            ErrorKind::Io(_) => {
                RepositoryError::ConnectionError(format!("IO error: {}", err))
            }
            _ => RepositoryError::Generic(Box::new(err)),
        }
    }
}

// BSON serialization errors

impl From<bson::ser::Error> for RepositoryError {
    fn from(err: bson::ser::Error) -> Self {
        RepositoryError::SerializationError(format!("BSON serialization error: {}", err))
    }
}

impl From<bson::de::Error> for RepositoryError {
    fn from(err: bson::de::Error) -> Self {
        RepositoryError::SerializationError(format!("BSON deserialization error: {}", err))
    }
}

// Removed blanket From<E> implementation to avoid conflict with core::convert::From

// Result type alias for convenience
pub type RepositoryResult<T> = Result<T, RepositoryError>;
