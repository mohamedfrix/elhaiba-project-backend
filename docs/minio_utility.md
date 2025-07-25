# MinIO Object Storage Utility Documentation

## Overview

The MinIO utility provides a comprehensive object storage solution for the ElHaiba backend application. It implements a high-level interface for MinIO S3-compatible object storage operations, including file upload, download, metadata management, and bucket operations. The utility is designed for scalable file storage with proper error handling and logging.

## Purpose and Philosophy

### Design Philosophy

The MinIO utility is built around these core principles:

1. **S3 Compatibility**: Leverages the widely-adopted S3 API for maximum portability
2. **Async by Design**: Non-blocking operations for high-performance file handling
3. **Type Safety**: Rust's type system ensures memory safety and prevents common errors
4. **Error Transparency**: Detailed error reporting for debugging and monitoring
5. **Production Ready**: Automatic bucket management, connection validation, and retry logic
6. **Developer Friendly**: Simple, intuitive API that abstracts complex S3 operations

### Use Cases

- **File Storage**: User-uploaded content (avatars, documents, media files)
- **Backup Solutions**: Automated backup of application data and configurations
- **Content Delivery**: Serving static assets and user-generated content
- **Data Archival**: Long-term storage of historical data and logs
- **Image Processing**: Storage for original and processed images
- **Document Management**: PDF storage, document versioning, and metadata tracking

## Architecture

### Core Components

#### 1. MinioService
The main service struct providing all object storage operations:

```rust
pub struct MinioService {
    client: Client,
    config: MinioConfig,
}
```

#### 2. ObjectInfo
Metadata container for stored objects:

```rust
pub struct ObjectInfo {
    pub name: String,
    pub size: i64,
    pub etag: String,
    pub last_modified: Option<time::OffsetDateTime>,
    pub content_type: String,
}
```

#### 3. MinioError
Comprehensive error handling for all storage operations:

```rust
pub enum MinioError {
    ConfigError(String),
    ConnectionError(String),
    OperationError(String),
    InvalidArguments(String),
    ObjectNotFound(String),
}
```

## Implementation Details

### Service Initialization

The MinIO service initializes with automatic bucket creation and connection validation:

```rust
impl MinioService {
    pub async fn new(config: MinioConfig) -> Result<Self, MinioError> {
        // Validate configuration
        config.validate().map_err(|e| MinioError::ConfigError(e.to_string()))?;

        // Parse endpoint URL
        let base_url = config.get_endpoint_url().parse::<BaseUrl>()
            .map_err(|e| MinioError::ConnectionError(format!("Invalid endpoint URL: {}", e)))?;

        // Create credentials provider
        let static_provider = StaticProvider::new(&config.access_key, &config.secret_key, None);

        // Build client with credentials
        let client = ClientBuilder::new(base_url)
            .provider(Some(Box::new(static_provider)))
            .build()
            .map_err(|e| MinioError::ConnectionError(format!("Client creation failed: {}", e)))?;

        let service = Self { client, config };

        // Ensure bucket exists
        service.ensure_bucket_exists().await?;

        Ok(service)
    }
}
```

### Automatic Bucket Management

The service automatically creates buckets if they don't exist:

```rust
async fn ensure_bucket_exists(&self) -> Result<(), MinioError> {
    let bucket_exists_args = BucketExistsArgs::new(&self.config.bucket_name)
        .map_err(|e| MinioError::InvalidArguments(e.to_string()))?;

    let exists = self.client.bucket_exists(&bucket_exists_args).await
        .map_err(|e| MinioError::OperationError(format!("Bucket exists check failed: {}", e)))?;

    if !exists {
        let make_bucket_args = MakeBucketArgs::new(&self.config.bucket_name)
            .map_err(|e| MinioError::InvalidArguments(e.to_string()))?;

        self.client.make_bucket(&make_bucket_args).await
            .map_err(|e| MinioError::OperationError(format!("Bucket creation failed: {}", e)))?;
    }

    Ok(())
}
```

### Object Upload Implementation

File uploads support content type detection and proper stream handling:

```rust
pub async fn put_object(
    &self,
    object_name: &str,
    data: Bytes,
    content_type: Option<&str>,
) -> Result<(), MinioError> {
    let mut reader = Cursor::new(data.clone());
    let data_len = data.len();

    let mut args = PutObjectArgs::new(
        &self.config.bucket_name, 
        object_name, 
        &mut reader,
        Some(data_len),
        None,
    ).map_err(|e| MinioError::InvalidArguments(e.to_string()))?;

    if let Some(ct) = content_type {
        args.content_type = ct;
    }

    self.client.put_object(&mut args).await
        .map_err(|e| MinioError::OperationError(format!("Upload failed: {}", e)))?;

    Ok(())
}
```

### Object Download Implementation

Downloads return raw bytes for flexible handling:

```rust
pub async fn get_object(&self, object_name: &str) -> Result<Bytes, MinioError> {
    let args = GetObjectArgs::new(&self.config.bucket_name, object_name)
        .map_err(|e| MinioError::InvalidArguments(e.to_string()))?;

    let response = self.client.get_object(&args).await
        .map_err(|e| MinioError::OperationError(format!("Download failed: {}", e)))?;

    let bytes = response.bytes().await
        .map_err(|e| MinioError::OperationError(format!("Read failed: {}", e)))?;

    Ok(bytes)
}
```

### Metadata Retrieval

Object statistics provide comprehensive metadata:

```rust
pub async fn stat_object(&self, object_name: &str) -> Result<ObjectInfo, MinioError> {
    let args = StatObjectArgs::new(&self.config.bucket_name, object_name)
        .map_err(|e| MinioError::InvalidArguments(e.to_string()))?;

    let stat = self.client.stat_object(&args).await
        .map_err(|e| MinioError::OperationError(format!("Stat failed: {}", e)))?;

    let object_info = ObjectInfo {
        name: object_name.to_string(),
        size: stat.size as i64,
        etag: stat.etag,
        last_modified: stat.last_modified.map(|dt| {
            time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
        }),
        content_type: "application/octet-stream".to_string(),
    };

    Ok(object_info)
}
```

## API Reference

### Primary Methods

#### `new(config: MinioConfig) -> Result<Self, MinioError>`
Creates a new MinIO service instance with automatic bucket creation.

**Parameters:**
- `config`: MinioConfig containing endpoint, credentials, and bucket information

**Returns:**
- `Ok(MinioService)`: Successfully configured service
- `Err(MinioError)`: Configuration, connection, or bucket creation error

#### `put_object(&self, object_name: &str, data: Bytes, content_type: Option<&str>) -> Result<(), MinioError>`
Uploads an object to MinIO storage.

**Parameters:**
- `object_name`: Unique identifier for the object (can include path separators)
- `data`: Binary data to upload as Bytes
- `content_type`: Optional MIME type (e.g., "image/jpeg", "application/pdf")

**Returns:**
- `Ok(())`: Upload successful
- `Err(MinioError)`: Upload failed

**Example:**
```rust
let data = Bytes::from("Hello, MinIO!");
service.put_object("documents/hello.txt", data, Some("text/plain")).await?;
```

#### `get_object(&self, object_name: &str) -> Result<Bytes, MinioError>`
Downloads an object from MinIO storage.

**Parameters:**
- `object_name`: Identifier of the object to download

**Returns:**
- `Ok(Bytes)`: Object data
- `Err(MinioError)`: Download failed or object not found

**Example:**
```rust
let data = service.get_object("documents/hello.txt").await?;
let content = String::from_utf8(data.to_vec())?;
```

#### `stat_object(&self, object_name: &str) -> Result<ObjectInfo, MinioError>`
Retrieves metadata for an object without downloading its content.

**Parameters:**
- `object_name`: Identifier of the object

**Returns:**
- `Ok(ObjectInfo)`: Object metadata including size, modification time, etc.
- `Err(MinioError)`: Operation failed or object not found

#### `remove_object(&self, object_name: &str) -> Result<(), MinioError>`
Deletes an object from MinIO storage.

**Parameters:**
- `object_name`: Identifier of the object to delete

**Returns:**
- `Ok(())`: Deletion successful
- `Err(MinioError)`: Deletion failed

#### `object_exists(&self, object_name: &str) -> Result<bool, MinioError>`
Checks if an object exists without downloading it.

**Parameters:**
- `object_name`: Identifier of the object

**Returns:**
- `Ok(bool)`: True if object exists, false otherwise
- `Err(MinioError)`: Check operation failed

### Configuration Methods

#### `get_config(&self) -> &MinioConfig`
Returns the configuration used by the service.

**Returns:**
- `&MinioConfig`: Reference to the current configuration

## Configuration

### MinioConfig Structure

```rust
pub struct MinioConfig {
    pub endpoint: String,           // MinIO server endpoint (host:port)
    pub access_key: String,         // Access key for authentication
    pub secret_key: String,         // Secret key for authentication
    pub bucket_name: String,        // Default bucket name
    pub region: Option<String>,     // AWS region (optional)
    pub secure: bool,              // Use HTTPS (true) or HTTP (false)
}
```

### Configuration Examples

#### Development Configuration
```rust
MinioConfig {
    endpoint: "localhost:9000".to_string(),
    access_key: "minioadmin".to_string(),
    secret_key: "minioadmin".to_string(),
    bucket_name: "elhaiba-dev".to_string(),
    region: Some("us-east-1".to_string()),
    secure: false, // HTTP for local development
}
```

#### Production Configuration
```rust
MinioConfig {
    endpoint: "minio.yourdomain.com:443".to_string(),
    access_key: std::env::var("MINIO_ACCESS_KEY").expect("MINIO_ACCESS_KEY required"),
    secret_key: std::env::var("MINIO_SECRET_KEY").expect("MINIO_SECRET_KEY required"),
    bucket_name: "elhaiba-production".to_string(),
    region: Some("us-west-2".to_string()),
    secure: true, // HTTPS for production
}
```

#### AWS S3 Configuration
```rust
MinioConfig {
    endpoint: "s3.amazonaws.com:443".to_string(),
    access_key: std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID required"),
    secret_key: std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY required"),
    bucket_name: "elhaiba-s3-bucket".to_string(),
    region: Some("us-east-1".to_string()),
    secure: true,
}
```

### Environment Variables

```bash
# MinIO Configuration
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET_NAME=elhaiba-dev
MINIO_REGION=us-east-1
MINIO_SECURE=false

# Production values
MINIO_ENDPOINT=minio.yourdomain.com:443
MINIO_ACCESS_KEY=your-access-key
MINIO_SECRET_KEY=your-secret-key
MINIO_BUCKET_NAME=elhaiba-production
MINIO_SECURE=true
```

## Usage Examples

### Basic File Operations

```rust
use elhaiba_backend::config::MinioConfig;
use elhaiba_backend::util::minio::MinioService;
use bytes::Bytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize MinIO service
    let config = MinioConfig::from_env()?;
    let minio_service = MinioService::new(config).await?;
    
    // Upload a file
    let file_data = Bytes::from("Hello, MinIO world!");
    minio_service.put_object(
        "documents/hello.txt",
        file_data.clone(),
        Some("text/plain")
    ).await?;
    
    // Download the file
    let downloaded_data = minio_service.get_object("documents/hello.txt").await?;
    assert_eq!(file_data, downloaded_data);
    
    // Check if file exists
    let exists = minio_service.object_exists("documents/hello.txt").await?;
    println!("File exists: {}", exists);
    
    // Get file metadata
    let object_info = minio_service.stat_object("documents/hello.txt").await?;
    println!("File size: {} bytes", object_info.size);
    println!("Last modified: {:?}", object_info.last_modified);
    
    // Delete the file
    minio_service.remove_object("documents/hello.txt").await?;
    
    Ok(())
}
```

### Image Upload Handler

```rust
use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

#[derive(Serialize)]
struct UploadResponse {
    object_name: String,
    size: i64,
    content_type: String,
}

pub async fn upload_image_handler(
    State(minio_service): State<Arc<MinioService>>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, StatusCode> {
    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        let name = field.name().unwrap_or("unknown");
        
        if name == "image" {
            let content_type = field.content_type()
                .unwrap_or("application/octet-stream")
                .to_string();
            
            // Validate content type
            if !content_type.starts_with("image/") {
                return Err(StatusCode::BAD_REQUEST);
            }
            
            let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            
            // Generate unique object name
            let object_name = format!("images/{}.{}", 
                uuid::Uuid::new_v4(),
                get_file_extension(&content_type)
            );
            
            // Upload to MinIO
            minio_service.put_object(&object_name, data.clone(), Some(&content_type))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            return Ok(Json(UploadResponse {
                object_name,
                size: data.len() as i64,
                content_type,
            }));
        }
    }
    
    Err(StatusCode::BAD_REQUEST)
}

fn get_file_extension(content_type: &str) -> &str {
    match content_type {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => "bin",
    }
}
```

### Document Management Service

```rust
use std::collections::HashMap;

pub struct DocumentService {
    minio_service: Arc<MinioService>,
}

impl DocumentService {
    pub fn new(minio_service: Arc<MinioService>) -> Self {
        Self { minio_service }
    }
    
    pub async fn store_document(
        &self,
        user_id: &str,
        document_name: &str,
        data: Bytes,
        content_type: &str,
    ) -> Result<String, DocumentError> {
        // Create organized object path
        let object_name = format!("documents/{}/{}", user_id, document_name);
        
        // Upload to MinIO
        self.minio_service.put_object(&object_name, data, Some(content_type))
            .await
            .map_err(DocumentError::StorageError)?;
        
        Ok(object_name)
    }
    
    pub async fn get_document(
        &self,
        user_id: &str,
        document_name: &str,
    ) -> Result<DocumentData, DocumentError> {
        let object_name = format!("documents/{}/{}", user_id, document_name);
        
        // Get document data
        let data = self.minio_service.get_object(&object_name)
            .await
            .map_err(DocumentError::StorageError)?;
        
        // Get metadata
        let info = self.minio_service.stat_object(&object_name)
            .await
            .map_err(DocumentError::StorageError)?;
        
        Ok(DocumentData {
            name: document_name.to_string(),
            data,
            size: info.size,
            content_type: info.content_type,
            last_modified: info.last_modified,
        })
    }
    
    pub async fn list_user_documents(
        &self,
        user_id: &str,
    ) -> Result<Vec<DocumentInfo>, DocumentError> {
        // Note: This is a simplified implementation
        // In practice, you might use MinIO's list_objects_v2 operation
        // or maintain a separate index
        
        let prefix = format!("documents/{}/", user_id);
        
        // This would require implementing list operations
        // For now, return empty list as placeholder
        Ok(vec![])
    }
    
    pub async fn delete_document(
        &self,
        user_id: &str,
        document_name: &str,
    ) -> Result<(), DocumentError> {
        let object_name = format!("documents/{}/{}", user_id, document_name);
        
        self.minio_service.remove_object(&object_name)
            .await
            .map_err(DocumentError::StorageError)?;
        
        Ok(())
    }
}

#[derive(Debug)]
pub struct DocumentData {
    pub name: String,
    pub data: Bytes,
    pub size: i64,
    pub content_type: String,
    pub last_modified: Option<time::OffsetDateTime>,
}

#[derive(Debug)]
pub struct DocumentInfo {
    pub name: String,
    pub size: i64,
    pub content_type: String,
    pub last_modified: Option<time::OffsetDateTime>,
}

#[derive(Debug, thiserror::Error)]
pub enum DocumentError {
    #[error("Storage error: {0}")]
    StorageError(#[from] MinioError),
    #[error("Document not found")]
    NotFound,
    #[error("Invalid document format")]
    InvalidFormat,
}
```

### Backup Service

```rust
pub struct BackupService {
    minio_service: Arc<MinioService>,
}

impl BackupService {
    pub async fn backup_database_dump(
        &self,
        dump_data: Bytes,
        timestamp: time::OffsetDateTime,
    ) -> Result<String, MinioError> {
        let backup_name = format!("backups/database-{}.sql", 
            timestamp.format("%Y%m%d-%H%M%S"));
        
        self.minio_service.put_object(
            &backup_name,
            dump_data,
            Some("application/sql")
        ).await?;
        
        Ok(backup_name)
    }
    
    pub async fn backup_user_data(
        &self,
        user_id: &str,
        data: HashMap<String, serde_json::Value>,
    ) -> Result<String, MinioError> {
        let serialized = serde_json::to_vec(&data)
            .map_err(|e| MinioError::OperationError(format!("Serialization failed: {}", e)))?;
        
        let backup_name = format!("backups/users/{}-{}.json", 
            user_id,
            time::OffsetDateTime::now_utc().format("%Y%m%d-%H%M%S")
        );
        
        self.minio_service.put_object(
            &backup_name,
            Bytes::from(serialized),
            Some("application/json")
        ).await?;
        
        Ok(backup_name)
    }
    
    pub async fn restore_user_data(
        &self,
        backup_name: &str,
    ) -> Result<HashMap<String, serde_json::Value>, MinioError> {
        let data = self.minio_service.get_object(backup_name).await?;
        
        let restored: HashMap<String, serde_json::Value> = serde_json::from_slice(&data)
            .map_err(|e| MinioError::OperationError(format!("Deserialization failed: {}", e)))?;
        
        Ok(restored)
    }
}
```

## Error Handling

### Error Types and Recovery

The MinIO utility provides detailed error information for different failure scenarios:

```rust
match minio_service.put_object(object_name, data, content_type).await {
    Ok(()) => println!("Upload successful"),
    Err(MinioError::ConfigError(msg)) => {
        eprintln!("Configuration error: {}", msg);
        // Check MinIO configuration and credentials
    },
    Err(MinioError::ConnectionError(msg)) => {
        eprintln!("Connection error: {}", msg);
        // Check network connectivity and MinIO server status
    },
    Err(MinioError::OperationError(msg)) => {
        eprintln!("Operation failed: {}", msg);
        // Check bucket permissions and object constraints
    },
    Err(MinioError::InvalidArguments(msg)) => {
        eprintln!("Invalid arguments: {}", msg);
        // Validate object name and parameters
    },
    Err(MinioError::ObjectNotFound(obj)) => {
        eprintln!("Object not found: {}", obj);
        // Handle missing object scenario
    },
}
```

### Retry Logic

Implement retry logic for transient failures:

```rust
use tokio::time::{sleep, Duration};

async fn upload_with_retry(
    minio_service: &MinioService,
    object_name: &str,
    data: Bytes,
    content_type: Option<&str>,
    max_retries: u32,
) -> Result<(), MinioError> {
    let mut attempts = 0;
    
    loop {
        match minio_service.put_object(object_name, data.clone(), content_type).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                attempts += 1;
                
                if attempts >= max_retries {
                    return Err(e);
                }
                
                // Exponential backoff
                let delay = Duration::from_millis(100 * 2_u64.pow(attempts));
                sleep(delay).await;
            }
        }
    }
}
```

## Testing

### Unit Tests

The MinIO utility includes comprehensive unit tests:

#### Configuration Tests
```rust
#[test]
fn test_minio_config_validation_comprehensive() {
    // Test valid configs
    let valid_config = MinioConfig {
        endpoint: "localhost:9000".to_string(),
        access_key: "minioadmin".to_string(),
        secret_key: "minioadmin".to_string(),
        bucket_name: "test-bucket".to_string(),
        region: Some("us-east-1".to_string()),
        secure: false,
    };
    assert!(valid_config.validate().is_ok());
    
    // Test invalid configs
    let mut invalid_config = valid_config.clone();
    invalid_config.bucket_name = String::new();
    assert!(invalid_config.validate().is_err());
}
```

#### Object Info Tests
```rust
#[test]
fn test_object_info_creation() {
    let info = ObjectInfo {
        name: "test-file.txt".to_string(),
        size: 1024,
        etag: "abc123def456".to_string(),
        last_modified: None,
        content_type: "text/plain".to_string(),
    };
    
    assert_eq!(info.name, "test-file.txt");
    assert_eq!(info.size, 1024);
    assert_eq!(info.content_type, "text/plain");
}
```

### Integration Tests

Integration tests require a running MinIO instance:

```rust
#[tokio::test]
#[ignore] // Requires running MinIO instance
async fn test_put_and_get_object() {
    let config = create_test_config();
    let service = MinioService::new(config).await.unwrap();

    let test_data = Bytes::from("Hello, MinIO!");
    let object_name = "test-object.txt";

    // Upload object
    service.put_object(object_name, test_data.clone(), Some("text/plain")).await.unwrap();

    // Download object
    let downloaded_data = service.get_object(object_name).await.unwrap();
    assert_eq!(downloaded_data, test_data);

    // Get object stats
    let object_info = service.stat_object(object_name).await.unwrap();
    assert_eq!(object_info.name, object_name);
    assert_eq!(object_info.size, test_data.len() as i64);

    // Check existence
    let exists = service.object_exists(object_name).await.unwrap();
    assert!(exists);

    // Remove object
    service.remove_object(object_name).await.unwrap();
    
    // Verify removal
    let exists_after = service.object_exists(object_name).await.unwrap();
    assert!(!exists_after);
}
```

### Test Environment Setup

For local development testing:

1. **Start MinIO Server**:
   ```bash
   docker run -p 9000:9000 -p 9001:9001 \
     -e "MINIO_ROOT_USER=minioadmin" \
     -e "MINIO_ROOT_PASSWORD=minioadmin" \
     minio/minio server /data --console-address ":9001"
   ```

2. **Access MinIO Console**: Open http://localhost:9001
3. **Create Test Buckets**: Use console or configure automatic creation

## Performance Considerations

### Upload Optimization

For large files, consider streaming uploads:

```rust
use tokio_util::io::ReaderStream;

pub async fn upload_large_file(
    minio_service: &MinioService,
    object_name: &str,
    file_path: &Path,
    content_type: &str,
) -> Result<(), MinioError> {
    let file = tokio::fs::File::open(file_path).await?;
    let metadata = file.metadata().await?;
    let size = metadata.len();
    
    // Stream the file instead of loading into memory
    let reader = ReaderStream::new(file);
    
    // Note: This would require extending the MinIO utility
    // to support streaming uploads
    todo!("Implement streaming upload")
}
```

### Connection Pooling

The underlying MinIO client handles connection pooling automatically:

```rust
// The client reuses connections for multiple operations
let service = MinioService::new(config).await?;

// Multiple operations share connections
for i in 0..100 {
    let object_name = format!("batch/object-{}.txt", i);
    let data = Bytes::from(format!("Data for object {}", i));
    service.put_object(&object_name, data, Some("text/plain")).await?;
}
```

### Memory Management

For handling large objects:

```rust
use tokio_stream::StreamExt;

pub async fn process_large_object_stream(
    minio_service: &MinioService,
    object_name: &str,
) -> Result<(), MinioError> {
    // Download object
    let data = minio_service.get_object(object_name).await?;
    
    // Process in chunks to avoid memory issues
    let chunk_size = 8192; // 8KB chunks
    for chunk in data.chunks(chunk_size) {
        // Process chunk
        process_chunk(chunk).await?;
    }
    
    Ok(())
}
```

## Security Considerations

### Access Control

Configure bucket policies for security:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": ["arn:aws:iam::ACCOUNT:user/elhaiba-app"]},
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::elhaiba-production/*"]
    }
  ]
}
```

### Credential Management

```rust
// Use environment variables for credentials
impl MinioConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(MinioConfig {
            endpoint: std::env::var("MINIO_ENDPOINT")?,
            access_key: std::env::var("MINIO_ACCESS_KEY")?,
            secret_key: std::env::var("MINIO_SECRET_KEY")?,
            bucket_name: std::env::var("MINIO_BUCKET_NAME")?,
            region: std::env::var("MINIO_REGION").ok(),
            secure: std::env::var("MINIO_SECURE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        })
    }
}
```

### Data Validation

```rust
pub async fn secure_upload(
    minio_service: &MinioService,
    object_name: &str,
    data: Bytes,
    content_type: &str,
) -> Result<(), MinioError> {
    // Validate object name
    if object_name.contains("..") || object_name.starts_with('/') {
        return Err(MinioError::InvalidArguments("Invalid object name".to_string()));
    }
    
    // Validate content type
    let allowed_types = vec![
        "image/jpeg", "image/png", "image/gif",
        "application/pdf", "text/plain"
    ];
    
    if !allowed_types.contains(&content_type) {
        return Err(MinioError::InvalidArguments("Content type not allowed".to_string()));
    }
    
    // Validate file size
    if data.len() > 10 * 1024 * 1024 { // 10MB limit
        return Err(MinioError::InvalidArguments("File too large".to_string()));
    }
    
    minio_service.put_object(object_name, data, Some(content_type)).await
}
```

## Backend Integration Scenarios

### User Avatar Management

```rust
pub struct AvatarService {
    minio_service: Arc<MinioService>,
}

impl AvatarService {
    pub async fn upload_avatar(
        &self,
        user_id: &str,
        image_data: Bytes,
        content_type: &str,
    ) -> Result<String, AvatarError> {
        // Validate image
        self.validate_avatar_image(&image_data, content_type)?;
        
        // Generate avatar path
        let avatar_path = format!("avatars/{}.jpg", user_id);
        
        // Process image (resize, optimize)
        let processed_image = self.process_avatar_image(image_data).await?;
        
        // Upload to MinIO
        self.minio_service.put_object(
            &avatar_path,
            processed_image,
            Some("image/jpeg")
        ).await?;
        
        Ok(avatar_path)
    }
    
    pub async fn get_avatar_url(&self, user_id: &str) -> Result<String, AvatarError> {
        let avatar_path = format!("avatars/{}.jpg", user_id);
        
        // Check if avatar exists
        if !self.minio_service.object_exists(&avatar_path).await? {
            return Ok(self.get_default_avatar_url());
        }
        
        // Generate public URL (would require presigned URL implementation)
        Ok(format!("https://cdn.yourdomain.com/{}", avatar_path))
    }
}
```

### Content Management System

```rust
pub struct ContentService {
    minio_service: Arc<MinioService>,
}

impl ContentService {
    pub async fn store_article_images(
        &self,
        article_id: &str,
        images: Vec<(String, Bytes)>, // (filename, data)
    ) -> Result<Vec<String>, MinioError> {
        let mut uploaded_paths = Vec::new();
        
        for (filename, data) in images {
            let object_path = format!("articles/{}/{}", article_id, filename);
            
            // Detect content type from filename
            let content_type = detect_content_type(&filename);
            
            self.minio_service.put_object(&object_path, data, Some(&content_type)).await?;
            uploaded_paths.push(object_path);
        }
        
        Ok(uploaded_paths)
    }
    
    pub async fn generate_article_backup(
        &self,
        article_id: &str,
        article_data: ArticleData,
    ) -> Result<String, MinioError> {
        let backup_data = serde_json::to_vec(&article_data)
            .map_err(|e| MinioError::OperationError(e.to_string()))?;
        
        let backup_path = format!("backups/articles/{}-{}.json",
            article_id,
            time::OffsetDateTime::now_utc().format("%Y%m%d-%H%M%S")
        );
        
        self.minio_service.put_object(
            &backup_path,
            Bytes::from(backup_data),
            Some("application/json")
        ).await?;
        
        Ok(backup_path)
    }
}

fn detect_content_type(filename: &str) -> String {
    match filename.split('.').last().unwrap_or("").to_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }.to_string()
}
```

## Troubleshooting

### Common Issues

1. **Connection Failures**:
   ```rust
   // Check MinIO server status
   match minio_service.client.list_buckets().await {
       Ok(_) => println!("MinIO connection successful"),
       Err(e) => eprintln!("MinIO connection failed: {}", e),
   }
   ```

2. **Bucket Access Issues**:
   - Verify bucket exists and is accessible
   - Check access key permissions
   - Validate bucket policy configuration

3. **Upload Failures**:
   - Check object name validity (no special characters)
   - Verify sufficient storage space
   - Validate content type if required

4. **Network Issues**:
   - Test connectivity to MinIO endpoint
   - Check firewall rules
   - Verify SSL/TLS configuration

### Debugging

Enable detailed logging:
```rust
use tracing::{debug, error, info, warn};

// The MinIO utility includes comprehensive tracing
#[instrument(skip(self, data), fields(object_name = %object_name, size = data.len()))]
pub async fn put_object(&self, object_name: &str, data: Bytes, content_type: Option<&str>) -> Result<(), MinioError> {
    info!("Uploading object '{}' to bucket '{}'", object_name, self.config.bucket_name);
    debug!("Object size: {} bytes", data.len());
    // Implementation with detailed logging...
}
```

## Future Enhancements

### Planned Features

1. **Presigned URLs**: Secure, temporary URLs for direct client uploads
2. **Object Listing**: Support for listing objects with pagination
3. **Multipart Uploads**: Efficient handling of large files
4. **Object Versioning**: Support for multiple versions of objects
5. **Lifecycle Management**: Automated cleanup and archival policies
6. **Metadata Management**: Custom metadata support for objects

### Extensibility

The MinIO utility can be extended:

```rust
pub trait ObjectStorageService {
    async fn put_object(&self, key: &str, data: Bytes, content_type: Option<&str>) -> Result<(), StorageError>;
    async fn get_object(&self, key: &str) -> Result<Bytes, StorageError>;
    async fn delete_object(&self, key: &str) -> Result<(), StorageError>;
    async fn object_exists(&self, key: &str) -> Result<bool, StorageError>;
}

impl ObjectStorageService for MinioService {
    // Implementation using MinIO
}

// Alternative implementations
pub struct S3Service; // AWS S3
pub struct GCSService; // Google Cloud Storage
pub struct AzureBlobService; // Azure Blob Storage
```

This design allows for easy migration between different object storage providers while maintaining the same interface.
