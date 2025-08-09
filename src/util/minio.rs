use crate::config::MinioConfig;
use bytes::Bytes;
use minio::s3::args::{
    BucketExistsArgs, GetObjectArgs, MakeBucketArgs, PutObjectArgs, RemoveObjectArgs,
    StatObjectArgs,
};
use minio::s3::client::{Client, ClientBuilder};
use minio::s3::creds::StaticProvider;
use minio::s3::http::BaseUrl;
use std::io::Cursor;
use tracing::{debug, error, info, instrument, warn};

#[derive(Debug, Clone)]
pub struct MinioService {
    client: Client,
    pub config: MinioConfig,
}

impl MinioService {
    /// Create a new MinIO service instance
    #[instrument(skip(config), fields(endpoint = %config.endpoint, bucket = %config.bucket_name))]
    pub async fn new(config: MinioConfig) -> Result<Self, MinioError> {
        info!("Initializing MinIO service");
        
        // Validate configuration first
        config.validate().map_err(|e| {
            error!("MinIO configuration validation failed: {}", e);
            MinioError::ConfigError(e.to_string())
        })?;

        let base_url = config.get_endpoint_url().parse::<BaseUrl>()
            .map_err(|e| {
                error!("Failed to parse MinIO endpoint URL: {}", e);
                MinioError::ConnectionError(format!("Invalid endpoint URL: {}", e))
            })?;

        debug!("Creating MinIO client with endpoint: {}", config.get_endpoint_url());

        let static_provider = StaticProvider::new(&config.access_key, &config.secret_key, None);

        let client = ClientBuilder::new(base_url)
            .provider(Some(Box::new(static_provider)))
            .build()
            .map_err(|e| {
                error!("Failed to create MinIO client: {}", e);
                MinioError::ConnectionError(format!("Client creation failed: {}", e))
            })?;

        let service = Self { client, config };

        // Test connection and ensure bucket exists
        service.ensure_bucket_exists().await?;

        info!("MinIO service initialized successfully");
        Ok(service)
    }

    /// Ensure the configured bucket exists, create if it doesn't
    #[instrument(skip(self))]
    async fn ensure_bucket_exists(&self) -> Result<(), MinioError> {
        info!("Checking if bucket '{}' exists", self.config.bucket_name);

        let bucket_exists_args = BucketExistsArgs::new(&self.config.bucket_name)
            .map_err(|e| {
                error!("Failed to create bucket exists args: {}", e);
                MinioError::InvalidArguments(e.to_string())
            })?;

        let exists = self.client.bucket_exists(&bucket_exists_args).await
            .map_err(|e| {
                error!("Failed to check if bucket exists: {}", e);
                MinioError::OperationError(format!("Bucket exists check failed: {}", e))
            })?;

        if exists {
            info!("Bucket '{}' already exists", self.config.bucket_name);
            return Ok(());
        }

        warn!("Bucket '{}' does not exist, creating it", self.config.bucket_name);

        let make_bucket_args = MakeBucketArgs::new(&self.config.bucket_name)
            .map_err(|e| {
                error!("Failed to create make bucket args: {}", e);
                MinioError::InvalidArguments(e.to_string())
            })?;

        self.client.make_bucket(&make_bucket_args).await
            .map_err(|e| {
                error!("Failed to create bucket '{}': {}", self.config.bucket_name, e);
                MinioError::OperationError(format!("Bucket creation failed: {}", e))
            })?;

        info!("Successfully created bucket '{}'", self.config.bucket_name);
        Ok(())
    }

    /// Upload an object to MinIO
    #[instrument(skip(self, data), fields(object_name = %object_name, size = data.len()))]
    pub async fn put_object(
        &self,
        object_name: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(), MinioError> {
        info!("Uploading object '{}' to bucket '{}'", object_name, self.config.bucket_name);
        debug!("Object size: {} bytes", data.len());

        // Clone what is needed for the blocking task
        let bucket_name = self.config.bucket_name.clone();
        let object_name_owned = object_name.to_string();
        let client = self.client.clone();
        let content_type_owned = content_type.map(|ct| ct.to_string());

        tokio::task::spawn_blocking(move || {
            let mut reader = Cursor::new(data);
            let data_len = reader.get_ref().len();

            // Keep the content_type String alive for the duration of args
            let ct_holder = content_type_owned;

            let mut args = PutObjectArgs::new(
                &bucket_name,
                &object_name_owned,
                &mut reader,
                Some(data_len),
                None,
            ).map_err(|e| {
                MinioError::InvalidArguments(e.to_string())
            })?;

            if let Some(ref ct) = ct_holder {
                args.content_type = ct;
            }

            // This is a blocking call
            futures::executor::block_on(client.put_object(&mut args))
                .map_err(|e| MinioError::OperationError(format!("Upload failed: {}", e)))?;

            info!("Successfully uploaded object '{}'", &object_name_owned);
            Ok(())
        })
        .await
        .map_err(|e| {
            error!("Failed to join blocking task for put_object: {}", e);
            MinioError::OperationError(format!("Join error: {}", e))
        })??;
        Ok(())
    }

    /// Download an object from MinIO
    #[instrument(skip(self), fields(object_name = %object_name))]
    pub async fn get_object(&self, object_name: &str) -> Result<Bytes, MinioError> {
        info!("Downloading object '{}' from bucket '{}'", object_name, self.config.bucket_name);

        let args = GetObjectArgs::new(&self.config.bucket_name, object_name)
            .map_err(|e| {
                error!("Failed to create get object args: {}", e);
                MinioError::InvalidArguments(e.to_string())
            })?;

        let response = self.client.get_object(&args).await
            .map_err(|e| {
                error!("Failed to get object '{}': {}", object_name, e);
                MinioError::OperationError(format!("Download failed: {}", e))
            })?;

        let bytes = response.bytes().await
            .map_err(|e| {
                error!("Failed to read object data: {}", e);
                MinioError::OperationError(format!("Read failed: {}", e))
            })?;

        debug!("Downloaded object '{}' ({} bytes)", object_name, bytes.len());
        info!("Successfully downloaded object '{}'", object_name);

        Ok(bytes)
    }

    /// Get object metadata/stats
    #[instrument(skip(self), fields(object_name = %object_name))]
    pub async fn stat_object(&self, object_name: &str) -> Result<ObjectInfo, MinioError> {
        info!("Getting stats for object '{}' in bucket '{}'", object_name, self.config.bucket_name);

        let args = StatObjectArgs::new(&self.config.bucket_name, object_name)
            .map_err(|e| {
                error!("Failed to create stat object args: {}", e);
                MinioError::InvalidArguments(e.to_string())
            })?;

        let stat = self.client.stat_object(&args).await
            .map_err(|e| {
                error!("Failed to get object stats for '{}': {}", object_name, e);
                MinioError::OperationError(format!("Stat failed: {}", e))
            })?;

        let object_info = ObjectInfo {
            name: object_name.to_string(),
            size: stat.size as i64,
            etag: stat.etag,
            last_modified: stat.last_modified.map(|dt| {
                time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
                    .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
            }),
            content_type: "application/octet-stream".to_string(), // Default since not available in response
        };

        debug!("Object stats: {:?}", object_info);
        info!("Successfully retrieved stats for object '{}'", object_name);

        Ok(object_info)
    }

    /// Delete an object from MinIO
    #[instrument(skip(self), fields(object_name = %object_name))]
    pub async fn remove_object(&self, object_name: &str) -> Result<(), MinioError> {
        info!("Deleting object '{}' from bucket '{}'", object_name, self.config.bucket_name);

        let args = RemoveObjectArgs::new(&self.config.bucket_name, object_name)
            .map_err(|e| {
                error!("Failed to create remove object args: {}", e);
                MinioError::InvalidArguments(e.to_string())
            })?;

        self.client.remove_object(&args).await
            .map_err(|e| {
                error!("Failed to delete object '{}': {}", object_name, e);
                MinioError::OperationError(format!("Delete failed: {}", e))
            })?;

        info!("Successfully deleted object '{}'", object_name);
        Ok(())
    }

    /// Check if an object exists
    #[instrument(skip(self), fields(object_name = %object_name))]
    pub async fn object_exists(&self, object_name: &str) -> Result<bool, MinioError> {
        debug!("Checking if object '{}' exists in bucket '{}'", object_name, self.config.bucket_name);

        match self.stat_object(object_name).await {
            Ok(_) => {
                debug!("Object '{}' exists", object_name);
                Ok(true)
            }
            Err(MinioError::OperationError(_)) => {
                debug!("Object '{}' does not exist", object_name);
                Ok(false)
            }
            Err(e) => {
                error!("Error checking if object '{}' exists: {}", object_name, e);
                Err(e)
            }
        }
    }

    /// Get the configuration used by this service
    pub fn get_config(&self) -> &MinioConfig {
        &self.config
    }

    /// Generate a presigned URL for an object (placeholder implementation)
    #[instrument(skip(self), fields(object_name = %object_name, expires_in_secs = expires_in_secs))]
    pub async fn generate_presigned_url(
        &self,
        object_name: &str,
        expires_in_secs: u32,
    ) -> Result<String, MinioError> {
        info!(
            "Generating presigned URL for object '{}' with expiry {} seconds",
            object_name, expires_in_secs
        );
        warn!("Presigned URL generation is not yet implemented in this version");
        Err(MinioError::OperationError(
            "Presigned URL generation not implemented".to_string(),
        ))
    }

    /// Generate a public download link for an object (not secure, just a direct link)
    pub fn generate_download_link(&self, base_url: &str, bucket_name: &str, object_name: &str) -> String {
        format!(
            "{}/{}/{}",
            base_url.trim_end_matches('/'),
            bucket_name,
            object_name
        )
    }
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub name: String,
    pub size: i64,
    pub etag: String,
    pub last_modified: Option<time::OffsetDateTime>,
    pub content_type: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MinioError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Operation error: {0}")]
    OperationError(String),

    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),

    #[error("Object not found: {0}")]
    ObjectNotFound(String),
}
