use bytes::Bytes;
use dotenv::dotenv;
use elhaiba_backend::config::MinioConfig;
use elhaiba_backend::util::minio::MinioService;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize tracing with detailed logging
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("debug"));
    
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_level(true)
        .with_ansi(true)
        .init();

    info!("🚀 Starting Elhaiba Backend MinIO Test Application");

    // Load environment variables from .env file
    match dotenv() {
        Ok(_) => info!("✅ Successfully loaded .env file"),
        Err(e) => warn!("⚠️ Failed to load .env file: {} (using system env vars)", e),
    }

    // Test MinIO configuration loading
    info!("📋 Testing MinIO configuration loading...");
    let minio_config = match MinioConfig::from_env() {
        Ok(config) => {
            info!("✅ MinIO configuration loaded successfully");
            config
        }
        Err(e) => {
            error!("❌ Failed to load MinIO configuration: {}", e);
            warn!("🔄 Using default configuration for testing");
            MinioConfig::default()
        }
    };

    // Validate the configuration
    info!("🔍 Validating MinIO configuration...");
    if let Err(e) = minio_config.validate() {
        error!("❌ MinIO configuration validation failed: {}", e);
        return;
    }
    info!("✅ MinIO configuration validation passed");

    // Initialize MinIO service
    info!("🔧 Initializing MinIO service...");
    let minio_service = match MinioService::new(minio_config).await {
        Ok(service) => {
            info!("✅ MinIO service initialized successfully");
            service
        }
        Err(e) => {
            error!("❌ Failed to initialize MinIO service: {}", e);
            warn!("💡 Make sure MinIO server is running on the configured endpoint");
            info!("🐳 You can start MinIO with Docker:");
            info!("   docker run -p 9000:9000 -p 9001:9001 minio/minio server /data --console-address ':9001'");
            return;
        }
    };

    // Test file operations
    info!("📁 Testing MinIO file operations...");
    
    // Test 1: Upload a file
    let test_content = "Hello, MinIO! This is a test file created by Elhaiba Backend.";
    let test_data = Bytes::from(test_content);
    let test_filename = "test-file.txt";
    
    info!("⬆️ Testing file upload...");
    match minio_service.put_object(test_filename, test_data.clone(), Some("text/plain")).await {
        Ok(_) => info!("✅ File upload successful"),
        Err(e) => {
            error!("❌ File upload failed: {}", e);
            return;
        }
    }

    // Test 2: Check if file exists
    info!("🔍 Testing file existence check...");
    match minio_service.object_exists(test_filename).await {
        Ok(exists) => {
            if exists {
                info!("✅ File existence check passed - file exists");
            } else {
                error!("❌ File existence check failed - file should exist");
                return;
            }
        }
        Err(e) => {
            error!("❌ File existence check error: {}", e);
            return;
        }
    }

    // Test 3: Get file metadata
    info!("📊 Testing file metadata retrieval...");
    match minio_service.stat_object(test_filename).await {
        Ok(object_info) => {
            info!("✅ File metadata retrieved successfully:");
            info!("   📄 Name: {}", object_info.name);
            info!("   📏 Size: {} bytes", object_info.size);
            info!("   🔖 ETag: {}", object_info.etag);
            info!("   📅 Last Modified: {:?}", object_info.last_modified);
            info!("   🏷️ Content Type: {}", object_info.content_type);
        }
        Err(e) => {
            error!("❌ File metadata retrieval failed: {}", e);
            return;
        }
    }

    // Test 4: Download the file
    info!("⬇️ Testing file download...");
    match minio_service.get_object(test_filename).await {
        Ok(downloaded_data) => {
            let downloaded_content = String::from_utf8_lossy(&downloaded_data);
            if downloaded_content == test_content {
                info!("✅ File download successful - content matches");
                info!("   📄 Downloaded content: '{}'", downloaded_content);
            } else {
                error!("❌ File download failed - content mismatch");
                error!("   Expected: '{}'", test_content);
                error!("   Got: '{}'", downloaded_content);
                return;
            }
        }
        Err(e) => {
            error!("❌ File download failed: {}", e);
            return;
        }
    }

    // Test 5: Upload another file with different content type
    let json_content = r#"{"message": "Hello from Elhaiba Backend", "timestamp": "2025-01-20T12:00:00Z"}"#;
    let json_data = Bytes::from(json_content);
    let json_filename = "test-data.json";
    
    info!("⬆️ Testing JSON file upload...");
    match minio_service.put_object(json_filename, json_data, Some("application/json")).await {
        Ok(_) => info!("✅ JSON file upload successful"),
        Err(e) => {
            error!("❌ JSON file upload failed: {}", e);
            return;
        }
    }

    // Test 6: Test non-existent file
    info!("🔍 Testing non-existent file check...");
    let non_existent_file = "this-file-does-not-exist.txt";
    match minio_service.object_exists(non_existent_file).await {
        Ok(exists) => {
            if !exists {
                info!("✅ Non-existent file check passed - file doesn't exist");
            } else {
                warn!("⚠️ Non-existent file check unexpected - file shouldn't exist");
            }
        }
        Err(e) => {
            error!("❌ Non-existent file check error: {}", e);
        }
    }

    // Test 7: Clean up - delete test files
    info!("🧹 Cleaning up test files...");
    
    for filename in &[test_filename, json_filename] {
        info!("🗑️ Deleting file: {}", filename);
        match minio_service.remove_object(filename).await {
            Ok(_) => info!("✅ File '{}' deleted successfully", filename),
            Err(e) => error!("❌ Failed to delete file '{}': {}", filename, e),
        }
    }

    // Final verification - check if files are deleted
    info!("🔍 Verifying file deletion...");
    for filename in &[test_filename, json_filename] {
        match minio_service.object_exists(filename).await {
            Ok(exists) => {
                if !exists {
                    info!("✅ File '{}' successfully deleted", filename);
                } else {
                    warn!("⚠️ File '{}' still exists after deletion", filename);
                }
            }
            Err(e) => error!("❌ Error checking if file '{}' was deleted: {}", filename, e),
        }
    }

    info!("🎉 MinIO test suite completed successfully!");
    info!("🔧 MinIO service configuration:");
    let config = minio_service.get_config();
    info!("   🌐 Endpoint: {}", config.get_endpoint_url());
    info!("   🪣 Bucket: {}", config.bucket_name);
    info!("   🔐 Secure: {}", config.secure);
    info!("   🌍 Region: {:?}", config.region);

    info!("👋 Application finished successfully");
}
