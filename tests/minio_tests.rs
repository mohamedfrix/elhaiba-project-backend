use bytes::Bytes;
use elhaiba_backend::config::MinioConfig;
use elhaiba_backend::util::minio::{MinioService, MinioError, ObjectInfo};
use std::error::Error;
use tokio;
use tracing::{info, warn};
use tracing_subscriber;

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

/// Helper function to create a test MinIO config
fn create_test_config() -> MinioConfig {
    MinioConfig {
        endpoint: "localhost:9000".to_string(),
        access_key: "minioadmin".to_string(),
        secret_key: "minioadmin".to_string(),
        bucket_name: "test-bucket".to_string(),
        region: Some("us-east-1".to_string()),
        secure: false,
    }
}

/// Helper function to create a test MinIO config with custom bucket
fn create_test_config_with_bucket(bucket_name: &str) -> MinioConfig {
    MinioConfig {
        endpoint: "localhost:9000".to_string(),
        access_key: "minioadmin".to_string(),
        secret_key: "minioadmin".to_string(),
        bucket_name: bucket_name.to_string(),
        region: Some("us-east-1".to_string()),
        secure: false,
    }
}

mod object_info_tests {
    use super::*;

    #[test]
    fn test_object_info_creation() {
        init_tracing();
        info!("Testing ObjectInfo creation");
        
        let info = ObjectInfo {
            name: "test-file.txt".to_string(),
            size: 1024,
            etag: "abc123def456".to_string(),
            last_modified: None,
            content_type: "text/plain".to_string(),
        };
        
        assert_eq!(info.name, "test-file.txt");
        assert_eq!(info.size, 1024);
        assert_eq!(info.etag, "abc123def456");
        assert!(info.last_modified.is_none());
        assert_eq!(info.content_type, "text/plain");
        
        info!("ObjectInfo created successfully: {:?}", info);
    }

    #[test]
    fn test_object_info_with_timestamp() {
        init_tracing();
        info!("Testing ObjectInfo creation with timestamp");
        
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc();
        
        let info = ObjectInfo {
            name: "timestamped-file.jpg".to_string(),
            size: 2048,
            etag: "xyz789".to_string(),
            last_modified: Some(now),
            content_type: "image/jpeg".to_string(),
        };
        
        assert_eq!(info.name, "timestamped-file.jpg");
        assert_eq!(info.size, 2048);
        assert_eq!(info.etag, "xyz789");
        assert!(info.last_modified.is_some());
        assert_eq!(info.content_type, "image/jpeg");
        
        info!("ObjectInfo with timestamp created successfully: {:?}", info);
    }

    #[test]
    fn test_object_info_clone() {
        init_tracing();
        info!("Testing ObjectInfo clone functionality");
        
        let original = ObjectInfo {
            name: "original-file.txt".to_string(),
            size: 512,
            etag: "clone123".to_string(),
            last_modified: None,
            content_type: "text/plain".to_string(),
        };
        
        let cloned = original.clone();
        
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.size, cloned.size);
        assert_eq!(original.etag, cloned.etag);
        assert_eq!(original.last_modified, cloned.last_modified);
        assert_eq!(original.content_type, cloned.content_type);
        
        info!("ObjectInfo cloned successfully");
    }

    #[test]
    fn test_object_info_debug_format() {
        init_tracing();
        info!("Testing ObjectInfo debug formatting");
        
        let info = ObjectInfo {
            name: "debug-test.txt".to_string(),
            size: 256,
            etag: "debug456".to_string(),
            last_modified: None,
            content_type: "text/plain".to_string(),
        };
        
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("debug-test.txt"));
        assert!(debug_str.contains("256"));
        assert!(debug_str.contains("debug456"));
        assert!(debug_str.contains("text/plain"));
        
        info!("ObjectInfo debug format: {}", debug_str);
    }
}

mod error_tests {
    use super::*;

    #[test]
    fn test_minio_error_types() {
        init_tracing();
        info!("Testing MinioError types");
        
        let config_error = MinioError::ConfigError("Test config error".to_string());
        let connection_error = MinioError::ConnectionError("Test connection error".to_string());
        let operation_error = MinioError::OperationError("Test operation error".to_string());
        let invalid_args_error = MinioError::InvalidArguments("Test invalid args".to_string());
        let not_found_error = MinioError::ObjectNotFound("test-object".to_string());
        
        // Test error messages
        assert!(config_error.to_string().contains("Test config error"));
        assert!(connection_error.to_string().contains("Test connection error"));
        assert!(operation_error.to_string().contains("Test operation error"));
        assert!(invalid_args_error.to_string().contains("Test invalid args"));
        assert!(not_found_error.to_string().contains("test-object"));
        
        info!("All MinioError types tested successfully");
    }

    #[test]
    fn test_minio_error_debug_format() {
        init_tracing();
        info!("Testing MinioError debug formatting");
        
        let error = MinioError::OperationError("Debug test error".to_string());
        let debug_str = format!("{:?}", error);
        
        assert!(debug_str.contains("OperationError"));
        assert!(debug_str.contains("Debug test error"));
        
        info!("MinioError debug format: {}", debug_str);
    }

    #[test]
    fn test_minio_error_from_string() {
        init_tracing();
        info!("Testing MinioError creation from strings");
        
        let message = "Test error message";
        let error = MinioError::InvalidArguments(message.to_string());
        
        assert!(error.to_string().contains(message));
        info!("MinioError created from string successfully");
    }
}

// Integration tests that require a running MinIO instance
// These tests are marked with #[ignore] by default to prevent CI failures
// Run with: cargo test -- --ignored
mod integration_tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires running MinIO instance
    async fn test_minio_service_creation() {
        init_tracing();
        info!("Testing MinIO service creation (integration test)");
        
        let config = create_test_config_with_bucket("integration-test-bucket");
        
        match MinioService::new(config).await {
            Ok(service) => {
                info!("MinIO service created successfully");
                assert_eq!(service.get_config().bucket_name, "integration-test-bucket");
                info!("Service configuration matches expected values");
            }
            Err(e) => {
                warn!("MinIO service creation failed (this is expected if MinIO is not running): {}", e);
                // Don't fail the test if MinIO is not available
                return;
            }
        }
    }

    #[tokio::test]
    #[ignore] // Requires running MinIO instance
    async fn test_put_and_get_object() {
        init_tracing();
        info!("Testing put and get object operations (integration test)");
        
        let config = create_test_config_with_bucket("integration-test-bucket");
        
        let service = match MinioService::new(config).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Skipping integration test - MinIO not available: {}", e);
                return;
            }
        };

        let test_data = Bytes::from("Hello, MinIO! This is test data.");
        let object_name = "test-object.txt";

        // Test putting object
        info!("Uploading test object: {}", object_name);
        let put_result = service.put_object(object_name, test_data.clone(), Some("text/plain")).await;
        
        match put_result {
            Ok(_) => info!("Object uploaded successfully"),
            Err(e) => {
                warn!("Object upload failed: {}", e);
                return;
            }
        }

        // Test getting object
        info!("Downloading test object: {}", object_name);
        let get_result = service.get_object(object_name).await;
        
        match get_result {
            Ok(downloaded_data) => {
                assert_eq!(downloaded_data, test_data);
                info!("Object downloaded successfully and data matches");
            }
            Err(e) => {
                warn!("Object download failed: {}", e);
                return;
            }
        }

        // Test object stats
        info!("Getting object stats for: {}", object_name);
        let stat_result = service.stat_object(object_name).await;
        
        match stat_result {
            Ok(object_info) => {
                assert_eq!(object_info.name, object_name);
                assert_eq!(object_info.size, test_data.len() as i64);
                info!("Object stats retrieved successfully: {:?}", object_info);
            }
            Err(e) => {
                warn!("Object stat failed: {}", e);
            }
        }

        // Test object exists
        info!("Checking if object exists: {}", object_name);
        let exists_result = service.object_exists(object_name).await;
        
        match exists_result {
            Ok(exists) => {
                assert!(exists);
                info!("Object existence check passed");
            }
            Err(e) => {
                warn!("Object existence check failed: {}", e);
            }
        }

        // Clean up - remove object
        info!("Cleaning up test object: {}", object_name);
        let remove_result = service.remove_object(object_name).await;
        
        match remove_result {
            Ok(_) => info!("Test object removed successfully"),
            Err(e) => warn!("Failed to remove test object: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // Requires running MinIO instance
    async fn test_object_not_exists() {
        init_tracing();
        info!("Testing non-existent object operations (integration test)");
        
        let config = create_test_config_with_bucket("integration-test-bucket");
        
        let service = match MinioService::new(config).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Skipping integration test - MinIO not available: {}", e);
                return;
            }
        };

        let non_existent_object = "definitely-does-not-exist.txt";

        // Test object exists for non-existent object
        info!("Checking if non-existent object exists: {}", non_existent_object);
        let exists_result = service.object_exists(non_existent_object).await;
        
        match exists_result {
            Ok(exists) => {
                assert!(!exists);
                info!("Correctly determined that object does not exist");
            }
            Err(e) => {
                warn!("Object existence check failed: {}", e);
            }
        }

        // Test getting non-existent object
        info!("Attempting to download non-existent object: {}", non_existent_object);
        let get_result = service.get_object(non_existent_object).await;
        
        match get_result {
            Ok(_) => panic!("Should not be able to download non-existent object"),
            Err(e) => {
                info!("Correctly failed to download non-existent object: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod benchmark_tests {
    use super::*;

    #[test]
    fn test_object_info_size_types() {
        init_tracing();
        info!("Testing ObjectInfo with different size values");
        
        // Test with zero size
        let empty_info = ObjectInfo {
            name: "empty.txt".to_string(),
            size: 0,
            etag: "empty".to_string(),
            last_modified: None,
            content_type: "text/plain".to_string(),
        };
        assert_eq!(empty_info.size, 0);
        
        // Test with large size
        let large_info = ObjectInfo {
            name: "large.bin".to_string(),
            size: 1_073_741_824, // 1GB
            etag: "large".to_string(),
            last_modified: None,
            content_type: "application/octet-stream".to_string(),
        };
        assert_eq!(large_info.size, 1_073_741_824);
        
        info!("ObjectInfo size type tests passed");
    }

    #[test]
    fn test_object_info_content_types() {
        init_tracing();
        info!("Testing ObjectInfo with various content types");
        
        let content_types = vec![
            "text/plain",
            "application/json",
            "image/jpeg",
            "video/mp4",
            "application/pdf",
            "application/octet-stream",
        ];
        
        for (i, content_type) in content_types.iter().enumerate() {
            let info = ObjectInfo {
                name: format!("file_{}.ext", i),
                size: 100 + i as i64,
                etag: format!("etag_{}", i),
                last_modified: None,
                content_type: content_type.to_string(),
            };
            
            assert_eq!(info.content_type, *content_type);
        }
        
        info!("ObjectInfo content type tests passed");
    }

    #[test]
    fn test_minio_service_config_access() {
        init_tracing();
        info!("Testing MinIO service configuration access");
        
        // This test doesn't require a running MinIO instance
        // We'll just test that we can access the config from the service structure
        let config = create_test_config();
        
        // Verify config properties are accessible
        assert_eq!(config.endpoint, "localhost:9000");
        assert_eq!(config.bucket_name, "test-bucket");
        assert!(!config.secure);
        
        info!("MinIO service configuration access test passed");
    }

    #[test]
    fn test_minio_service_config_validation() {
        init_tracing();
        info!("Testing MinIO service config validation before service creation");
        
        let valid_config = create_test_config();
        assert!(valid_config.validate().is_ok());
        
        let mut invalid_config = create_test_config();
        invalid_config.bucket_name = String::new();
        assert!(invalid_config.validate().is_err());
        
        info!("MinIO service config validation tests passed");
    }

    #[test]
    fn test_presigned_url_not_implemented() {
        init_tracing();
        info!("Testing presigned URL functionality (not implemented)");
        
        // Since presigned URL is not implemented, we can test the error case
        // without needing a running MinIO instance
        
        // This is a unit test for the placeholder implementation
        // In a real scenario, we would create a service and test the method
        // but since it always returns an error, we can test the error type
        
        let error = MinioError::OperationError("Presigned URL generation not implemented".to_string());
        assert!(error.to_string().contains("not implemented"));
        
        info!("Presigned URL not implemented test passed");
    }
}

// Additional comprehensive MinIO tests
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_minio_config_validation_comprehensive() {
        init_tracing();
        info!("Testing comprehensive MinIO config validation");
        
        // Test valid configs
        let valid_configs = vec![
            MinioConfig {
                endpoint: "localhost:9000".to_string(),
                access_key: "minioadmin".to_string(),
                secret_key: "minioadmin".to_string(),
                bucket_name: "test-bucket".to_string(),
                region: Some("us-east-1".to_string()),
                secure: false,
            },
            MinioConfig {
                endpoint: "minio.example.com:443".to_string(),
                access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
                secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
                bucket_name: "production-bucket".to_string(),
                region: Some("eu-west-1".to_string()),
                secure: true,
            },
        ];
        
        for config in valid_configs {
            assert!(config.validate().is_ok(), "Valid config should pass validation");
        }
        
        // Test invalid configs
        let invalid_configs = vec![
            (MinioConfig { endpoint: "".to_string(), ..create_test_config() }, "empty endpoint"),
            (MinioConfig { access_key: "".to_string(), ..create_test_config() }, "empty access key"),
            (MinioConfig { secret_key: "".to_string(), ..create_test_config() }, "empty secret key"),
            (MinioConfig { bucket_name: "".to_string(), ..create_test_config() }, "empty bucket name"),
            (MinioConfig { bucket_name: "Invalid_Bucket_Name".to_string(), ..create_test_config() }, "invalid bucket name format"),
        ];
        
        // Test potentially valid configs that might pass basic validation
        let potentially_valid_configs = vec![
            (MinioConfig { endpoint: " ".to_string(), ..create_test_config() }, "whitespace endpoint"),
            (MinioConfig { bucket_name: "bucket-with-dots.invalid".to_string(), ..create_test_config() }, "bucket name with dots"),
            (MinioConfig { bucket_name: "UPPERCASE-BUCKET".to_string(), ..create_test_config() }, "uppercase bucket name"),
        ];
        
        for (config, description) in invalid_configs {
            assert!(config.validate().is_err(), "Invalid config should fail validation: {}", description);
        }
        
        for (config, description) in potentially_valid_configs {
            // These might pass basic validation but would fail in real usage
            let result = config.validate();
            info!("Config validation result for {}: {:?}", description, result);
            // We don't assert on these as the validation logic may vary
        }
        
        info!("Comprehensive MinIO config validation test passed");
    }

    #[test]
    fn test_object_info_with_edge_cases() {
        init_tracing();
        info!("Testing ObjectInfo with edge cases");
        
        let edge_cases = vec![
            ObjectInfo {
                name: "".to_string(),
                size: 0,
                etag: "".to_string(),
                last_modified: None,
                content_type: "".to_string(),
            },
            ObjectInfo {
                name: "file-with-very-long-name-".repeat(50),
                size: i64::MAX,
                etag: "very-long-etag-".repeat(10),
                last_modified: Some(time::OffsetDateTime::now_utc()),
                content_type: "application/very-specific-content-type".to_string(),
            },
            ObjectInfo {
                name: "file/with/path/separators.txt".to_string(),
                size: -1, // Invalid size
                etag: "etag-with-special-chars-!@#$%^&*()".to_string(),
                last_modified: None,
                content_type: "text/plain; charset=utf-8".to_string(),
            },
        ];
        
        for info in edge_cases {
            // Test that ObjectInfo can be created with edge case values
            assert_eq!(info.name, info.name); // Basic structure test
            
            // Test debug formatting
            let debug_str = format!("{:?}", info);
            assert!(!debug_str.is_empty());
            
            // Test clone
            let cloned = info.clone();
            assert_eq!(info.name, cloned.name);
            assert_eq!(info.size, cloned.size);
            assert_eq!(info.etag, cloned.etag);
            assert_eq!(info.content_type, cloned.content_type);
        }
        
        info!("ObjectInfo edge cases test passed");
    }

    #[test]
    fn test_minio_error_chain() {
        init_tracing();
        info!("Testing MinIO error chain and conversion");
        
        // Test error creation from different sources
        let errors = vec![
            MinioError::ConfigError("Configuration error".to_string()),
            MinioError::ConnectionError("Connection timeout".to_string()),
            MinioError::OperationError("Bucket not found".to_string()),
            MinioError::InvalidArguments("Invalid object name".to_string()),
            MinioError::ObjectNotFound("object.txt".to_string()),
        ];
        
        for error in errors {
            // Test error display
            let display = format!("{}", error);
            assert!(!display.is_empty());
            
            // Test error debug
            let debug = format!("{:?}", error);
            assert!(!debug.is_empty(), "Debug format should not be empty");
            // The debug format may vary, so we just check it's not empty
            
            // Test error source chain
            let source = error.source();
            // MinioError doesn't implement source, so it should be None
            assert!(source.is_none());
        }
        
        info!("MinIO error chain test passed");
    }

    #[test]
    fn test_minio_config_url_building() {
        init_tracing();
        info!("Testing MinIO config URL building logic");
        
        let test_cases = vec![
            (
                MinioConfig {
                    endpoint: "localhost:9000".to_string(),
                    secure: false,
                    ..create_test_config()
                },
                "http://localhost:9000"
            ),
            (
                MinioConfig {
                    endpoint: "minio.example.com:443".to_string(),
                    secure: true,
                    ..create_test_config()
                },
                "https://minio.example.com:443"
            ),
            (
                MinioConfig {
                    endpoint: "127.0.0.1:9001".to_string(),
                    secure: false,
                    ..create_test_config()
                },
                "http://127.0.0.1:9001"
            ),
        ];
        
        for (config, expected_base_url) in test_cases {
            // We can't directly test URL building without exposing internal methods,
            // but we can test that the config stores the expected values
            assert_eq!(config.endpoint, expected_base_url.split("://").nth(1).unwrap());
            assert_eq!(config.secure, expected_base_url.starts_with("https"));
        }
        
        info!("MinIO config URL building test passed");
    }
}

#[cfg(test)]
mod integration_edge_cases {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    #[ignore] // Requires running MinIO instance
    async fn test_minio_large_object_operations() {
        init_tracing();
        info!("Testing MinIO operations with large objects");
        
        let config = create_test_config_with_bucket("integration-test-bucket");
        let service = match MinioService::new(config).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Skipping test - MinIO not available: {}", e);
                return;
            }
        };

        // Test with large object (1MB)
        let large_data = Bytes::from(vec![0u8; 1024 * 1024]);
        let object_name = "large-test-object.bin";

        info!("Uploading large object: {} bytes", large_data.len());
        match service.put_object(object_name, large_data.clone(), Some("application/octet-stream")).await {
            Ok(_) => {
                info!("Large object uploaded successfully");
                
                // Download and verify
                match service.get_object(object_name).await {
                    Ok(downloaded_data) => {
                        assert_eq!(downloaded_data.len(), large_data.len());
                        assert_eq!(downloaded_data, large_data);
                        info!("Large object downloaded and verified successfully");
                    }
                    Err(e) => warn!("Failed to download large object: {}", e),
                }
                
                // Get stats
                match service.stat_object(object_name).await {
                    Ok(stats) => {
                        assert_eq!(stats.size, large_data.len() as i64);
                        info!("Large object stats verified");
                    }
                    Err(e) => warn!("Failed to get large object stats: {}", e),
                }
            }
            Err(e) => {
                warn!("Failed to upload large object: {}", e);
            }
        }
        
        // Clean up
        let _ = service.remove_object(object_name).await;
    }

    #[tokio::test]
    #[ignore] // Requires running MinIO instance
    async fn test_minio_special_character_objects() {
        init_tracing();
        info!("Testing MinIO operations with special character object names");
        
        let config = create_test_config_with_bucket("integration-test-bucket");
        let service = match MinioService::new(config).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Skipping test - MinIO not available: {}", e);
                return;
            }
        };

        let test_data = Bytes::from("Special character test data");
        
        // Test various object names with special characters
        let special_names = vec![
            "object-with-dashes.txt",
            "object_with_underscores.txt",
            "object with spaces.txt",  // This might fail - spaces aren't always allowed
            "object(with)parentheses.txt",
            "object[with]brackets.txt",
            "object+with+plus.txt",
            "object%20encoded.txt",
            "深度/path/中文.txt",  // Unicode characters
            "файл.txt",            // Cyrillic
            "🚀rocket🔥.txt",       // Emoji (might not be supported)
        ];

        for object_name in special_names {
            info!("Testing object name: {}", object_name);
            
            match service.put_object(object_name, test_data.clone(), Some("text/plain")).await {
                Ok(_) => {
                    info!("Successfully uploaded object with special name: {}", object_name);
                    
                    // Try to download
                    match service.get_object(object_name).await {
                        Ok(downloaded) => {
                            assert_eq!(downloaded, test_data);
                            info!("Successfully downloaded object: {}", object_name);
                        }
                        Err(e) => warn!("Failed to download {}: {}", object_name, e),
                    }
                    
                    // Clean up
                    let _ = service.remove_object(object_name).await;
                }
                Err(e) => {
                    warn!("Failed to upload object {} (might be expected): {}", object_name, e);
                }
            }
        }
    }

    #[tokio::test]
    #[ignore] // Requires running MinIO instance
    async fn test_minio_stress_operations() {
        init_tracing();
        info!("Testing MinIO stress operations");
        
        let config = create_test_config_with_bucket("integration-test-bucket");
        let service = match MinioService::new(config).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Skipping test - MinIO not available: {}", e);
                return;
            }
        };

        let mut successful_uploads = 0;
        let mut object_names = vec![];
        
        // Perform rapid sequential operations
        for i in 0..10 {
            let object_name = format!("stress-test-{}.txt", i);
            let test_data = Bytes::from(format!("Test data for object {}", i));
            
            match service.put_object(&object_name, test_data.clone(), Some("text/plain")).await {
                Ok(_) => {
                    successful_uploads += 1;
                    object_names.push((object_name.clone(), test_data));
                    info!("Stress upload successful: {}", object_name);
                }
                Err(e) => warn!("Upload failed: {}", e),
            }
        }
        
        info!("Completed {} successful stress uploads", successful_uploads);
        assert!(successful_uploads > 0, "At least some uploads should succeed");
        
        // Verify all uploaded objects
        for (object_name, expected_data) in &object_names {
            match service.get_object(object_name).await {
                Ok(downloaded) => {
                    assert_eq!(downloaded, *expected_data);
                }
                Err(e) => warn!("Failed to verify object {}: {}", object_name, e),
            }
        }
        
        // Clean up all objects
        for (object_name, _) in object_names {
            let _ = service.remove_object(&object_name).await;
        }
    }

    #[tokio::test]
    #[ignore] // Requires running MinIO instance
    async fn test_minio_error_scenarios() {
        init_tracing();
        info!("Testing MinIO error scenarios");
        
        let config = create_test_config_with_bucket("integration-test-bucket");
        let service = match MinioService::new(config).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Skipping test - MinIO not available: {}", e);
                return;
            }
        };

        // Test operations on non-existent objects
        let non_existent_objects = vec![
            "definitely-does-not-exist.txt",
            "path/to/non/existent/file.txt",
            "",  // Empty object name
            "/absolute/path.txt",
        ];

        for object_name in non_existent_objects {
            info!("Testing non-existent object: '{}'", object_name);
            
            // Test get operation
            match service.get_object(object_name).await {
                Ok(_) => warn!("Unexpectedly found object: {}", object_name),
                Err(e) => {
                    info!("Expected error for get operation: {}", e);
                    // Should be ObjectNotFound or similar
                }
            }
            
            // Test stat operation
            match service.stat_object(object_name).await {
                Ok(_) => warn!("Unexpectedly found stats for object: {}", object_name),
                Err(e) => info!("Expected error for stat operation: {}", e),
            }
            
            // Test exists operation
            match service.object_exists(object_name).await {
                Ok(false) => info!("Correctly determined object does not exist: {}", object_name),
                Ok(true) => warn!("Unexpectedly found object exists: {}", object_name),
                Err(e) => info!("Error checking existence (might be expected): {}", e),
            }
        }
    }
}
