use crate::server::{
    errors::ServerError,
    health::perform_health_checks,
    models::*,
    state::AppState,
    utils::*,
};
use crate::shared::age::{decrypt_with_age_private_key, encrypt_with_age_timeout, generate_temp_age_key_pair, is_valid_age_public_key, AgeError};
use crate::sops::*;
use crate::shared::secure_secret::{SecureSecret};
use crate::server::docker::validate_docker_client_for_request;

use axum::response::Response;
use axum::{extract::{ConnectInfo, Path, State}, http::StatusCode, response::IntoResponse, Json, Router};
use log::{debug, error, info, warn};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use std::time::Duration;
use crate::shared::file_lock::FileLock;

/// Health check endpoint
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Response {
    info!("Health check endpoint called");
    let timeout = std::time::Duration::from_secs(state.server_config.health_check_timeout_seconds());
    debug!("Health check timeout: {:?}", timeout);

    // Perform health checks with timeout
    debug!("Starting health checks with timeout...");
    let checks = tokio::time::timeout(timeout, perform_health_checks(&state)).await
        .unwrap_or_else(|_| {
            warn!("Health checks timed out after {:?}", timeout);
            HealthChecks {
                sops_wrapper: false,
                master_key: false,
                docker_api: false,
                secrets_directory: false,
                sops_file: false,
            }
        });

    // Only fail if one of the critical checks is false
    let status = checks.sops_wrapper && checks.docker_api && checks.secrets_directory;
    debug!("Critical checks breakdown: sops_wrapper={}, docker_api={}, secrets_directory={}", 
              checks.sops_wrapper, checks.docker_api, checks.secrets_directory);

    let timestamp = chrono::Utc::now().to_rfc3339();
    let response_status = if status { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR };

    (
        response_status,
        Json(HealthResponse {
            timestamp,
            checks,
        })
    ).into_response()
}

/// Get a secret by name with authorization and client encryption
pub async fn get_secret_handler(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<GetSecretRequest>,
) -> Response {
    let client_ip = addr.ip();

    debug!("Processing get_secret request: secret='{}', client_ip={}", secret_name, client_ip);
    debug!("Request headers: {:?}", headers.keys().collect::<Vec<_>>());

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_rate_limit(client_ip).await {
        warn!("Rate limit exceeded for client {}: {:?}", client_ip, e);
        return e.into_response();
    }

    // Validate age public key
    if !is_valid_age_public_key(&request.public_key) {
        warn!("Invalid age public key provided: {}", request.public_key);
        return ServerError::InvalidPublicKey.into_response();
    }

    // Use DockerValidationOptions from server config
    let validation_options = state.server_config.docker_validation();
    // Get client name from Docker
    let container_info = match validate_docker_client_for_request(&state.ip_cache, &state.docker_client, &client_ip, &headers, validation_options).await {
        Ok(info) => {
            debug!("Client validation successful: container={}, image={}", info.name, info.image);
            debug!("Container details: state={}, networks={:?}", info.state, info.networks.keys().collect::<Vec<_>>());
            info
        }
        Err(e) => {
            error!("Client validation failed for IP {}: {:?}", client_ip, e);
            return ServerError::DockerApi(format!("Docker validation failed: {}", e)).into_response();
        }
    };


    // Get secret value using the public API (which now handles all validation and authorization)
    let secret_value = match get_secret(
        &state.sops_client, 
        &secret_name, 
        &container_info.image_name_no_version, 
        Some(Duration::from_secs(state.server_config.sops_timeout_seconds()))
    ).await {
        Ok(secret) => {
            debug!("Secret value retrieved successfully: secret='{}', value_length={}", secret_name, secret.expose_secret().len());
            secret.expose_secret().to_string()
        }
        Err(e) => {
            error!("Failed to get secret value for '{}': {:?}", secret_name, e);
            return ServerError::Sops(e).into_response();
        }
    };

    // Create secrets directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(state.server_config.secrets_dir()) {
        error!("Failed to create secrets directory '{}': {}", state.server_config.secrets_dir().display(), e);
        return ServerError::FileSystem(format!("Failed to create secrets directory: {}", e))
            .into_response();
    }

    // Generate unique file name
    let file_name = format!("{}_{}.age", secret_name, Uuid::new_v4());
    let file_path = PathBuf::from(state.server_config.secrets_dir()).join(&file_name);
    debug!("Generated file path: {}", file_path.display());

    // Hash the data for security purposes
    let file_hash = calculate_secret_hash(&secret_value);
    debug!("Generated file hash: {}", file_hash);

    // Encrypt secret with client's public key
    let encrypted_data = match encrypt_with_age_timeout(
        &request.public_key,
        &secret_value,
        state.server_config.age_timeout_seconds(),
    ).await {
        Ok(data) => {
            info!("Secret encrypted successfully, data length: {}", data.len());
            data
        }
        Err(e) => {
            error!("Failed to encrypt secret: {:?}", e);
            return e.into_response();
        }
    };

    // Write encrypted data to file
    let mut file = match fs::File::create(&file_path) {
        Ok(file) => {
            debug!("Created secret file: {}", file_path.display());
            file
        }
        Err(e) => {
            error!("Failed to create secret file '{}': {}", file_path.display(), e);
            return ServerError::FileSystem(format!("Failed to create secret file: {}", e))
                .into_response();
        }
    };

    if let Err(e) = file.write_all(&encrypted_data) {
        error!("Failed to write encrypted data to file '{}': {}", file_path.display(), e);
        return ServerError::FileSystem(format!("Failed to write secret file: {}", e))
            .into_response();
    }

    #[cfg(unix)]
    {
        // Set restrictive file permissions (owner read/write only)
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = file.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            if let Err(e) = fs::set_permissions(&file_path, perms) {
                error!("Failed to set file permissions on '{}': {}", file_path.display(), e);
                return ServerError::FileSystem(format!("Failed to set file permissions: {}", e))
                    .into_response();
            }
        }
    }

    // Note: SecureSecret automatically zeroizes on drop

    // Schedule cleanup of the encrypted file for when the timeout occurs
    let timeout_seconds = state.server_config.get_secret_file_cleanup_timeout();
    
    // Avoid cloning by using reference to file_path
    if let Ok(abs_path) = file_path.canonicalize() {
        info!("Scheduling file cleanup: {} (timeout: {}s)", abs_path.display(), timeout_seconds);
        state.file_cleanup.add_file(abs_path, Duration::from_secs(timeout_seconds)).await;
    } else {
        error!("Failed to canonicalize file path for cleanup: {}", file_path.display());
        eprintln!("⚠️  Failed to canonicalize file path for cleanup: {}", file_path.display());
    }

    info!("Get secret request completed successfully: secret='{}', file='{}'", secret_name, file_name);

    (StatusCode::OK, Json(
        SecretResponse {
            file_path: file_name,
            timeout_seconds,
            secret_hash: file_hash,
        }
    )).into_response()
}

/// Helper function to validate write permissions for a secret
async fn validate_write_permission(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    timeout_seconds: u64,
) -> Result<bool, ServerError> {
    let timeout_duration = Some(Duration::from_secs(timeout_seconds));

    // Check if secret exists first
    let secret_exists = match secret_exists(sops_client, secret_name, timeout_duration).await {
        Ok(exists) => {
            if exists {
                info!("Secret '{}' exists, checking write permission", secret_name);
            } else {
                info!("Secret '{}' does not exist, allowing creation", secret_name);
            }
            exists
        }
        Err(e) => {
            warn!("Failed to check if secret '{}' exists: {:?}", secret_name, e);
            return Err(ServerError::Sops(e));
        }
    };

    // Only check write permission if the secret already exists
    if secret_exists {
        let can_write = match can_write(sops_client, client_name, secret_name, timeout_duration).await {
            Ok(can_write) => {
                info!("Write permission check result: client='{}', secret='{}', can_write={}", client_name, secret_name, can_write);
                can_write
            }
            Err(e) => {
                warn!("Write permission check failed for client '{}' on secret '{}': {:?}", client_name, secret_name, e);
                return Err(ServerError::Sops(e));
            }
        };

        if !can_write {
            warn!("Access denied: client '{}' not authorized to write secret '{}'", client_name, secret_name);
            return Err(ServerError::AccessDenied(
                format!("Client '{}' is not authorized to write secret '{}'", client_name, secret_name)
            ));
        }
    } else {
        info!("Allowing client '{}' to create new secret '{}'", client_name, secret_name);
    }

    Ok(true)
}

/// Write secret initiation endpoint
pub async fn write_secret_init_handler(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(_secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<WriteSecretInitRequest>,
) -> Response {
    let client_ip = addr.ip();

    info!("Processing write_secret_init request: secret='{}', client_ip={}", request.secret_name, client_ip);

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_rate_limit(client_ip).await {
        warn!("Rate limit exceeded for client {}: {:?}", client_ip, e);
        return e.into_response();
    }

    // Use DockerValidationOptions from server config
    let validation_options = state.server_config.docker_validation();

    // Get client name from Docker with enhanced validation (including header support for testing)
    let container_info = match validate_docker_client_for_request(&state.ip_cache, &state.docker_client, &client_ip, &headers, validation_options).await {
        Ok(info) => {
            info!("Client validation successful: container={}, image={}", info.name, info.image);
            info
        }
        Err(e) => {
            warn!("Client validation failed for IP {}: {:?}", client_ip, e);
            return ServerError::DockerApi(format!("Docker validation failed: {}", e)).into_response();
        }
    };


    if let Err(e) = validate_write_permission(
        &state.sops_client,
        &container_info.image_name_no_version,
        &request.secret_name,
        state.server_config.sops_timeout_seconds(),
    ).await {
        return e.into_response();
    }

    // Generate temporary age key pair
    let temp_key_pair = match generate_temp_age_key_pair(std::time::Duration::from_secs(state.server_config.age_timeout_seconds())).await {
        Ok(key_pair) => {
            info!("Generated temporary age key pair successfully");
            key_pair
        }
        Err(AgeError::Timeout) => {
            warn!("Age key pair generation timed out");
            return ServerError::AgeTimeout.into_response();
        }
        Err(e) => {
            warn!("Failed to generate temporary age key pair: {:?}", e);
            return ServerError::AgeEncryption(format!("Failed to generate temporary key pair: {}", e)).into_response();
        }
    };

    // Create secrets directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(state.server_config.secrets_dir()) {
        error!("Failed to create secrets directory '{}': {}", state.server_config.secrets_dir().display(), e);
        return ServerError::FileSystem(format!("Failed to create secrets directory: {}", e)).into_response();
    }

    // Generate a unique operation ID
    let operation_id = Uuid::new_v4().to_string();
    info!("Generated operation ID: {}", operation_id);

    // Calculate expiration time (5 minutes from now)
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0))
        .as_secs() + 300; // 5 minutes

    // Store the write operation
    let write_op = WriteOperation {
        secret_name: request.secret_name.to_string(),
        client_ip,
        public_key: temp_key_pair.public_key.to_string(),
        private_key: temp_key_pair.private_key.to_string(),
        secret_hash: request.secret_hash.to_string(),
        file_path: format!("{}.age", operation_id),
        expires_at,
    };

    let operation_key = format!("{}:{}", container_info.image_name_no_version, request.secret_name);
    state.write_operations.write().await.insert(operation_key, write_op);

    info!("Write operation stored: secret='{}', client='{}', expires_at={}", request.secret_name, container_info.image_name_no_version, expires_at);

    // Return the temporary public key and operation ID
    Json(WriteSecretInitResponse {
        public_key: temp_key_pair.public_key.to_string(),
        file_path: format!("{}.age", operation_id),
        expires_at: expires_at.to_string(),
    }).into_response()
}

/// Write secret completion endpoint
pub async fn write_secret_complete_handler(
    State(state): State<Arc<AppState>>,
    Path(secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let client_ip = addr.ip();

    info!("Processing write_secret_complete request: secret='{}', client_ip={}", secret_name, client_ip);

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_rate_limit(client_ip).await {
        warn!("Rate limit exceeded for client {}: {:?}", client_ip, e);
        return e.into_response();
    }

    // Use DockerValidationOptions from server config
    let validation_options = state.server_config.docker_validation();
    // Get client name from Docker with enhanced validation (including header support for testing)
    let container_info = match validate_docker_client_for_request(&state.ip_cache, &state.docker_client, &client_ip, &headers, validation_options).await {
        Ok(info) => {
            info!("Client validation successful: container={}, image={}", info.name, info.image);
            info
        }
        Err(e) => {
            warn!("Client validation failed for IP {}: {:?}", client_ip, e);
            return ServerError::DockerApi(format!("Docker validation failed: {}", e)).into_response();
        }
    };

    // Find the write operation for this client and secret
    let operation_key = format!("{}:{}", container_info.image_name_no_version, secret_name);
    let write_ops = state.write_operations.read().await;

    if !write_ops.contains_key(&operation_key) {
        warn!("Write operation not found: no active operation for client '{}' and secret '{}'", container_info.image_name_no_version, secret_name);
        return ServerError::WriteOperationNotFound.into_response();
    }

    let operation = write_ops.get(&operation_key).unwrap();
    info!("Found write operation: secret='{}', client='{}', expires_at={}", operation.secret_name, container_info.image_name_no_version, operation.expires_at);

    // Check if operation has expired
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_secs();
    if current_time > operation.expires_at {
        warn!("Write operation expired: secret='{}', client='{}', current_time={}, expires_at={}", secret_name, container_info.image_name_no_version, current_time, operation.expires_at);
        // Remove expired operation
        let mut write_ops = state.write_operations.write().await;

        write_ops.retain(|_, op| op.secret_name != secret_name || op.client_ip != client_ip);
        return ServerError::WriteOperationExpired.into_response();
    }

    // Read the encrypted file
    let encrypted_file_path = PathBuf::from(state.server_config.secrets_dir()).join(&operation.file_path);
    let encrypted_data = if encrypted_file_path.exists() {
        // Try to canonicalize if file exists
        match encrypted_file_path.canonicalize() {
            Ok(path) => {
                info!("Reading encrypted file: {}", path.display());
                
                match tokio::fs::read(&path).await {
                    Ok(data) => {
                        info!("Encrypted file read successfully, data length: {}", data.len());
                        data
                    }
                    Err(e) => {
                        warn!("Failed to read encrypted file '{}': {}", path.display(), e);
                        return ServerError::FileSystem(format!("Failed to read encrypted file: {}", e)).into_response();
                    }
                }
            }
            Err(e) => {
                warn!("Failed to canonicalize file path '{}': {}, trying original path", encrypted_file_path.display(), e);
                // Fall back to reading the original path
                match tokio::fs::read(&encrypted_file_path).await {
                    Ok(data) => {
                        info!("Encrypted file read successfully using original path, data length: {}", data.len());
                        data
                    }
                    Err(e) => {
                        warn!("Failed to read encrypted file '{}': {}", encrypted_file_path.display(), e);
                        return ServerError::FileSystem(format!("Failed to read encrypted file: {}", e)).into_response();
                    }
                }
            }
        }
    } else {
        // File doesn't exist, try to read it anyway (might be a symlink or other issue)
        match tokio::fs::read(&encrypted_file_path).await {
            Ok(data) => {
                info!("Encrypted file read successfully, data length: {}", data.len());
                data
            }
            Err(e) => {
                warn!("Failed to read encrypted file '{}': {}", encrypted_file_path.display(), e);
                return ServerError::FileSystem(format!("Failed to read encrypted file: {}", e)).into_response();
            }
        }
    };

    let decrypted_secret = match decrypt_with_age_private_key(&operation.private_key, &encrypted_data, Duration::from_secs(state.server_config.age_timeout_seconds())).await {
        Ok(secret) => {
            info!("Secret decrypted successfully, length: {}", secret.len());
            secret
        }
        Err(AgeError::Timeout) => {
            warn!("Age decryption timed out");
            return ServerError::AgeTimeout.into_response();
        }
        Err(e) => {
            warn!("Failed to decrypt secret: {:?}", e);
            return ServerError::AgeEncryption(format!("Failed to decrypt secret: {}", e)).into_response();
        }
    };

    // Create secure wrapper for the decrypted secret
    let secure_secret = SecureSecret::new(decrypted_secret);

    // Validate secret hash using constant-time comparison
    if !secure_secret.verify_hash(&operation.secret_hash) {
        warn!("Hash mismatch: provided hash does not match calculated hash");
        return ServerError::HashMismatch.into_response();
    }

    info!("Hash validation passed");

    // Use the enhanced set_secret function that handles all authorization internally
    // First check if secret exists to determine operation type
    let secret_exists = match secret_exists(&state.sops_client, &secret_name, Some(Duration::from_secs(state.server_config.sops_timeout_seconds()))).await {
        Ok(exists) => exists,
        Err(e) => {
            warn!("Failed to check if secret exists: {:?}", e);
            // Assume it doesn't exist if we can't check
            return ServerError::Sops(e).into_response();
        }
    };

    let result = set_secret(
        &state.sops_client,
        &secret_name,
        secure_secret.expose_secret(),
        &container_info.image_name_no_version,
        Some(Duration::from_secs(state.server_config.sops_timeout_seconds()))
    ).await;
    
    match result {
        Ok(_) => {
            let operation_type = if secret_exists { "updated" } else { "created" };
            info!("Write secret completion successful: secret='{}' ({})", secret_name, operation_type);
            (StatusCode::OK, Json(
                WriteSecretCompleteResponse {
                    status: operation_type.to_string(),
                    message: operation_type.to_string(),
                }
            )).into_response()
        }
        Err(e) => {
            warn!("Write secret completion failed: secret='{}', error={:?}", secret_name, e);
            ServerError::Sops(e).into_response()
        }
    }
}

/// Create the router with all endpoints
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/secret/{secret_name}", axum::routing::post(get_secret_handler))
        .route("/secret/{secret_name}/write/init", axum::routing::post(write_secret_init_handler))
        .route("/secret/{secret_name}/write/complete", axum::routing::post(write_secret_complete_handler))
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1MB limit
}
