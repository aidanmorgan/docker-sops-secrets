use crate::server::{
    errors::ServerError,
    health::perform_health_checks,
    models::*,
    secure_secret::SecureSecret,
    state::AppState,
    utils::*,
};
use crate::shared::age::{decrypt_with_age_private_key, generate_temp_age_key_pair, AgeError};
use crate::shared::sops::SopsError;
use axum::response::Response;
use axum::{extract::{ConnectInfo, Path, State}, http::StatusCode, response::IntoResponse, Json, Router};
use log::{debug, error, info, trace, warn};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroize;


/// Health check endpoint
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Response {
    info!("Health check endpoint called");
    let timeout = std::time::Duration::from_secs(state.server_config.health_check_timeout_seconds);
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
                age_executable: false,
                secrets_directory: false,
                sops_file: false,
            }
        });

    // Only fail if one of the critical checks is false
    let status = checks.sops_wrapper && checks.age_executable && checks.docker_api && checks.secrets_directory;
    debug!("Critical checks breakdown: sops_wrapper={}, age_executable={}, docker_api={}, secrets_directory={}", 
              checks.sops_wrapper, checks.age_executable, checks.docker_api, checks.secrets_directory);

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
pub async fn get_secret(
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
    let validation_options = &state.server_config.docker_validation;

    // Get client name from Docker
    let container_info = match validate_docker_client_for_request(&state.ip_cache, &state.docker_client, &client_ip, &headers, validation_options).await {
        Ok(info) => {
            debug!("Client validation successful: container={}, image={}", info.name, info.image);
            debug!("Container details: state={}, networks={:?}", info.state, info.networks.keys().collect::<Vec<_>>());
            info
        }
        Err(e) => {
            error!("Client validation failed for IP {}: {:?}", client_ip, e);
            return e.into_response();
        }
    };

    // Check authorization using the validated container image name (without version)
    let is_authorized = match check_read_permission_with_timeout(&state.sops_client, &container_info.image_name_no_version, &secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(authorized) => {
            debug!("Authorization check result: client='{}', secret='{}', authorized={}", container_info.image_name_no_version, secret_name, authorized);
            authorized
        }
        Err(e) => {
            error!("Authorization check failed for client '{}' on secret '{}': {:?}", container_info.image_name_no_version, secret_name, e);
            return e.into_response();
        }
    };

    if !is_authorized {
        warn!("Access denied: client '{}' not authorized to read secret '{}'", container_info.image_name_no_version, secret_name);
        return ServerError::AccessDenied(
            format!("Client '{}' is not authorized to read secret '{}'", container_info.image_name_no_version, secret_name)
        ).into_response();
    }

    // Get secret data
    let mut secret_data = match get_secret_data_with_timeout(&state.sops_client, &secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(data) => {
            debug!("Secret data retrieved successfully: secret='{}', owner='{}'", secret_name, data.owner);
            debug!("Secret metadata: readers_count={}, writers_count={}", data.readers.len(), data.writers.len());
            data
        }
        Err(e) => {
            error!("Failed to get secret data for '{}': {:?}", secret_name, e);
            return e.into_response();
        }
    };

    // Create a secure wrapper for the secret value
    let secure_secret = SecureSecret::new(secret_data.value.clone());
    let secret_value = secure_secret.expose_secret();
    debug!("Secret value length: {}", secret_value.len());

    // Create secrets directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&state.server_config.secrets_dir) {
        error!("Failed to create secrets directory '{}': {}", state.server_config.secrets_dir, e);
        return ServerError::FileSystem(format!("Failed to create secrets directory: {}", e))
            .into_response();
    }

    // Generate unique file name
    let file_name = format!("{}_{}.age", secret_name, Uuid::new_v4());
    let file_path = PathBuf::from(&state.server_config.secrets_dir).join(&file_name);
    debug!("Generated file path: {}", file_path.display());

    // Hash the data for security purposes
    let file_hash = calculate_secret_hash(secret_value);
    debug!("Generated file hash: {}", file_hash);

    // Encrypt secret with client's public key
    let encrypted_data = match encrypt_with_age_timeout(
        &state.server_config.age_executable_path,
        &request.public_key,
        secret_value,
        state.server_config.age_timeout_seconds,
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

    // Zero out the secret value from memory
    (&mut secret_data.value).zeroize();

    // Schedule cleanup of the encrypted file for when the timeout occurs
    let timeout_seconds = state.server_config.get_secret_file_cleanup_timeout;
    let file_path_clone = file_path.clone();
    let file_cleanup = state.file_cleanup.clone();
    tokio::spawn(async move {
        // Ensure the file path is absolute before adding to cleanup
        if let Ok(abs_path) = file_path_clone.canonicalize() {
            info!("Scheduling file cleanup: {} (timeout: {}s)", abs_path.display(), timeout_seconds);
            file_cleanup.add_file(abs_path, std::time::Duration::from_secs(timeout_seconds)).await;
        } else {
            error!("Failed to canonicalize file path for cleanup: {}", file_path_clone.display());
            eprintln!("⚠️  Failed to canonicalize file path for cleanup: {}", file_path_clone.display());
        }
    });

    info!("Get secret request completed successfully: secret='{}', file='{}'", secret_name, file_name);

    (StatusCode::OK, Json(
        SecretResponse {
            file_path: file_name,
            timeout_seconds,
            secret_hash: file_hash,
        }
    )).into_response()
}

/// Write secret initiation endpoint
pub async fn write_secret_init(
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
    let validation_options = &state.server_config.docker_validation;

    // Get client name from Docker with enhanced validation (including header support for testing)
    let container_info = match validate_docker_client_for_request(&state.ip_cache, &state.docker_client, &client_ip, &headers, validation_options).await {
        Ok(info) => {
            info!("Client validation successful: container={}, image={}", info.name, info.image);
            info
        }
        Err(e) => {
            warn!("Client validation failed for IP {}: {:?}", client_ip, e);
            return e.into_response();
        }
    };

    // Check if secret exists first using a more efficient method
    let secret_exists = match check_secret_exists_with_timeout(&state.sops_client, &request.secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(exists) => {
            if exists {
                info!("Secret '{}' exists, checking write permission", request.secret_name);
            } else {
                info!("Secret '{}' does not exist, allowing creation", request.secret_name);
            }
            exists
        }
        Err(e) => {
            warn!("Failed to check if secret '{}' exists: {:?}", request.secret_name, e);
            return e.into_response();
        }
    };

    // Only check write permission if the secret already exists
    if secret_exists {
        let can_write = match check_write_permission_with_timeout(&state.sops_client, &container_info.image_name_no_version, &request.secret_name, state.server_config.sops_timeout_seconds).await {
            Ok(can_write) => {
                info!("Write permission check result: client='{}', secret='{}', can_write={}", container_info.image_name_no_version, request.secret_name, can_write);
                can_write
            }
            Err(e) => {
                warn!("Write permission check failed for client '{}' on secret '{}': {:?}", container_info.image_name_no_version, request.secret_name, e);
                return e.into_response();
            }
        };

        if !can_write {
            warn!("Access denied: client '{}' not authorized to write secret '{}'", container_info.image_name_no_version, request.secret_name);
            return ServerError::AccessDenied(
                format!("Client '{}' is not authorized to write secret '{}'", container_info.image_name_no_version, request.secret_name)
            ).into_response();
        }
    } else {
        info!("Allowing client '{}' to create new secret '{}'", container_info.image_name_no_version, request.secret_name);
    }

    // Generate temporary age key pair
    let temp_key_pair = match generate_temp_age_key_pair(std::time::Duration::from_secs(state.server_config.age_timeout_seconds)).await {
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
    if let Err(e) = fs::create_dir_all(&state.server_config.secrets_dir) {
        error!("Failed to create secrets directory '{}': {}", state.server_config.secrets_dir, e);
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
        secret_name: request.secret_name.clone(),
        client_ip,
        public_key: temp_key_pair.public_key.clone(),
        private_key: temp_key_pair.private_key.clone(),
        secret_hash: request.secret_hash.clone(),
        file_path: format!("{}.age", operation_id),
        expires_at,
    };

    let operation_key = format!("{}:{}", container_info.image_name_no_version, request.secret_name);
    state.write_operations.write().await.insert(operation_key, write_op);

    info!("Write operation stored: secret='{}', client='{}', expires_at={}", request.secret_name, container_info.image_name_no_version, expires_at);

    // Return the temporary public key and operation ID
    Json(WriteSecretInitResponse {
        public_key: temp_key_pair.public_key.clone(),
        file_path: format!("{}.age", operation_id),
        expires_at: expires_at.to_string(),
    }).into_response()
}

/// Write secret completion endpoint
pub async fn write_secret_complete(
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
    let validation_options = &state.server_config.docker_validation;

    // Get client name from Docker with enhanced validation (including header support for testing)
    let container_info = match validate_docker_client_for_request(&state.ip_cache, &state.docker_client, &client_ip, &headers, validation_options).await {
        Ok(info) => {
            info!("Client validation successful: container={}, image={}", info.name, info.image);
            info
        }
        Err(e) => {
            warn!("Client validation failed for IP {}: {:?}", client_ip, e);
            return e.into_response();
        }
    };

    // Check if secret exists first using a more efficient method
    let secret_exists = match check_secret_exists_with_timeout(&state.sops_client, &secret_name, state.server_config.sops_timeout_seconds).await {
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
            return e.into_response();
        }
    };

    // Only check write permission if the secret already exists
    if secret_exists {
        let can_write = match check_write_permission_with_timeout(&state.sops_client, &container_info.image_name_no_version, &secret_name, state.server_config.sops_timeout_seconds).await {
            Ok(can_write) => {
                info!("Write permission check result: client='{}', secret='{}', can_write={}", container_info.image_name_no_version, secret_name, can_write);
                can_write
            }
            Err(e) => {
                warn!("Write permission check failed for client '{}' on secret '{}': {:?}", container_info.image_name_no_version, secret_name, e);
                return e.into_response();
            }
        };

        if !can_write {
            warn!("Access denied: client '{}' not authorized to write secret '{}'", container_info.image_name_no_version, secret_name);
            return ServerError::AccessDenied(
                format!("Client '{}' is not authorized to write secret '{}'", container_info.image_name_no_version, secret_name)
            ).into_response();
        }
    } else {
        info!("Allowing client '{}' to create new secret '{}'", container_info.image_name_no_version, secret_name);
    }

    // Find the write operation for this client and secret
    let operation_cache = {
        let write_ops = state.write_operations.read().await;

        write_ops.iter()
            .find(|x| x.1.secret_name == secret_name && x.1.client_ip == client_ip)
            .map(|(_, op)| op.clone())
    };

    if operation_cache.is_none() {
        warn!("Write operation not found: no active operation for client '{}' and secret '{}'", container_info.image_name_no_version, secret_name);
        return ServerError::WriteOperationNotFound.into_response();
    }

    let operation = operation_cache.unwrap();
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
    let encrypted_file_path = PathBuf::from(&state.server_config.secrets_dir).join(&operation.file_path);

    let encrypted_data = match encrypted_file_path.canonicalize() {
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
            warn!("Failed to generate file path for '{}': {}", operation.file_path, e);
            return ServerError::FileSystem(format!("Failed to generate file path: {}", e)).into_response();
        }
    };

    let decrypted_secret = match decrypt_with_age_private_key(&operation.private_key, &encrypted_data, std::time::Duration::from_secs(state.server_config.age_timeout_seconds)).await {
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

    // Add or update the secret
    let result: Result<(), ServerError> = if secret_exists {
        info!("Updating existing secret: '{}'", secret_name);
        // Update existing secret
        update_secret_with_timeout(&state.sops_client, &secret_name, secure_secret.expose_secret(), state.server_config.sops_timeout_seconds).await
    } else {
        info!("Creating new secret: '{}' with owner '{}'", secret_name, container_info.image_name_no_version);
        // Create new secret with client as owner
        create_secret_with_timeout(&state.sops_client, &container_info.image_name_no_version, &secret_name, secure_secret.expose_secret(), state.server_config.sops_timeout_seconds).await
    };

    // Secure secret is automatically zeroized when dropped

    match result {
        Ok(_) => {
            info!("Write secret completion successful: secret='{}', operation='{}'", secret_name, if secret_exists { "update" } else { "create" });
            (StatusCode::OK, Json(
                WriteSecretCompleteResponse {
                    status: "success".to_string(),
                    message: if secret_exists {
                        "updated".to_string()
                    } else {
                        "created".to_string()
                    },
                }
            )).into_response()
        }
        Err(e) => {
            warn!("Write secret completion failed: secret='{}', error={:?}", secret_name, e);
            e.into_response()
        }
    }
}

/// Create the router with all endpoints
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/secret/{secret_name}", axum::routing::post(get_secret))
        .route("/secret/{secret_name}/write/init", axum::routing::post(write_secret_init))
        .route("/secret/{secret_name}/write/complete", axum::routing::post(write_secret_complete))
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1MB limit
} 