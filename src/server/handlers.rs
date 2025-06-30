use axum::response::Response;
use axum::{extract::{ConnectInfo, Path, State}, http::StatusCode, response::IntoResponse, Json, Router};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroize;
use crate::shared::age::{decrypt_with_age_private_key, generate_temp_age_key_pair, AgeError};
use crate::server::{
    errors::ServerError,
    models::*,
    secure_secret::SecureSecret,
    state::AppState,
    utils::*,
    health::perform_health_checks,
    config::DockerValidationOptions,
};

/// Health check endpoint
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Response {
    let timeout = std::time::Duration::from_secs(state.server_config.health_check_timeout_seconds);

    // Perform health checks with timeout
    let checks = tokio::time::timeout(timeout, perform_health_checks(&state)).await
        .unwrap_or_else(|_| HealthChecks {
            sops_wrapper: false,
            master_key: false,
            docker_api: false,
            age_executable: false,
            secrets_directory: false,
        });

    let status = checks.sops_wrapper && checks.master_key && checks.docker_api && checks.age_executable && checks.secrets_directory;
    let timestamp = chrono::Utc::now().to_rfc3339();

    (
        if status { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR },
            Json(HealthResponse {
                timestamp,
                checks,
            })
    ).into_response()
}

/// Get a secret by name with authorization and client encryption
pub async fn get_secret(
    State(state): State<Arc<AppState>>,
    Path(secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<GetSecretRequest>,
) -> Response {
    let client_ip = addr.ip();

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_rate_limit(client_ip).await {
        return e.into_response();
    }

    // Validate age public key
    if !is_valid_age_public_key(&request.public_key) {
        return ServerError::InvalidPublicKey.into_response();
    }

    // Use DockerValidationOptions from server config
    let validation_options = &state.server_config.docker_validation;

    // Get client name from Docker with enhanced validation
    let container_info = match validate_client_with_timeout(&state.ip_cache, &state.docker_client, &client_ip, validation_options).await {
        Ok(info) => info,
        Err(e) => return e.into_response(),
    };

    // Check authorization using the validated container image name (without version)
    let is_authorized = match check_read_permission_with_timeout(&state.sops_client, &container_info.image_name_no_version, &secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(authorized) => authorized,
        Err(e) => return e.into_response(),
    };

    if !is_authorized {
        return ServerError::AccessDenied(
            format!("Client '{}' is not authorized to read secret '{}'", container_info.image_name_no_version, secret_name)
        ).into_response();
    }

    // Get secret data
    let mut secret_data = match get_secret_data_with_timeout(&state.sops_client, &secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(data) => data,
        Err(e) => return e.into_response(),
    };

    // Create a secure wrapper for the secret value
    let secure_secret = SecureSecret::new(secret_data.value.clone());
    let secret_value = secure_secret.expose_secret();

    // Create secrets directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&state.server_config.secrets_dir) {
        return ServerError::FileSystem(format!("Failed to create secrets directory: {}", e))
            .into_response();
    }

    // Generate unique file name
    let file_name = format!("{}_{}.age", secret_name, Uuid::new_v4());
    let file_path = match PathBuf::from(&state.server_config.secrets_dir).join(&file_name).canonicalize() {
        Ok(path) => path,
        Err(e) => return ServerError::FileSystem(format!("Failed to generate file path: {}", e)).into_response(),
    };

    // Hash the data for security purposes
    let file_hash = calculate_secret_hash(secret_value);

    // Encrypt secret with client's public key
    let encrypted_data = match encrypt_with_age_timeout(
        &state.server_config.age_executable_path,
        &request.public_key,
        secret_value,
        state.server_config.age_timeout_seconds,
    ).await {
        Ok(data) => data,
        Err(e) => return e.into_response(),
    };

    // Write encrypted data to file
    let mut file = match fs::File::create(&file_path) {
        Ok(file) => file,
        Err(e) => return ServerError::FileSystem(format!("Failed to create secret file: {}", e))
            .into_response(),
    };

    if let Err(e) = file.write_all(&encrypted_data) {
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
            file_cleanup.add_file(abs_path, std::time::Duration::from_secs(timeout_seconds)).await;
        } else {
            eprintln!("⚠️  Failed to canonicalize file path for cleanup: {}", file_path_clone.display());
        }
    });

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
    State(state): State<Arc<AppState>>,
    Path(_secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<WriteSecretInitRequest>,
) -> Response {
    let client_ip = addr.ip();

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_rate_limit(client_ip).await {
        return e.into_response();
    }

    // Use DockerValidationOptions from server config
    let validation_options = &state.server_config.docker_validation;

    // Get client name from Docker with enhanced validation
    let container_info = match validate_client_with_timeout(&state.ip_cache, &state.docker_client, &client_ip, validation_options).await {
        Ok(info) => info,
        Err(e) => return e.into_response(),
    };

    // Check if secret exists and client has write permission
    let can_write = match check_write_permission_with_timeout(&state.sops_client, &container_info.image_name_no_version, &request.secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(can_write) => can_write,
        Err(e) => return e.into_response(),
    };

    if !can_write {
        return ServerError::AccessDenied(
            format!("Client '{}' is not authorized to write secret '{}'", container_info.image_name_no_version, request.secret_name)
        ).into_response();
    }

    // Generate temporary age key pair
    let temp_key_pair = match generate_temp_age_key_pair(std::time::Duration::from_secs(state.server_config.age_timeout_seconds)).await {
        Ok(key_pair) => key_pair,
        Err(AgeError::Timeout) => return ServerError::AgeTimeout.into_response(),
        Err(e) => return ServerError::AgeEncryption(format!("Failed to generate temporary key pair: {}", e)).into_response(),
    };

    // Create secrets directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&state.server_config.secrets_dir) {
        return ServerError::FileSystem(format!("Failed to create secrets directory: {}", e)).into_response();
    }

    // Generate a unique operation ID
    let operation_id = Uuid::new_v4().to_string();
    
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
) -> impl IntoResponse {
    let client_ip = addr.ip();

    // Check rate limit
    if let Err(e) = state.rate_limiter.check_rate_limit(client_ip).await {
        return e.into_response();
    }

    // Use DockerValidationOptions from server config
    let validation_options = &state.server_config.docker_validation;

    // Get client name from Docker with enhanced validation
    let container_info = match validate_client_with_timeout(&state.ip_cache, &state.docker_client, &client_ip, validation_options).await {
        Ok(info) => info,
        Err(e) => return e.into_response(),
    };

    // Check if client has write permission
    let can_write = match check_write_permission_with_timeout(&state.sops_client, &container_info.image_name_no_version, &secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(can_write) => can_write,
        Err(e) => return e.into_response(),
    };

    if !can_write {
        return ServerError::AccessDenied(
            format!("Client '{}' is not authorized to write secret '{}'", container_info.image_name_no_version, secret_name)
        ).into_response();
    }

    // Check if secret exists
    let secret_exists = match get_secret_data_with_timeout(&state.sops_client, &secret_name, state.server_config.sops_timeout_seconds).await {
        Ok(_) => true,
        Err(ServerError::Sops(crate::shared::SopsError::NoSecretFound)) => false,
        Err(e) => return e.into_response(),
    };

    if !secret_exists {
        return ServerError::WriteOperationNotFound.into_response();
    }

    // Find the write operation for this client and secret
    let operation_cache = {
        let write_ops = state.write_operations.read().await;

        write_ops.iter()
            .find(|x| x.1.secret_name == secret_name && x.1.client_ip == client_ip)
            .map(|(_, op)| op.clone())
    };

    if operation_cache.is_none() {
        return ServerError::WriteOperationNotFound.into_response();
    }

    let operation = operation_cache.unwrap();

    // Check if operation has expired
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_secs();
    if current_time > operation.expires_at {
        // Remove expired operation
        let mut write_ops = state.write_operations.write().await;

        write_ops.retain(|_, op| op.secret_name != secret_name || op.client_ip != client_ip);
        return ServerError::WriteOperationExpired.into_response();
    }

    // Read the encrypted file
    let encrypted_file_path = PathBuf::from(&state.server_config.secrets_dir).join(&operation.file_path).canonicalize();
    
    let encrypted_data = match encrypted_file_path {
        Ok(path) => match tokio::fs::read(&path).await {
            Ok(data) => data,
            Err(e) => return ServerError::FileSystem(format!("Failed to read encrypted file: {}", e)).into_response(),
        },
        Err(e) => return ServerError::FileSystem(format!("Failed to generate file path: {}", e)).into_response(),
    };
    
    let decrypted_secret = match decrypt_with_age_private_key(&operation.private_key, &encrypted_data, std::time::Duration::from_secs(state.server_config.age_timeout_seconds)).await {
        Ok(secret) => secret,
        Err(AgeError::Timeout) => return ServerError::AgeTimeout.into_response(),
        Err(e) => return ServerError::AgeEncryption(format!("Failed to decrypt secret: {}", e)).into_response(),
    };

    // Create secure wrapper for the decrypted secret
    let secure_secret = SecureSecret::new(decrypted_secret);

    // Validate secret hash using constant-time comparison
    if !secure_secret.verify_hash(&operation.secret_hash) {
        return ServerError::HashMismatch.into_response();
    }

    // Add or update the secret
    let result: Result<(), ServerError> = if secret_exists {
        // Update existing secret
        update_secret_with_timeout(&state.sops_client, &secret_name, secure_secret.expose_secret(), state.server_config.sops_timeout_seconds).await
    } else {
        // Create new secret with client as owner
        create_secret_with_timeout(&state.sops_client, &container_info.image_name_no_version, &secret_name, secure_secret.expose_secret(), state.server_config.sops_timeout_seconds).await
    };
    
    // Secure secret is automatically zeroized when dropped

    match result {
        Ok(_) => {
            (StatusCode::OK, Json(
                WriteSecretCompleteResponse {
                    status: "success".to_string(),
                    message: if secret_exists {
                        format!("Secret '{}' updated successfully", secret_name)
                    } else {
                        format!("Secret '{}' created successfully", secret_name)
                    },
                }
            )).into_response()
        },
        Err(e) => e.into_response(),
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
} 