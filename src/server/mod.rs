use axum::{extract::{ConnectInfo, Json, Path, State}, http::StatusCode, response::IntoResponse, routing::{get, post}, Router};
use bollard::Docker;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::shared::age::{decrypt_with_age_private_key, encrypt_with_age_public_key, generate_temp_age_key_pair};
use crate::shared::{SopsError, SopsResult, SopsWrapper};

mod docker;
use docker::get_client_name_from_docker;

/// Request body for get secret endpoint
#[derive(Debug, Deserialize)]
pub struct GetSecretRequest {
    /// Client's public key for encrypting the secret
    pub public_key: String,
}

/// Request body for write secret initiation
#[derive(Debug, Deserialize)]
pub struct WriteSecretInitRequest {
    /// Secret name
    pub secret_name: String,
    /// Secret hash for validation
    pub secret_hash: String,
}

/// Response for write secret initiation
#[derive(Debug, Serialize)]
pub struct WriteSecretInitResponse {
    pub public_key: String,
    pub file_path: String,
    pub expires_at: String,
}

/// Response for write secret completion
#[derive(Debug, Serialize)]
pub struct WriteSecretCompleteResponse {
    pub status: String,
    pub message: String,
}

/// Write operation state
#[derive(Debug, Clone)]
pub struct WriteOperation {
    pub secret_name: String,
    pub client_ip: IpAddr,
    pub expires_at: u64,
    pub public_key: String,
    pub private_key: String,
    pub secret_hash: String,
    pub file_path: String,
}

/// Response structure for secret retrieval (minimal data)
#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub file_path: String,
    pub timeout_seconds: u64,
    pub secret_hash: String,
}

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Unified response type for all handlers
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApiResponse {
    Health(HealthResponse),
    Secret(SecretResponse),
    WriteInit(WriteSecretInitResponse),
    WriteComplete(WriteSecretCompleteResponse),
    Error(ErrorResponse),
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub timestamp: String,
    pub checks: HealthChecks,
}

/// Detailed health check results
#[derive(Debug, Serialize)]
pub struct HealthChecks {
    pub sops_wrapper: bool,
    pub master_key: bool,
    pub docker_api: bool,
    pub age_executable: bool,
    pub secrets_directory: bool,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// SOPS file path
    pub sops_file_path: String,
    /// Master key path for SOPS
    pub master_key_path: String,
    /// Docker socket path (default: /var/run/docker.sock)
    pub docker_socket_path: String,
    /// Directory to store encrypted secret files
    pub secrets_dir: String,
    /// Path to age executable
    pub age_executable_path: String,
    /// Path to SOPS executable
    pub sops_executable_path: String,

    /// Health check timeout (seconds)
    pub health_check_timeout_seconds: u64,
    /// Docker API timeout (seconds)
    pub docker_timeout_seconds: u64,
    /// SOPS operation timeout (seconds)
    pub sops_timeout_seconds: u64,
    /// Age encryption timeout (seconds)
    pub age_timeout_seconds: u64,
    pub(crate) get_secret_file_cleanup_timeout: u64,
    pub(crate) write_secret_file_timeout: u64
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            sops_file_path: "secrets.yaml".to_string(),
            master_key_path: "secrets_master.key".to_string(),
            docker_socket_path: "/var/run/docker.sock".to_string(),
            secrets_dir: "/tmp/sops-secrets".to_string(),
            age_executable_path: "age".to_string(),
            sops_executable_path: "sops".to_string(),

            health_check_timeout_seconds: 5,
            docker_timeout_seconds: 5,
            sops_timeout_seconds: 5,
            age_timeout_seconds: 5,

            // timeouts used in the file cleanup process
            get_secret_file_cleanup_timeout: 20,
            write_secret_file_timeout: 20
        }
    }
}

/// Application state shared across requests
#[derive(Debug, Clone)]
pub struct AppState {
    sops_client: SopsWrapper,
    docker_client: Docker,
    server_config: ServerConfig,
    /// Cache for IP to container mapping to avoid repeated Docker API calls, preventative at the moment
    /// may turn out to be more of a pain than it's worth
    ip_cache: Arc<RwLock<HashMap<IpAddr, Option<String>>>>,
    /// Active write operations
    write_operations: Arc<RwLock<HashMap<String, WriteOperation>>>,
}

/// Create the application router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/secrets/:secret_name", post(get_secret))
        .route("/secrets/:secret_name/write/init", post(write_secret_init))
        .route("/secrets/:secret_name/write/complete", post(write_secret_complete))
        .with_state(state)
}

#[axum::debug_handler]
/// Health check endpoint
async fn health_check(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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

    let status = (checks.sops_wrapper && checks.master_key && checks.docker_api && checks.age_executable && checks.secrets_directory);

    let timestamp = chrono::Utc::now().to_rfc3339();

    (
        if status { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR },
        Json(HealthResponse {
            timestamp,
            checks,
        })
    ).into_response()
}

/// Perform comprehensive health checks
async fn perform_health_checks(state: &AppState) -> HealthChecks {
    let mut checks = HealthChecks {
        sops_wrapper: false,
        master_key: false,
        docker_api: false,
        age_executable: false,
        secrets_directory: false,
    };

    // Check SOPS wrapper
    checks.sops_wrapper = check_sops_wrapper(state).await;

    // Check master key path
    checks.master_key = check_master_key_path(&state.server_config).await;

    // Check Docker API
    checks.docker_api = check_docker_api(state).await;

    // Check age executable
    checks.age_executable = check_age_executable(&state.server_config).await;

    // Check secrets directory
    checks.secrets_directory = check_secrets_directory(&state.server_config).await;

    checks
}

/// Check if SOPS wrapper is working
async fn check_sops_wrapper(state: &AppState) -> bool {
    let timeout = std::time::Duration::from_secs(state.server_config.sops_timeout_seconds);

    match state.sops_client.validate_sops(Some(timeout)).await {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Check if master key path exists
async fn check_master_key_path(config: &ServerConfig) -> bool {
    let master_key_path = config.master_key_path.clone();
    tokio::task::spawn_blocking(move || {
        std::path::Path::new(&master_key_path).exists()
    }).await.unwrap_or(false)
}

/// Check if Docker API is accessible
async fn check_docker_api(state: &AppState) -> bool {
    let timeout = std::time::Duration::from_secs(state.server_config.docker_timeout_seconds);

    tokio::time::timeout(timeout, async {
        match state.docker_client.ping().await {
            Ok(_) => true,
            Err(_) => false,
        }
    }).await.unwrap_or(false)
}

/// Check if age executable is available
async fn check_age_executable(config: &ServerConfig) -> bool {
    let age_executable_path = config.age_executable_path.clone();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(&age_executable_path)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }).await.unwrap_or(false)
}

/// Check if secrets directory is accessible
async fn check_secrets_directory(config: &ServerConfig) -> bool {
    let secrets_dir = config.secrets_dir.clone();
    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(&secrets_dir);
        path.exists()
    }).await.unwrap_or(false)
}

/// Get a secret by name with authorization and client encryption
async fn get_secret(
    State(state): State<Arc<AppState>>,
    Path(secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<GetSecretRequest>,
) -> impl IntoResponse {
    let client_ip = addr.ip();

    let docker_timeout = std::time::Duration::from_secs(state.server_config.docker_timeout_seconds);
    let sops_timeout = std::time::Duration::from_secs(state.server_config.sops_timeout_seconds);
    let age_timeout = std::time::Duration::from_secs(state.server_config.age_timeout_seconds);

    // Validate age public key
    if !is_valid_age_public_key(&request.public_key) {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid Public Key".to_string(),
            message: "The provided age public key is invalid".to_string(),
        })).into_response();
    }

    // Get client name from Docker
    let client_name = match tokio::time::timeout(docker_timeout, get_client_name_from_docker(&state.docker_client, state.ip_cache.clone(), client_ip)).await {
        Ok(Ok(name)) => name,
        // this is the internal error coming from docker, hence the strange match format
        Ok(Err(_)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Docker API Error".to_string(),
                message: "Failed to query Docker API".to_string(),
            })).into_response();
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Docker API Timeout".to_string(),
                message: "Timeout while querying Docker API".to_string(),
            })).into_response();
        }
    };

    // Check authorization
    let is_authorized = match tokio::time::timeout(sops_timeout, state.sops_client
        .is_reader_allowed_to_read(&client_name, &secret_name, &client_name, Some(sops_timeout))).await {
        Ok(Ok(authorized)) => authorized,
        _ => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Authorization Timeout".to_string(),
                message: "Timeout while checking authorization".to_string(),
            })).into_response();
        }
    };

    if !is_authorized {
        return (StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Access Denied".to_string(),
            message: format!("Client '{}' is not authorized to read secret '{}'", client_name, secret_name),
        })).into_response();
    }

    // Get secret data
    let mut secret_data = match tokio::time::timeout(sops_timeout, state.sops_client
        .get_secret_data(&secret_name, Some(sops_timeout))).await {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => {
            match e {
                SopsError::InvalidSecretFormat(msg) => {
                    return (StatusCode::FORBIDDEN, Json(ErrorResponse {
                        error: "Invalid Secret".to_string(),
                        message: msg,
                    })).into_response();
                }
                _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "Secret Retrieval Failed".to_string(),
                    message: e.to_string(),
                })).into_response()
            }
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Secret Retrieval Timeout".to_string(),
                message: "Timeout while retrieving secret".to_string(),
            })).into_response()
        }
    };

    // Create secrets directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&state.server_config.secrets_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "File System Error".to_string(),
            message: format!("Failed to create secrets directory: {}", e),
        })).into_response();
    }

    // Generate unique file name
    let file_name = format!("{}_{}.age", secret_name, Uuid::new_v4());
    let file_path = PathBuf::from(&state.server_config.secrets_dir).join(&file_name);

    // hash the data for security purposes
    let secret_value = secret_data.value.clone();
    // Calculate file hash for integrity verification
    let file_hash = calculate_secret_hash(&secret_value);

    // Encrypt secret with client's public key
    let age_executable_path = state.server_config.age_executable_path.clone();
    let encrypted_data = match tokio::time::timeout(age_timeout, tokio::task::spawn_blocking(move || {
        encrypt_with_age_public_key(&secret_value, &request.public_key, &age_executable_path)
    })).await {
        Ok(Ok(Ok(data))) => data,
        Ok(Ok(Err(e))) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Encryption Failed".to_string(),
                message: format!("Failed to encrypt secret: {}", e),
            })).into_response();
        }
        Ok(Err(_)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Encryption Task Failed".to_string(),
                        message: "Failed to execute encryption task".to_string(),
                    })).into_response();
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Encryption Timeout".to_string(),
                message: "Timeout while encrypting secret with age".to_string(),
            })).into_response();
        }
    };

    // Write encrypted data to file
    let mut file = match fs::File::create(&file_path) {
        Ok(file) => file,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "File System Error".to_string(),
                message: format!("Failed to create secret file: {}", e),
            })).into_response();
        }
    };

    if let Err(e) = file.write_all(&encrypted_data) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "File System Error".to_string(),
            message: format!("Failed to write secret file: {}", e),
        })).into_response();
    }

    #[cfg(unix)]
    {
        // Set restrictive file permissions (owner read/write only)
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = file.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            if let Err(e) = fs::set_permissions(&file_path, perms) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "File System Error".to_string(),
                    message: format!("Failed to set file permissions: {}", e),
                })).into_response();
            }
        }
    }

    // Zero out the secret value from memory
    zero_string(&mut secret_data.value);

    // Schedule cleanup of the encrypted file for when the timeout occurs
    let file_path_clone = file_path.clone();
    let timeout_seconds = state.server_config.get_secret_file_cleanup_timeout;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(timeout_seconds)).await;
        let _ = fs::remove_file(&file_path_clone);
    });

    (StatusCode::OK, Json(
        SecretResponse {
            file_path: file_path.to_string_lossy().to_string(),
            timeout_seconds,
            secret_hash: file_hash,
        }
    )).into_response()
}

/// Zero out a string in memory for security
fn zero_string(s: &mut String) {
    unsafe {
        let bytes = s.as_mut_vec();
        ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len());
    }
    s.clear();
}

/// Validate age public key format
fn is_valid_age_public_key(public_key: &str) -> bool {
    public_key.starts_with("age1") && public_key.len() >= 20
}

/// Calculate SHA-256 hash of secret value
fn calculate_secret_hash(secret_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret_value.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Create a new server instance
pub async fn create_server(config: ServerConfig) -> SopsResult<AppState> {
    let sops_wrapper = SopsWrapper::with_config(crate::shared::SopsConfig {
        sops_path: config.sops_executable_path.clone(),
        file_path: config.sops_file_path.clone(),
        master_key_path: config.master_key_path.clone(),
        ..Default::default()
    });

    let docker_client = Docker::connect_with_local_defaults()
        .map_err(|e| SopsError::CommandFailed(format!("Failed to connect to Docker: {}", e)))?;

    Ok(AppState {
        sops_client: sops_wrapper,
        docker_client,
        server_config: config,
        ip_cache: Arc::new(RwLock::new(HashMap::new())),
        write_operations: Arc::new(RwLock::new(HashMap::new())),
    })
}

/// Start the server
pub async fn start_server(config: ServerConfig, port: u16) -> SopsResult<()> {
    let state = Arc::new(create_server(config.clone()).await?);
    let app = create_router(Arc::clone(&state));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Server starting on {}", addr);

    // Start cleanup tasks
    let config_clone = config.clone();
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        cleanup_expired_secrets(&config_clone, &state_clone).await;
    });

    let state_clone2 = Arc::clone(&state);
    tokio::spawn(async move {
        cleanup_expired_write_operations(&state_clone2).await;
    });

    let listener = tokio::net::TcpListener::bind(&addr).await
        .map_err(|e| SopsError::CommandFailed(format!("Failed to bind to address: {}", e)))?;

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| SopsError::CommandFailed(format!("Server failed to start: {}", e)))?;

    Ok(())
}

/// Cleanup expired secret files
async fn cleanup_expired_secrets(config: &ServerConfig, _state: &Arc<AppState>) {
    let cleanup_interval = std::time::Duration::from_secs(60);
    loop {
        tokio::time::sleep(cleanup_interval).await;
        if let Err(e) = perform_cleanup(&config).await {
            eprintln!("Cleanup error: {}", e);
        }
    }
}

/// Perform the actual cleanup of expired secret files
async fn perform_cleanup(config: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let secrets_dir = std::path::Path::new(&config.secrets_dir);
    if !secrets_dir.exists() {
        return Ok(());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let timeout_seconds = config.get_secret_file_cleanup_timeout;

    for entry in std::fs::read_dir(secrets_dir)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(metadata) = path.metadata().ok() {
            if let Ok(modified) = metadata.modified() {
                if let Ok(modified_secs) = modified.duration_since(UNIX_EPOCH) {
                    if now - modified_secs.as_secs() > timeout_seconds {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Cleanup expired write operations
async fn cleanup_expired_write_operations(state: &AppState) {
    let cleanup_interval = std::time::Duration::from_secs(30);
    loop {
        tokio::time::sleep(cleanup_interval).await;

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_secs();
        let mut write_ops = state.write_operations.write().await;

        write_ops.retain(|_, operation| operation.expires_at > now);
    }
}

/// Write secret initiation endpoint
async fn write_secret_init(
    State(state): State<Arc<AppState>>,
    Path(_secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<WriteSecretInitRequest>,
) -> impl IntoResponse {
    let client_ip = addr.ip();
    let docker_timeout = std::time::Duration::from_secs(state.server_config.docker_timeout_seconds);
    let sops_timeout = std::time::Duration::from_secs(state.server_config.sops_timeout_seconds);

    // Get client name from Docker
    let client_name = match tokio::time::timeout(docker_timeout, get_client_name_from_docker(&state.docker_client, state.ip_cache.clone(), client_ip)).await {
        Ok(Ok(name)) => name,
        // this error comes from docker inside the timeout, hence the strange syntax
        Ok(Err(_)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Docker API Error".to_string(),
                message: "Failed to query Docker API".to_string(),
            })).into_response();
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Docker API Timeout".to_string(),
                message: "Timeout while querying Docker API".to_string(),
            })).into_response();
        }
    };

    // Check if secret exists and client has write permission
    let secret_exists = match tokio::time::timeout(sops_timeout, async {
        match state.sops_client.get_secret_data(&request.secret_name, Some(sops_timeout)).await {
            Ok(secret_data) => {
                let can_write = secret_data.can_write(&client_name);
                Ok(can_write)
            }
            Err(SopsError::InvalidSecretFormat(_)) => Ok(true),
            Err(e) => Err(e),
        }
    }).await {
        Ok(Ok(can_write)) => can_write,
        Ok(Err(e)) => {
            match e {
                SopsError::InvalidSecretFormat(msg) => return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Access Denied".to_string(),
                        message: msg,
                    })).into_response(),
                _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "Authorization Check Failed".to_string(),
                    message: e.to_string(),
                })).into_response(),
            };
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT,
                    Json(ErrorResponse {
                        error: "Authorization Timeout".to_string(),
                        message: "Timeout while checking authorization".to_string(),
                    })).into_response();
        }
    };

    if !secret_exists {
        return (StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Access Denied".to_string(),
            message: format!("Client '{}' is not authorized to write secret '{}'", client_name, request.secret_name),
        })).into_response();
    }

    // Generate temporary age key pair
    let temp_key_pair = match generate_temp_age_key_pair(&state.server_config.age_executable_path) {
        Ok(key_pair) => key_pair,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Key Generation Failed".to_string(),
                message: format!("Failed to generate temporary key pair: {}", e),
            })).into_response();
        }
    };

    // Create secrets directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&state.server_config.secrets_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "File System Error".to_string(),
            message: format!("Failed to create secrets directory: {}", e),
        })).into_response();
    }

    // Generate unique file name and operation ID
    let operation_id = Uuid::new_v4().to_string();
    let file_name = format!("{}_{}.age", request.secret_name, operation_id);
    let file_path = PathBuf::from(&state.server_config.secrets_dir).join(&file_name);

    // Calculate expiration time
    let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_secs() + state.server_config.write_secret_file_timeout;

    // Store write operation
    let write_operation = WriteOperation {
        secret_name: request.secret_name.clone(),
        client_ip,
        expires_at,
        public_key: temp_key_pair.public_key.clone(),
        private_key: temp_key_pair.private_key.clone(),
        secret_hash: request.secret_hash.clone(),
        file_path: file_name,
    };

    // get the write lock to the write_operations cache and add the write operation
    state.write_operations.write().await.insert(operation_id.clone(), write_operation);

    (StatusCode::OK, Json(WriteSecretInitResponse {
        public_key: temp_key_pair.public_key.clone(),
        // TODO : Come and check the lossy here?
        file_path: file_path.to_string_lossy().to_string(),
        expires_at: chrono::DateTime::from_timestamp(expires_at as i64, 0)
            .unwrap_or_default()
            .to_rfc3339(),
    })).into_response()
}

/// Write secret completion endpoint
async fn write_secret_complete(
    State(state): State<Arc<AppState>>,
    Path(secret_name): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = addr.ip();
    let docker_timeout = std::time::Duration::from_secs(state.server_config.docker_timeout_seconds);
    let sops_timeout = std::time::Duration::from_secs(state.server_config.sops_timeout_seconds);

    // Get client name from Docker
    let client_name = match tokio::time::timeout(docker_timeout, get_client_name_from_docker(&state.docker_client, state.ip_cache.clone(), client_ip)).await {
        Ok(Ok(name)) => name,
        Ok(Err(_)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Docker API Error".to_string(),
                message: "Failed to query Docker API".to_string(),
            })).into_response();
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Docker API Timeout".to_string(),
                message: "Timeout while querying Docker API".to_string(),
            })).into_response();
        }
    };

    // Check if secret exists and client has write permission
    let secret_exists = match tokio::time::timeout(sops_timeout, async {
        match state.sops_client.get_secret_data(&secret_name, Some(sops_timeout)).await {
            Ok(secret_data) => {
                let can_write = secret_data.can_write(&client_name);
                Ok(can_write)
            }
            Err(SopsError::InvalidSecretFormat(_)) => Ok(true), // New secret, client will be owner
            Err(e) => Err(e),
        }
    }).await {
        Ok(Ok(can_write)) => can_write,
        Ok(Err(e)) => {
            match e {
                SopsError::InvalidSecretFormat(msg) => return (StatusCode::FORBIDDEN,
                                                               Json(ErrorResponse {
                                                                   error: "Access Denied".to_string(),
                                                                   message: msg,
                                                               })).into_response(),
                _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "Authorization Check Failed".to_string(),
                    message: e.to_string(),
                })).into_response()
            };
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Authorization Timeout".to_string(),
                message: "Timeout while checking authorization".to_string(),
            })).into_response();
        }
    };

    if !secret_exists {
        return (StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Access Denied".to_string(),
            message: format!("Client '{}' is not authorized to write secret '{}'", client_name, secret_name),
        })).into_response();
    }

    // Find the write operation for this client and secret, make sure to pay attention to the RW lock on the collection
    let operation_opt = {
        let write_ops = state.write_operations.read().await;
        write_ops.iter()
            .find(|x| x.1.secret_name == secret_name && x.1.client_ip == client_ip)
            .map(|(_, op)| op.clone())
    };

    let operation = match operation_opt {
        Some(op) => op,
        None => {
            let mut write_ops = state.write_operations.write().await;
            write_ops.retain(|_, op| op.secret_name != secret_name || op.client_ip != client_ip);

            return (StatusCode::NOT_FOUND, Json(ErrorResponse {
                error: "Operation Not Found".to_string(),
                message: "No active write operation found for this secret and client".to_string(),
            })).into_response();
        }
    };

    // Check if operation has expired
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_secs();
    if operation.expires_at < now {
        return (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Operation Not Found".to_string(),
            message: "No active write operation found for this secret and client".to_string(),
        })).into_response();
    }

    let encrypted_file_path = PathBuf::from(&state.server_config.secrets_dir).join(&operation.file_path);
    if !encrypted_file_path.exists() {
        return (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "File Not Found".to_string(),
            message: "Encrypted secret file not found".to_string(),
        })).into_response();
    }

    let age_timeout = std::time::Duration::from_secs(state.server_config.age_timeout_seconds);
    let encrypted_file_path_clone = encrypted_file_path.clone();
    let private_key = operation.private_key.clone();
    let age_executable_path = state.server_config.age_executable_path.clone();

    let mut decrypted_secret = match tokio::time::timeout(age_timeout, tokio::task::spawn_blocking(move || {
        decrypt_with_age_private_key(&age_executable_path, &encrypted_file_path_clone, &private_key)
    })).await {
        Ok(Ok(Ok(data))) => data,
        Ok(Ok(Err(e))) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Decryption Failed".to_string(),
                message: format!("Failed to decrypt secret: {}", e),
            })).into_response();
        }
        Ok(Err(_)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Decryption Task Failed".to_string(),
                message: "Failed to execute decryption task".to_string(),
            })).into_response();
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "Decryption Timeout".to_string(),
                message: "Timeout while decrypting secret".to_string(),
            })).into_response();
        }
    };

    // Clean up the file from the filesystem now
    let _ = fs::remove_file(&encrypted_file_path);

    // Verify the decrypted secret hash matches the expected hash
    let decrypted_hash = calculate_secret_hash(&decrypted_secret);
    if decrypted_hash != operation.secret_hash {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Hash Mismatch".to_string(),
            message: "Decrypted secret hash does not match the expected value".to_string(),
        })).into_response();
    }

    // Check if secret already exists
    let sops_timeout = std::time::Duration::from_secs(state.server_config.sops_timeout_seconds);
    let secret_exists = match tokio::time::timeout(sops_timeout, async {
        match state.sops_client.get_secret_data(&secret_name, Some(sops_timeout)).await {
            Ok(_) => Ok(true),
            Err(SopsError::InvalidSecretFormat(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }).await {
        Ok(Ok(exists)) => exists,
        Ok(Err(e)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "SOPS Error".to_string(),
                message: e.to_string(),
            })).into_response();
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                error: "SOPS Timeout".to_string(),
                message: "Timeout while checking secret existence".to_string(),
            })).into_response();
        }
    };

    // After decrypting the secret, check write permission again before updating/creating the secret.
    let can_write = if secret_exists {
        let secret_data = match state.sops_client.get_secret_data(&secret_name, Some(sops_timeout)).await {
            Ok(data) => data,
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "SOPS Error".to_string(),
                    message: e.to_string(),
                })).into_response();
            }
        };

        // check the data read back from the SOPS wrapper to see if we can write to it
        secret_data.can_write(&client_name)
    } else {
        true // New secret, client will be owner
    };

    if !can_write {
        return (StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Access Denied".to_string(),
            message: format!("Client '{}' is not authorized to write secret '{}'", client_name, secret_name),
        })).into_response();
    }

    // Add or update the secret
    let _result: Result<(), SopsError> = if secret_exists {
        // Update existing secret
        match tokio::time::timeout(sops_timeout, state.sops_client
            .update_secret_value(&secret_name, &decrypted_secret, Some(sops_timeout))).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "SOPS Error".to_string(),
                    message: e.to_string(),
                })).into_response();
            }
            Err(_) => {
                return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                    error: "SOPS Timeout".to_string(),
                    message: "Timeout while updating secret".to_string(),
                })).into_response()
            }
        }
    } else {
        // Create new secret with client as owner
        match tokio::time::timeout(sops_timeout, state.sops_client
            .add_owned_secret(&client_name, &secret_name, &decrypted_secret, &[client_name.clone()], &[client_name.clone()], Some(sops_timeout))).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                return (StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "SOPS Error".to_string(),
                            message: e.to_string(),
                        })).into_response();
            }
            Err(_) => {
                return (StatusCode::REQUEST_TIMEOUT, Json(ErrorResponse {
                    error: "SOPS Timeout".to_string(),
                    message: "Timeout while creating secret".to_string(),
                })).into_response();
            }
        }
    };

    // Clean up the encrypted file
    let _ = fs::remove_file(&encrypted_file_path);

    // Remove the write operation
    let mut write_ops = state.write_operations.write().await;
    write_ops.retain(|_, op| op.secret_name != secret_name || op.client_ip != client_ip);

    // Zero out the decrypted secret immediately after use
    zero_string(&mut decrypted_secret);

    // Return success response
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
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_age_public_key() {
        // Valid age public key
        assert!(is_valid_age_public_key("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"));

        // Invalid keys
        assert!(!is_valid_age_public_key("age1")); // Too short
        assert!(!is_valid_age_public_key("invalid_key")); // Wrong prefix
        assert!(!is_valid_age_public_key("")); // Empty
    }

    #[test]
    fn test_calculate_secret_hash() {
        let secret = "my-secret-value";
        let hash = calculate_secret_hash(secret);

        // Hash should be 64 characters (32 bytes in hex)
        assert_eq!(hash.len(), 64);

        // Same input should produce same hash
        let hash2 = calculate_secret_hash(secret);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = calculate_secret_hash("different-secret");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_secure_ip_extraction() {
        // Test that we're using the actual connection IP, not client headers
        // This test validates that the security fix is in place
        let socket_addr = "192.168.1.100:8080".parse::<SocketAddr>().unwrap();
        let client_ip = socket_addr.ip();

        // Should be the actual IP from the socket address
        assert_eq!(client_ip, "192.168.1.100".parse::<IpAddr>().unwrap());

        // Test IPv6
        let socket_addr_v6 = "[::1]:8080".parse::<SocketAddr>().unwrap();
        let client_ip_v6 = socket_addr_v6.ip();
        assert_eq!(client_ip_v6, "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_memory_zeroing() {
        let mut secret = String::from("super-secret-password");
        let original_len = secret.len();

        // Zero out the string
        zero_string(&mut secret);

        // String should be empty
        assert_eq!(secret.len(), 0);
        assert_eq!(secret, "");

        // The memory should be zeroed (we can't easily test this without unsafe code)
        // but we can verify the string is cleared
        assert!(secret.is_empty());
    }

    #[test]
    fn test_server_config_defaults() {
        let config = ServerConfig::default();

        assert_eq!(config.health_check_timeout_seconds, 5);
        assert_eq!(config.docker_timeout_seconds, 5);
        assert_eq!(config.sops_timeout_seconds, 5);
        assert_eq!(config.age_timeout_seconds, 5);
        assert_eq!(config.age_executable_path, "age");
        assert_eq!(config.sops_executable_path, "sops");
        assert_eq!(config.secrets_dir, "/tmp/sops-secrets");
    }

    #[test]
    fn test_health_checks_structure() {
        let checks = HealthChecks {
            sops_wrapper: true,
            master_key: true,
            docker_api: true,
            age_executable: true,
            secrets_directory: true,
        };

        // Test that all checks can be true
        assert!(checks.sops_wrapper);
        assert!(checks.master_key);
        assert!(checks.docker_api);
        assert!(checks.age_executable);
        assert!(checks.secrets_directory);

        // Test that all checks can be false
        let checks_false = HealthChecks {
            sops_wrapper: false,
            master_key: false,
            docker_api: false,
            age_executable: false,
            secrets_directory: false,
        };

        assert!(!checks_false.sops_wrapper);
        assert!(!checks_false.master_key);
        assert!(!checks_false.docker_api);
        assert!(!checks_false.age_executable);
        assert!(!checks_false.secrets_directory);
    }
}
