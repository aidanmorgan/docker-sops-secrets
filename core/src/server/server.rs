use bollard::Docker;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use axum::Router;
use tokio::sync::RwLock;

use super::config::ServerConfig;
use super::file_cleaner::FileCleanupManager;
use super::handlers::create_router;
use super::health;
use super::rate_limiter::RateLimiter;
use super::state::AppState;
use crate::sops::{SopsConfig, SopsWrapper, public::initialize_sops_file_if_not_exists};

// Helper for canonicalized display
fn canonical_display(path: &std::path::PathBuf) -> String {
    path.canonicalize().map(|p| p.display().to_string()).unwrap_or_else(|_| path.display().to_string())
}

/// Create a new server instance
pub async fn create_server(config: ServerConfig) -> Result<(Arc<AppState>, Router), Box<dyn Error>> {
    info!("Creating server with configuration: {:?}", config);

    // Set up panic hook to ensure panics are logged properly
    std::panic::set_hook(Box::new(|panic_info| {
        info!("PANIC: {:?}", panic_info);
        eprintln!("💥 PANIC: {:?}", panic_info);
    }));

    debug!("Initializing SOPS wrapper...");
    let sops_wrapper = SopsWrapper::with_config(SopsConfig::with_sops_path(
        config.sops_file_path().to_path_buf(),
        config.master_key_path().to_path_buf(),
        config.sops_executable_path().to_path_buf(),
    ));
    debug!("SOPS wrapper initialized");

    // Initialize SOPS file if it doesn't exist and auto-creation is enabled
    if config.auto_create_sops_file() {
        debug!("Auto-creation of SOPS file is enabled, checking if file needs to be initialized...");
        if let Err(e) = initialize_sops_file_if_not_exists(&sops_wrapper, None).await {
            warn!("Warning: Failed to initialize SOPS file: {}", e);
            eprintln!("⚠️  Warning: Failed to initialize SOPS file: {}", e);
        } else {
            debug!("SOPS file initialization completed");
        }
    } else {
        debug!("Auto-creation of SOPS file is disabled, skipping initialization");
    }

    info!("Connecting to Docker API...");
    let docker_client = match Docker::connect_with_local_defaults() {
        Ok(client) => {
            info!("Docker client connected successfully");
            client
        }
        Err(e) => {
            error!("Failed to connect to Docker API: {}", e);
            return Err(Box::new(e));
        }
    };

    debug!("Initializing file cleanup manager...");
    let file_cleanup = Arc::new(FileCleanupManager::new(
        config.file_cleanup_max_retries(),
        config.file_cleanup_retry_delay_seconds(),
    ));

    // Clone the Arc before spawning the background task
    file_cleanup.clone().spawn_background_task();
    debug!("File cleanup manager initialized and background task spawned");

    // Clean up any orphaned files from previous runs
    debug!("Cleaning up orphaned files from previous runs...");
    let secrets_dir = config.secrets_dir().to_path_buf();
    let cleanup_timeout = config.get_secret_file_cleanup_timeout();
    if let Err(e) = FileCleanupManager::cleanup_orphaned_files(&secrets_dir, cleanup_timeout).await {
        warn!("Warning: Failed to cleanup orphaned files: {}", e);
    }

    let app_state = AppState {
        sops_client: Arc::new(sops_wrapper),
        docker_client: Arc::new(docker_client),
        server_config: Arc::new(config.clone()),
        ip_cache: Arc::new(RwLock::new(HashMap::new())),
        write_operations: Arc::new(RwLock::new(HashMap::new())),
        file_cleanup,
        rate_limiter: Arc::new(RateLimiter::new(config.rate_limit_max_requests(), config.rate_limit_window_seconds())),
    };

    let state = Arc::new(app_state);
    let state_for_cleanup = Arc::clone(&state);

    // Spawn periodic health check task
    if config.enable_health_check() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let _ = health::perform_health_checks(&state_for_cleanup).await;
            }
        });
    }

    let app = create_router(Arc::clone(&state));
    Ok((state, app))
}

/// Start the server on the specified port
pub async fn start_server(config: ServerConfig, port: u16) -> Result<(), Box<dyn Error>> {
    info!("Starting server on port {}", port);

    // Set up panic hook to ensure panics are logged properly
    std::panic::set_hook(Box::new(|panic_info| {
        info!("PANIC: {:?}", panic_info);
        eprintln!("💥 PANIC: {:?}", panic_info);
    }));

    // Initialize SOPS wrapper
    debug!("Initializing SOPS wrapper...");
    let sops_wrapper = SopsWrapper::with_config(SopsConfig::with_sops_path(
        config.sops_file_path().to_path_buf(),
        config.master_key_path().to_path_buf(),
        config.sops_executable_path().to_path_buf(),
    ));

    // Initialize SOPS file if auto-creation is enabled
    if config.auto_create_sops_file() {
        debug!("Auto-creation of SOPS file is enabled, checking if file needs to be initialized...");
        if let Err(e) = initialize_sops_file_if_not_exists(&sops_wrapper, None).await {
            warn!("Warning: Failed to initialize SOPS file: {}", e);
        }
    }

    // Connect to Docker API
    info!("Connecting to Docker API...");
    let docker_client = Docker::connect_with_local_defaults()
        .map_err(|e| {
            error!("Failed to connect to Docker API: {}", e);
            e
        })?;
    info!("Docker client connected successfully");

    // Initialize file cleanup manager
    debug!("Initializing file cleanup manager...");
    let file_cleanup = Arc::new(FileCleanupManager::new(
        config.file_cleanup_max_retries(),
        config.file_cleanup_retry_delay_seconds(),
    ));
    file_cleanup.clone().spawn_background_task();

    // Clean up orphaned files from previous runs
    debug!("Cleaning up orphaned files from previous runs...");
    let secrets_dir = config.secrets_dir().to_path_buf();
    let cleanup_timeout = config.get_secret_file_cleanup_timeout();
    if let Err(e) = FileCleanupManager::cleanup_orphaned_files(&secrets_dir, cleanup_timeout).await {
        warn!("Warning: Failed to cleanup orphaned files: {}", e);
    }

    // Create application state
    let state = Arc::new(AppState {
        sops_client: Arc::new(sops_wrapper),
        docker_client: Arc::new(docker_client),
        server_config: Arc::new(config.clone()),
        ip_cache: Arc::new(RwLock::new(HashMap::new())),
        write_operations: Arc::new(RwLock::new(HashMap::new())),
        file_cleanup,
        rate_limiter: Arc::new(RateLimiter::new(config.rate_limit_max_requests(), config.rate_limit_window_seconds())),
    });

    // Spawn background tasks
    spawn_background_tasks(&state);

    // Create router and start server
    let app = create_router(state);
    
    info!("Binding to address 0.0.0.0:{}", port);
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    info!("Starting Axum server...");
    match axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
        Ok(_) => {
            info!("Server stopped normally");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(Box::new(e))
        }
    }
}

/// Spawn all background tasks for the server
fn spawn_background_tasks(state: &Arc<AppState>) {
    // Health check task
    let state_for_health = Arc::clone(state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let _ = health::perform_health_checks(&state_for_health).await;
        }
    });

    // Write operations cleanup task
    let state_for_cleanup = Arc::clone(state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_expired_write_operations(&state_for_cleanup).await;
        }
    });
}

/// Cleanup expired write operations
async fn cleanup_expired_write_operations(state: &Arc<AppState>) {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0))
        .as_secs();

    let mut write_ops = state.write_operations.write().await;
    write_ops.retain(|_, op| current_time <= op.expires_at);
}
