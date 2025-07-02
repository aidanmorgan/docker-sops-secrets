use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use bollard::Docker;
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use super::config::ServerConfig;
use super::file_cleaner::FileCleanupManager;
use super::handlers::create_router;
use super::rate_limiter::RateLimiter;
use super::state::AppState;
use crate::shared::sops::SopsConfig;
use crate::shared::sops::SopsWrapper;


/// Create a new server instance
pub async fn create_server(config: ServerConfig) -> Result<AppState, Box<dyn Error>> {
    info!("Creating server with configuration: {:?}", config);

    // Set up panic hook to ensure panics are logged properly
    std::panic::set_hook(Box::new(|panic_info| {
        info!("PANIC: {:?}", panic_info);
        eprintln!("💥 PANIC: {:?}", panic_info);
    }));

    debug!("Initializing SOPS wrapper...");
    let sops_wrapper = SopsWrapper::with_config(SopsConfig {
        sops_path: config.sops_executable_path.clone(),
        file_path: config.sops_file_path.clone(),
        master_key_path: config.master_key_path.clone(),
        default_timeout: Duration::from_secs(config.sops_timeout_seconds),
        lock_timeout: Duration::from_secs(30),
        env_vars: HashMap::new(),
        working_dir: None,
    });
    debug!("SOPS wrapper initialized");

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
        config.file_cleanup_max_retries,
        config.file_cleanup_retry_delay_seconds,
    ));

    file_cleanup.clone().spawn_background_task();
    debug!("File cleanup manager initialized and background task spawned");

    // Clean up any orphaned files from previous runs
    debug!("Cleaning up orphaned files from previous runs...");
    let secrets_dir = PathBuf::from(&config.secrets_dir);
    let cleanup_timeout = config.get_secret_file_cleanup_timeout;
    if let Err(e) = FileCleanupManager::cleanup_orphaned_files(&secrets_dir, cleanup_timeout).await {
        warn!("Warning: Failed to cleanup orphaned files on startup: {}", e);
        eprintln!("⚠️  Warning: Failed to cleanup orphaned files on startup: {}", e);
    } else {
        debug!("Orphaned files cleanup completed");
    }

    debug!("Creating application state...");
    let app_state = AppState {
        sops_client: sops_wrapper,
        docker_client,
        server_config: config,
        ip_cache: Arc::new(RwLock::new(HashMap::new())),
        write_operations: Arc::new(RwLock::new(HashMap::new())),
        file_cleanup,
        rate_limiter: Arc::new(RateLimiter::new(10, 60)),
    };
    debug!("Application state created successfully");

    Ok(app_state)
}

/// Start the server on the specified port
pub async fn start_server(config: ServerConfig, port: u16) -> Result<(), Box<dyn Error>> {
    info!("Starting server on port {}", port);

    debug!("Creating server instance...");
    let app_state = create_server(config).await?;
    let state = Arc::new(app_state);
    debug!("Server instance created");

    // Start cleanup task for write operations only (file cleanup is handled by FileCleanupManager)
    debug!("Starting write operations cleanup task...");
    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            super::utils::cleanup_expired_write_operations(&state_clone).await;
        }
    });
    debug!("Write operations cleanup task started");

    debug!("Creating router...");
    let app = create_router(state);
    debug!("Router created");

    info!("Binding to address 0.0.0.0:{}", port);
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    info!("Starting Axum server...");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    match axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await {
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