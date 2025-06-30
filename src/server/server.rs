use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use bollard::Docker;

use crate::shared::SopsWrapper;
use super::config::ServerConfig;
use super::state::AppState;
use super::file_cleaner::FileCleanupManager;
use super::rate_limiter::RateLimiter;
use super::handlers::create_router;

/// Create a new server instance
pub async fn create_server(config: ServerConfig) -> Result<AppState, Box<dyn Error>> {
    let sops_wrapper = SopsWrapper::with_config(crate::shared::SopsConfig {
        sops_path: config.sops_executable_path.clone(),
        file_path: config.sops_file_path.clone(),
        master_key_path: config.master_key_path.clone(),
        default_timeout: Duration::from_secs(config.sops_timeout_seconds),
        env_vars: HashMap::new(),
        working_dir: None,
    });

    let docker_client = Docker::connect_with_local_defaults()?;

    let file_cleanup = Arc::new(FileCleanupManager::new(
        config.file_cleanup_max_retries,
        config.file_cleanup_retry_delay_seconds,
    ));
    
    file_cleanup.clone().spawn_background_task();

    // Clean up any orphaned files from previous runs
    let secrets_dir = PathBuf::from(&config.secrets_dir);
    let cleanup_timeout = config.get_secret_file_cleanup_timeout;
    if let Err(e) = FileCleanupManager::cleanup_orphaned_files(&secrets_dir, cleanup_timeout).await {
        eprintln!("⚠️  Warning: Failed to cleanup orphaned files on startup: {}", e);
    }

    let app_state = AppState {
        sops_client: sops_wrapper,
        docker_client,
        server_config: config,
        ip_cache: Arc::new(RwLock::new(HashMap::new())),
        write_operations: Arc::new(RwLock::new(HashMap::new())),
        file_cleanup,
        rate_limiter: Arc::new(RateLimiter::new(10, 60)),
    };

    Ok(app_state)
}

/// Start the server on the specified port
pub async fn start_server(config: ServerConfig, port: u16) -> Result<(), Box<dyn Error>> {
    let app_state = create_server(config).await?;
    let state = Arc::new(app_state);

    // Start cleanup task for write operations only (file cleanup is handled by FileCleanupManager)
    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            super::utils::cleanup_expired_write_operations(&state_clone).await;
        }
    });

    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    axum::serve(listener, app).await?;

    Ok(())
} 