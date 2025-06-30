use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use bollard::Docker;

use crate::shared::sops::SopsWrapper;
use crate::shared::sops::SopsConfig;
use super::config::ServerConfig;
use super::state::AppState;
use super::file_cleaner::FileCleanupManager;
use super::rate_limiter::RateLimiter;
use super::handlers::create_router;
use crate::test_log;

/// Create a new server instance
pub async fn create_server(config: ServerConfig) -> Result<AppState, Box<dyn Error>> {
    test_log!("Creating server with configuration: {:?}", config);
    
    test_log!("Initializing SOPS wrapper...");
    let sops_wrapper = SopsWrapper::with_config(SopsConfig {
        sops_path: config.sops_executable_path.clone(),
        file_path: config.sops_file_path.clone(),
        master_key_path: config.master_key_path.clone(),
        default_timeout: Duration::from_secs(config.sops_timeout_seconds),
        env_vars: HashMap::new(),
        working_dir: None,
    });
    test_log!("SOPS wrapper initialized");

    test_log!("Connecting to Docker API...");
    let docker_client = match Docker::connect_with_local_defaults() {
        Ok(client) => {
            test_log!("Docker client connected successfully");
            client
        }
        Err(e) => {
            test_log!("Failed to connect to Docker API: {}", e);
            return Err(Box::new(e));
        }
    };

    test_log!("Initializing file cleanup manager...");
    let file_cleanup = Arc::new(FileCleanupManager::new(
        config.file_cleanup_max_retries,
        config.file_cleanup_retry_delay_seconds,
    ));
    
    file_cleanup.clone().spawn_background_task();
    test_log!("File cleanup manager initialized and background task spawned");

    // Clean up any orphaned files from previous runs
    test_log!("Cleaning up orphaned files from previous runs...");
    let secrets_dir = PathBuf::from(&config.secrets_dir);
    let cleanup_timeout = config.get_secret_file_cleanup_timeout;
    if let Err(e) = FileCleanupManager::cleanup_orphaned_files(&secrets_dir, cleanup_timeout).await {
        test_log!("Warning: Failed to cleanup orphaned files on startup: {}", e);
        eprintln!("⚠️  Warning: Failed to cleanup orphaned files on startup: {}", e);
    } else {
        test_log!("Orphaned files cleanup completed");
    }

    test_log!("Creating application state...");
    let app_state = AppState {
        sops_client: sops_wrapper,
        docker_client,
        server_config: config,
        ip_cache: Arc::new(RwLock::new(HashMap::new())),
        write_operations: Arc::new(RwLock::new(HashMap::new())),
        file_cleanup,
        rate_limiter: Arc::new(RateLimiter::new(10, 60)),
    };
    test_log!("Application state created successfully");

    Ok(app_state)
}

/// Start the server on the specified port
pub async fn start_server(config: ServerConfig, port: u16) -> Result<(), Box<dyn Error>> {
    test_log!("Starting server on port {}", port);
    
    test_log!("Creating server instance...");
    let app_state = create_server(config).await?;
    let state = Arc::new(app_state);
    test_log!("Server instance created");

    // Start cleanup task for write operations only (file cleanup is handled by FileCleanupManager)
    test_log!("Starting write operations cleanup task...");
    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            super::utils::cleanup_expired_write_operations(&state_clone).await;
        }
    });
    test_log!("Write operations cleanup task started");

    test_log!("Creating router...");
    let app = create_router(state);
    test_log!("Router created");

    test_log!("Binding to address 0.0.0.0:{}", port);
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        Ok(listener) => {
            test_log!("Successfully bound to port {}", port);
            listener
        }
        Err(e) => {
            test_log!("Failed to bind to port {}: {}", port, e);
            return Err(Box::new(e));
        }
    };
    
    test_log!("Starting Axum server...");
    match axum::serve(listener, app).await {
        Ok(_) => {
            test_log!("Server stopped normally");
            Ok(())
        }
        Err(e) => {
            test_log!("Server error: {}", e);
            Err(Box::new(e))
        }
    }
} 