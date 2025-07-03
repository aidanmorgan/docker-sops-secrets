use tokio::time::{timeout, Duration};
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;

use crate::server::config::ServerConfig;
use crate::server::models::HealthChecks;
use crate::server::state::AppState;
use crate::sops::SopsWrapper;
use bollard::Docker;

// Static thread pool for health checks
static HEALTH_CHECK_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Perform comprehensive health checks on the server
pub async fn perform_health_checks(state: &AppState) -> HealthChecks {
    log::info!("Starting comprehensive health checks...");

    // Get or create the static runtime
    let runtime = HEALTH_CHECK_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("Failed to create health check runtime")
    });

    // Set timeout for all health checks (5 seconds)
    let health_check_timeout = Duration::from_secs(5);

    // Clone the Arc references for each spawned task
    let sops_client = Arc::clone(&state.sops_client);
    let docker_client = Arc::clone(&state.docker_client);
    let server_config_1 = Arc::clone(&state.server_config);
    let server_config_2 = Arc::clone(&state.server_config);
    let server_config_3 = Arc::clone(&state.server_config);

    // Spawn health checks on the dedicated runtime and collect handles
    let handles = vec![
        runtime.spawn(async move { check_sops_wrapper_static(&sops_client).await }),
        runtime.spawn(async move { check_working_directory(&server_config_1).await }),
        runtime.spawn(async move { check_docker_api_static(&docker_client).await }),
        runtime.spawn(async move { check_sops_file_path(&server_config_2).await }),
        runtime.spawn(async move { check_master_key_path(&server_config_3).await }),
    ];

    // Wait for all checks to complete with timeout and extract results cleanly
    let results = timeout(health_check_timeout, async {
        futures::future::join_all(handles).await
            .into_iter()
            .map(|handle| handle.unwrap_or(false))
            .collect::<Vec<bool>>()
    }).await;

    let results = results.unwrap_or_else(|_| vec![false; 5]);
    let [sops_wrapper, secrets_directory, docker_api, sops_file, master_key] = 
        results.as_slice() else { unreachable!() };

    log::debug!("SOPS wrapper check: {}", sops_wrapper);
    log::debug!("Secrets directory check: {}", secrets_directory);
    log::debug!("Docker API check: {}", docker_api);
    log::debug!("SOPS file check: {}", sops_file);
    log::debug!("Master key check: {}", master_key);

    let result = HealthChecks {
        sops_wrapper: *sops_wrapper,
        master_key: *master_key,
        docker_api: *docker_api,
        secrets_directory: *secrets_directory,
        sops_file: *sops_file,
    };

    log::info!("Health check results: {:?}", result);
    result
}

/// Check if SOPS executable is available (static version for parallel execution)
async fn check_sops_wrapper_static(sops_client: &Arc<SopsWrapper>) -> bool {
    log::info!("Checking SOPS wrapper...");
    let result = sops_client.validate_sops(None).await.is_ok();
    log::info!("SOPS wrapper validation result: {}", result);
    result
}

/// Check if SOPS executable is available
async fn check_sops_wrapper(state: &AppState) -> bool {
    check_sops_wrapper_static(&state.sops_client).await
}

/// Check if SOPS file exists
async fn check_sops_file_path(config: &Arc<ServerConfig>) -> bool {
    log::info!("Checking SOPS file path: {}", config.sops_file_path().display());
    let path = config.sops_file_path();
    let exists = path.exists();
    log::info!("SOPS file exists: {} (path: {:?})", exists, path);
    exists
}

/// Check if master key file exists and is readable
async fn check_master_key_path(config: &Arc<ServerConfig>) -> bool {
    log::info!("Checking master key path: {}", config.master_key_path().display());
    let path = config.master_key_path();
    let exists = path.exists();
    log::info!("Master key exists: {} (path: {:?})", exists, path);
    exists
}

/// Check if Docker API is accessible
async fn check_docker_api(state: &AppState) -> bool {
    check_docker_api_static(&state.docker_client).await
}

/// Check if Docker API is accessible (static version for parallel execution)
async fn check_docker_api_static(docker_client: &Arc<Docker>) -> bool {
    log::info!("Checking Docker API connectivity...");
    match docker_client.ping().await {
        Ok(_) => {
            log::info!("Docker API ping successful");
            true
        }
        Err(e) => {
            log::info!("Docker API ping failed: {}", e);
            false
        }
    }
}

/// Check if secrets directory exists and is writable
async fn check_working_directory(config: &Arc<ServerConfig>) -> bool {
    log::info!("Checking secrets directory: {}", config.secrets_dir().display());
    let path = config.secrets_dir();
    if !path.exists() {
        log::info!("Secrets directory does not exist: {:?}", path);
        return false;
    }
    log::info!("Secrets directory exists: {:?}", path);

    // Try to create a temporary file to test write permissions
    let test_file = path.join("test_write_permission");
    log::info!("Testing write permissions with file: {:?}", test_file);
    match std::fs::File::create(&test_file) {
        Ok(_) => {
            let _ = std::fs::remove_file(test_file);
            log::info!("Secrets directory is writable");
            true
        }
        Err(e) => {
            log::info!("Secrets directory is not writable: {}", e);
            false
        }
    }
}
