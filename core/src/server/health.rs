use std::path::Path;
use tokio::process::Command;

use crate::server::config::ServerConfig;
use crate::server::models::HealthChecks;
use crate::server::state::AppState;


/// Perform comprehensive health checks on the server
pub async fn perform_health_checks(state: &AppState) -> HealthChecks {
    log::info!("Starting comprehensive health checks...");

    let sops_executable = check_sops_wrapper(state).await;
    log::info!("SOPS wrapper check: {}", sops_executable);

    let age_executable = check_age_executable(&state.server_config).await;
    log::info!("Age executable check: {}", age_executable);

    let secrets_directory = check_secrets_directory(&state.server_config).await;
    log::info!("Secrets directory check: {}", secrets_directory);

    let docker_api = check_docker_api(state).await;
    log::info!("Docker API check: {}", docker_api);

    let sops_file = check_sops_file_path(&state.server_config).await;
    log::info!("SOPS file check: {}", sops_file);

    let master_key = check_master_key_path(&state.server_config).await;
    log::info!("Master key check: {}", master_key);

    let result = HealthChecks {
        sops_wrapper: sops_executable,
        master_key,
        docker_api,
        age_executable,
        secrets_directory,
        sops_file,
    };

    log::info!("Health check results: {:?}", result);
    result
}

/// Check if SOPS executable is available
async fn check_sops_wrapper(state: &AppState) -> bool {
    log::info!("Checking SOPS wrapper...");
    let result = state.sops_client.validate_sops(None).await.is_ok();
    log::info!("SOPS wrapper validation result: {}", result);
    result
}

/// Check if SOPS file exists
async fn check_sops_file_path(config: &ServerConfig) -> bool {
    log::info!("Checking SOPS file path: {}", config.sops_file_path);
    let path = std::path::Path::new(&config.sops_file_path);
    let exists = path.exists();
    log::info!("SOPS file exists: {} (path: {:?})", exists, path);
    exists
}

/// Check if master key file exists and is readable
async fn check_master_key_path(config: &ServerConfig) -> bool {
    log::info!("Checking master key path: {}", config.master_key_path);
    let path = std::path::Path::new(&config.master_key_path);
    let exists = path.exists();
    log::info!("Master key exists: {} (path: {:?})", exists, path);
    exists
}

/// Check if Docker API is accessible
async fn check_docker_api(state: &AppState) -> bool {
    log::info!("Checking Docker API connectivity...");
    match state.docker_client.ping().await {
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

/// Check if age executable is available
async fn check_age_executable(config: &ServerConfig) -> bool {
    log::info!("Checking age executable: {}", config.age_executable_path);
    let output = Command::new(&config.age_executable_path)
        .arg("--version")
        .output()
        .await;

    match output {
        Ok(output) => {
            let success = output.status.success();
            log::info!("Age executable check result: {} (exit code: {})", success, output.status);
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                log::info!("Age version output: {}", stdout.trim());
            }
            success
        }
        Err(e) => {
            log::info!("Age executable check failed: {}", e);
            false
        }
    }
}

/// Check if secrets directory exists and is writable
async fn check_secrets_directory(config: &ServerConfig) -> bool {
    log::info!("Checking secrets directory: {}", config.secrets_dir);
    let path = Path::new(&config.secrets_dir);
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