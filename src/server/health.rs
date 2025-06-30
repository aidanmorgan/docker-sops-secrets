use std::path::Path;
use tokio::process::Command;

use crate::server::config::ServerConfig;
use crate::server::state::AppState;
use crate::server::models::HealthChecks;
use crate::test_log;

/// Perform comprehensive health checks on the server
pub async fn perform_health_checks(state: &AppState) -> HealthChecks {
    test_log!("Starting comprehensive health checks...");
    
    let sops_executable = check_sops_wrapper(state).await;
    test_log!("SOPS wrapper check: {}", sops_executable);
    
    let age_executable = check_age_executable(&state.server_config).await;
    test_log!("Age executable check: {}", age_executable);
    
    let secrets_directory = check_secrets_directory(&state.server_config).await;
    test_log!("Secrets directory check: {}", secrets_directory);
    
    let docker_api = check_docker_api(state).await;
    test_log!("Docker API check: {}", docker_api);
    
    let sops_file = check_sops_file_path(&state.server_config).await;
    test_log!("SOPS file check: {}", sops_file);
    
    let master_key = check_master_key_path(&state.server_config).await;
    test_log!("Master key check: {}", master_key);

    let result = HealthChecks {
        sops_wrapper: sops_executable,
        master_key,
        docker_api,
        age_executable,
        secrets_directory,
        sops_file,
    };
    
    test_log!("Health check results: {:?}", result);
    result
}

/// Check if SOPS executable is available
async fn check_sops_wrapper(state: &AppState) -> bool {
    test_log!("Checking SOPS wrapper...");
    let result = state.sops_client.validate_sops(None).await.is_ok();
    test_log!("SOPS wrapper validation result: {}", result);
    result
}

/// Check if SOPS file exists
async fn check_sops_file_path(config: &ServerConfig) -> bool {
    test_log!("Checking SOPS file path: {}", config.sops_file_path);
    let path = std::path::Path::new(&config.sops_file_path);
    let exists = path.exists();
    test_log!("SOPS file exists: {} (path: {:?})", exists, path);
    exists
}

/// Check if master key file exists and is readable
async fn check_master_key_path(config: &ServerConfig) -> bool {
    test_log!("Checking master key path: {}", config.master_key_path);
    let path = std::path::Path::new(&config.master_key_path);
    let exists = path.exists();
    test_log!("Master key exists: {} (path: {:?})", exists, path);
    exists
}

/// Check if Docker API is accessible
async fn check_docker_api(state: &AppState) -> bool {
    test_log!("Checking Docker API connectivity...");
    match state.docker_client.ping().await {
        Ok(_) => {
            test_log!("Docker API ping successful");
            true
        }
        Err(e) => {
            test_log!("Docker API ping failed: {}", e);
            false
        }
    }
}

/// Check if age executable is available
async fn check_age_executable(config: &ServerConfig) -> bool {
    test_log!("Checking age executable: {}", config.age_executable_path);
    let output = Command::new(&config.age_executable_path)
        .arg("--version")
        .output()
        .await;

    match output {
        Ok(output) => {
            let success = output.status.success();
            test_log!("Age executable check result: {} (exit code: {})", success, output.status);
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                test_log!("Age version output: {}", stdout.trim());
            }
            success
        }
        Err(e) => {
            test_log!("Age executable check failed: {}", e);
            false
        }
    }
}

/// Check if secrets directory exists and is writable
async fn check_secrets_directory(config: &ServerConfig) -> bool {
    test_log!("Checking secrets directory: {}", config.secrets_dir);
    let path = Path::new(&config.secrets_dir);
    if !path.exists() {
        test_log!("Secrets directory does not exist: {:?}", path);
        return false;
    }
    test_log!("Secrets directory exists: {:?}", path);

    // Try to create a temporary file to test write permissions
    let test_file = path.join("test_write_permission");
    test_log!("Testing write permissions with file: {:?}", test_file);
    match std::fs::File::create(&test_file) {
        Ok(_) => {
            let _ = std::fs::remove_file(test_file);
            test_log!("Secrets directory is writable");
            true
        }
        Err(e) => {
            test_log!("Secrets directory is not writable: {}", e);
            false
        }
    }
} 