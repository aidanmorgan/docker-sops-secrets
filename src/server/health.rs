use std::path::Path;
use tokio::process::Command;

use crate::server::config::ServerConfig;
use crate::server::state::AppState;
use crate::server::models::HealthChecks;

/// Perform comprehensive health checks on the server
pub async fn perform_health_checks(state: &AppState) -> HealthChecks {
    let sops_executable = check_sops_wrapper(state).await;
    let age_executable = check_age_executable(&state.server_config).await;
    let secrets_directory = check_secrets_directory(&state.server_config).await;
    let docker_api = check_docker_api(state).await;
    let sops_file = check_sops_file_path(&state.server_config).await;
    let master_key = check_master_key_path(&state.server_config).await;

    HealthChecks {
        sops_wrapper: sops_executable,
        master_key,
        docker_api,
        age_executable,
        secrets_directory,
        sops_file,
    }
}

/// Check if SOPS executable is available
async fn check_sops_wrapper(state: &AppState) -> bool {
    state.sops_client.validate_sops(None).await.is_ok()
}

/// Check if SOPS file exists
async fn check_sops_file_path(config: &ServerConfig) -> bool {
    std::path::Path::new(&config.sops_file_path).exists()
}

/// Check if master key file exists and is readable
async fn check_master_key_path(config: &ServerConfig) -> bool {
    std::path::Path::new(&config.master_key_path).exists()
}

/// Check if Docker API is accessible
async fn check_docker_api(state: &AppState) -> bool {
    state.docker_client.ping().await.is_ok()
}

/// Check if age executable is available
async fn check_age_executable(config: &ServerConfig) -> bool {
    let output = Command::new(&config.age_executable_path)
        .arg("--version")
        .output()
        .await;

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Check if secrets directory exists and is writable
async fn check_secrets_directory(config: &ServerConfig) -> bool {
    let path = Path::new(&config.secrets_dir);
    if !path.exists() {
        return false;
    }

    // Try to create a temporary file to test write permissions
    let test_file = path.join("test_write_permission");
    match std::fs::File::create(&test_file) {
        Ok(_) => {
            let _ = std::fs::remove_file(test_file);
            true
        }
        Err(_) => false,
    }
} 