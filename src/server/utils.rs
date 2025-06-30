use std::net::IpAddr;
use std::ops::Add;
use std::time::Duration;
use chrono::Utc;
use regex::Regex;
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

use crate::shared::{SopsWrapper, SecretData};
use crate::server::errors::ServerError;
use crate::server::docker::{ContainerCache, ContainerCacheEntry, ContainerInfo, perform_comprehensive_validation, DockerError};
use crate::shared::age::encrypt_with_age_public_key;
use crate::server::config::DockerValidationOptions;

lazy_static! {
    static ref AGE_PUBLIC_KEY_REGEX: Regex = Regex::new(r"^age1[a-z0-9]{58}$").unwrap();
}

/// Enhanced client validation with comprehensive security checks
pub async fn validate_client_with_timeout(
    cache: &ContainerCache,
    docker: &bollard::Docker,
    client_ip: &IpAddr,
    validation_options: &DockerValidationOptions,
) -> Result<ContainerInfo, ServerError> {
    let now = Utc::now();

    // Check cache first for performance
    let rr = cache.read().await;
    if rr.contains_key(&client_ip.to_string()) {
        let entry = &rr[&client_ip.to_string()];
        if entry.expires_at <= now.timestamp_millis() {
            // Cache expired, remove it
            cache.write().await.remove(&client_ip.to_string());
        } else {
            // Cache hit, but we still need to perform validation
            // For now, we'll proceed with full validation for security
        }
    }

    let docker_timeout = Duration::from_secs(validation_options.timeout_seconds);
    
    // Use comprehensive validation with configurable options
    let result = tokio::time::timeout(
        docker_timeout,
        perform_comprehensive_validation(
            docker,
            &client_ip.to_string(),
            &validation_options.docker_network_name,
            validation_options
        )
    )
    .await
    .map_err(|_| ServerError::DockerTimeout)?
    .map_err(|e| match e {
        DockerError::DockerApi(api_error) => ServerError::DockerApi(api_error.to_string()),
        DockerError::ContainerNotFound(ip) => ServerError::DockerApi(format!("Container not found for IP: {}", ip)),
        DockerError::InvalidIpAddress(msg) => ServerError::DockerApi(msg),
        DockerError::InspectionFailed(msg) => ServerError::DockerApi(msg),
        DockerError::NetworkValidation(msg) => ServerError::DockerApi(msg),
        DockerError::StateValidation(msg) => ServerError::DockerApi(msg),
        DockerError::LabelValidation(msg) => ServerError::DockerApi(msg),
        DockerError::RegistryValidation(msg) => ServerError::DockerApi(msg),
        DockerError::Timeout(msg) => ServerError::DockerApi(msg),
    })?;

    // Cache the result for future requests
    let mut wr = cache.write().await;
    wr.insert(client_ip.to_string(), ContainerCacheEntry {
        container_name: result.name.clone(),
        expires_at: Utc::now().add(Duration::from_secs(validation_options.timeout_seconds * 2)).timestamp_millis() as i64
    });

    Ok(result)
}

/// Check authorization with timeout
pub async fn check_read_permission_with_timeout(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    timeout: u64,
) -> Result<bool, ServerError> {
    let data = get_secret_data_with_timeout(sops_client, secret_name, timeout).await?;

    if data.owner == client_name || data.can_read(client_name) {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Get secret data with timeout
pub async fn get_secret_data_with_timeout(
    sops_client: &SopsWrapper,
    secret_name: &str,
    timeout: u64,
) -> Result<SecretData, ServerError> {
    let sops_timeout = Duration::from_secs(timeout);
    sops_client.get_secret_data(secret_name, Some(sops_timeout))
        .await
        .map_err(ServerError::Sops)
}

/// Encrypt data with age using timeout
pub async fn encrypt_with_age_timeout(
    _age_executable_path: &str,
    public_key: &str,
    data: &str,
    timeout_seconds: u64,
) -> Result<Vec<u8>, ServerError> {
    let age_timeout = Duration::from_secs(timeout_seconds);
    let public_key = public_key.to_string();
    let data = data.to_string();

    tokio::time::timeout(
        age_timeout,
        encrypt_with_age_public_key(&public_key, &data, age_timeout)
    )
    .await
    .map_err(|_| ServerError::AgeTimeout)?
    .map_err(|e| ServerError::AgeEncryption(format!("Encryption error: {}", e)))
}

/// Check write permission with timeout
pub async fn check_write_permission_with_timeout(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    timeout: u64,
) -> Result<bool, ServerError> {
    let data = get_secret_data_with_timeout(sops_client, secret_name, timeout).await?;
    if data.owner == client_name || data.can_write(client_name) {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Update secret with timeout
pub async fn update_secret_with_timeout(
    sops_client: &SopsWrapper,
    secret_name: &str,
    secret_value: &str,
    timeout: u64,
) -> Result<(), ServerError> {
    let sops_timeout = Duration::from_secs(timeout);
    sops_client.update_secret_value(secret_name, secret_value, Some(sops_timeout))
        .await
        .map_err(ServerError::Sops)
}

/// Create new secret with timeout
pub async fn create_secret_with_timeout(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    secret_value: &str,
    timeout: u64,
) -> Result<(), ServerError> {
    let sops_timeout = Duration::from_secs(timeout);
    sops_client.add_owned_secret(client_name, secret_name, secret_value, &[], &[], Some(sops_timeout))
        .await
        .map_err(ServerError::Sops)
}

/// Validate age public key format
pub fn is_valid_age_public_key(public_key: &str) -> bool {
    AGE_PUBLIC_KEY_REGEX.is_match(public_key)
}

/// Calculate SHA256 hash of secret value
pub fn calculate_secret_hash(secret_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret_value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Cleanup expired write operations
pub async fn cleanup_expired_write_operations(state: &crate::server::state::AppState) {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0))
        .as_secs();
    
    let mut write_ops = state.write_operations.write().await;
    write_ops.retain(|_, op| current_time <= op.expires_at);
} 