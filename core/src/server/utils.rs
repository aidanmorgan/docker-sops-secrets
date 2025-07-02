use chrono::Utc;
use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::ops::Add;
use std::time::Duration;

use crate::server::config::DockerValidationOptions;
use crate::server::docker::{perform_comprehensive_validation, ContainerCache, ContainerCacheEntry, ContainerInfo, DockerError};
use crate::server::errors::ServerError;
use crate::shared::age::encrypt_with_age_public_key;
use crate::shared::sops::{SecretData, SopsWrapper};

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
    info!("Starting client validation for IP: {}", client_ip);
    debug!("Validation options: {:?}", validation_options);

    let now = Utc::now();

    // Check cache first for performance
    debug!("Checking IP cache for {}", client_ip);
    let rr = cache.read().await;
    if rr.contains_key(&client_ip.to_string()) {
        let entry = &rr[&client_ip.to_string()];
        debug!("Cache hit for IP {}: container={}, expires_at={}", client_ip, entry.container_name, entry.expires_at);
        if entry.expires_at <= now.timestamp_millis() {
            debug!("Cache entry expired for IP {}", client_ip);
            // Cache expired, remove it
            cache.write().await.remove(&client_ip.to_string());
        } else {
            debug!("Cache entry still valid for IP {}", client_ip);
            // Cache hit, but we still need to perform validation
            // For now, we'll proceed with full validation for security
        }
    } else {
        debug!("No cache entry found for IP {}", client_ip);
    }

    let docker_timeout = Duration::from_secs(validation_options.timeout_seconds);
    debug!("Docker timeout set to {:?}", docker_timeout);

    // Use comprehensive validation with configurable options
    info!("Starting comprehensive Docker validation...");
    let result = tokio::time::timeout(
        docker_timeout,
        perform_comprehensive_validation(
            docker,
            &client_ip.to_string(),
            &validation_options.docker_network_name,
            validation_options,
        ),
    )
        .await
        .map_err(|_| {
            warn!("Docker validation timed out after {:?}", docker_timeout);
            ServerError::DockerTimeout
        })?
        .map_err(|e| {
            error!("Docker validation failed: {:?}", e);
            match e {
                DockerError::DockerApi(api_error) => ServerError::DockerApi(api_error.to_string()),
                DockerError::ContainerNotFound(ip) => ServerError::DockerApi(format!("Container not found for IP: {}", ip)),
                DockerError::InvalidIpAddress(msg) => ServerError::DockerApi(msg),
                DockerError::InspectionFailed(msg) => ServerError::DockerApi(msg),
                DockerError::NetworkValidation(msg) => ServerError::DockerApi(msg),
                DockerError::StateValidation(msg) => ServerError::DockerApi(msg),
                DockerError::LabelValidation(msg) => ServerError::DockerApi(msg),
                DockerError::RegistryValidation(msg) => ServerError::DockerApi(msg),
                DockerError::Timeout(msg) => ServerError::DockerApi(msg),
            }
        })?;

    info!("Docker validation successful: container={}, image={}", result.name, result.image);

    // Cache the result for future requests
    let cache_duration = validation_options.timeout_seconds * 2;
    debug!("Caching result for {} seconds", cache_duration);
    let mut wr = cache.write().await;
    wr.insert(client_ip.to_string(), ContainerCacheEntry {
        container_name: result.name.clone(),
        expires_at: Utc::now().add(Duration::from_secs(cache_duration)).timestamp_millis() as i64,
    });

    info!("Client validation completed successfully for IP: {}", client_ip);
    Ok(result)
}

/// Enhanced client validation with header support for testing mode
pub async fn validate_docker_client_for_request(
    _cache: &ContainerCache,
    _docker: &bollard::Docker,
    _client_ip: &IpAddr,
    headers: &axum::http::HeaderMap,
    _validation_options: &DockerValidationOptions,
) -> Result<ContainerInfo, ServerError> {
    #[cfg(feature = "insecure_mode")]
    {
        // Extract client name from X-Client-Name header
        let client_name = headers
            .get("X-Client-Name")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("test-client");
        info!("LOCAL MODE: Using client name from header: {}", client_name);
        return Ok(ContainerInfo {
            name: client_name.to_string(),
            image: "test-image".to_string(),
            image_name_no_version: "test-image".to_string(),
            state: "running".to_string(),
            labels: std::collections::HashMap::new(),
            networks: std::collections::HashMap::new(),
        });
    }
    #[cfg(not(feature = "insecure_mode"))]
    {
        // Normal Docker validation
        validate_client_with_timeout(_cache, _docker, _client_ip, _validation_options).await
    }
}

/// Check authorization with timeout
pub async fn check_read_permission_with_timeout(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    timeout: u64,
) -> Result<bool, ServerError> {
    info!("Checking read permission for client '{}' on secret '{}'", client_name, secret_name);

    let data = get_secret_data_with_timeout(sops_client, secret_name, timeout).await?;
    debug!("Secret data retrieved: owner='{}', can_read={:?}", data.owner, data.can_read(client_name));

    if data.owner == client_name || data.can_read(client_name) {
        info!("Read permission granted for client '{}' on secret '{}'", client_name, secret_name);
        Ok(true)
    } else {
        warn!("Read permission denied for client '{}' on secret '{}'", client_name, secret_name);
        Ok(false)
    }
}

/// Check if a secret exists with timeout using fast JSON parsing
pub async fn check_secret_exists_with_timeout(
    sops_client: &SopsWrapper,
    secret_name: &str,
    timeout: u64,
) -> Result<bool, ServerError> {
    debug!("Checking if secret exists (fast): secret_name='{}', timeout={}s", secret_name, timeout);

    // Create the secret key that would be used in the SOPS file
    let secret_key = format!("{}_secret", secret_name);

    let sops_timeout = Duration::from_secs(timeout);
    let result = sops_client.key_exists(&secret_key, Some(sops_timeout), None)
        .await
        .map_err(|e| {
            error!("Failed to check if secret '{}' exists (fast): {:?}", secret_name, e);
            ServerError::Sops(e)
        });

    match &result {
        Ok(exists) => {
            debug!("Secret '{}' exists check result: {}", secret_name, exists);
        }
        Err(e) => {
            warn!("Secret '{}' exists check failed: {:?}", secret_name, e);
        }
    }

    result
}

/// Get secret data with timeout
pub async fn get_secret_data_with_timeout(
    sops_client: &SopsWrapper,
    secret_name: &str,
    timeout: u64,
) -> Result<SecretData, ServerError> {
    debug!("Getting secret data for '{}' with timeout {}s", secret_name, timeout);
    let sops_timeout = Duration::from_secs(timeout);
    let result = sops_client.get_secret_data(secret_name, Some(sops_timeout))
        .await
        .map_err(|e| {
            error!("Failed to get secret data for '{}': {:?}", secret_name, e);
            ServerError::Sops(e)
        });

    match &result {
        Ok(_data) => { info!("Successfully retrieved secret data for '{}'", secret_name); }
        Err(_) => { warn!("Failed to retrieve secret data for '{}'", secret_name); }
    }

    result
}

/// Encrypt data with age using timeout
pub async fn encrypt_with_age_timeout(
    _age_executable_path: &str,
    public_key: &str,
    data: &str,
    timeout_seconds: u64,
) -> Result<Vec<u8>, ServerError> {
    debug!("Encrypting data with age: public_key_length={}, data_length={}, timeout={}s", public_key.len(), data.len(), timeout_seconds);

    let age_timeout = Duration::from_secs(timeout_seconds);
    let public_key = public_key.to_string();
    let data = data.to_string();

    let result = tokio::time::timeout(
        age_timeout,
        encrypt_with_age_public_key(&public_key, &data, age_timeout),
    )
        .await
        .map_err(|_| {
            warn!("Age encryption timed out after {:?}", age_timeout);
            ServerError::AgeTimeout
        })?
        .map_err(|e| {
            error!("Age encryption failed: {:?}", e);
            ServerError::AgeEncryption(format!("Encryption error: {}", e))
        });

    match &result {
        Ok(encrypted_data) => { info!("Age encryption successful, encrypted data length: {}", encrypted_data.len()); }
        Err(e) => { error!("Age encryption failed: {:?}", e); }
    }

    result
}

/// Check write permission with timeout
pub async fn check_write_permission_with_timeout(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    timeout: u64,
) -> Result<bool, ServerError> {
    info!("Checking write permission for client '{}' on secret '{}'", client_name, secret_name);

    let data = get_secret_data_with_timeout(sops_client, secret_name, timeout).await?;
    debug!("Secret data retrieved: owner='{}', can_write={:?}", data.owner, data.can_write(client_name));

    if data.owner == client_name || data.can_write(client_name) {
        info!("Write permission granted for client '{}' on secret '{}'", client_name, secret_name);
        Ok(true)
    } else {
        warn!("Write permission denied for client '{}' on secret '{}'", client_name, secret_name);
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
    debug!("Updating secret '{}' with timeout {}s", secret_name, timeout);
    let sops_timeout = Duration::from_secs(timeout);
    let result = sops_client.update_secret_value(secret_name, secret_value, Some(sops_timeout))
        .await
        .map_err(|e| {
            error!("Failed to update secret '{}': {:?}", secret_name, e);
            ServerError::Sops(e)
        });

    match &result {
        Ok(_) => { info!("Successfully updated secret '{}'", secret_name); }
        Err(_) => { warn!("Failed to update secret '{}'", secret_name); }
    }

    result
}

/// Create new secret with timeout
pub async fn create_secret_with_timeout(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    secret_value: &str,
    timeout: u64,
) -> Result<(), ServerError> {
    debug!("Creating new secret '{}' for client '{}' with timeout {}s", secret_name, client_name, timeout);
    let sops_timeout = Duration::from_secs(timeout);
    let result = sops_client.add_owned_secret(client_name, secret_name, secret_value, &[], &[], Some(sops_timeout))
        .await
        .map_err(|e| {
            error!("Failed to create secret '{}' for client '{}': {:?}", secret_name, client_name, e);
            ServerError::Sops(e)
        });

    match &result {
        Ok(_) => { info!("Successfully created secret '{}' for client '{}'", secret_name, client_name); }
        Err(_) => { warn!("Failed to create secret '{}' for client '{}'", secret_name, client_name); }
    }

    result
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