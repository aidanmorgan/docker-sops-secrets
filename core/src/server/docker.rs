use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{debug, error, info, warn};
use chrono::Utc;

use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use bollard::Docker;

use thiserror::Error;

// Import the test_log macro from crate root


/// Docker-specific error types
#[derive(Error, Debug)]
pub enum DockerError {
    #[error("Invalid IP address format: {0}")]
    InvalidIpAddress(String),

    #[error("Container not found for IP: {0}")]
    ContainerNotFound(String),

    #[error("Docker API error: {0}")]
    DockerApi(#[from] bollard::errors::Error),

    #[error("Container inspection failed: {0}")]
    InspectionFailed(String),

    #[error("Network validation failed: {0}")]
    NetworkValidation(String),

    #[error("Container state validation failed: {0}")]
    StateValidation(String),

    #[error("Label validation failed: {0}")]
    LabelValidation(String),

    #[error("Registry validation failed: {0}")]
    RegistryValidation(String),

    #[error("Timeout error: {0}")]
    Timeout(String),
}

/// Cache entry for container name mapping
#[derive(Debug, Clone)]
pub struct ContainerCacheEntry {
    pub container_name: String,
    pub expires_at: i64,
}

/// Extended container information for validation
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub name: String,
    pub image: String,
    pub image_name_no_version: String,
    pub state: String,
    pub labels: HashMap<String, String>,
    pub networks: HashMap<String, String>, // network name -> IP address
}

/// Cache for IP to container mapping to avoid repeated Docker API calls
pub type ContainerCache = Arc<RwLock<HashMap<String, ContainerCacheEntry>>>;

/// Create a new container cache
pub fn create_container_cache() -> ContainerCache {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Enhanced container validatio
/// n with multiple security checks
async fn validate_container_security(
    docker_client: &Docker,
    client_ip: &String,
    network_name: &Option<String>,
    list_options: Option<ListContainersOptionsBuilder>,
    inspect_options: Option<InspectContainerOptionsBuilder>,
) -> Result<ContainerInfo, DockerError> {
    info!("Starting container security validation for IP: {}", client_ip);
    info!("Network filter: {:?}", network_name);

    // Validate IP address format
    info!("Validating IP address format: {}", client_ip);
    let _parsed_ip: IpAddr = client_ip.parse()
        .map_err(|e| {
            info!("Invalid IP address format: {}", e);
            DockerError::InvalidIpAddress(format!("Failed to parse IP {}: {}", client_ip, e))
        })?;
    info!("IP address format is valid");

    // Query Docker API for all containers
    info!("Querying Docker API for containers...");
    let containers = match docker_client.list_containers(
        list_options.map(|o| o.build()).or(Some(ListContainersOptionsBuilder::new().all(true).build()))
    ).await {
        Ok(containers) => {
            info!("Successfully retrieved {} containers from Docker API", containers.len());
            containers
        }
        Err(e) => {
            info!("Failed to list containers from Docker API: {}", e);
            return Err(DockerError::DockerApi(e));
        }
    };

    info!("Searching for container with IP: {}", client_ip);
    for (i, container) in containers.iter().enumerate() {
        info!("Checking container {}: id={:?}, name={:?}", i, container.id, container.names);

        if let Some(network_settings) = &container.network_settings {
            if let Some(networks) = &network_settings.networks {
                info!("Container has {} networks", networks.len());
                for (net_name, net) in networks {
                    debug!("Checking network '{}' with IP: {:?}", net_name, net.ip_address);

                    // If a specific network is requested, only check that network
                    if let Some(requested_network) = network_name {
                        if requested_network != net_name {
                            debug!("Skipping network '{}' (not requested)", net_name);
                            continue;
                        }
                    }

                    if let Some(ip_str) = &net.ip_address {
                        info!("Comparing IP {} with target {}", ip_str, client_ip);
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            if ip.to_string() == *client_ip {
                                debug!("Found matching container with IP {}: {:?}", client_ip, container.id);
                                if let Some(container_id) = &container.id {
                                    debug!("Getting detailed container info for {}", container_id);
                                    return get_detailed_container_info(docker_client, container_id, inspect_options).await;
                                }
                            }
                        } else {
                            info!("Failed to parse IP address: {}", ip_str);
                        }
                    } else {
                        info!("No IP address found for network '{}'", net_name);
                    }
                }
            } else {
                info!("Container has no networks");
            }
        } else {
            info!("Container has no network settings");
        }
    }

    info!("No container found with IP: {}", client_ip);
    Err(DockerError::ContainerNotFound(client_ip.to_string()))
}

/// Get detailed container information for security validation
async fn get_detailed_container_info(
    docker_client: &Docker,
    container_id: &str,
    inspect_options: Option<InspectContainerOptionsBuilder>,
) -> Result<ContainerInfo, DockerError> {
    let inspect_options = inspect_options
        .map(|o| o.build())
        .unwrap_or_else(|| InspectContainerOptionsBuilder::default().build());
    let container_details = docker_client.inspect_container(container_id, Some(inspect_options)).await?;

    let state = container_details.state
        .and_then(|s| s.status)
        .map(|status| status.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let config = container_details.config;
    let labels = config.as_ref()
        .and_then(|c| c.labels.as_ref())
        .map(|l| l.clone())
        .unwrap_or_default();

    let image = config
        .as_ref()
        .and_then(|c| c.image.as_ref())
        .map(|i| i.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let image_name_no_version = extract_image_name_without_version(&image);

    let name = container_details.name
        .unwrap_or_else(|| "unknown".to_string())
        .trim_start_matches('/')
        .to_string();

    // Build networks HashMap from container details
    let mut networks = HashMap::new();
    if let Some(network_settings) = container_details.network_settings {
        if let Some(networks_data) = network_settings.networks {
            for (net_name, net) in networks_data {
                if let Some(ip_str) = net.ip_address {
                    networks.insert(net_name, ip_str);
                }
            }
        }
    }

    Ok(ContainerInfo {
        name,
        image,
        image_name_no_version,
        state,
        labels,
        networks,
    })
}

/// Validate container is in a healthy/running state
pub fn validate_container_state(container_info: &ContainerInfo) -> Result<(), DockerError> {
    match container_info.state.as_str() {
        "running" => Ok(()),
        "created" | "restarting" => Err(DockerError::StateValidation("Container is not in running state".to_string())),
        "paused" => Err(DockerError::StateValidation("Container is paused".to_string())),
        "exited" | "dead" => Err(DockerError::StateValidation("Container is not running".to_string())),
        _ => Err(DockerError::StateValidation(format!("Unknown container state: {}", container_info.state))),
    }
}

/// Validate container has required security labels
pub fn validate_container_labels(container_info: &ContainerInfo, required_labels: &[String]) -> Result<(), DockerError> {
    for required_label in required_labels {
        if !container_info.labels.contains_key(required_label) {
            return Err(DockerError::LabelValidation(format!("Container missing required label: {}", required_label)));
        }
    }
    Ok(())
}

/// Validate container is in the expected network
pub fn validate_network_membership(container_info: &ContainerInfo, expected_network: &Option<String>) -> Result<(), DockerError> {
    if let Some(expected) = expected_network {
        if !container_info.networks.contains_key(expected) {
            return Err(DockerError::NetworkValidation(format!("Container not in expected network. Expected: {}, Found: {}",
                                                              expected, container_info.networks.keys().cloned().collect::<Vec<_>>().join(", "))));
        }
    }
    Ok(())
}

/// Validate container image is from allowed registry/namespace
fn validate_image_source(container_info: &ContainerInfo, allowed_registries: &[String]) -> Result<(), DockerError> {
    if allowed_registries.is_empty() {
        return Ok(()); // No restrictions
    }

    for allowed_registry in allowed_registries {
        if container_info.image.starts_with(allowed_registry) {
            return Ok(());
        }
    }

    Err(DockerError::RegistryValidation(format!("Container image '{}' not from allowed registries: {:?}",
                                                container_info.image, allowed_registries)))
}

/// Comprehensive container security validation with configurable checks
pub async fn perform_comprehensive_validation(
    docker_client: &Docker,
    client_ip: &String,
    network_name: &Option<String>,
    validation_options: &crate::server::config::DockerValidationOptions,
) -> Result<ContainerInfo, DockerError> {
    info!("Starting comprehensive validation for IP: {}", client_ip);
    info!("Validation options: validate_state={}, validate_network={}, validate_labels={}, validate_registry={}", 
          validation_options.validate_container_state(), 
          validation_options.validate_network_membership(), 
          validation_options.validate_labels(), 
          validation_options.validate_registry());


    let list_options = validation_options.list_options().cloned();
    let inspect_options = validation_options.inspect_options().cloned();

    info!("Performing container security validation...");
    let container_info = validate_container_security(docker_client, client_ip, network_name, list_options, inspect_options).await?;
    info!("Container security validation successful: name={}, image={}, state={}", 
          container_info.name, container_info.image, container_info.state);

    // Validate container state if enabled
    if validation_options.validate_container_state() {
        info!("Validating container state: {}", container_info.state);
        match validate_container_state(&container_info) {
            Ok(_) => {
                info!("Container state validation passed");
                Ok(())
            }
            Err(e) => {
                info!("Container state validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        info!("Container state validation skipped");
    }

    // Validate network membership if enabled
    if validation_options.validate_network_membership() {
        info!("Validating network membership. Expected: {:?}, Available: {:?}", 
              network_name, container_info.networks.keys().collect::<Vec<_>>());
        match validate_network_membership(&container_info, network_name) {
            Ok(_) => {
                info!("Network membership validation passed");
                Ok(())
            }
            Err(e) => {
                info!("Network membership validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        info!("Network membership validation skipped");
    }

    // Validate required labels if enabled
    if validation_options.validate_labels() {
        info!("Validating required labels: {:?}", validation_options.required_labels());
        info!("Container labels: {:?}", container_info.labels);
        match validate_container_labels(&container_info, validation_options.required_labels()) {
            Ok(_) => {
                info!("Container labels validation passed");
                Ok(())
            }
            Err(e) => {
                info!("Container labels validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        info!("Container labels validation skipped");
    }

    // Validate image source if enabled
    if validation_options.validate_registry() {
        info!("Validating image source. Image: {}, Allowed registries: {:?}", 
              container_info.image, validation_options.allowed_registries());
        match validate_image_source(&container_info, validation_options.allowed_registries()) {
            Ok(_) => {
                info!("Image source validation passed");
                Ok(())
            }
            Err(e) => {
                info!("Image source validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        info!("Image source validation skipped");
    }

    info!("Comprehensive validation completed successfully for container: {}", container_info.name);
    Ok(container_info)
}

/// Extracts the image name without the version tag or digest.
fn extract_image_name_without_version(image: &str) -> String {
    let image_without_registry = if let Some(slash_idx) = image.rfind('/') {
        if image[..slash_idx].contains('.') {
            image
        } else {
            &image[slash_idx + 1..]
        }
    } else {
        image
    };
    if let Some(colon_idx) = image_without_registry.rfind(':') {
        let before_colon = &image_without_registry[..colon_idx];
        if before_colon.contains('.') {
            image_without_registry.to_string()
        } else {
            before_colon.to_string()
        }
    } else {
        image_without_registry.to_string()
    }
}

/// Enhanced client validation with header support for testing mode
#[allow(dead_code)]
pub async fn validate_docker_client_for_request(
    ip_cache: &Arc<RwLock<HashMap<String, ContainerCacheEntry>>>,
    docker_client: &bollard::Docker,
    client_ip: &IpAddr,
    headers: &axum::http::HeaderMap,
    validation_options: &crate::server::config::DockerValidationOptions,
) -> Result<ContainerInfo, DockerError> {
    #[cfg(feature = "insecure_mode")]
    {
        let docker_instance_name = headers
            .get("X-Docker-InstanceName")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("test-instance");

        let docker_image = headers
            .get("X-Docker-ImageName")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("test-image");

        let docker_state = headers
            .get("X-Docker-State")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("running");

        let docker_labels = headers.get("X-Docker-Labels")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                let mut labels = HashMap::new();
                for pair in s.split(',') {
                    if let Some((key, value)) = pair.trim().split_once('=') {
                        labels.insert(key.trim().to_string(), value.trim().to_string());
                    }
                }
                labels
            })
            .unwrap_or_else(HashMap::new);

        let docker_networks = headers.get("X-Docker-Networks")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                let mut labels = HashMap::new();
                for pair in s.split(',') {
                    if let Some((key, value)) = pair.trim().split_once('=') {
                        labels.insert(key.trim().to_string(), value.trim().to_string());
                    }
                }
                labels
            })
            .unwrap_or_else(HashMap::new);



        warn!("LOCAL MODE: Using Docker image name from header: {}", docker_image);

        // Create ContainerInfo from headers
        let container_info = ContainerInfo {
            name: docker_instance_name.to_string(),
            image: docker_image.to_string(),
            image_name_no_version: docker_image.to_string(),
            state: docker_state.to_string(),
            labels: docker_labels,
            networks: docker_networks,
        };

        // Apply the same validation logic as secure mode, but using header values
        info!("Starting comprehensive validation for headers-based container info");
        
        // Validate container state if enabled
        if validation_options.validate_container_state() {
            info!("Validating container state: {}", container_info.state);
            validate_container_state(&container_info)?;
        } else {
            info!("Container state validation skipped");
        }

        // Validate network membership if enabled
        if validation_options.validate_network_membership() {
            info!("Validating network membership. Networks: {:?}, Expected: {:?}", 
                  container_info.networks.keys().collect::<Vec<_>>(), validation_options.docker_network_name());
            let network_name = validation_options.docker_network_name().cloned();
            validate_network_membership(&container_info, &network_name)?;
        } else {
            info!("Network membership validation skipped");
        }

        // Validate required labels if enabled
        if validation_options.validate_labels() {
            info!("Validating required labels: {:?}", validation_options.required_labels());
            info!("Container labels: {:?}", container_info.labels);
            validate_container_labels(&container_info, validation_options.required_labels())?;
        } else {
            info!("Container labels validation skipped");
        }

        // Validate image source if enabled
        if validation_options.validate_registry() {
            info!("Validating image source. Image: {}, Allowed registries: {:?}", 
                  container_info.image, validation_options.allowed_registries());
            validate_image_source(&container_info, validation_options.allowed_registries())?;
        } else {
            info!("Image source validation skipped");
        }

        info!("Comprehensive validation completed successfully for headers-based container: {}", container_info.name);
        return Ok(container_info);
    }
    #[cfg(feature = "secure_mode")]
    {
        info!("Starting client validation for IP: {}", client_ip);
        debug!("Validation options: {:?}", validation_options);

        let now = Utc::now();
        // Check cache first for performance
        debug!("Checking IP cache for {}", client_ip);

        let rr = ip_cache.read().await;

        if rr.contains_key(&client_ip.to_string()) {
            let entry = &rr[&client_ip.to_string()];
            debug!("Cache hit for IP {}: container={}, expires_at={}", client_ip, entry.container_name, entry.expires_at);
            if entry.expires_at <= now.timestamp_millis() {
                debug!("Cache entry expired for IP {}", client_ip);
                // Cache expired, remove it
                ip_cache.write().await.remove(&client_ip.to_string());
            } else {
                debug!("Cache entry still valid for IP {}", client_ip);
                // Cache hit, but we still need to perform validation
                // For now, we'll proceed with full validation for security
            }
        } else {
            debug!("No cache entry found for IP {}", client_ip);
        }

        let docker_timeout = std::time::Duration::from_secs(validation_options.timeout_seconds());
        debug!("Docker timeout set to {:?}", docker_timeout);
        // Use comprehensive validation with configurable options
        info!("Starting comprehensive Docker validation...");

        // Convert Option<&String> to &Option<String> for network_name
        let network_name = validation_options.docker_network_name().cloned();
        let result = tokio::time::timeout(
            docker_timeout,
            perform_comprehensive_validation(
                docker_client,
                &client_ip.to_string(),
                &network_name,
                validation_options,
            ),
        )
        .await
        .map_err(|_| {
            warn!("Docker validation timed out after {:?}", docker_timeout);
            DockerError::Timeout("Docker validation timed out".to_string())
        })?
        .map_err(|e| {
            error!("Docker validation failed: {:?}", e);
            e
        })?;

        info!("Docker validation successful: container={}, image={}", result.name, result.image);
        // Cache the result for future requests
        let cache_entry = ContainerCacheEntry {
            container_name: result.name.to_string(),
            expires_at: chrono::Utc::now().timestamp() + 300, // 5 minutes cache
        };
        ip_cache.write().await.insert(client_ip.to_string(), cache_entry);

        info!("Client validation completed successfully for IP: {}", client_ip);
        Ok(result)
    }

    #[cfg(not(any(feature = "secure_mode", feature = "insecure_mode")))]
    {
        panic!("Code must be built with either secure or insecure mode.")
    }
}
