use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use bollard::Docker;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

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

/// Enhanced container validation with multiple security checks
async fn validate_container_security(
    docker_client: &Docker,
    client_ip: &String,
    network_name: &Option<String>,
    list_options: Option<ListContainersOptionsBuilder>,
    inspect_options: Option<InspectContainerOptionsBuilder>,
) -> Result<ContainerInfo, DockerError> {
    log::info!("Starting container security validation for IP: {}", client_ip);
    log::info!("Network filter: {:?}", network_name);

    // Validate IP address format
    log::info!("Validating IP address format: {}", client_ip);
    let _parsed_ip: IpAddr = client_ip.parse()
        .map_err(|e| {
            log::info!("Invalid IP address format: {}", e);
            DockerError::InvalidIpAddress(format!("Failed to parse IP {}: {}", client_ip, e))
        })?;
    log::info!("IP address format is valid");

    // Query Docker API for all containers
    log::info!("Querying Docker API for containers...");
    let containers = match docker_client.list_containers(
        list_options.map(|o| o.build()).or(Some(ListContainersOptionsBuilder::new().all(true).build()))
    ).await {
        Ok(containers) => {
            log::info!("Successfully retrieved {} containers from Docker API", containers.len());
            containers
        }
        Err(e) => {
            log::info!("Failed to list containers from Docker API: {}", e);
            return Err(DockerError::DockerApi(e));
        }
    };

    log::info!("Searching for container with IP: {}", client_ip);
    for (i, container) in containers.iter().enumerate() {
        log::info!("Checking container {}: id={:?}, name={:?}", i, container.id, container.names);

        if let Some(network_settings) = &container.network_settings {
            if let Some(networks) = &network_settings.networks {
                log::info!("Container has {} networks", networks.len());
                for (net_name, net) in networks {
                    log::info!("Checking network '{}' with IP: {:?}", net_name, net.ip_address);

                    // If a specific network is requested, only check that network
                    if let Some(requested_network) = network_name {
                        if requested_network != net_name {
                            log::info!("Skipping network '{}' (not requested)", net_name);
                            continue;
                        }
                    }

                    if let Some(ip_str) = &net.ip_address {
                        log::info!("Comparing IP {} with target {}", ip_str, client_ip);
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            if ip.to_string() == *client_ip {
                                log::info!("Found matching container with IP {}: {:?}", client_ip, container.id);
                                if let Some(container_id) = &container.id {
                                    log::info!("Getting detailed container info for {}", container_id);
                                    return get_detailed_container_info(docker_client, container_id, inspect_options).await;
                                }
                            }
                        } else {
                            log::info!("Failed to parse IP address: {}", ip_str);
                        }
                    } else {
                        log::info!("No IP address found for network '{}'", net_name);
                    }
                }
            } else {
                log::info!("Container has no networks");
            }
        } else {
            log::info!("Container has no network settings");
        }
    }

    log::info!("No container found with IP: {}", client_ip);
    Err(DockerError::ContainerNotFound(client_ip.clone()))
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
        .and_then(|c| c.labels.clone())
        .unwrap_or_default();

    let image = config
        .as_ref()
        .and_then(|c| c.image.clone())
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
    log::info!("Starting comprehensive validation for IP: {}", client_ip);
    log::info!("Validation options: validate_state={}, validate_network={}, validate_labels={}, validate_registry={}", 
              validation_options.validate_container_state, 
              validation_options.validate_network_membership, 
              validation_options.validate_labels, 
              validation_options.validate_registry);


    let list_options = validation_options.list_options.clone();
    let inspect_options = validation_options.inspect_options.clone();

    log::info!("Performing container security validation...");
    let container_info = validate_container_security(docker_client, client_ip, network_name, list_options, inspect_options).await?;
    log::info!("Container security validation successful: name={}, image={}, state={}", 
              container_info.name, container_info.image, container_info.state);

    // Validate container state if enabled
    if validation_options.validate_container_state {
        log::info!("Validating container state: {}", container_info.state);
        match validate_container_state(&container_info) {
            Ok(_) => {
                log::info!("Container state validation passed");
                Ok(())
            }
            Err(e) => {
                log::info!("Container state validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        log::info!("Container state validation skipped");
    }

    // Validate network membership if enabled
    if validation_options.validate_network_membership {
        log::info!("Validating network membership. Expected: {:?}, Available: {:?}", 
                  network_name, container_info.networks.keys().collect::<Vec<_>>());
        match validate_network_membership(&container_info, network_name) {
            Ok(_) => {
                log::info!("Network membership validation passed");
                Ok(())
            }
            Err(e) => {
                log::info!("Network membership validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        log::info!("Network membership validation skipped");
    }

    // Validate required labels if enabled
    if validation_options.validate_labels {
        log::info!("Validating required labels: {:?}", validation_options.required_labels);
        log::info!("Container labels: {:?}", container_info.labels);
        match validate_container_labels(&container_info, &validation_options.required_labels) {
            Ok(_) => {
                log::info!("Container labels validation passed");
                Ok(())
            }
            Err(e) => {
                log::info!("Container labels validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        log::info!("Container labels validation skipped");
    }

    // Validate image source if enabled
    if validation_options.validate_registry {
        log::info!("Validating image source. Image: {}, Allowed registries: {:?}", 
                  container_info.image, validation_options.allowed_registries);
        match validate_image_source(&container_info, &validation_options.allowed_registries) {
            Ok(_) => {
                log::info!("Image source validation passed");
                Ok(())
            }
            Err(e) => {
                log::info!("Image source validation failed: {:?}", e);
                Err(e)
            }
        }?;
    } else {
        log::info!("Image source validation skipped");
    }

    log::info!("Comprehensive validation completed successfully for container: {}", container_info.name);
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