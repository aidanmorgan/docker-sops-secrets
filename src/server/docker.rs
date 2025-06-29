use bollard::Docker;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Looks up the client name (container image name) for a given IP address using Docker API and a cache.
pub async fn get_client_name_from_docker(
    docker_client: &Docker,
    ip_cache: Arc<RwLock<HashMap<IpAddr, Option<String>>>>,
    client_ip: IpAddr,
) -> Result<String, Box<dyn std::error::Error>> {
    // Check cache first
    {
        let cache = ip_cache.read().await;
        if let Some(Some(name)) = cache.get(&client_ip) {
            return Ok(name.clone());
        }
    }

    // Query Docker API for all containers
    let containers = docker_client.list_containers(None::<bollard::container::ListContainersOptions<String>>).await?;

    for container in containers {
        if let Some(network_settings) = container.network_settings {
            if let Some(networks) = network_settings.networks {
                for (_net_name, net) in networks {
                    if let Some(ip_str) = net.ip_address {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            if ip == client_ip {
                                // Extract image name without version tag
                                let image = container.image.unwrap_or_default();
                                let image_name = extract_image_name_without_version(&image);
                                // Update cache
                                let mut cache = ip_cache.write().await;
                                cache.insert(client_ip, Some(image_name.clone()));
                                return Ok(image_name);
                            }
                        }
                    }
                }
            }
        }
    }
    // Not found, cache as None
    let mut cache = ip_cache.write().await;
    cache.insert(client_ip, None);
    Err("Client container not found for IP".into())
}

/// Extracts the image name without the version tag or digest.
pub fn extract_image_name_without_version(image: &str) -> String {
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