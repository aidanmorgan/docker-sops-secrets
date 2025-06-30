use bollard::query_parameters::{ListContainersOptionsBuilder, InspectContainerOptionsBuilder};

/// Docker validation options for client security checks
/// 
/// This struct provides fine-grained control over Docker container validation
/// to ensure only authorized containers can access secrets.
/// 
/// # Examples
/// 
/// ## Minimal validation (default)
/// ```rust
/// use sops_secrets::server::config::DockerValidationOptions;
/// 
/// let options = DockerValidationOptions::default();
/// // Only validates network membership
/// ```
/// 
/// ## Moderate validation
/// ```rust
/// use sops_secrets::server::config::DockerValidationOptions;
/// 
/// let options = DockerValidationOptions::moderate();
/// // Validates container state and network membership
/// ```
/// 
/// ## Strict validation
/// ```rust
/// use sops_secrets::server::config::DockerValidationOptions;
/// 
/// let options = DockerValidationOptions::strict();
/// // Validates all checks (requires labels and registries to be configured)
/// ```
/// 
/// ## Custom validation with labels
/// ```rust
/// use sops_secrets::server::config::DockerValidationOptions;
/// 
/// let options = DockerValidationOptions::default()
///     .with_container_state_validation()
///     .with_label_validation(vec![
///         "security.verified=true".to_string(),
///         "environment=production".to_string()
///     ]);
/// ```
/// 
/// ## Custom validation with registry restrictions
/// ```rust
/// use sops_secrets::server::config::DockerValidationOptions;
/// 
/// let options = DockerValidationOptions::default()
///     .with_registry_validation(vec![
///         "docker.io/library".to_string(),
///         "my-registry.com".to_string()
///     ]);
/// ```
#[derive(Debug, Clone)]
pub struct DockerValidationOptions {
    /// Enable container state validation (default: false)
    /// 
    /// When enabled, only containers in "running" state are allowed.
    /// This prevents access from stopped, paused, or restarting containers.
    pub validate_container_state: bool,
    
    /// Enable network membership validation (default: true)
    /// 
    /// When enabled, containers must be in the specified Docker network.
    /// This is the primary security boundary and is enabled by default.
    pub validate_network_membership: bool,
    
    /// Enable label validation (default: false)
    /// 
    /// When enabled, containers must have all required labels.
    /// Useful for enforcing security policies and environment requirements.
    pub validate_labels: bool,
    
    /// Enable registry validation (default: false)
    /// 
    /// When enabled, container images must come from allowed registries.
    /// Useful for preventing use of untrusted or unauthorized images.
    pub validate_registry: bool,
    
    /// Required Docker labels for client containers
    /// 
    /// Example: `["security.verified=true", "environment=prod"]`
    /// Only used when `validate_labels` is true.
    pub required_labels: Vec<String>,
    
    /// Allowed Docker registries for client containers
    /// 
    /// Example: `["docker.io/library", "my-registry.com"]`
    /// Only used when `validate_registry` is true.
    pub allowed_registries: Vec<String>,

    /// Docker network name to check for client containers (optional, checks all networks if not specified)
    pub docker_network_name: Option<String>,

    /// Docker API timeout in seconds
    pub timeout_seconds: u64,

    /// Docker list containers options builder
    /// 
    /// Used to configure how containers are listed from the Docker API.
    /// If None, default options will be used.
    pub list_options: Option<ListContainersOptionsBuilder>,

    /// Docker inspect container options builder
    /// 
    /// Used to configure how containers are inspected from the Docker API.
    /// If None, default options will be used.
    pub inspect_options: Option<InspectContainerOptionsBuilder>,
}

impl DockerValidationOptions {
    /// Create a new DockerValidationOptions with all validations enabled
    pub fn strict() -> Self {
        Self {
            validate_container_state: true,
            validate_network_membership: true,
            validate_labels: true,
            validate_registry: true,
            required_labels: vec![],
            allowed_registries: vec![],
            docker_network_name: None,
            timeout_seconds: 10,
            list_options: None,
            inspect_options: None,
        }
    }

    /// Create a new DockerValidationOptions with minimal validation (network only)
    pub fn minimal() -> Self {
        Self::default()
    }

    /// Create a new DockerValidationOptions with moderate validation
    pub fn moderate() -> Self {
        Self {
            validate_container_state: true,
            validate_network_membership: true,
            validate_labels: false,
            validate_registry: false,
            required_labels: vec![],
            allowed_registries: vec![],
            docker_network_name: None,
            timeout_seconds: 10,
            list_options: None,
            inspect_options: None,
        }
    }
}

impl Default for DockerValidationOptions {
    fn default() -> Self {
        Self {
            validate_container_state: true,
            validate_network_membership: true,
            validate_labels: false,
            validate_registry: false,
            required_labels: vec![],
            allowed_registries: vec![],
            docker_network_name: None,
            timeout_seconds: 10,
            list_options: None,
            inspect_options: None,
        }
    }
}

/// Server configuration structure
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// SOPS file path
    pub sops_file_path: String,
    /// Master key path for SOPS
    pub master_key_path: String,
    /// Docker socket path (default: /var/run/docker.sock)
    pub docker_socket_path: String,
    /// Docker network name to check for client containers (optional, checks all networks if not specified)
    pub docker_network_name: Option<String>,
    /// Directory to store encrypted secret files
    pub secrets_dir: String,
    /// Path to age executable
    pub age_executable_path: String,
    /// Path to SOPS executable
    pub sops_executable_path: String,

    /// Health check timeout (seconds)
    pub health_check_timeout_seconds: u64,
    /// Docker API timeout (seconds)
    pub docker_timeout_seconds: u64,
    /// SOPS operation timeout (seconds)
    pub sops_timeout_seconds: u64,
    /// Age encryption timeout (seconds)
    pub age_timeout_seconds: u64,
    pub get_secret_file_cleanup_timeout: u64,
    pub write_secret_file_timeout: u64,
    
    /// Maximum number of retries for file deletion (default: 3)
    pub file_cleanup_max_retries: u32,
    /// Delay between retry attempts for file deletion (seconds, default: 5)
    pub file_cleanup_retry_delay_seconds: u64,

    /// Docker validation options for client security
    pub docker_validation: DockerValidationOptions,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            sops_file_path: "secrets.yaml".to_string(),
            master_key_path: "master_key.age".to_string(),
            docker_socket_path: "/var/run/docker.sock".to_string(),
            docker_network_name: None,
            secrets_dir: "/tmp/sops-secrets".to_string(),
            age_executable_path: "/usr/local/bin/age".to_string(),
            sops_executable_path: "/usr/local/bin/sops".to_string(),
            health_check_timeout_seconds: 30,
            docker_timeout_seconds: 10,
            sops_timeout_seconds: 30,
            age_timeout_seconds: 30,
            get_secret_file_cleanup_timeout: 300,
            write_secret_file_timeout: 300,
            file_cleanup_max_retries: 3,
            file_cleanup_retry_delay_seconds: 5,
            
            // Docker validation with sensible defaults
            docker_validation: DockerValidationOptions::default(),
        }
    }
} 