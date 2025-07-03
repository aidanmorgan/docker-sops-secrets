use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use std::path::PathBuf;

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
    /// Enable container state validation (default: true)
    ///
    /// When enabled, only containers in "running" state are allowed.
    /// This prevents access from stopped, paused, or restarting containers.
    validate_container_state: bool,

    /// Enable network membership validation (default: true)
    ///
    /// When enabled, containers must be in the specified Docker network.
    /// This is the primary security boundary and is enabled by default.
    validate_network_membership: bool,

    /// Enable label validation (default: false)
    ///
    /// When enabled, containers must have all required labels.
    /// Useful for enforcing security policies and environment requirements.
    validate_labels: bool,

    /// Enable registry validation (default: false)
    ///
    /// When enabled, container images must come from allowed registries.
    /// Useful for preventing use of untrusted or unauthorized images.
    validate_registry: bool,

    /// Required Docker labels for client containers
    ///
    /// Example: `["security.verified=true", "environment=prod"]`
    /// Only used when `validate_labels` is true.
    required_labels: Vec<String>,

    /// Allowed Docker registries for client containers
    ///
    /// Example: `["docker.io/library", "my-registry.com"]`
    /// Only used when `validate_registry` is true.
    allowed_registries: Vec<String>,

    /// Docker network name to check for client containers (optional, checks all networks if not specified)
    docker_network_name: Option<String>,

    /// Docker API timeout in seconds
    timeout_seconds: u64,

    /// Docker list containers options builder
    ///
    /// Used to configure how containers are listed from the Docker API.
    /// If None, default options will be used.
    list_options: Option<ListContainersOptionsBuilder>,

    /// Docker inspect container options builder
    ///
    /// Used to configure how containers are inspected from the Docker API.
    /// If None, default options will be used.
    inspect_options: Option<InspectContainerOptionsBuilder>,
}

impl DockerValidationOptions {
    /// Create a new DockerValidationOptions with all validations enabled
    pub fn strict() -> Self {
        Self::default()
            .with_container_state_validation(true)
            .with_network_membership_validation(true)
            .with_label_validation(vec![])
            .with_registry_validation(vec![])
    }

    /// Create a new DockerValidationOptions with minimal validation (network only)
    pub fn minimal() -> Self {
        Self::default()
    }

    /// Create a new DockerValidationOptions with moderate validation
    pub fn moderate() -> Self {
        Self::default()
            .with_container_state_validation(true)
            .with_network_membership_validation(true)
    }

    // Accessor methods (getters)

    /// Returns whether container state validation is enabled
    pub fn validate_container_state(&self) -> bool {
        self.validate_container_state
    }

    /// Returns whether network membership validation is enabled
    pub fn validate_network_membership(&self) -> bool {
        self.validate_network_membership
    }

    /// Returns whether label validation is enabled
    pub fn validate_labels(&self) -> bool {
        self.validate_labels
    }

    /// Returns whether registry validation is enabled
    pub fn validate_registry(&self) -> bool {
        self.validate_registry
    }

    /// Returns the required labels for container validation
    pub fn required_labels(&self) -> &[String] {
        &self.required_labels
    }

    /// Returns the allowed registries for container validation
    pub fn allowed_registries(&self) -> &[String] {
        &self.allowed_registries
    }

    /// Returns the Docker network name to check for client containers
    pub fn docker_network_name(&self) -> Option<&String> {
        self.docker_network_name.as_ref()
    }

    /// Returns the Docker API timeout in seconds
    pub fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }

    /// Returns the Docker list containers options builder
    pub fn list_options(&self) -> Option<&ListContainersOptionsBuilder> {
        self.list_options.as_ref()
    }

    /// Returns the Docker inspect container options builder
    pub fn inspect_options(&self) -> Option<&InspectContainerOptionsBuilder> {
        self.inspect_options.as_ref()
    }

    // Builder methods

    /// Enable or disable container state validation
    pub fn with_container_state_validation(mut self, enabled: bool) -> Self {
        self.validate_container_state = enabled;
        self
    }

    /// Enable or disable network membership validation
    pub fn with_network_membership_validation(mut self, enabled: bool) -> Self {
        self.validate_network_membership = enabled;
        self
    }

    /// Enable label validation with the specified required labels
    pub fn with_label_validation(mut self, labels: Vec<String>) -> Self {
        self.validate_labels = true;
        self.required_labels = labels;
        self
    }

    /// Enable registry validation with the specified allowed registries
    pub fn with_registry_validation(mut self, registries: Vec<String>) -> Self {
        self.validate_registry = true;
        self.allowed_registries = registries;
        self
    }

    /// Set the Docker network name to check for client containers
    pub fn with_docker_network_name(mut self, network_name: Option<String>) -> Self {
        self.docker_network_name = network_name;
        self
    }

    /// Set the Docker API timeout in seconds
    pub fn with_timeout_seconds(mut self, timeout: u64) -> Self {
        self.timeout_seconds = timeout;
        self
    }

    /// Set the Docker list containers options builder
    pub fn with_list_options(mut self, options: Option<ListContainersOptionsBuilder>) -> Self {
        self.list_options = options;
        self
    }

    /// Set the Docker inspect container options builder
    pub fn with_inspect_options(mut self, options: Option<InspectContainerOptionsBuilder>) -> Self {
        self.inspect_options = options;
        self
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
    sops_file_path: PathBuf,
    /// Master key path for SOPS
    master_key_path: PathBuf,
    /// Docker socket path (default: /var/run/docker.sock)
    docker_socket_path: PathBuf,
    /// Docker network name to check for client containers (optional, checks all networks if not specified)
    docker_network_name: Option<String>,
    /// Directory to store encrypted secret files
    secrets_transfer_dir_path: PathBuf,
    /// Path to SOPS executable
    sops_executable_path: PathBuf,

    /// Health check timeout (seconds)
    health_check_timeout_seconds: u64,
    /// Docker API timeout (seconds)
    docker_timeout_seconds: u64,
    /// SOPS operation timeout (seconds)
    sops_timeout_seconds: u64,
    /// Age encryption timeout (seconds)
    age_timeout_seconds: u64,
    /// Timeout for cleaning up secret files after retrieval
    get_secret_file_cleanup_timeout: u64,
    /// Timeout for writing secret files
    write_secret_file_timeout: u64,

    /// Maximum number of retries for file deletion (default: 3)
    file_cleanup_max_retries: u32,
    /// Delay between retry attempts for file deletion (seconds, default: 5)
    file_cleanup_retry_delay_seconds: u64,

    /// Rate limiter configuration
    /// Maximum number of requests allowed per time window (default: 20)
    rate_limit_max_requests: Option<usize>,
    /// Rate limiter time window in seconds (default: 1)
    rate_limit_window_seconds: Option<u64>,

    /// Docker validation options for client security
    docker_validation: DockerValidationOptions,

    enable_health_checks: bool,

    /// Automatically create SOPS file if it doesn't exist (default: true)
    auto_create_sops_file: bool,
}

impl ServerConfig {
    // Accessor methods (getters)

    /// Returns the SOPS file path
    pub fn sops_file_path(&self) -> &PathBuf {
        &self.sops_file_path
    }

    /// Returns the master key path for SOPS
    pub fn master_key_path(&self) -> &PathBuf {
        &self.master_key_path
    }

    /// Returns the Docker socket path
    pub fn docker_socket_path(&self) -> &PathBuf {
        &self.docker_socket_path
    }

    /// Returns the Docker network name to check for client containers
    pub fn docker_network_name(&self) -> Option<&String> {
        self.docker_network_name.as_ref()
    }

    /// Returns the directory to store encrypted secret files
    pub fn secrets_dir(&self) -> &PathBuf {
        &self.secrets_transfer_dir_path
    }

    /// Returns the path to SOPS executable
    pub fn sops_executable_path(&self) -> &PathBuf {
        &self.sops_executable_path
    }

    /// Returns the health check timeout in seconds
    pub fn health_check_timeout_seconds(&self) -> u64 {
        self.health_check_timeout_seconds
    }

    /// Returns the Docker API timeout in seconds
    pub fn docker_timeout_seconds(&self) -> u64 {
        self.docker_timeout_seconds
    }

    /// Returns the SOPS operation timeout in seconds
    pub fn sops_timeout_seconds(&self) -> u64 {
        self.sops_timeout_seconds
    }

    /// Returns the Age encryption timeout in seconds
    pub fn age_timeout_seconds(&self) -> u64 {
        self.age_timeout_seconds
    }

    /// Returns the timeout for cleaning up secret files after retrieval
    pub fn get_secret_file_cleanup_timeout(&self) -> u64 {
        self.get_secret_file_cleanup_timeout
    }

    /// Returns the timeout for writing secret files
    pub fn write_secret_file_timeout(&self) -> u64 {
        self.write_secret_file_timeout
    }

    /// Returns the maximum number of retries for file deletion
    pub fn file_cleanup_max_retries(&self) -> u32 {
        self.file_cleanup_max_retries
    }

    /// Returns the delay between retry attempts for file deletion in seconds
    pub fn file_cleanup_retry_delay_seconds(&self) -> u64 {
        self.file_cleanup_retry_delay_seconds
    }

    /// Returns the maximum number of requests allowed per time window
    pub fn rate_limit_max_requests(&self) -> Option<usize> {
        self.rate_limit_max_requests
    }

    /// Returns the rate limiter time window in seconds
    pub fn rate_limit_window_seconds(&self) -> Option<u64> {
        self.rate_limit_window_seconds
    }

    /// Returns the Docker validation options for client security
    pub fn docker_validation(&self) -> &DockerValidationOptions {
        &self.docker_validation
    }

    /// Returns whether to automatically create SOPS file if it doesn't exist
    pub fn auto_create_sops_file(&self) -> bool {
        self.auto_create_sops_file
    }

    // Builder methods

    /// Set the SOPS file path
    pub fn with_sops_file_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.sops_file_path = path.into();
        self
    }

    /// Set the master key path for SOPS
    pub fn with_master_key_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.master_key_path = path.into();
        self
    }

    /// Set the Docker socket path
    pub fn with_docker_socket_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.docker_socket_path = path.into();
        self
    }

    /// Set the Docker network name to check for client containers
    pub fn with_docker_network_name(mut self, network_name: Option<String>) -> Self {
        self.docker_network_name = network_name;
        self
    }

    /// Set the directory to store encrypted secret files
    pub fn with_secrets_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.secrets_transfer_dir_path = dir.into();
        self
    }


    /// Set the path to SOPS executable
    pub fn with_sops_executable_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.sops_executable_path = path.into();
        self
    }

    /// Set the health check timeout in seconds
    pub fn with_health_check_timeout_seconds(mut self, timeout: u64) -> Self {
        self.health_check_timeout_seconds = timeout;
        self
    }

    /// Set the Docker API timeout in seconds
    pub fn with_docker_timeout_seconds(mut self, timeout: u64) -> Self {
        self.docker_timeout_seconds = timeout;
        self
    }

    /// Set the SOPS operation timeout in seconds
    pub fn with_sops_timeout_seconds(mut self, timeout: u64) -> Self {
        self.sops_timeout_seconds = timeout;
        self
    }

    /// Set the Age encryption timeout in seconds
    pub fn with_age_timeout_seconds(mut self, timeout: u64) -> Self {
        self.age_timeout_seconds = timeout;
        self
    }

    /// Set the timeout for cleaning up secret files after retrieval
    pub fn with_get_secret_file_cleanup_timeout(mut self, timeout: u64) -> Self {
        self.get_secret_file_cleanup_timeout = timeout;
        self
    }

    /// Set the timeout for writing secret files
    pub fn with_write_secret_file_timeout(mut self, timeout: u64) -> Self {
        self.write_secret_file_timeout = timeout;
        self
    }

    /// Set the maximum number of retries for file deletion
    pub fn with_file_cleanup_max_retries(mut self, retries: u32) -> Self {
        self.file_cleanup_max_retries = retries;
        self
    }

    /// Set the delay between retry attempts for file deletion in seconds
    pub fn with_file_cleanup_retry_delay_seconds(mut self, delay: u64) -> Self {
        self.file_cleanup_retry_delay_seconds = delay;
        self
    }

    /// Set the maximum number of requests allowed per time window
    pub fn with_rate_limit_max_requests(mut self, max_requests: Option<usize>) -> Self {
        self.rate_limit_max_requests = max_requests;
        self
    }

    /// Set the rate limiter time window in seconds
    pub fn with_rate_limit_window_seconds(mut self, window: Option<u64>) -> Self {
        self.rate_limit_window_seconds = window;
        self
    }

    /// Set the Docker validation options for client security
    pub fn with_docker_validation(mut self, validation: DockerValidationOptions) -> Self {
        self.docker_validation = validation;
        self
    }

    /// Set whether to automatically create SOPS file if it doesn't exist
    pub fn with_auto_create_sops_file(mut self, auto_create: bool) -> Self {
        self.auto_create_sops_file = auto_create;
        self
    }

    pub fn enable_health_check(&self) -> bool {
        self.enable_health_checks
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            sops_file_path: "/etc/sops-secrets/secrets.json".to_string().into(),
            master_key_path: "/etc/sops-secrets/master_key.age".to_string().into(),
            docker_socket_path: "/var/run/docker.sock".to_string().into(),
            docker_network_name: None,
            secrets_transfer_dir_path: "/run/secrets".to_string().into(),
            sops_executable_path: "/usr/local/bin/sops".to_string().into(),
            health_check_timeout_seconds: 30,
            docker_timeout_seconds: 10,
            sops_timeout_seconds: 30,
            age_timeout_seconds: 30,
            get_secret_file_cleanup_timeout: 300,
            write_secret_file_timeout: 300,
            file_cleanup_max_retries: 3,
            file_cleanup_retry_delay_seconds: 5,
            rate_limit_max_requests: None,
            rate_limit_window_seconds: None,

            // Docker validation with sensible defaults
            docker_validation: DockerValidationOptions::default(),

            // Auto-create SOPS file by default
            auto_create_sops_file: true,
            enable_health_checks: true
        }
    }
}
