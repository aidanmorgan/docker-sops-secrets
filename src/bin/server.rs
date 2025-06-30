use clap::Parser;
use dotenv::dotenv;
use sops_secrets::server::{start_server, ServerConfig};
use sops_secrets::server::config::DockerValidationOptions;
use bollard::query_parameters::{ListContainersOptionsBuilder, InspectContainerOptionsBuilder};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(long, env = "SERVER_PORT", default_value_t = 8080)]
    port: u16,

    /// SOPS file path
    #[arg(long, env = "SOPS_FILE_PATH", default_value = "secrets.yaml")]
    sops_file_path: String,

    /// Master key path for SOPS
    #[arg(long, env = "SOPS_MASTER_KEY_PATH", default_value = "master_key.age")]
    master_key_path: String,

    /// Docker socket path
    #[arg(long, env = "DOCKER_SOCKET_PATH", default_value = "/var/run/docker.sock")]
    docker_socket_path: String,

    /// Docker network name
    #[arg(long, env = "DOCKER_NETWORK_NAME")]
    docker_network_name: Option<String>,

    /// Directory to store encrypted secret files
    #[arg(long, env = "SECRETS_DIR", default_value = "/var/tmp/sops-secrets")]
    secrets_dir: String,

    /// Path to age executable
    #[arg(long, env = "AGE_EXECUTABLE_PATH", default_value = "/usr/local/bin/age")]
    age_executable_path: String,

    /// Path to SOPS executable
    #[arg(long, env = "SOPS_EXECUTABLE_PATH", default_value = "/usr/local/bin/sops")]
    sops_executable_path: String,

    /// Health check timeout (seconds)
    #[arg(long, env = "HEALTH_CHECK_TIMEOUT_SECONDS", default_value_t = 5)]
    health_check_timeout_seconds: u64,

    /// Docker API timeout (seconds)
    #[arg(long, env = "DOCKER_TIMEOUT_SECONDS", default_value_t = 5)]
    docker_timeout_seconds: u64,

    /// SOPS operation timeout (seconds)
    #[arg(long, env = "SOPS_TIMEOUT_SECONDS", default_value_t = 5)]
    sops_timeout_seconds: u64,

    /// Age encryption timeout (seconds)
    #[arg(long, env = "AGE_TIMEOUT_SECONDS", default_value_t = 5)]
    age_timeout_seconds: u64,

    /// Secret file cleanup timeout (seconds)
    #[arg(long, env = "GET_SECRET_FILE_CLEANUP_TIMEOUT", default_value_t = 20)]
    get_secret_file_cleanup_timeout: u64,

    /// Write secret file timeout (seconds)
    #[arg(long, env = "WRITE_SECRET_FILE_TIMEOUT", default_value_t = 20)]
    write_secret_file_timeout: u64,

    /// Maximum number of retries for file deletion
    #[arg(long, env = "FILE_CLEANUP_MAX_RETRIES", default_value_t = 3)]
    file_cleanup_max_retries: u32,

    /// Delay between retry attempts for file deletion (seconds)
    #[arg(long, env = "FILE_CLEANUP_RETRY_DELAY_SECONDS", default_value_t = 5)]
    file_cleanup_retry_delay_seconds: u64,

    /// Docker validation level: none, light, moderate, severe
    #[arg(long, env = "DOCKER_VALIDATION_LEVEL", default_value = "light")]
    docker_validation_level: String,

    /// Comma-separated list of trusted Docker registries
    #[arg(long, env = "DOCKER_TRUSTED_REGISTRIES")]
    docker_trusted_registries: Option<String>,

    /// Comma-separated list of required Docker labels (format: key=value)
    #[arg(long, env = "DOCKER_REQUIRED_LABELS")]
    docker_required_labels: Option<String>,
}

fn create_docker_validation_options(args: &Args) -> DockerValidationOptions {
    // Parse trusted registries
    let allowed_registries: Vec<String> = args.docker_trusted_registries
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    // Parse required labels
    let required_labels: Vec<String> = args.docker_required_labels
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    // Hardcoded Docker list/inspect options
    let list_options = ListContainersOptionsBuilder::new().all(true);
    let inspect_options = InspectContainerOptionsBuilder::default().size(false);

    // Create validation options based on level
    let mut validation_options = match args.docker_validation_level.to_lowercase().as_str() {
        "none" => DockerValidationOptions {
            validate_container_state: false,
            validate_network_membership: false,
            validate_labels: false,
            validate_registry: false,
            required_labels: vec![],
            allowed_registries: vec![],
            docker_network_name: args.docker_network_name.clone(),
            timeout_seconds: args.docker_timeout_seconds,
            list_options: Some(list_options),
            inspect_options: Some(inspect_options),
        },
        "light" => DockerValidationOptions {
            validate_container_state: false,
            validate_network_membership: true,
            validate_labels: false,
            validate_registry: false,
            required_labels: vec![],
            allowed_registries: vec![],
            docker_network_name: args.docker_network_name.clone(),
            timeout_seconds: args.docker_timeout_seconds,
            list_options: Some(list_options),
            inspect_options: Some(inspect_options),
        },
        "moderate" => DockerValidationOptions {
            validate_container_state: true,
            validate_network_membership: true,
            validate_labels: false,
            validate_registry: false,
            required_labels: vec![],
            allowed_registries: vec![],
            docker_network_name: args.docker_network_name.clone(),
            timeout_seconds: args.docker_timeout_seconds,
            list_options: Some(list_options),
            inspect_options: Some(inspect_options),
        },
        "severe" => DockerValidationOptions {
            validate_container_state: true,
            validate_network_membership: true,
            validate_labels: true,
            validate_registry: true,
            required_labels: required_labels.clone(),
            allowed_registries: allowed_registries.clone(),
            docker_network_name: args.docker_network_name.clone(),
            timeout_seconds: args.docker_timeout_seconds,
            list_options: Some(list_options),
            inspect_options: Some(inspect_options),
        },
        _ => {
            eprintln!("Warning: Invalid docker validation level '{}', using 'light'", args.docker_validation_level);
            DockerValidationOptions {
                validate_container_state: false,
                validate_network_membership: true,
                validate_labels: false,
                validate_registry: false,
                required_labels: vec![],
                allowed_registries: vec![],
                docker_network_name: args.docker_network_name.clone(),
                timeout_seconds: args.docker_timeout_seconds,
                list_options: Some(list_options),
                inspect_options: Some(inspect_options),
            }
        }
    };

    // Override with custom settings if provided
    if !allowed_registries.is_empty() {
        validation_options.allowed_registries = allowed_registries;
        validation_options.validate_registry = true;
    }

    if !required_labels.is_empty() {
        validation_options.required_labels = required_labels;
        validation_options.validate_labels = true;
    }

    validation_options
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let args = Args::parse();

    let docker_validation = create_docker_validation_options(&args);

    let config = ServerConfig {
        sops_file_path: args.sops_file_path,
        master_key_path: args.master_key_path,
        docker_socket_path: args.docker_socket_path,
        docker_network_name: args.docker_network_name,
        secrets_dir: args.secrets_dir,
        age_executable_path: args.age_executable_path,
        sops_executable_path: args.sops_executable_path,
        health_check_timeout_seconds: args.health_check_timeout_seconds,
        docker_timeout_seconds: args.docker_timeout_seconds,
        sops_timeout_seconds: args.sops_timeout_seconds,
        age_timeout_seconds: args.age_timeout_seconds,
        get_secret_file_cleanup_timeout: args.get_secret_file_cleanup_timeout,
        write_secret_file_timeout: args.write_secret_file_timeout,
        file_cleanup_max_retries: args.file_cleanup_max_retries,
        file_cleanup_retry_delay_seconds: args.file_cleanup_retry_delay_seconds,
        docker_validation,
    };

    let port = args.port;
    println!("Starting server on port {}", port);
    println!("Docker validation level: {}", args.docker_validation_level);

    if let Err(e) = start_server(config, port).await {
        eprintln!("Server failed to start: {}", e);
        std::process::exit(1);
    }
} 