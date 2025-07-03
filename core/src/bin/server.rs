use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use clap::Parser;
use dotenv::dotenv;
use sops_secrets::server::config::DockerValidationOptions;
use sops_secrets::server::{start_server, ServerConfig};
use sops_secrets::shared::logging;

/// SOPS Secrets Server
/// 
/// A secure server for managing encrypted secrets using SOPS and Docker container validation.
/// 
/// # Rate Limiter Examples
/// 
/// ## Default rate limiting (20 requests per second)
/// ```bash
/// sops-secrets-server
/// ```
/// 
/// ## Custom rate limiting (50 requests per 10 seconds)
/// ```bash
/// sops-secrets-server --rate-limit-max-requests 50 --rate-limit-window-seconds 10
/// ```
/// 
/// ## Strict rate limiting (5 requests per second)
/// ```bash
/// sops-secrets-server --rate-limit-max-requests 5 --rate-limit-window-seconds 1
/// ```
/// 
/// ## Using environment variables
/// ```bash
/// export RATE_LIMIT_MAX_REQUESTS=30
/// export RATE_LIMIT_WINDOW_SECONDS=5
/// sops-secrets-server
/// ```

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(long, env = "SERVER_PORT", default_value_t = 3102)]
    port: u16,

    /// SOPS file path
    #[arg(long, env = "SOPS_FILE_PATH", default_value = "/etc/sops-secrets/secrets.json")]
    sops_file_path: String,

    /// Master key path for SOPS
    #[arg(long, env = "SOPS_MASTER_KEY_PATH", default_value = "/run/secrets/sops_master_key")]
    // set this to the docker-secrets approach to see if we can store the AGE key in docker secrets
    master_key_path: String,

    /// Directory to store encrypted secret files
    #[arg(long, env = "SECRETS_DIR", default_value = "/var/tmp/sops-secrets")]
    secrets_working_dir_path: String,


    /// Docker socket path
    #[arg(long, env = "DOCKER_SOCKET_PATH", default_value = "/var/run/docker.sock")]
    docker_socket_path: String,

    /// Docker network name
    #[arg(long, env = "DOCKER_NETWORK_NAME")]
    docker_network_name: Option<String>,


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

    /// Rate limiter: maximum number of requests per time window (default: 20)
    #[arg(long, env = "RATE_LIMIT_MAX_REQUESTS")]
    rate_limit_max_requests: Option<usize>,

    /// Rate limiter: time window in seconds (default: 1)
    #[arg(long, env = "RATE_LIMIT_WINDOW_SECONDS")]
    rate_limit_window_seconds: Option<u64>,

    /// Automatically create SOPS file if it doesn't exist
    #[arg(long, env = "AUTO_CREATE_SOPS_FILE", default_value_t = true, action = clap::ArgAction::SetTrue)]
    #[arg(long = "no-auto-create-sops-file", action = clap::ArgAction::SetFalse)]
    auto_create_sops_file: bool,
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

    // Create validation options based on level - avoid cloning by using references
    let mut validation_options = match args.docker_validation_level.to_lowercase().as_str() {
        "none" => DockerValidationOptions::default()
            .with_container_state_validation(false)
            .with_network_membership_validation(false)
            .with_docker_network_name(args.docker_network_name.clone())
            .with_timeout_seconds(args.docker_timeout_seconds)
            .with_list_options(Some(list_options))
            .with_inspect_options(Some(inspect_options)),
        "light" => DockerValidationOptions::default()
            .with_container_state_validation(false)
            .with_network_membership_validation(true)
            .with_docker_network_name(args.docker_network_name.clone())
            .with_timeout_seconds(args.docker_timeout_seconds)
            .with_list_options(Some(list_options))
            .with_inspect_options(Some(inspect_options)),
        "moderate" => DockerValidationOptions::default()
            .with_container_state_validation(true)
            .with_network_membership_validation(true)
            .with_docker_network_name(args.docker_network_name.clone())
            .with_timeout_seconds(args.docker_timeout_seconds)
            .with_list_options(Some(list_options))
            .with_inspect_options(Some(inspect_options)),
        "severe" => DockerValidationOptions::default()
            .with_container_state_validation(true)
            .with_network_membership_validation(true)
            .with_label_validation(required_labels.clone())
            .with_registry_validation(allowed_registries.clone())
            .with_docker_network_name(args.docker_network_name.clone())
            .with_timeout_seconds(args.docker_timeout_seconds)
            .with_list_options(Some(list_options))
            .with_inspect_options(Some(inspect_options)),
        _ => {
            eprintln!("Warning: Invalid docker validation level '{}', using 'light'", args.docker_validation_level);
            DockerValidationOptions::default()
                .with_container_state_validation(false)
                .with_network_membership_validation(true)
                .with_docker_network_name(args.docker_network_name.clone())
                .with_timeout_seconds(args.docker_timeout_seconds)
                .with_list_options(Some(list_options))
                .with_inspect_options(Some(inspect_options))
        }
    };

    // Override with custom settings if provided - avoid cloning by using references
    if !allowed_registries.is_empty() && args.docker_validation_level.to_lowercase() != "severe" {
        validation_options = validation_options.with_registry_validation(allowed_registries);
    }

    if !required_labels.is_empty() && args.docker_validation_level.to_lowercase() != "severe" {
        validation_options = validation_options.with_label_validation(required_labels);
    }

    validation_options
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Initialize the custom logger
    logging::init_logger();

    let args = Args::parse();

    let docker_validation = create_docker_validation_options(&args);

    // Use the builder pattern to create the ServerConfig
    let config = ServerConfig::default()
        .with_sops_file_path(args.sops_file_path)
        .with_master_key_path(args.master_key_path)
        .with_docker_socket_path(args.docker_socket_path)
        .with_docker_network_name(args.docker_network_name)
        .with_secrets_dir(args.secrets_working_dir_path)
        .with_sops_executable_path(args.sops_executable_path)
        .with_health_check_timeout_seconds(args.health_check_timeout_seconds)
        .with_docker_timeout_seconds(args.docker_timeout_seconds)
        .with_sops_timeout_seconds(args.sops_timeout_seconds)
        .with_age_timeout_seconds(args.age_timeout_seconds)
        .with_get_secret_file_cleanup_timeout(args.get_secret_file_cleanup_timeout)
        .with_write_secret_file_timeout(args.write_secret_file_timeout)
        .with_file_cleanup_max_retries(args.file_cleanup_max_retries)
        .with_file_cleanup_retry_delay_seconds(args.file_cleanup_retry_delay_seconds)
        .with_rate_limit_max_requests(args.rate_limit_max_requests)
        .with_rate_limit_window_seconds(args.rate_limit_window_seconds)
        .with_docker_validation(docker_validation)
        .with_auto_create_sops_file(args.auto_create_sops_file);

    let port = args.port;
    println!("Starting server on port {}", port);
    println!("Docker validation level: {}", args.docker_validation_level);
    println!("Auto-create SOPS file: {}", args.auto_create_sops_file);
    
    // Log rate limiter configuration
    let max_requests = args.rate_limit_max_requests.unwrap_or(20);
    let window_seconds = args.rate_limit_window_seconds.unwrap_or(1);
    println!("Rate limiter: {} requests per {} second(s)", max_requests, window_seconds);

    if let Err(e) = start_server(config, port).await {
        eprintln!("Server failed to start: {}", e);
        std::process::exit(1);
    }
}