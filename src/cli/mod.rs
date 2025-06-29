use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::server::{start_server, ServerConfig};
use crate::shared::{add_owned_secret, get_owned_secret};

#[derive(Parser)]
#[command(name = "sops-secrets")]
#[command(about = "SOPS Secrets Management with Docker-based Authorization")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the REST API server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

        /// SOPS file path
        #[arg(long, default_value = "secrets.yaml")]
        sops_file: PathBuf,

        /// Master key path
        #[arg(long, default_value = "age1default")]
        master_key: String,

        /// Docker socket path
        #[arg(long, default_value = "/var/run/docker.sock")]
        docker_socket: String,

        /// Timeout in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,

        /// Directory to store encrypted secret files
        #[arg(long, default_value = "/tmp/sops-secrets")]
        secrets_dir: String,

        /// Path to age executable
        #[arg(long, default_value = "age")]
        age_executable: String,

        /// Path to SOPS executable
        #[arg(long, default_value = "sops")]
        sops_executable: String,

        /// Health check timeout in seconds
        #[arg(long, default_value_t = 20)]
        health_check_timeout: u64,

        /// Docker API timeout in seconds
        #[arg(long, default_value_t = 20)]
        docker_timeout: u64,

        /// SOPS operation timeout in seconds
        #[arg(long, default_value_t = 20)]
        sops_timeout: u64,

        /// Age encryption timeout in seconds
        #[arg(long, default_value_t = 20)]
        age_timeout: u64,
    },

    /// Add a secret with access control
    AddSecret {
        /// SOPS file path
        #[arg(long, default_value = "secrets.yaml")]
        sops_file: PathBuf,

        /// Master key path
        #[arg(long, default_value = "age1default")]
        master_key: String,

        /// Owner name
        #[arg(short, long)]
        owner: String,

        /// Secret name
        #[arg(short, long)]
        name: String,

        /// Secret value
        #[arg(short, long)]
        value: String,

        /// Allowed readers (comma-separated)
        #[arg(long, default_value = "")]
        readers: String,

        /// Allowed writers (comma-separated)
        #[arg(long, default_value = "")]
        writers: String,
    },

    /// Get a secret value
    GetSecret {
        /// SOPS file path
        #[arg(long, default_value = "secrets.yaml")]
        sops_file: PathBuf,

        /// Master key path
        #[arg(long, default_value = "age1default")]
        master_key: String,

        /// Owner name
        #[arg(short, long)]
        owner: String,

        /// Secret name
        #[arg(short, long)]
        name: String,
    },
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { port, sops_file, master_key, docker_socket, timeout, secrets_dir, age_executable, sops_executable, health_check_timeout, docker_timeout, sops_timeout, age_timeout } => {
            let config = ServerConfig {
                sops_file_path: sops_file.to_string_lossy().to_string(),
                master_key_path: master_key,
                docker_socket_path: docker_socket,
                secrets_dir: secrets_dir,
                age_executable_path: age_executable,
                sops_executable_path: sops_executable,
                health_check_timeout_seconds: health_check_timeout,
                docker_timeout_seconds: docker_timeout,
                sops_timeout_seconds: sops_timeout,
                age_timeout_seconds: age_timeout,
                get_secret_file_cleanup_timeout: 60,
                write_secret_file_timeout: 60
            };

            println!("Starting server on port {} with config:", port);
            println!("  SOPS file: {}", config.sops_file_path);
            println!("  Master key: {}", config.master_key_path);
            println!("  Docker socket: {}", config.docker_socket_path);
            println!("  Secrets directory: {}", config.secrets_dir);
            println!("  Age executable: {}", config.age_executable_path);
            println!("  SOPS executable: {}", config.sops_executable_path);
            println!("  Health check timeout: {} seconds", config.health_check_timeout_seconds);
            println!("  Docker timeout: {} seconds", config.docker_timeout_seconds);
            println!("  SOPS timeout: {} seconds", config.sops_timeout_seconds);
            println!("  Age timeout: {} seconds", config.age_timeout_seconds);

            start_server(config, port).await?;
        }

        Commands::AddSecret { sops_file, master_key, owner, name, value, readers, writers } => {
            let readers_vec: Vec<String> = if readers.is_empty() {
                vec![]
            } else {
                readers.split(',').map(|s| s.trim().to_string()).collect()
            };

            let writers_vec: Vec<String> = if writers.is_empty() {
                vec![]
            } else {
                writers.split(',').map(|s| s.trim().to_string()).collect()
            };

            add_owned_secret(
                &sops_file.to_string_lossy(),
                &owner,
                &name,
                &value,
                &readers_vec,
                &writers_vec,
                &master_key,
                None,
            ).await?;

            println!("Secret '{}' added successfully for owner '{}'", name, owner);
        }

        Commands::GetSecret { sops_file, master_key, owner, name } => {
            let secret_value = get_owned_secret(
                &sops_file.to_string_lossy(),
                &owner,
                &name,
                &master_key,
                None,
            ).await?;

            println!("Secret '{}' value: {}", name, secret_value);
        }
    }

    Ok(())
}
