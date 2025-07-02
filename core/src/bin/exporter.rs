use clap::Parser;
use dotenv::dotenv;
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::timeout;
use zeroize::Zeroize;

use sops_secrets::shared::age::{decrypt_with_age_private_key, generate_temp_age_key_pair, AgeError};
use sops_secrets::shared::logging;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Export secrets from sops-secrets server as environment variables or files"
)]
struct Args {
    /// Comma-separated list of secret names to export
    #[arg(long, short, env = "SECRETS")]
    secrets: Option<String>,

    /// Server URL
    #[arg(long, env = "SOPS_SERVER_URL", default_value = "http://localhost:3102")]
    server_url: String,

    /// Base directory for reading encrypted secret files
    #[arg(long, env = "SECRETS_WORKING_DIR", default_value = "/var/tmp/sops-secrets")]
    secrets_working_dir: String,

    /// Timeout for server operations (seconds)
    #[arg(long, env = "SERVER_TIMEOUT_SECONDS", default_value_t = 30)]
    timeout_seconds: u64,

    /// Prefix for environment variable names (only used with --export-env)
    #[arg(long, env = "ENV_PREFIX", default_value = "")]
    prefix: String,

    /// Export secrets as environment variables
    #[arg(long)]
    export_env: bool,

    /// Export secrets as individual files in a directory
    #[arg(long)]
    export_dir: bool,

    /// Directory to write secret files to (only used with --export-dir), defaults to the same directory used by docker secrets for convenience.
    #[arg(long, env = "EXPORT_DIR", default_value = "/run/secrets")]
    export_directory: String,

    /// Command to execute after setting environment variables (only used with --export-env)
    #[arg(long, short)]
    exec: Option<String>,

    /// Arguments for the command to execute (only used with --export-env)
    #[arg(long, short)]
    args: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExporterError {
    #[error("Server error: {0}")]
    Server(String),
    #[error("Age encryption error: {0}")]
    Age(#[from] AgeError),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout")]
    Timeout,
    #[error("No secrets specified")]
    NoSecrets,
    #[error("Hash validation failed for secret {0}")]
    HashMismatch(String),
    #[error("No export mode specified. Use --export-env or --export-dir (but not both)")]
    NoExportMode,
}

/// Calculate SHA256 hash of a string
fn calculate_secret_hash(secret_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret_value.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Get a single secret from the server
async fn get_secret(
    client: &Client,
    server_url: &str,
    secret_name: &str,
    secrets_working_dir: &str,
    timeout_duration: Duration,
) -> Result<String, ExporterError> {
    // Generate a unique key pair for this secret
    let key_pair = generate_temp_age_key_pair(timeout_duration)
        .await
        .map_err(|e| ExporterError::Age(e))?;

    let secret_url = format!("{}/secrets/{}", server_url, secret_name);
    let request_body = json!({
        "public_key": key_pair.public_key
    });

    let response = timeout(
        timeout_duration,
        client
            .post(&secret_url)
            .json(&request_body)
            .send(),
    )
        .await
        .map_err(|_| ExporterError::Timeout)?
        .map_err(|e| ExporterError::Http(e))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(ExporterError::Server(format!(
            "Failed to get secret '{}': {}",
            secret_name, error_text
        )));
    }

    let secret_response: serde_json::Value = response
        .json()
        .await
        .map_err(|e| ExporterError::Http(e))?;

    let file_path = secret_response.get("file_path")
        .and_then(|f| f.as_str())
        .ok_or_else(|| ExporterError::Server(format!(
            "Invalid response format for secret '{}': missing file_path",
            secret_name
        )))?;

    let expected_hash = secret_response.get("secret_hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| ExporterError::Server(format!(
            "Invalid response format for secret '{}': missing secret_hash",
            secret_name
        )))?;

    // Construct the full path to the encrypted file
    let full_path = Path::new(secrets_working_dir).join(file_path);

    // Read the encrypted file
    let encrypted_data = match fs::read(&full_path) {
        Ok(data) => data,
        Err(e) => {
            // Clean up key pair before returning error
            drop(key_pair);
            return Err(ExporterError::Io(e));
        }
    };

    // Decrypt the secret using the private key
    let decrypted = match decrypt_with_age_private_key(
        &key_pair.private_key,
        &encrypted_data,
        timeout_duration,
    ).await {
        Ok(data) => data,
        Err(e) => {
            // Clean up key pair before returning error
            drop(key_pair);
            // Try to delete the file even if decryption failed
            let _ = fs::remove_file(&full_path);
            return Err(ExporterError::Age(e));
        }
    };

    // Validate the hash
    let actual_hash = calculate_secret_hash(&decrypted);
    if actual_hash != expected_hash {
        // Clean up key pair before returning error
        drop(key_pair);
        // Try to delete the file even if hash validation failed
        let _ = fs::remove_file(&full_path);
        return Err(ExporterError::HashMismatch(secret_name.to_string()));
    }

    // Delete the encrypted file immediately after successful decryption and validation
    if let Err(e) = fs::remove_file(&full_path) {
        eprintln!("⚠️  Warning: Failed to delete encrypted file {}: {}", full_path.display(), e);
    }

    // Clean up the key pair immediately after use
    drop(key_pair);

    Ok(decrypted)
}

/// Get multiple secrets from the server
async fn get_secrets(
    client: &Client,
    server_url: &str,
    secret_names: &[String],
    secrets_working_dir: &str,
    timeout_duration: Duration,
) -> Result<HashMap<String, String>, ExporterError> {
    let mut secrets = HashMap::new();
    let mut failed_secrets = Vec::new();

    for secret_name in secret_names {
        match get_secret(client, server_url, secret_name, secrets_working_dir, timeout_duration).await {
            Ok(value) => {
                secrets.insert(secret_name.clone(), value);
                eprintln!("✅ Retrieved secret: {}", secret_name);
            }
            Err(e) => {
                eprintln!("❌ Failed to retrieve secret '{}': {}", secret_name, e);
                failed_secrets.push(secret_name.clone());
                // Continue with other secrets instead of failing completely
            }
        }
    }

    // If all secrets failed, return an error
    if secrets.is_empty() && !failed_secrets.is_empty() {
        return Err(ExporterError::Server(format!(
            "Failed to retrieve any secrets. Failed secrets: {}",
            failed_secrets.join(", ")
        )));
    }

    Ok(secrets)
}

/// Write secrets to individual files in a directory and zeroize the data
fn write_secrets_to_directory_and_zeroize(
    secrets: &mut HashMap<String, String>,
    export_directory: &str,
) -> Result<(), ExporterError> {
    // Create the export directory if it doesn't exist
    fs::create_dir_all(export_directory)
        .map_err(|e| ExporterError::Io(e))?;

    let mut files_written = Vec::new();

    for (secret_name, secret_value) in secrets.iter() {
        let file_path = Path::new(export_directory).join(secret_name);

        // Write the secret to a file
        fs::write(&file_path, secret_value)
            .map_err(|e| ExporterError::Io(e))?;

        files_written.push(secret_name.clone());
    }

    // Zeroize all secrets in the HashMap immediately after writing files
    for (_, value) in secrets.iter_mut() {
        value.zeroize();
    }
    secrets.clear();

    println!("📁 Wrote {} secret files to {}: {}", files_written.len(), export_directory, files_written.join(", "));

    Ok(())
}

/// Set environment variables in the current process and zeroize the data
fn set_environment_variables_and_zeroize(
    secrets: &mut HashMap<String, String>,
    prefix: &str,
) -> Result<(), ExporterError> {
    let mut env_vars_set = Vec::new();

    for (key, value) in secrets.iter() {
        let env_key = if prefix.is_empty() {
            key.to_uppercase()
        } else {
            format!("{}{}", prefix.to_uppercase(), key.to_uppercase())
        };

        unsafe {
            env::set_var(&env_key, value);
            env_vars_set.push(env_key);
        }
    }

    // Zeroize all secrets in the HashMap immediately after setting environment variables
    for (_, value) in secrets.iter_mut() {
        value.zeroize();
    }
    secrets.clear();

    println!("🔐 Set {} environment variables: {}", env_vars_set.len(), env_vars_set.join(", "));

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), ExporterError> {
    dotenv().ok();

    // Initialize the custom logger
    logging::init_logger();

    let args = Args::parse();

    // Validate export mode
    if !args.export_env && !args.export_dir {
        return Err(ExporterError::NoExportMode);
    }

    if args.export_env && args.export_dir {
        return Err(ExporterError::Server("Cannot use both --export-env and --export-dir. Choose one export mode.".to_string()));
    }

    // Get list of secrets to export
    let secret_names = if let Some(secrets_arg) = args.secrets {
        secrets_arg
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>()
    } else {
        return Err(ExporterError::NoSecrets);
    };

    if secret_names.is_empty() {
        return Err(ExporterError::NoSecrets);
    }

    println!("🚀 Connecting to sops-secrets server at {}", args.server_url);
    println!("📋 Requesting {} secrets: {}", secret_names.len(), secret_names.join(", "));
    println!("📁 Reading encrypted files from: {}", args.secrets_working_dir);
    println!("🔍 Server will identify container automatically based on IP address");

    if args.export_env {
        println!("🔐 Export mode: Environment variables");
    }
    if args.export_dir {
        println!("📁 Export mode: Directory ({})", args.export_directory);
    }

    // Create HTTP client
    let client = Client::new();

    // Get all secrets
    let mut secrets = get_secrets(
        &client,
        &args.server_url,
        &secret_names,
        &args.secrets_working_dir,
        Duration::from_secs(args.timeout_seconds),
    )
        .await?;

    if secrets.is_empty() {
        println!("😞 No secrets were successfully retrieved");
        return Err(ExporterError::NoSecrets);
    }

    println!("🎉 Successfully retrieved {} secrets", secrets.len());

    // Export secrets based on selected mode
    if args.export_env {
        set_environment_variables_and_zeroize(&mut secrets, &args.prefix)?;
        println!("✨ Environment variables set in current process");

        // Execute command if specified
        if let Some(exec) = &args.exec {
            println!("🚀 Executing command: {} {}", exec, args.args.join(" "));

            let mut command = Command::new(exec);
            command.args(&args.args);

            // Inherit stdin, stdout, and stderr from parent process
            command.stdin(Stdio::inherit());
            command.stdout(Stdio::inherit());
            command.stderr(Stdio::inherit());

            // Spawn the child process
            let mut child = command.spawn()
                .map_err(|e| ExporterError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to spawn command '{}': {}", exec, e),
                )))?;

            // Wait for the child process to complete
            let status = child.wait()
                .map_err(|e| ExporterError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to wait for command '{}': {}", exec, e),
                )))?;

            // Exit with the same code as the child process
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    if args.export_dir {
        write_secrets_to_directory_and_zeroize(&mut secrets, &args.export_directory)?;
        println!("✨ Secret files written to directory");
    }

    Ok(())
}
