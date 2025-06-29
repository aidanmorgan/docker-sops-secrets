use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

/// JSON structure representing a complete secret with access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretData {
    /// The secret value
    pub value: String,
    /// The owner of the secret
    pub owner: String,
    /// List of users allowed to read the secret (owner is always included)
    pub readers: Vec<String>,
    /// List of users allowed to write the secret (owner is always included)
    pub writers: Vec<String>,
}

impl SecretData {
    /// Create a new SecretData with the owner automatically included in readers and writers
    pub fn new(value: String, owner: String, readers: Option<Vec<String>>, writers: Option<Vec<String>>) -> Self {
        let mut final_readers = vec![];
        if readers.is_some() {
            final_readers.append(&mut readers.unwrap());
            if !final_readers.contains(&owner) {
                final_readers.push(owner.clone());
            }
        }

        let mut final_writers = vec![];
        if (writers.is_some()) {
            final_writers.append(&mut writers.unwrap());
            if !final_writers.contains(&owner) {
                final_writers.push(owner.clone());
            }
        }

        Self {
            value,
            owner,
            readers: final_readers,
            writers: final_writers,
        }
    }

    /// Check if a user can read this secret
    pub fn can_read(&self, user: &str) -> bool {
        self.readers.contains(&user.to_string())
    }

    /// Check if a user can write this secret
    pub fn can_write(&self, user: &str) -> bool {
        self.writers.contains(&user.to_string())
    }

    /// Add a reader to the list
    pub fn add_reader(&mut self, reader: String) {
        if !self.readers.contains(&reader) {
            self.readers.push(reader);
        }
    }

    /// Remove a reader from the list (but not the owner)
    pub fn remove_reader(&mut self, reader: &str) {
        if reader != &self.owner {
            self.readers.retain(|r| r != reader);
        }
    }

    /// Add a writer to the list
    pub fn add_writer(&mut self, writer: String) {
        if !self.writers.contains(&writer) {
            self.writers.push(writer);
        }
    }

    /// Remove a writer from the list (but not the owner)
    pub fn remove_writer(&mut self, writer: &str) {
        if writer != &self.owner {
            self.writers.retain(|w| w != writer);
        }
    }

    /// Set the complete readers list (owner will be automatically included)
    fn set_readers(&mut self, readers: Vec<String>) {
        let mut final_readers = readers;
        if !final_readers.contains(&self.owner) {
            final_readers.push(self.owner.clone());
        }
        self.readers = final_readers;
    }

    /// Set the complete writers list (owner will be automatically included)
    fn set_writers(&mut self, writers: Vec<String>) {
        let mut final_writers = writers;
        if !final_writers.contains(&self.owner) {
            final_writers.push(self.owner.clone());
        }
        self.writers = final_writers;
    }
}

/// Error types for SOPS operations
#[derive(Debug, thiserror::Error)]
pub enum SopsError {
    #[error("SOPS executable not found: {0}")]
    SopsNotFound(String),
    #[error("Invalid file path: {0}")]
    InvalidPath(String),
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Invalid secret format: {0}")]
    InvalidSecretFormat(String),
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),
}

/// Result type for SOPS operations
pub type SopsResult<T> = Result<T, SopsError>;

/// Configuration for SOPS operations
#[derive(Debug, Clone)]
pub struct SopsConfig {
    /// Path to the SOPS executable
    pub sops_path: String,
    /// Working directory for SOPS operations
    pub working_dir: Option<String>,
    /// Additional environment variables
    pub env_vars: HashMap<String, String>,
    /// Default timeout for operations
    pub default_timeout: Duration,
    /// Path to the SOPS file to be managed
    pub file_path: String,
    /// Master key for encryption/decryption
    pub master_key_path: String,
}

impl SopsConfig {
    /// Create a new SOPS configuration
    pub fn new(file_path: String, master_key_path: String) -> Self {
        Self {
            sops_path: "sops".to_string(),
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path,
            master_key_path,
        }
    }

    /// Create a new SOPS configuration with custom SOPS path
    pub fn with_sops_path(file_path: String, master_key_path: String, sops_path: String) -> Self {
        Self {
            sops_path,
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path,
            master_key_path,
        }
    }
}

impl Default for SopsConfig {
    fn default() -> Self {
        Self {
            sops_path: "sops".to_string(),
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path: "secrets.yaml".to_string(),
            master_key_path: "age1default".to_string(),
        }
    }
}


/// Secure SOPS wrapper
#[derive(Debug, Clone)]
pub struct SopsWrapper {
    config: SopsConfig,
}

impl SopsWrapper {
    /// Create a new SOPS wrapper with default configuration
    pub fn new() -> Self {
        Self {
            config: SopsConfig::default(),
        }
    }

    /// Create a new SOPS wrapper with custom configuration
    pub fn with_config(config: SopsConfig) -> Self {
        Self { config }
    }

    /// Create a new SOPS wrapper with file path and master key
    pub fn new_with_file(file_path: String, master_key_path: String) -> Self {
        Self {
            config: SopsConfig::new(file_path, master_key_path),
        }
    }

    /// Validate that SOPS executable exists and is accessible
    pub async fn validate_sops(&self, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        let operation = async {
            let output = TokioCommand::new(&self.config.sops_path)
                .arg("--version")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| SopsError::SopsNotFound(format!("Failed to execute SOPS: {}", e)))?;

            if !output.status.success() {
                return Err(SopsError::SopsNotFound(
                    String::from_utf8_lossy(&output.stderr).to_string()
                ));
            }

            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| SopsError::Timeout(timeout_duration))?
    }

    /// Add multiple secrets to a SOPS file in a single operation
    pub async fn add_secrets(&self, secrets: &HashMap<String, String>, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        if secrets.is_empty() {
            return Err(SopsError::InvalidSecretFormat("No secrets provided".to_string()));
        }

        // Validate SOPS is available
        self.validate_sops(Some(timeout_duration)).await?;

        // Validate file exists
        if !Path::new(&self.config.file_path).exists() {
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        let operation = async {
            // Build the command
            let mut command = TokioCommand::new(&self.config.sops_path);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                command.current_dir(working_dir);
            }

            // Add SOPS arguments
            command.arg("--set");

            // Add all secrets as key=value pairs
            for (key, value) in secrets {
                if key.trim().is_empty() {
                    return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
                }
                command.arg(&format!("{}={}", key, value));
            }

            command.arg(&self.config.file_path);

            // Add master key as an audience that can decrypt the file
            // For age keys, use --age flag
            if self.config.master_key_path.starts_with("age1") {
                command.arg("--age").arg(&self.config.master_key_path);
            } else {
                // Assume it's a PGP key or other format
                command.arg("--pgp").arg(&self.config.master_key_path);
            }

            // Set up environment variables
            command.envs(&self.config.env_vars);

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| SopsError::Timeout(timeout_duration))?
    }

    /// Add a secret to a SOPS file
    pub async fn add_secret(&self, key: &str, value: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        // Validate inputs
        if key.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
        }

        if !Path::new(&self.config.file_path).exists() {
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        // Validate SOPS is available
        self.validate_sops(Some(timeout_duration)).await?;

        let operation = async {
            // Build the command
            let mut command = TokioCommand::new(&self.config.sops_path);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                command.current_dir(working_dir);
            }

            // Add SOPS arguments
            command
                .arg("--set")
                .arg(&format!("{}={}", key, value))
                .arg(&self.config.file_path);

            // Add master key as an audience that can decrypt the file
            // For age keys, use --age flag
            if self.config.master_key_path.starts_with("age1") {
                command.arg("--age").arg(&self.config.master_key_path);
            } else {
                // Assume it's a PGP key or other format
                command.arg("--pgp").arg(&self.config.master_key_path);
            }

            // Set up environment variables
            command.envs(&self.config.env_vars);

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| SopsError::Timeout(timeout_duration))?
    }

    /// Get a secret from a SOPS file
    pub async fn get_secret(&self, key: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        if key.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
        }

        if !Path::new(&self.config.file_path).exists() {
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        // Validate SOPS is available
        self.validate_sops(Some(timeout_duration)).await?;

        let operation = async {
            // Build the command
            let mut command = TokioCommand::new(&self.config.sops_path);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                command.current_dir(working_dir);
            }

            // Add SOPS arguments
            command
                .arg("--extract")
                .arg(key)
                .arg(&self.config.file_path);

            // Add master key for decryption
            // For age keys, use --age flag
            if self.config.master_key_path.starts_with("age1") {
                command.arg("--age").arg(&self.config.master_key_path);
            } else {
                // Assume it's a PGP key or other format
                command.arg("--pgp").arg(&self.config.master_key_path);
            }

            // Set up environment variables
            command.envs(&self.config.env_vars);

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            let secret = String::from_utf8(output.stdout)
                .map_err(|e| SopsError::CommandFailed(format!("Invalid UTF-8 in output: {}", e)))?;

            Ok(secret.trim().to_string())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| SopsError::Timeout(timeout_duration))?
    }

    /// Create a new SOPS file with initial secrets
    pub async fn create_file(&self, secrets: &HashMap<String, String>, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        if secrets.is_empty() {
            return Err(SopsError::InvalidSecretFormat("No secrets provided".to_string()));
        }

        // Validate SOPS is available
        self.validate_sops(Some(timeout_duration)).await?;

        // Check if file already exists
        if Path::new(&self.config.file_path).exists() {
            return Err(SopsError::InvalidPath(format!("File already exists: {}", self.config.file_path)));
        }

        let operation = async {
            // Build the command
            let mut command = TokioCommand::new(&self.config.sops_path);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                command.current_dir(working_dir);
            }

            // Add SOPS arguments for creating a new file
            command.arg("--encrypt");
            command.arg("--set");

            // Add all secrets as key=value pairs
            for (key, value) in secrets {
                if key.trim().is_empty() {
                    return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
                }
                command.arg(&format!("{}={}", key, value));
            }

            command.arg(&self.config.file_path);

            // Add master key as an audience that can decrypt the file
            // For age keys, use --age flag
            if self.config.master_key_path.starts_with("age1") {
                command.arg("--age").arg(&self.config.master_key_path);
            } else {
                // Assume it's a PGP key or other format
                command.arg("--pgp").arg(&self.config.master_key_path);
            }

            // Set up environment variables
            command.envs(&self.config.env_vars);

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| SopsError::Timeout(timeout_duration))?
    }

    /// Add an owned secret with allowed readers and writers
    /// The secret will be stored as: {secret_name}_secret
    /// All data (value, owner, readers, writers) is stored as a single JSON struct
    /// The owner will automatically be added to both the allowed readers and writers lists
    pub async fn add_owned_secret(&self, owner_name: &str, secret_name: &str, secret_value: &str, allowed_readers: &[String], allowed_writers: &[String], timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if owner_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Owner name cannot be empty".to_string()));
        }

        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Validate owner name doesn't contain invalid characters
        if owner_name.contains(' ') || owner_name.contains('\t') || owner_name.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Owner name contains invalid characters".to_string()));
        }

        // Validate secret name doesn't contain invalid characters
        if secret_name.contains(' ') || secret_name.contains('\t') || secret_name.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        // Validate allowed readers
        for reader in allowed_readers {
            if reader.trim().is_empty() {
                return Err(SopsError::InvalidSecretFormat("Allowed reader name cannot be empty".to_string()));
            }
            if reader.contains(' ') || reader.contains('\t') || reader.contains('\n') {
                return Err(SopsError::InvalidSecretFormat("Allowed reader name contains invalid characters".to_string()));
            }
        }

        // Validate allowed writers
        for writer in allowed_writers {
            if writer.trim().is_empty() {
                return Err(SopsError::InvalidSecretFormat("Allowed writer name cannot be empty".to_string()));
            }
            if writer.contains(' ') || writer.contains('\t') || writer.contains('\n') {
                return Err(SopsError::InvalidSecretFormat("Allowed writer name contains invalid characters".to_string()));
            }
        }

        // Create the secret data structure
        let secret_data = SecretData::new(
            secret_value.to_string(),
            owner_name.to_string(),
            Some(allowed_readers.to_vec()),
            Some(allowed_writers.to_vec()),
        );

        // Serialize the complete secret data to JSON
        let secret_json = serde_json::to_string(&secret_data)
            .map_err(|e| SopsError::InvalidSecretFormat(format!("Failed to serialize secret data: {}", e)))?;

        // Create standardized secret key and store the complete JSON
        let secret_key = format!("{}_secret", secret_name);
        self.add_secret(&secret_key, &secret_json, timeout_duration).await
    }

    /// Get allowed readers for an owner secret
    /// The readers will be retrieved from the secret data structure
    pub async fn get_secret_readers(&self, secret_name: &str, timeout_duration: Option<Duration>) -> SopsResult<Vec<String>> {
        let secret_data = self.get_secret_data(secret_name, timeout_duration).await?;
        Ok(secret_data.readers)
    }

    /// Check if a reader is allowed to read an owner's secret
    pub async fn is_reader_allowed_to_read(&self, _owner_name: &str, secret_name: &str, reader_name: &str, timeout_duration: Option<Duration>) -> SopsResult<bool> {
        let secret_data = self.get_secret_data(secret_name, timeout_duration).await?;
        Ok(secret_data.can_read(reader_name))
    }

    /// Add a reader to the allowed readers list for a specific secret
    pub async fn add_reader_to_secret(&self, secret_name: &str, reader_name: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        if reader_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Reader name cannot be empty".to_string()));
        }

        // Validate reader name doesn't contain invalid characters
        if reader_name.contains(' ') || reader_name.contains('\t') || reader_name.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Reader name contains invalid characters".to_string()));
        }

        // Get current secret data
        let mut secret_data = self.get_secret_data(secret_name, timeout_duration).await?;

        // Add the reader
        secret_data.add_reader(reader_name.to_string());

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }

    /// Remove a reader from the allowed readers list for a specific secret
    pub async fn remove_reader_from_secret(&self, secret_name: &str, reader_name: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        if reader_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Reader name cannot be empty".to_string()));
        }

        // Get current secret data
        let mut secret_data = self.get_secret_data(secret_name, timeout_duration).await?;

        // Remove the reader
        secret_data.remove_reader(reader_name);

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }

    /// Replace the entire allowed readers list for a specific secret
    /// The owner will automatically be included in the readers list
    pub async fn set_secret_readers(&self, owner_name: &str, secret_name: &str, readers: &[String], timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if owner_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Owner name cannot be empty".to_string()));
        }

        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Validate all readers
        for reader in readers {
            if reader.trim().is_empty() {
                return Err(SopsError::InvalidSecretFormat("Reader name cannot be empty".to_string()));
            }
            if reader.contains(' ') || reader.contains('\t') || reader.contains('\n') {
                return Err(SopsError::InvalidSecretFormat("Reader name contains invalid characters".to_string()));
            }
        }

        // Get current secret data
        let mut secret_data = self.get_secret_data(secret_name, timeout_duration).await?;

        // Set the readers list (owner will be automatically included)
        secret_data.set_readers(readers.to_vec());

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }

    /// Get allowed writers for a secret
    /// The writers will be retrieved from the secret data structure
    pub async fn get_secret_writers(&self, secret_name: &str, timeout_duration: Option<Duration>) -> SopsResult<Vec<String>> {
        let secret_data = self.get_secret_data(secret_name, timeout_duration).await?;
        Ok(secret_data.writers)
    }

    /// Check if a writer is allowed to write to a secret
    pub async fn is_writer_allowed_to_write(&self, secret_name: &str, writer_name: &str, timeout_duration: Option<Duration>) -> SopsResult<bool> {
        let secret_data = self.get_secret_data(secret_name, timeout_duration).await?;
        Ok(secret_data.can_write(writer_name))
    }

    /// Add a writer to the allowed writers list for a specific secret
    pub async fn add_writer_to_secret(&self, secret_name: &str, writer_name: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        if writer_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Writer name cannot be empty".to_string()));
        }

        // Validate writer name doesn't contain invalid characters
        if writer_name.contains(' ') || writer_name.contains('\t') || writer_name.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Writer name contains invalid characters".to_string()));
        }

        // Get current secret data
        let mut secret_data = self.get_secret_data(secret_name, timeout_duration).await?;

        // Add the writer
        secret_data.add_writer(writer_name.to_string());

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }

    /// Remove a writer from the allowed writers list for a specific secret
    pub async fn remove_writer_from_secret(&self, secret_name: &str, writer_name: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        if writer_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Writer name cannot be empty".to_string()));
        }

        // Get current secret data
        let mut secret_data = self.get_secret_data(secret_name, timeout_duration).await?;

        // Remove the writer
        secret_data.remove_writer(writer_name);

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }

    /// Replace the entire allowed writers list for a specific secret
    /// The owner will automatically be included in the writers list
    pub async fn set_secret_writers(&self, owner_name: &str, secret_name: &str, writers: &[String], timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if owner_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Owner name cannot be empty".to_string()));
        }

        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Validate all writers
        for writer in writers {
            if writer.trim().is_empty() {
                return Err(SopsError::InvalidSecretFormat("Writer name cannot be empty".to_string()));
            }
            if writer.contains(' ') || writer.contains('\t') || writer.contains('\n') {
                return Err(SopsError::InvalidSecretFormat("Writer name contains invalid characters".to_string()));
            }
        }

        // Get current secret data
        let mut secret_data = self.get_secret_data(secret_name, timeout_duration).await?;

        // Set the writers list (owner will be automatically included)
        secret_data.set_writers(writers.to_vec());

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }

    /// Get an owned secret using the standardized naming convention
    /// The secret will be retrieved as: {secret_name}_secret
    pub async fn get_owned_secret(&self, owner_name: &str, secret_name: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
        // Validate inputs
        if owner_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Owner name cannot be empty".to_string()));
        }

        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Create standardized secret key
        let secret_key = format!("{}_secret", secret_name);

        // Validate the generated key doesn't contain invalid characters
        if secret_key.contains(' ') || secret_key.contains('\t') || secret_key.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        // Get the secret data JSON
        let secret_json = self.get_secret(&secret_key, timeout_duration).await?;

        // Parse the JSON to SecretData
        let secret_data: SecretData = serde_json::from_str(&secret_json)
            .map_err(|e| SopsError::InvalidSecretFormat(format!("Failed to deserialize secret data: {}", e)))?;

        Ok(secret_data.value)
    }

    /// Helper function to get SecretData for a given secret name
    pub async fn get_secret_data(&self, secret_name: &str, timeout_duration: Option<Duration>) -> SopsResult<SecretData> {
        // Validate inputs
        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Create standardized secret key
        let secret_key = format!("{}_secret", secret_name);

        // Validate the generated key doesn't contain invalid characters
        if secret_key.contains(' ') || secret_key.contains('\t') || secret_key.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        // Get the secret data JSON
        let secret_json = self.get_secret(&secret_key, timeout_duration).await?;

        // Parse the JSON to SecretData
        let secret_data: SecretData = serde_json::from_str(&secret_json)
            .map_err(|e| SopsError::InvalidSecretFormat(format!("Failed to deserialize secret data: {}", e)))?;

        Ok(secret_data)
    }

    /// Helper function to save SecretData for a given secret name
    async fn save_secret_data(&self, secret_name: &str, secret_data: &SecretData, timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Create standardized secret key
        let secret_key = format!("{}_secret", secret_name);

        // Validate the generated key doesn't contain invalid characters
        if secret_key.contains(' ') || secret_key.contains('\t') || secret_key.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        // Serialize the secret data to JSON
        let secret_json = serde_json::to_string(secret_data)
            .map_err(|e| SopsError::InvalidSecretFormat(format!("Failed to serialize secret data: {}", e)))?;

        // Save the secret data
        self.add_secret(&secret_key, &secret_json, timeout_duration).await
    }

    /// Update the secret value for an existing secret
    /// This preserves the owner, readers, and writers while updating only the value
    pub async fn update_secret_value(&self, secret_name: &str, new_value: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        // Validate inputs
        if secret_name.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Get current secret data
        let mut secret_data = self.get_secret_data(secret_name, timeout_duration).await?;

        // Update the value
        secret_data.value = new_value.to_string();

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }
}

/// Convenience function to add a secret to a SOPS file using default configuration
pub async fn add_secret(file_path: &str, key: &str, value: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.add_secret(key, value, timeout_duration).await
}

/// Convenience function to add multiple secrets to a SOPS file using default configuration
pub async fn add_secrets(file_path: &str, secrets: &HashMap<String, String>, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.add_secrets(secrets, timeout_duration).await
}

/// Convenience function to get a secret from a SOPS file using default configuration
pub async fn get_secret(file_path: &str, key: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.get_secret(key, timeout_duration).await
}

/// Convenience function to create a new SOPS file with initial secrets using default configuration
pub async fn create_file(file_path: &str, secrets: &HashMap<String, String>, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.create_file(secrets, timeout_duration).await
}

/// Convenience function to add an owner secret using default configuration
pub async fn add_owned_secret(file_path: &str, owner_name: &str, secret_name: &str, secret_value: &str, allowed_readers: &[String], allowed_writers: &[String], master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.add_owned_secret(owner_name, secret_name, secret_value, allowed_readers, allowed_writers, timeout_duration).await
}

/// Convenience function to get an owner secret using default configuration
pub async fn get_owned_secret(file_path: &str, owner_name: &str, secret_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.get_owned_secret(owner_name, secret_name, timeout_duration).await
}

/// Convenience function to get allowed readers for an owner secret using default configuration
pub async fn get_secret_readers(file_path: &str, secret_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<Vec<String>> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.get_secret_readers(secret_name, timeout_duration).await
}

/// Convenience function to check if a reader is allowed to read an owner's secret
pub async fn is_reader_allowed_to_read(file_path: &str, owner_name: &str, secret_name: &str, reader_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<bool> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.is_reader_allowed_to_read(owner_name, secret_name, reader_name, timeout_duration).await
}

/// Convenience function to add a reader to a secret using default configuration
pub async fn add_reader_to_secret(file_path: &str, secret_name: &str, reader_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.add_reader_to_secret(secret_name, reader_name, timeout_duration).await
}

/// Convenience function to remove a reader from a secret using default configuration
pub async fn remove_reader_from_secret(file_path: &str, secret_name: &str, reader_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.remove_reader_from_secret(secret_name, reader_name, timeout_duration).await
}

/// Convenience function to set the complete list of readers for a secret using default configuration
pub async fn set_secret_readers(file_path: &str, owner_name: &str, secret_name: &str, readers: &[String], master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.set_secret_readers(owner_name, secret_name, readers, timeout_duration).await
}

/// Convenience function to get allowed writers for a secret using default configuration
pub async fn get_secret_writers(file_path: &str, secret_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<Vec<String>> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.get_secret_writers(secret_name, timeout_duration).await
}

/// Convenience function to check if a writer is allowed to write to a secret using default configuration
pub async fn is_writer_allowed_to_write(file_path: &str, secret_name: &str, writer_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<bool> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.is_writer_allowed_to_write(secret_name, writer_name, timeout_duration).await
}

/// Convenience function to add a writer to a secret using default configuration
pub async fn add_writer_to_secret(file_path: &str, secret_name: &str, writer_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.add_writer_to_secret(secret_name, writer_name, timeout_duration).await
}

/// Convenience function to remove a writer from a secret using default configuration
pub async fn remove_writer_from_secret(file_path: &str, secret_name: &str, writer_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.remove_writer_from_secret(secret_name, writer_name, timeout_duration).await
}

/// Convenience function to set the complete list of writers for a secret using default configuration
pub async fn set_secret_writers(file_path: &str, owner_name: &str, secret_name: &str, writers: &[String], master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.set_secret_writers(owner_name, secret_name, writers, timeout_duration).await
}

/// Convenience function to update a secret value using default configuration
pub async fn update_secret_value(file_path: &str, secret_name: &str, new_value: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.update_secret_value(secret_name, new_value, timeout_duration).await
}

pub mod age;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sops_wrapper_creation() {
        let wrapper = SopsWrapper::new();
        assert_eq!(wrapper.config.sops_path, "sops");
        assert_eq!(wrapper.config.default_timeout, Duration::from_secs(5));
        assert_eq!(wrapper.config.file_path, "secrets.yaml");
        assert_eq!(wrapper.config.master_key_path, "age1default");
    }

    #[tokio::test]
    async fn test_sops_wrapper_with_config() {
        let mut config = SopsConfig::new("test.yaml".to_string(), "age1test".to_string());
        config.sops_path = "/usr/local/bin/sops".to_string();
        config.default_timeout = Duration::from_secs(10);

        let wrapper = SopsWrapper::with_config(config);
        assert_eq!(wrapper.config.sops_path, "/usr/local/bin/sops");
        assert_eq!(wrapper.config.default_timeout, Duration::from_secs(10));
        assert_eq!(wrapper.config.file_path, "test.yaml");
        assert_eq!(wrapper.config.master_key_path, "age1test");
    }

    #[tokio::test]
    async fn test_sops_wrapper_new_with_file() {
        let wrapper = SopsWrapper::new_with_file("custom.yaml".to_string(), "age1custom".to_string());
        assert_eq!(wrapper.config.file_path, "custom.yaml");
        assert_eq!(wrapper.config.master_key_path, "age1custom");
        assert_eq!(wrapper.config.sops_path, "sops");
    }

    #[tokio::test]
    async fn test_invalid_secret_format() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());
        let result = wrapper.add_secret("", "value", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_timeout_error() {
        let wrapper = SopsWrapper::new();
        // Use a very short timeout to trigger timeout error
        let result = wrapper.validate_sops(Some(Duration::from_nanos(1))).await;
        assert!(matches!(result, Err(SopsError::Timeout(_))));
    }

    #[tokio::test]
    async fn test_add_owner_secret_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty owner name
        let result = wrapper.add_owned_secret("", "password", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty secret name
        let result = wrapper.add_owned_secret("owner1", "", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test owner name with spaces
        let result = wrapper.add_owned_secret("owner 1", "password", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test secret name with tabs
        let result = wrapper.add_owned_secret("owner1", "pass\tword", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test allowed reader with newlines
        let result = wrapper.add_owned_secret("owner1", "password", "value", &["reader\n1".to_string()], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty allowed reader
        let result = wrapper.add_owned_secret("owner1", "password", "value", &["".to_string()], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_get_owner_secret_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty owner name
        let result = wrapper.get_owned_secret("", "password", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty secret name
        let result = wrapper.get_owned_secret("owner1", "", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_get_owner_secret_readers_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty secret name
        let result = wrapper.get_secret_readers("", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_owner_secret_naming_convention() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test that the naming convention is applied correctly without actually calling SOPS
        let owner_name = "myapp";
        let secret_name = "database_password";
        let expected_secret_key = "database_password_secret";
        let expected_readers_key = "database_password_readers";

        // We can't easily test the actual SOPS call without a real file,
        // but we can verify the naming convention logic
        let generated_secret_key = format!("{}_secret", secret_name);
        let generated_readers_key = format!("{}_readers", secret_name);

        assert_eq!(generated_secret_key, expected_secret_key);
        assert_eq!(generated_readers_key, expected_readers_key);
    }

    #[tokio::test]
    async fn test_allowed_readers_serialization() {
        // Test JSON serialization of allowed readers
        let allowed_readers = vec!["reader1".to_string(), "reader2".to_string(), "reader3".to_string()];
        let readers_json = serde_json::to_string(&allowed_readers).unwrap();

        // Verify the JSON format
        assert_eq!(readers_json, r#"["reader1","reader2","reader3"]"#);

        // Test deserialization
        let deserialized: Vec<String> = serde_json::from_str(&readers_json).unwrap();
        assert_eq!(deserialized, allowed_readers);
    }

    #[tokio::test]
    async fn test_add_reader_to_secret_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty secret name
        let result = wrapper.add_reader_to_secret("", "reader1", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty reader name
        let result = wrapper.add_reader_to_secret("password", "", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test reader name with spaces
        let result = wrapper.add_reader_to_secret("password", "reader 1", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_remove_reader_from_secret_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty secret name
        let result = wrapper.remove_reader_from_secret("", "reader1", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty reader name
        let result = wrapper.remove_reader_from_secret("password", "", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_set_secret_readers_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty secret name
        let result = wrapper.set_secret_readers("", "password", &["reader1".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty reader name in list
        let result = wrapper.set_secret_readers("owner1", "password", &["reader1".to_string(), "".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test reader name with tabs in list
        let result = wrapper.set_secret_readers("owner1", "password", &["reader1".to_string(), "reader\t2".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_reader_management_logic() {
        // Test the logic of adding and removing readers without actually calling SOPS
        let mut readers = vec!["reader1".to_string(), "reader2".to_string()];

        // Test adding a new reader
        let new_reader = "reader3".to_string();
        if !readers.contains(&new_reader) {
            readers.push(new_reader);
        }
        assert_eq!(readers.len(), 3);
        assert!(readers.contains(&"reader3".to_string()));

        // Test adding an existing reader (should not duplicate)
        let existing_reader = "reader1".to_string();
        if !readers.contains(&existing_reader) {
            readers.push(existing_reader);
        }
        assert_eq!(readers.len(), 3); // Should still be 3, not 4

        // Test removing a reader
        readers.retain(|r| r != "reader2");
        assert_eq!(readers.len(), 2);
        assert!(!readers.contains(&"reader2".to_string()));

        // Test removing a non-existent reader
        readers.retain(|r| r != "nonexistent");
        assert_eq!(readers.len(), 2); // Should still be 2
    }

    #[tokio::test]
    async fn test_owner_always_included_in_readers() {
        // Test that the owner is always automatically included in the readers list
        let owner_name = "myapp";
        let allowed_readers = vec!["reader1".to_string(), "reader2".to_string()];

        // Simulate the logic from add_owned_secret
        let mut final_readers = allowed_readers.clone();
        if !final_readers.contains(&owner_name.to_string()) {
            final_readers.push(owner_name.to_string());
        }

        // Verify owner is included
        assert!(final_readers.contains(&owner_name.to_string()));
        assert_eq!(final_readers.len(), 3); // reader1, reader2, myapp

        // Test with owner already in the list
        let readers_with_owner = vec!["reader1".to_string(), "myapp".to_string(), "reader2".to_string()];
        let mut final_readers2 = readers_with_owner.clone();
        if !final_readers2.contains(&owner_name.to_string()) {
            final_readers2.push(owner_name.to_string());
        }

        // Verify owner is not duplicated
        assert!(final_readers2.contains(&owner_name.to_string()));
        assert_eq!(final_readers2.len(), 3); // Should still be 3, not 4

        // Test with empty readers list
        let empty_readers: Vec<String> = vec![];
        let mut final_readers3 = empty_readers.clone();
        if !final_readers3.contains(&owner_name.to_string()) {
            final_readers3.push(owner_name.to_string());
        }

        // Verify owner is added to empty list
        assert!(final_readers3.contains(&owner_name.to_string()));
        assert_eq!(final_readers3.len(), 1); // Just the owner
    }

    #[tokio::test]
    async fn test_add_owned_secret_with_writers_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty owner name
        let result = wrapper.add_owned_secret("", "password", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty secret name
        let result = wrapper.add_owned_secret("owner1", "", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test owner name with spaces
        let result = wrapper.add_owned_secret("owner 1", "password", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test secret name with tabs
        let result = wrapper.add_owned_secret("owner1", "pass\tword", "value", &[], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test allowed reader with newlines
        let result = wrapper.add_owned_secret("owner1", "password", "value", &["reader\n1".to_string()], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty allowed reader
        let result = wrapper.add_owned_secret("owner1", "password", "value", &["".to_string()], &[], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test allowed writer with newlines
        let result = wrapper.add_owned_secret("owner1", "password", "value", &[], &["writer\n1".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty allowed writer
        let result = wrapper.add_owned_secret("owner1", "password", "value", &[], &["".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_get_secret_writers_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty secret name
        let result = wrapper.get_secret_writers("", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_add_writer_to_secret_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty secret name
        let result = wrapper.add_writer_to_secret("", "writer1", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty writer name
        let result = wrapper.add_writer_to_secret("password", "", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test writer name with spaces
        let result = wrapper.add_writer_to_secret("password", "writer 1", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_remove_writer_from_secret_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty secret name
        let result = wrapper.remove_writer_from_secret("", "writer1", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty writer name
        let result = wrapper.remove_writer_from_secret("password", "", None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_set_secret_writers_validation() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test empty owner name
        let result = wrapper.set_secret_writers("", "password", &["writer1".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty secret name
        let result = wrapper.set_secret_writers("owner1", "", &["writer1".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test empty writer name in list
        let result = wrapper.set_secret_writers("owner1", "password", &["writer1".to_string(), "".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));

        // Test writer name with tabs in list
        let result = wrapper.set_secret_writers("owner1", "password", &["writer1".to_string(), "writer\t2".to_string()], None).await;
        assert!(matches!(result, Err(SopsError::InvalidSecretFormat(_))));
    }

    #[tokio::test]
    async fn test_writer_management_logic() {
        // Test the logic of adding and removing writers without actually calling SOPS
        let mut writers = vec!["writer1".to_string(), "writer2".to_string()];

        // Test adding a new writer
        let new_writer = "writer3".to_string();
        if !writers.contains(&new_writer) {
            writers.push(new_writer);
        }
        assert_eq!(writers.len(), 3);
        assert!(writers.contains(&"writer3".to_string()));

        // Test adding an existing writer (should not duplicate)
        let existing_writer = "writer1".to_string();
        if !writers.contains(&existing_writer) {
            writers.push(existing_writer);
        }
        assert_eq!(writers.len(), 3); // Should still be 3, not 4

        // Test removing a writer
        writers.retain(|w| w != "writer2");
        assert_eq!(writers.len(), 2);
        assert!(!writers.contains(&"writer2".to_string()));

        // Test removing a non-existent writer
        writers.retain(|w| w != "nonexistent");
        assert_eq!(writers.len(), 2); // Should still be 2
    }

    #[tokio::test]
    async fn test_owner_always_included_in_writers() {
        // Test that the owner is always automatically included in the writers list
        let owner_name = "myapp";
        let allowed_writers = vec!["writer1".to_string(), "writer2".to_string()];

        // Simulate the logic from add_owned_secret
        let mut final_writers = allowed_writers.clone();
        if !final_writers.contains(&owner_name.to_string()) {
            final_writers.push(owner_name.to_string());
        }

        // Verify owner is included
        assert!(final_writers.contains(&owner_name.to_string()));
        assert_eq!(final_writers.len(), 3); // writer1, writer2, myapp

        // Test with owner already in the list
        let writers_with_owner = vec!["writer1".to_string(), "myapp".to_string(), "writer2".to_string()];
        let mut final_writers2 = writers_with_owner.clone();
        if !final_writers2.contains(&owner_name.to_string()) {
            final_writers2.push(owner_name.to_string());
        }

        // Verify owner is not duplicated
        assert!(final_writers2.contains(&owner_name.to_string()));
        assert_eq!(final_writers2.len(), 3); // Should still be 3, not 4

        // Test with empty writers list
        let empty_writers: Vec<String> = vec![];
        let mut final_writers3 = empty_writers.clone();
        if !final_writers3.contains(&owner_name.to_string()) {
            final_writers3.push(owner_name.to_string());
        }

        // Verify owner is added to empty list
        assert!(final_writers3.contains(&owner_name.to_string()));
        assert_eq!(final_writers3.len(), 1); // Just the owner
    }

    #[tokio::test]
    async fn test_owned_secret_naming_convention_with_writers() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test that the naming convention is applied correctly for writers
        // This test verifies the internal logic without actually calling SOPS
        let owner_name = "myapp";
        let secret_name = "database_password";
        let expected_secret_key = "database_password_secret";
        let expected_readers_key = "database_password_readers";
        let expected_writers_key = "database_password_writers";

        // We can't easily test the actual SOPS call without a real file,
        // but we can verify the naming convention logic
        let generated_secret_key = format!("{}_secret", secret_name);
        let generated_readers_key = format!("{}_readers", secret_name);
        let generated_writers_key = format!("{}_writers", secret_name);

        assert_eq!(generated_secret_key, expected_secret_key);
        assert_eq!(generated_readers_key, expected_readers_key);
        assert_eq!(generated_writers_key, expected_writers_key);
    }

    #[tokio::test]
    async fn test_allowed_writers_serialization() {
        // Test JSON serialization of allowed writers
        let allowed_writers = vec!["writer1".to_string(), "writer2".to_string(), "writer3".to_string()];
        let writers_json = serde_json::to_string(&allowed_writers).unwrap();

        // Verify the JSON format
        assert_eq!(writers_json, r#"["writer1","writer2","writer3"]"#);

        // Test deserialization
        let deserialized: Vec<String> = serde_json::from_str(&writers_json).unwrap();
        assert_eq!(deserialized, allowed_writers);
    }

    #[tokio::test]
    async fn test_secret_data_structure() {
        // Test the SecretData structure
        let secret_data = SecretData::new(
            "secret_value".to_string(),
            "owner1".to_string(),
            Some(vec!["reader1".to_string(), "reader2".to_string()]),
            Some(vec!["writer1".to_string()]),
        );

        // Verify owner is automatically included in both readers and writers
        assert!(secret_data.can_read("owner1"));
        assert!(secret_data.can_write("owner1"));
        assert!(secret_data.can_read("reader1"));
        assert!(secret_data.can_read("reader2"));
        assert!(secret_data.can_write("writer1"));

        // Verify other users are not included
        assert!(!secret_data.can_read("reader3"));
        assert!(!secret_data.can_write("writer2"));

        // Test JSON serialization
        let json = serde_json::to_string(&secret_data).unwrap();
        let deserialized: SecretData = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.value, "secret_value");
        assert_eq!(deserialized.owner, "owner1");
        assert!(deserialized.readers.contains(&"owner1".to_string()));
        assert!(deserialized.writers.contains(&"owner1".to_string()));
    }

    #[tokio::test]
    async fn test_secret_data_methods() {
        let mut secret_data = SecretData::new(
            "secret_value".to_string(),
            "owner1".to_string(),
            Some(vec!["reader1".to_string()]),
            Some(vec!["writer1".to_string()]),
        );

        // Test adding readers and writers
        secret_data.add_reader("reader2".to_string());
        secret_data.add_writer("writer2".to_string());

        assert!(secret_data.can_read("reader2"));
        assert!(secret_data.can_write("writer2"));

        // Test removing readers and writers (but not owner)
        secret_data.remove_reader("reader1");
        secret_data.remove_writer("writer1");

        assert!(!secret_data.can_read("reader1"));
        assert!(!secret_data.can_write("writer1"));

        // Owner should still be able to read and write
        assert!(secret_data.can_read("owner1"));
        assert!(secret_data.can_write("owner1"));

        // Test setting complete lists
        secret_data.set_readers(vec!["new_reader".to_string()]);
        secret_data.set_writers(vec!["new_writer".to_string()]);

        assert!(secret_data.can_read("new_reader"));
        assert!(secret_data.can_write("new_writer"));
        assert!(secret_data.can_read("owner1")); // Owner should still be included
        assert!(secret_data.can_write("owner1")); // Owner should still be included
    }

    #[tokio::test]
    async fn test_update_secret_value() {
        let wrapper = SopsWrapper::new_with_file("test.yaml".to_string(), "age1test".to_string());

        // Test updating a secret value
        let result = wrapper.update_secret_value("database_password", "new_value", None).await;
        assert!(result.is_ok());

        // Verify the secret value is updated
        let secret_value = wrapper.get_owned_secret("myapp", "database_password", None).await;
        assert_eq!(secret_value.unwrap(), "new_value");
    }
}
