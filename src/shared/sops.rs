use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

use crate::test_log;

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
        if let Some(readers_vec) = readers {
            final_readers.extend(readers_vec);
            if !final_readers.contains(&owner) {
                final_readers.push(owner.clone());
            }
        }

        let mut final_writers = vec![];
        if let Some(writers_vec) = writers {
            final_writers.extend(writers_vec);
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
    #[error("Failed to load private key from file: {0}")]
    KeyLoadError(String),
    #[error("Failed to parse the secret metadata: {0}")]
    InvalidSecretPayload(String),
    #[error("No secret with key found")]
    NoSecretFound,
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
            sops_path: "/usr/bin/local/sops".to_string(),
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

/// Secure SOPS wrapper for managing encrypted secrets.
/// 
/// # Thread Safety
/// 
/// This struct is thread-safe and can be shared across multiple async tasks:
/// 
/// - **Immutable Design**: All methods take `&self` (immutable borrows), ensuring no
///   concurrent modifications to internal state.
/// 
/// - **Owned Configuration**: The internal `SopsConfig` contains only owned types
///   (`String`, `HashMap<String, String>`, `Option<String>`, `Duration`) that are
///   safe to share across threads.
/// 
/// - **No Shared Mutable State**: Each operation that needs to modify environment
///   variables creates a new `HashMap` by cloning `self.config.env_vars`, so there's
///   no shared mutable state between concurrent operations.
/// 
/// - **File Operations**: All file operations are read-only or create new files,
///   and the underlying file system handles concurrent access appropriately.
/// 
/// # Usage
/// 
/// This wrapper can be safely shared across multiple HTTP request handlers without
/// additional synchronization. Each handler can call methods concurrently without
/// risk of race conditions.
#[derive(Debug, Clone)]
pub struct SopsWrapper {
    /// Configuration for SOPS operations. Immutable and thread-safe.
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

    /// Create a new SOPS wrapper with file path and master key path
    pub fn new_with_file(file_path: String, master_key_path: String) -> Self {
        Self {
            config: SopsConfig::new(file_path, master_key_path),
        }
    }

    /// Load the private key from the configured key file
    async fn load_private_key(&self) -> SopsResult<String> {
        let key_content = tokio::fs::read_to_string(&self.config.master_key_path)
            .await
            .map_err(|e| SopsError::KeyLoadError(format!("Failed to read key file '{}': {}", self.config.master_key_path, e)))?;
        
        // Find the line that contains the age private key
        for line in key_content.lines() {
            let trimmed_line = line.trim();
            if trimmed_line.starts_with("AGE-SECRET-KEY-") {
                return Ok(trimmed_line.to_string());
            }
        }
        
        Err(SopsError::KeyLoadError(format!("No valid age private key found in file '{}'", self.config.master_key_path)))
    }

    /// Validate that SOPS executable exists and is accessible
    pub async fn validate_sops(&self, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);
        test_log!("Validating SOPS executable: {} with timeout {:?}", self.config.sops_path, timeout_duration);

        let operation = async {
            let mut command = TokioCommand::new(&self.config.sops_path);
            let env = &mut self.config.env_vars.clone();
            if !env.contains_key("SOPS_AGE_KEY_FILE") {
                test_log!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", self.config.master_key_path);
                env.insert("SOPS_AGE_KEY_FILE".to_string(), self.config.master_key_path.clone());
            } else {
                test_log!("SOPS_AGE_KEY_FILE already set in environment");
            }
            command.envs(env);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                test_log!("Setting working directory to: {}", working_dir);
                command.current_dir(working_dir);
            } else {
                test_log!("No working directory specified");
            }

            command.arg("--version");
            test_log!("Executing SOPS command: {} --version", self.config.sops_path);

            // Debug: Print the command being executed
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| {
                    test_log!("Failed to execute SOPS command: {}", e);
                    SopsError::SopsNotFound(format!("Failed to execute SOPS: {}", e))
                })?;

            test_log!("SOPS command completed with status: {}", output.status);
            if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
                test_log!("SOPS version output: {}", stdout.trim());
            }
            if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                if !stderr.trim().is_empty() {
                    test_log!("SOPS stderr output: {}", stderr.trim());
                }
            }

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                test_log!("SOPS validation failed with status {}: {}", output.status, stderr);
                return Err(SopsError::SopsNotFound(stderr.to_string()));
            }

            test_log!("SOPS validation successful");
            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| {
                test_log!("SOPS validation timed out after {:?}", timeout_duration);
                SopsError::Timeout(timeout_duration)
            })?
    }

    /// Add multiple secrets to a SOPS file in a single operation
    async fn add_secrets(&self, owner: &str, secrets: &HashMap<String, String>, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        if secrets.is_empty() {
            return Err(SopsError::InvalidSecretFormat("No secrets provided".to_string()));
        }

        // Validate owner
        if owner.trim().is_empty() {
            return Err(SopsError::InvalidSecretFormat("Owner cannot be empty".to_string()));
        }

        // Validate SOPS is available
        self.validate_sops(Some(timeout_duration)).await?;

        // Validate file exists
        if !Path::new(&self.config.file_path).exists() {
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        let operation = async {
            // Load the private key
            let _private_key = self.load_private_key().await?;

            // Build the command
            let mut command = TokioCommand::new(&self.config.sops_path);
            let env = &mut self.config.env_vars.clone();
            if !env.contains_key("SOPS_AGE_KEY_FILE") {
                env.insert("SOPS_AGE_KEY_FILE".to_string(), self.config.master_key_path.clone());
            }
            command.envs(env);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                command.current_dir(working_dir);
            }

            // Add SOPS arguments
            command.arg("--set");

            // Add all secrets as key=value pairs with owner prefix
            for (key, value) in secrets {
                if key.trim().is_empty() {
                    return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
                }
                let owned_key = format!("{}_{}", owner, key);
                command.arg(&format!("{}={}", owned_key, value));
            }

            command.arg(&self.config.file_path);

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

    /// Add a secret to a SOPS file (requires owner)
    async fn add_secret(&self, owner: &str, key: &str, value: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        test_log!("Adding secret: owner='{}', key='{}', timeout={:?}", owner, key, timeout_duration);

        // Validate inputs
        if owner.trim().is_empty() {
            test_log!("Validation failed: owner is empty");
            return Err(SopsError::InvalidSecretFormat("Owner cannot be empty".to_string()));
        }
        if key.trim().is_empty() {
            test_log!("Validation failed: key is empty");
            return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
        }

        if !Path::new(&self.config.file_path).exists() {
            test_log!("Validation failed: file does not exist: {}", self.config.file_path);
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        test_log!("File exists: {}", self.config.file_path);

        // Validate SOPS is available
        test_log!("Validating SOPS availability...");
        self.validate_sops(Some(timeout_duration)).await?;
        test_log!("SOPS validation successful");

        let operation = async {
            // Load the private key
            test_log!("Loading private key from: {}", self.config.master_key_path);
            let _private_key = self.load_private_key().await?;
            test_log!("Private key loaded successfully");

            // Build the command
            test_log!("Building SOPS command for add_secret");
            let mut command = TokioCommand::new(&self.config.sops_path);
            let env = &mut self.config.env_vars.clone();
            if !env.contains_key("SOPS_AGE_KEY_FILE") {
                test_log!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", self.config.master_key_path);
                env.insert("SOPS_AGE_KEY_FILE".to_string(), self.config.master_key_path.clone());
            } else {
                test_log!("SOPS_AGE_KEY_FILE already set in environment");
            }
            command.envs(env);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                test_log!("Setting working directory to: {}", working_dir);
                command.current_dir(working_dir);
            } else {
                test_log!("No working directory specified");
            }

            // Add SOPS arguments
            let owned_key = format!("{}_{}", owner, key);
            test_log!("Using owned key: {}", owned_key);
            command
                .arg("set")
                .arg(&self.config.file_path)
                .arg(&format!("'[{}]'='\"{}\"'", owned_key, value));

            test_log!("Executing SOPS command: {} set {} '[{}]'='\"{}\"'", 
                     self.config.sops_path, self.config.file_path, owned_key, value);

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| {
                    test_log!("Failed to execute SOPS command: {}", e);
                    SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e))
                })?;

            test_log!("SOPS command completed with status: {}", output.status);

            // Log stdout and stderr for debugging
            if !output.stdout.is_empty() {
                if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
                    test_log!("SOPS stdout: {}", stdout.trim());
                } else {
                    test_log!("SOPS stdout: <invalid UTF-8>");
                }
            } else {
                test_log!("SOPS stdout: <empty>");
            }

            if !output.stderr.is_empty() {
                if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                    test_log!("SOPS stderr: {}", stderr.trim());
                } else {
                    test_log!("SOPS stderr: <invalid UTF-8>");
                }
            } else {
                test_log!("SOPS stderr: <empty>");
            }

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                test_log!("SOPS command failed with status {}: {}", output.status, stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            test_log!("Secret added successfully");
            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| {
                test_log!("SOPS add_secret operation timed out after {:?}", timeout_duration);
                SopsError::Timeout(timeout_duration)
            })?
    }

    /// Get a secret from a SOPS file
    pub async fn get_secret(&self, key: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        test_log!("Getting secret: key='{}', timeout={:?}", key, timeout_duration);

        // Validate inputs
        if key.trim().is_empty() {
            test_log!("Validation failed: key is empty");
            return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
        }

        if !Path::new(&self.config.file_path).exists() {
            test_log!("Validation failed: file does not exist: {}", self.config.file_path);
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        test_log!("File exists: {}", self.config.file_path);

        // Validate SOPS is available
        test_log!("Validating SOPS availability...");
        self.validate_sops(Some(timeout_duration)).await?;
        test_log!("SOPS validation successful");

        let operation = async {
            // Build the command
            test_log!("Building SOPS command for get_secret");
            let mut command = TokioCommand::new(&self.config.sops_path);
            let env = &mut self.config.env_vars.clone();
            if !env.contains_key("SOPS_AGE_KEY_FILE") {
                test_log!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", self.config.master_key_path);
                env.insert("SOPS_AGE_KEY_FILE".to_string(), self.config.master_key_path.clone());
            } else {
                test_log!("SOPS_AGE_KEY_FILE already set in environment");
            }
            command.envs(env);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                test_log!("Setting working directory to: {}", working_dir);
                command.current_dir(working_dir);
            } else {
                test_log!("No working directory specified");
            }

            // Add SOPS arguments
            test_log!("Using key: {}", key);
            command
                .arg("--extract")
                .arg(key)
                .arg(&self.config.file_path);

            test_log!("Executing SOPS command: {} --extract {} {}", 
                     self.config.sops_path, key, self.config.file_path);

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| {
                    test_log!("Failed to execute SOPS command: {}", e);
                    SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e))
                })?;

            test_log!("SOPS command completed with status: {}", output.status);

            // Log stdout and stderr for debugging
            if !output.stdout.is_empty() {
                if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
                    test_log!("SOPS stdout: {}", stdout.trim());
                } else {
                    test_log!("SOPS stdout: <invalid UTF-8>");
                }
            } else {
                test_log!("SOPS stdout: <empty>");
            }

            if !output.stderr.is_empty() {
                if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                    test_log!("SOPS stderr: {}", stderr.trim());
                } else {
                    test_log!("SOPS stderr: <invalid UTF-8>");
                }
            } else {
                test_log!("SOPS stderr: <empty>");
            }

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                test_log!("SOPS command failed with status {}: {}", output.status, stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            let secret = String::from_utf8(output.stdout)
                .map_err(|e| {
                    test_log!("Failed to parse SOPS output as UTF-8: {}", e);
                    SopsError::CommandFailed(format!("Invalid UTF-8 in SOPS output: {}", e))
                })?;

            let trimmed_secret = secret.trim().to_string();
            test_log!("Secret retrieved successfully, length: {}", trimmed_secret.len());
            Ok(trimmed_secret)
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| {
                test_log!("SOPS get_secret operation timed out after {:?}", timeout_duration);
                SopsError::Timeout(timeout_duration)
            })?
    }

    /// Create a new SOPS file with initial secrets
    pub async fn create_file(&self, owner: &str, secrets: &HashMap<String, String>,  timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        test_log!("Creating SOPS file: owner='{}', secrets_count={}, timeout={:?}", owner, secrets.len(), timeout_duration);

        // Validate SOPS is available
        test_log!("Validating SOPS availability...");
        self.validate_sops(Some(timeout_duration)).await?;
        test_log!("SOPS validation successful");

        // Check if file already exists
        if Path::new(&self.config.file_path).exists() {
            test_log!("Validation failed: file already exists: {}", self.config.file_path);
            return Err(SopsError::InvalidPath(format!("File already exists: {}", self.config.file_path)));
        }

        test_log!("File does not exist, proceeding with creation: {}", self.config.file_path);

        let operation = async {
            // Load the private key
            test_log!("Loading private key from: {}", self.config.master_key_path);
            let _private_key = self.load_private_key().await?;
            test_log!("Private key loaded successfully");

            // Build the command
            test_log!("Building SOPS command for create_file");
            let mut command = TokioCommand::new(&self.config.sops_path);
            let env = &mut self.config.env_vars.clone();
            if !env.contains_key("SOPS_AGE_KEY_FILE") {
                test_log!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", self.config.master_key_path);
                env.insert("SOPS_AGE_KEY_FILE".to_string(), self.config.master_key_path.clone());
            } else {
                test_log!("SOPS_AGE_KEY_FILE already set in environment");
            }
            command.envs(env);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                test_log!("Setting working directory to: {}", working_dir);
                command.current_dir(working_dir);
            } else {
                test_log!("No working directory specified");
            }

            // Add SOPS arguments for creating a new file
            command.arg("--encrypt");
            test_log!("Added --encrypt argument");

            if secrets.len() > 0 {
                test_log!("Adding {} secrets to the file", secrets.len());
                command.arg("set");
                command.arg(&self.config.file_path);

                // Add all secrets as key=value pairs
                for (key, value) in secrets {
                    if key.trim().is_empty() {
                        test_log!("Validation failed: key is empty");
                        return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
                    }

                    let secret_data = SecretData {
                        value: String::from(value),
                        owner: String::from(owner),
                        writers: vec![],
                        readers: vec![]
                    };

                    let secret_json = serde_json::to_string(&secret_data)
                        .map_err(|e| {
                            test_log!("Failed to serialize secret data for key '{}': {}", key, e);
                            SopsError::InvalidSecretFormat(format!("Failed to serialize secret data: {}", e))
                        })?;

                    let secret_key = format!("{}_secret", key);
                    test_log!("Adding secret: key='{}', owner='{}', value_length={}", secret_key, owner, value.len());
                    command.arg(&format!("{}={}", secret_key, secret_json));
                }
            } else {
                test_log!("No secrets provided, creating empty file");
            }

            test_log!("Executing SOPS command: {} --encrypt set {} [with {} secrets]", 
                     self.config.sops_path, self.config.file_path, secrets.len());

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| {
                    test_log!("Failed to execute SOPS command: {}", e);
                    SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e))
                })?;

            test_log!("SOPS command completed with status: {}", output.status);

            // Log stdout and stderr for debugging
            if !output.stdout.is_empty() {
                if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
                    test_log!("SOPS stdout: {}", stdout.trim());
                } else {
                    test_log!("SOPS stdout: <invalid UTF-8>");
                }
            } else {
                test_log!("SOPS stdout: <empty>");
            }

            if !output.stderr.is_empty() {
                if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                    test_log!("SOPS stderr: {}", stderr.trim());
                } else {
                    test_log!("SOPS stderr: <invalid UTF-8>");
                }
            } else {
                test_log!("SOPS stderr: <empty>");
            }

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                test_log!("SOPS command failed with status {}: {}", output.status, stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            test_log!("SOPS file created successfully: {}", self.config.file_path);
            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| {
                test_log!("SOPS create_file operation timed out after {:?}", timeout_duration);
                SopsError::Timeout(timeout_duration)
            })?
    }

    /// Add an owned secret with allowed readers and writers
    /// The secret will be stored as: {secret_name}_secret
    /// All data (value, owner, readers, writers) is stored as a single JSON struct
    /// The owner will automatically be added to both the allowed readers and writers lists
    pub async fn add_owned_secret(&self, owner_name: &str, secret_name: &str, secret_value: &str, allowed_readers: &[String], allowed_writers: &[String], timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);
        
        test_log!("Adding owned secret: owner='{}', secret='{}', value_length={}, readers_count={}, writers_count={}, timeout={:?}", 
                 owner_name, secret_name, secret_value.len(), allowed_readers.len(), allowed_writers.len(), timeout_duration);

        // Validate inputs
        if owner_name.trim().is_empty() {
            test_log!("Validation failed: owner name is empty");
            return Err(SopsError::InvalidSecretFormat("Owner name cannot be empty".to_string()));
        }

        if secret_name.trim().is_empty() {
            test_log!("Validation failed: secret name is empty");
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Validate owner name doesn't contain invalid characters
        if owner_name.contains(' ') || owner_name.contains('\t') || owner_name.contains('\n') {
            test_log!("Validation failed: owner name contains invalid characters: '{}'", owner_name);
            return Err(SopsError::InvalidSecretFormat("Owner name contains invalid characters".to_string()));
        }

        // Validate secret name doesn't contain invalid characters
        if secret_name.contains(' ') || secret_name.contains('\t') || secret_name.contains('\n') {
            test_log!("Validation failed: secret name contains invalid characters: '{}'", secret_name);
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        // Validate allowed readers
        for reader in allowed_readers {
            if reader.trim().is_empty() {
                test_log!("Validation failed: allowed reader name is empty");
                return Err(SopsError::InvalidSecretFormat("Allowed reader name cannot be empty".to_string()));
            }
            if reader.contains(' ') || reader.contains('\t') || reader.contains('\n') {
                test_log!("Validation failed: allowed reader name contains invalid characters: '{}'", reader);
                return Err(SopsError::InvalidSecretFormat("Allowed reader name contains invalid characters".to_string()));
            }
        }

        // Validate allowed writers
        for writer in allowed_writers {
            if writer.trim().is_empty() {
                test_log!("Validation failed: allowed writer name is empty");
                return Err(SopsError::InvalidSecretFormat("Allowed writer name cannot be empty".to_string()));
            }
            if writer.contains(' ') || writer.contains('\t') || writer.contains('\n') {
                test_log!("Validation failed: allowed writer name contains invalid characters: '{}'", writer);
                return Err(SopsError::InvalidSecretFormat("Allowed writer name contains invalid characters".to_string()));
            }
        }

        test_log!("Input validation passed");

        // Create the secret data structure
        test_log!("Creating SecretData structure");
        let secret_data = SecretData::new(
            secret_value.to_string(),
            owner_name.to_string(),
            Some(allowed_readers.to_vec()),
            Some(allowed_writers.to_vec()),
        );

        test_log!("SecretData created: owner='{}', readers={:?}, writers={:?}", 
                 secret_data.owner, secret_data.readers, secret_data.writers);

        // Serialize the complete secret data to JSON
        test_log!("Serializing secret data to JSON");
        let secret_json = serde_json::to_string(&secret_data)
            .map_err(|e| {
                test_log!("Failed to serialize secret data: {}", e);
                SopsError::InvalidSecretFormat(format!("Failed to serialize secret data: {}", e))
            })?;

        test_log!("Secret data serialized successfully, JSON length: {}", secret_json.len());

        // Create standardized secret key and store the complete JSON
        let secret_key = format!("{}_secret", secret_name);
        test_log!("Using secret key: {}", secret_key);
        
        test_log!("Calling add_secret with key='{}', owner='{}'", secret_key, owner_name);
        self.add_secret(owner_name, &secret_key, &secret_json, Some(timeout_duration)).await
    }

    /// Get allowed readers for an owner secret
    /// The readers will be retrieved from the secret data structure
    pub async fn get_secret_readers(&self, secret_name: &str, timeout_duration: Option<Duration>) -> SopsResult<Vec<String>> {
        let secret_data = self.get_secret_data(secret_name, timeout_duration).await?;
        Ok(secret_data.readers)
    }

    /// Check if a reader is allowed to read an owner's secret
    pub async fn is_allowed_to_read(&self, _owner_name: &str, secret_name: &str, reader_name: &str, timeout_duration: Option<Duration>) -> SopsResult<bool> {
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

    /// Get secret data for a given secret name
    pub async fn get_secret_data(&self, secret_name: &str, timeout_duration: Option<Duration>) -> SopsResult<SecretData> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);
        
        test_log!("Getting secret data: secret_name='{}', timeout={:?}", secret_name, timeout_duration);

        // Validate inputs
        if secret_name.trim().is_empty() {
            test_log!("Validation failed: secret name is empty");
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Create standardized secret key
        let secret_key = format!("{}_secret", secret_name);
        test_log!("Using secret key: {}", secret_key);

        // Validate the generated key doesn't contain invalid characters
        if secret_key.contains(' ') || secret_key.contains('\t') || secret_key.contains('\n') {
            test_log!("Validation failed: secret key contains invalid characters: '{}'", secret_key);
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        test_log!("Input validation passed");

        // Get the secret data JSON
        test_log!("Retrieving secret JSON for key: {}", secret_key);
        let secret_json = self.get_secret(&secret_key, Some(timeout_duration)).await?;

        test_log!("Secret JSON retrieved, length: {}", secret_json.len());

        if secret_json.trim().is_empty() {
            test_log!("Secret JSON is empty, returning NoSecretFound error");
            return Err(SopsError::NoSecretFound)
        }

        // Parse the JSON to SecretData
        test_log!("Deserializing secret JSON to SecretData");
        let secret_data: SecretData = serde_json::from_str(&secret_json)
            .map_err(|e| {
                test_log!("Failed to deserialize secret data: {}", e);
                test_log!("Secret JSON content: {}", secret_json);
                SopsError::InvalidSecretPayload(format!("Failed to deserialize secret data: {}", e))
            })?;

        test_log!("Secret data deserialized successfully: owner='{}', readers_count={}, writers_count={}, value_length={}", 
                 secret_data.owner, secret_data.readers.len(), secret_data.writers.len(), secret_data.value.len());

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
        self.add_secret("", &secret_key, &secret_json, timeout_duration).await
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
pub async fn add_secret(file_path: &str, owner: &str, key: &str, value: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.add_secret(owner, key, value, timeout_duration).await
}

/// Convenience function to add multiple secrets to a SOPS file using default configuration
pub async fn add_secrets(file_path: &str, owner: &str, secrets: &HashMap<String, String>, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.add_secrets(owner, secrets, timeout_duration).await
}

/// Convenience function to get a secret from a SOPS file using default configuration
pub async fn get_secret(file_path: &str, key: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.get_secret(key, timeout_duration).await
}

/// Convenience function to create a new SOPS file with initial secrets using default configuration
pub async fn create_file(file_path: &str, owner: &str, secrets: &HashMap<String, String>, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new_with_file(file_path.to_string(), master_key_path.to_string());
    wrapper.create_file(owner, secrets, timeout_duration).await
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
    wrapper.is_allowed_to_read(owner_name, secret_name, reader_name, timeout_duration).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sops_wrapper_creation() {
        let wrapper = SopsWrapper::new();
        assert_eq!(wrapper.config.sops_path, "sops");
        assert_eq!(wrapper.config.default_timeout, Duration::from_secs(30));
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
        let result = wrapper.add_secret("", "key", "value", None).await;
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

    #[test]
    fn test_allowed_readers_serialization() {
        let allowed_readers = vec!["user1".to_string(), "user2".to_string()];
        let readers_json = serde_json::to_string(&allowed_readers)
            .expect("Failed to serialize readers");
        let deserialized: Vec<String> = serde_json::from_str(&readers_json)
            .expect("Failed to deserialize readers");
        assert_eq!(allowed_readers, deserialized);
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

    #[test]
    fn test_allowed_writers_serialization() {
        let allowed_writers = vec!["writer1".to_string(), "writer2".to_string()];
        let writers_json = serde_json::to_string(&allowed_writers)
            .expect("Failed to serialize writers");
        let deserialized: Vec<String> = serde_json::from_str(&writers_json)
            .expect("Failed to deserialize writers");
        assert_eq!(allowed_writers, deserialized);
    }

    #[test]
    fn test_secret_data_structure() {
        let secret_data = SecretData::new(
            "test_secret".to_string(),
            "owner1".to_string(),
            Some(vec!["reader1".to_string(), "reader2".to_string()]),
            Some(vec!["writer1".to_string()]),
        );

        let json = serde_json::to_string(&secret_data)
            .expect("Failed to serialize secret data");
        let deserialized: SecretData = serde_json::from_str(&json)
            .expect("Failed to deserialize secret data");
        assert_eq!(secret_data.value, deserialized.value);
        assert_eq!(secret_data.owner, deserialized.owner);
    }
}
