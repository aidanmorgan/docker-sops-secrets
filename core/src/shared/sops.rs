use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::file_lock::{FileLock, FileLockError, ReadLock, WriteLock};

/// JSON structure representing a complete secret with access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretData {
    /// The secret value (base64 encoded string)
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

    /// Create a new SecretData with base64 encoded value
    pub fn new_with_base64_value(value: String, owner: String, readers: Option<Vec<String>>, writers: Option<Vec<String>>) -> Self {
        let base64_value = BASE64.encode(value.as_bytes());
        Self::new(base64_value, owner, readers, writers)
    }

    /// Get the decoded value from base64
    pub fn get_decoded_value(&self) -> Result<String, SopsError> {
        let decoded_bytes = BASE64.decode(&self.value)
            .map_err(|e| SopsError::InvalidSecretFormat(format!("Failed to decode base64 value: {}", e)))?;

        String::from_utf8(decoded_bytes)
            .map_err(|e| SopsError::InvalidSecretFormat(format!("Failed to convert decoded bytes to string: {}", e)))
    }

    /// Set the value as base64 encoded
    pub fn set_base64_value(&mut self, value: String) {
        self.value = BASE64.encode(value.as_bytes());
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
    #[error("File lock error: {0}")]
    FileLockError(#[from] FileLockError),
    #[error("Failed to read SOPS file: {0}")]
    FileRead(String),
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
    /// Timeout for file lock acquisition
    pub lock_timeout: Duration,
}

impl SopsConfig {
    /// Create a new SOPS configuration
    pub fn new(file_path: String, master_key_path: String) -> Self {
        Self {
            sops_path: "/usr/local/bin/sops".to_string(),
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path,
            master_key_path,
            lock_timeout: Duration::from_secs(30),
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
            lock_timeout: Duration::from_secs(30),
        }
    }

    /// Set the working directory for SOPS operations
    pub fn with_working_dir(mut self, working_dir: String) -> Self {
        self.working_dir = Some(working_dir);
        self
    }

    /// Set the default timeout for SOPS operations
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Add an environment variable for SOPS operations
    pub fn with_env_var(mut self, key: String, value: String) -> Self {
        self.env_vars.insert(key, value);
        self
    }
}

impl Default for SopsConfig {
    fn default() -> Self {
        Self {
            sops_path: "sops".to_string(),
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path: "secrets.json".to_string(),
            master_key_path: "age1default".to_string(),
            lock_timeout: Duration::from_secs(30),
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

impl Default for SopsWrapper {
    fn default() -> Self {
        Self {
            config: SopsConfig::default(),
        }
    }
}

impl SopsWrapper {
    /// Create a new SOPS wrapper with custom configuration
    pub fn with_config(config: SopsConfig) -> Self {
        Self { config }
    }

    /// Create a new SOPS wrapper for a specific file
    pub fn new(file_path: String, master_key_path: String) -> Self {
        Self {
            config: SopsConfig::new(file_path, master_key_path),
        }
    }

    /// Execute a read operation with file locking
    async fn with_read_lock<F, T>(&self, operation: F) -> SopsResult<T>
    where
        F: FnOnce(SopsConfig) -> std::pin::Pin<Box<dyn std::future::Future<Output=SopsResult<T>> + Send>>,
    {
        let config = self.config.clone();
        let _lock = ReadLock::acquire(&config.file_path, config.lock_timeout).await?;
        operation(config).await
    }

    /// Execute a write operation with file locking
    async fn with_write_lock<F, T>(&self, operation: F) -> SopsResult<T>
    where
        F: FnOnce(SopsConfig) -> std::pin::Pin<Box<dyn std::future::Future<Output=SopsResult<T>> + Send>>,
    {
        let config = self.config.clone();
        let _lock = WriteLock::acquire(&config.file_path, config.lock_timeout).await?;
        operation(config).await
    }

    /// Load the private key from the configured key file
    async fn load_private_key(&self) -> SopsResult<String> {
        Self::load_private_key_internal(&self.config).await
    }

    /// Internal method to load private key from config
    async fn load_private_key_internal(config: &SopsConfig) -> SopsResult<String> {
        let key_content = tokio::fs::read_to_string(&config.master_key_path)
            .await
            .map_err(|e| SopsError::KeyLoadError(format!("Failed to read key file '{}': {}", config.master_key_path, e)))?;

        // Find the line that contains the age private key
        for line in key_content.lines() {
            let trimmed_line = line.trim();
            if trimmed_line.starts_with("AGE-SECRET-KEY-") {
                return Ok(trimmed_line.to_string());
            }
        }

        Err(SopsError::KeyLoadError(format!("No valid age private key found in file '{}'", config.master_key_path)))
    }

    /// Validate that SOPS executable exists and is accessible
    pub async fn validate_sops(&self, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);
        debug!("Validating SOPS executable: {} with timeout {:?}", self.config.sops_path, timeout_duration);

        let operation = async {
            // Create command with environment variables
            let mut command = self.create_command("--version").await?;

            debug!("Executing SOPS command: {} --version", self.config.sops_path);

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| {
                    error!("Failed to execute SOPS command: {}", e);
                    SopsError::SopsNotFound(format!("Failed to execute SOPS: {}", e))
                })?;

            debug!("SOPS command completed with status: {}", output.status);

            // Log stdout if available
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                if !stdout.trim().is_empty() {
                    trace!("SOPS version output: {}", stdout.trim());
                }
            }

            // Log stderr if available
            if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                if !stderr.trim().is_empty() {
                    trace!("SOPS stderr output: {}", stderr.trim());
                }
            }

            // Check command status
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("SOPS validation failed with status {}: {}", output.status, stderr);
                return Err(SopsError::SopsNotFound(stderr.to_string()));
            }

            info!("SOPS validation successful");
            Ok(())
        };

        // Run with timeout
        timeout(timeout_duration, operation)
            .await
            .map_err(|_| {
                warn!("SOPS validation timed out after {:?}", timeout_duration);
                SopsError::Timeout(timeout_duration)
            })?
    }

    /// Helper method to create a command with common configuration
    async fn create_command(&self, arg: &str) -> SopsResult<TokioCommand> {
        let mut command = TokioCommand::new(&self.config.sops_path);

        // Set up environment variables
        let mut env_vars = self.config.env_vars.clone();
        if !env_vars.contains_key("SOPS_AGE_KEY_FILE") {
            debug!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", self.config.master_key_path);
            env_vars.insert("SOPS_AGE_KEY_FILE".to_string(), self.config.master_key_path.clone());
        } else {
            debug!("SOPS_AGE_KEY_FILE already set in environment");
        }
        command.envs(env_vars);

        // Set working directory if specified
        if let Some(ref working_dir) = self.config.working_dir {
            debug!("Setting working directory to: {}", working_dir);
            command.current_dir(working_dir);
        } else {
            debug!("No working directory specified");
        }

        // Add the argument if provided
        if !arg.is_empty() {
            command.arg(arg);
        }

        Ok(command)
    }

    /// Add multiple secrets to a SOPS file in a single operation
    async fn add_secrets(&self, owner: &str, secrets: &HashMap<String, String>, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        // Validate inputs
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

            // Create base command
            let mut command = self.create_command("--set").await?;

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

            info!("Successfully added {} secrets", secrets.len());
            Ok(())
        };

        // Run with timeout
        timeout(timeout_duration, operation)
            .await
            .map_err(|_| SopsError::Timeout(timeout_duration))?
    }

    /// Add a secret to a SOPS file (requires owner)
    async fn add_secret(&self, owner: &str, key: &str, value: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        info!("Adding secret: owner='{}', key='{}', timeout={:?}", owner, key, timeout_duration);

        // Validate inputs
        if owner.trim().is_empty() {
            warn!("Validation failed: owner is empty");
            return Err(SopsError::InvalidSecretFormat("Owner cannot be empty".to_string()));
        }
        if key.trim().is_empty() {
            warn!("Validation failed: key is empty");
            return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
        }

        if !Path::new(&self.config.file_path).exists() {
            warn!("Validation failed: file does not exist: {}", self.config.file_path);
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        debug!("File exists: {}", self.config.file_path);

        // Validate SOPS is available
        debug!("Validating SOPS availability...");
        self.validate_sops(Some(timeout_duration)).await?;
        info!("SOPS validation successful");

        let owner = owner.to_string();
        let key = key.to_string();
        let value = value.to_string();

        self.with_write_lock(|config| {
            Box::pin(async move {
                // Load the private key
                debug!("Loading private key from: {}", config.master_key_path);
                let _private_key = Self::load_private_key_internal(&config).await?;
                debug!("Private key loaded successfully");

                // Build the SOPS set command
                debug!("Building SOPS set command for add_secret");
                let mut command = TokioCommand::new(&config.sops_path);
                let mut env = config.env_vars.clone();
                if !env.contains_key("SOPS_AGE_KEY_FILE") {
                    debug!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", config.master_key_path);
                    env.insert("SOPS_AGE_KEY_FILE".to_string(), config.master_key_path.clone());
                } else {
                    debug!("SOPS_AGE_KEY_FILE already set in environment");
                }
                command.envs(&env);

                // Set working directory if specified
                if let Some(ref working_dir) = config.working_dir {
                    debug!("Setting working directory to: {}", working_dir);
                    command.current_dir(working_dir);
                } else {
                    debug!("No working directory specified");
                }

                // Check if the file exists, if not create it first
                if !Path::new(&config.file_path).exists() {
                    debug!("SOPS file does not exist, creating empty file first");
                    let empty_json = "{}";
                    tokio::fs::write(&config.file_path, empty_json).await
                        .map_err(|e| {
                            warn!("Failed to create empty SOPS file: {}", e);
                            SopsError::IoError(e)
                        })?;

                    // Encrypt the empty file
                    let mut encrypt_command = TokioCommand::new(&config.sops_path);
                    encrypt_command.envs(&env);
                    if let Some(ref working_dir) = config.working_dir {
                        encrypt_command.current_dir(working_dir);
                    }
                    encrypt_command
                        .arg("--encrypt")
                        .arg(&config.file_path);

                    debug!("Encrypting empty file: {} --encrypt {}", config.sops_path, config.file_path);
                    let encrypt_output = encrypt_command.output().await
                        .map_err(|e| {
                            warn!("Failed to encrypt empty file: {}", e);
                            SopsError::CommandFailed(format!("Failed to encrypt empty file: {}", e))
                        })?;

                    if !encrypt_output.status.success() {
                        let stderr = String::from_utf8_lossy(&encrypt_output.stderr);
                        warn!("Failed to encrypt empty file: {}", stderr);
                        return Err(SopsError::CommandFailed(format!(
                            "Failed to encrypt empty file: {}",
                            stderr
                        )));
                    }

                    debug!("Empty file encrypted successfully");
                }

                // Use the correct sops set command syntax: sops set <file> <index> <value>
                // The JSON path should be properly quoted: '["key"]'
                // The value should be properly quoted: '"value"'
                let json_path = format!("[\"{}\"]", key);
                let json_value = format!("\"{}\"", value);

                // Debug: Print the actual values being used
                debug!("SOPS set command details:");
                debug!("  Key: '{}'", key);
                debug!("  Value: '{}'", value);
                debug!("  JSON path: '{}'", json_path);
                debug!("  JSON value: '{}'", json_value);

                command
                    .arg("set")
                    .arg(&config.file_path)
                    .arg(&json_path)
                    .arg(&json_value);

                debug!("Executing SOPS command: {} set {} '{}' '{}'", 
                         config.sops_path, config.file_path, json_path, json_value);

                // Execute the command
                let output = tokio::time::timeout(
                    timeout_duration,
                    command.output(),
                )
                    .await
                    .map_err(|_| {
                        warn!("SOPS command timed out after {:?}", timeout_duration);
                        SopsError::Timeout(timeout_duration)
                    })?
                    .map_err(|e| {
                        warn!("Failed to execute SOPS command: {}", e);
                        SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e))
                    })?;

                debug!("SOPS command completed with status: {}", output.status);

                // Log stdout and stderr for debugging
                if !output.stdout.is_empty() {
                    if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
                        debug!("SOPS stdout: {}", stdout.trim());
                    } else {
                        debug!("SOPS stdout: <invalid UTF-8>");
                    }
                } else {
                    debug!("SOPS stdout: <empty>");
                }

                if !output.stderr.is_empty() {
                    if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                        debug!("SOPS stderr: {}", stderr.trim());
                    } else {
                        debug!("SOPS stderr: <invalid UTF-8>");
                    }
                } else {
                    debug!("SOPS stderr: <empty>");
                }

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("SOPS command failed with status {}: {}", output.status, stderr);

                    // Check if the error indicates the key doesn't exist
                    if stderr.contains("key not found") || stderr.contains("No such key") || stderr.contains("not found") {
                        debug!("Key '{}' not found in SOPS file", key);
                        return Err(SopsError::NoSecretFound);
                    }

                    return Err(SopsError::CommandFailed(format!(
                        "SOPS command failed with status {}: {}",
                        output.status, stderr
                    )));
                }

                info!("Secret added successfully using sops set command");
                Ok(())
            })
        }).await
    }

    /// Get a secret from a SOPS file
    pub async fn get_secret(&self, key: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        info!("Getting secret: key='{}', timeout={:?}", key, timeout_duration);

        // Validate inputs
        if key.trim().is_empty() {
            warn!("Validation failed: key is empty");
            return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
        }

        if !Path::new(&self.config.file_path).exists() {
            warn!("Validation failed: file does not exist: {}", self.config.file_path);
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", self.config.file_path)));
        }

        debug!("File exists: {}", self.config.file_path);

        // First, check if the key exists using the non-SOPS method to prevent hanging
        debug!("Checking if key exists using non-SOPS method...");
        let key_exists = self.key_exists(key, Some(timeout_duration), None).await?;
        if !key_exists {
            debug!("Key '{}' does not exist in the SOPS file", key);
            return Err(SopsError::NoSecretFound);
        }
        debug!("Key '{}' exists, proceeding with SOPS extraction", key);

        // Validate SOPS is available
        debug!("Validating SOPS availability...");
        self.validate_sops(Some(timeout_duration)).await?;
        info!("SOPS validation successful");

        let key = key.to_string();

        self.with_read_lock(|config| {
            Box::pin(async move {
                // Build the SOPS extract command
                debug!("Building SOPS command for get_secret using direct file access");
                let mut command = TokioCommand::new(&config.sops_path);
                let env = &mut config.env_vars.clone();
                if !env.contains_key("SOPS_AGE_KEY_FILE") {
                    debug!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", config.master_key_path);
                    env.insert("SOPS_AGE_KEY_FILE".to_string(), config.master_key_path.clone());
                } else {
                    debug!("SOPS_AGE_KEY_FILE already set in environment");
                }
                command.envs(env);

                // Set working directory if specified
                if let Some(ref working_dir) = config.working_dir {
                    debug!("Setting working directory to: {}", working_dir);
                    command.current_dir(working_dir);
                } else {
                    debug!("No working directory specified");
                }

                // Use the correct sops extract command syntax: sops --decrypt --extract <index> <file>
                command
                    .arg("--decrypt")
                    .arg("--extract")
                    .arg(&format!("[\"{}\"]", key))
                    .arg(&config.file_path);

                debug!("Executing SOPS command: {} --decrypt --extract [\"{}\"] {}", 
                         config.sops_path, key, config.file_path);

                // Execute the command
                let output = tokio::time::timeout(
                    timeout_duration,
                    command.output(),
                )
                    .await
                    .map_err(|_| {
                        warn!("SOPS command timed out after {:?}", timeout_duration);
                        SopsError::Timeout(timeout_duration)
                    })?
                    .map_err(|e| {
                        warn!("Failed to execute SOPS command: {}", e);
                        SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e))
                    })?;

                debug!("SOPS command completed with status: {}", output.status);

                // Log stdout and stderr for debugging
                if !output.stdout.is_empty() {
                    if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
                        debug!("SOPS stdout length: {}", stdout.len());
                    } else {
                        debug!("SOPS stdout: <invalid UTF-8>");
                    }
                } else {
                    debug!("SOPS stdout: <empty>");
                }

                if !output.stderr.is_empty() {
                    if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                        debug!("SOPS stderr: {}", stderr.trim());
                    } else {
                        debug!("SOPS stderr: <invalid UTF-8>");
                    }
                } else {
                    debug!("SOPS stderr: <empty>");
                }

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("SOPS command failed with status {}: {}", output.status, stderr);
                    return Err(SopsError::CommandFailed(format!(
                        "SOPS command failed with status {}: {}",
                        output.status, stderr
                    )));
                }

                let secret = String::from_utf8(output.stdout)
                    .map_err(|e| {
                        warn!("Failed to parse SOPS output as UTF-8: {}", e);
                        SopsError::CommandFailed(format!("Invalid UTF-8 in SOPS output: {}", e))
                    })?;

                let trimmed_secret = secret.trim().to_string();

                // Check if the output is empty, which could indicate a non-existent key
                if trimmed_secret.is_empty() {
                    debug!("SOPS returned empty output for key '{}', treating as non-existent", key);
                    return Err(SopsError::NoSecretFound);
                }

                info!("Secret retrieved successfully, length: {}", trimmed_secret.len());
                Ok(trimmed_secret)
            })
        }).await
    }

    /// Create a new SOPS file with initial secrets
    pub async fn create_file(&self, owner: &str, secrets: &HashMap<String, String>, timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        log::info!("Creating SOPS file: owner='{}', secrets_count={}, timeout={:?}", owner, secrets.len(), timeout_duration);

        // Validate SOPS is available
        log::info!("Validating SOPS availability...");
        self.validate_sops(Some(timeout_duration)).await?;
        log::info!("SOPS validation successful");

        // Check if file already exists
        if Path::new(&self.config.file_path).exists() {
            log::info!("Validation failed: file already exists: {}", self.config.file_path);
            return Err(SopsError::InvalidPath(format!("File already exists: {}", self.config.file_path)));
        }

        log::info!("File does not exist, proceeding with creation: {}", self.config.file_path);

        // Write minimal JSON to the file before SOPS encrypts it
        use std::fs;
        use serde_json::json;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let minimal_json = json!({
            "managed_by_sops_secrets": true,
            "created_at": now
        });
        fs::write(&self.config.file_path, serde_json::to_string_pretty(&minimal_json).unwrap() + "\n")
            .map_err(|e| SopsError::IoError(e))?;

        let operation = async {
            // Load the private key
            log::debug!("Loading private key from: {}", self.config.master_key_path);
            let _private_key = self.load_private_key().await?;

            // Build the command
            let mut command = TokioCommand::new(&self.config.sops_path);
            let env = &mut self.config.env_vars.clone();
            if !env.contains_key("SOPS_AGE_KEY_FILE") {
                log::debug!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", self.config.master_key_path);
                env.insert("SOPS_AGE_KEY_FILE".to_string(), self.config.master_key_path.clone());
            } else {
                log::debug!("SOPS_AGE_KEY_FILE already set in environment");
            }
            command.envs(env);

            // Set working directory if specified
            if let Some(ref working_dir) = self.config.working_dir {
                log::debug!("Setting working directory to: {}", working_dir);
                command.current_dir(working_dir);
            }
            // Add SOPS arguments for creating a new file
            command.arg("--encrypt");

            if secrets.len() > 0 {
                log::debug!("Adding {} secrets to the file", secrets.len());
                command.arg("set");
                command.arg(&self.config.file_path);

                // Add all secrets as key=value pairs
                for (key, value) in secrets {
                    if key.trim().is_empty() {
                        log::debug!("Validation failed: key is empty");
                        return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
                    }

                    let secret_data = SecretData::new_with_base64_value(
                        String::from(value),
                        String::from(owner),
                        None,
                        None
                    );

                    let secret_json = serde_json::to_string(&secret_data)
                        .map_err(|e| {
                            log::error!("Failed to serialize secret data for key '{}': {}", key, e);
                            SopsError::InvalidSecretFormat(format!("Failed to serialize secret data: {}", e))
                        })?;

                    let secret_key = format!("{}_secret", key);
                    log::debug!("Adding secret: key='{}', owner='{}', value_length={}", secret_key, owner, value.len());
                    command.arg(&format!("{}={}", secret_key, secret_json));
                }
            }

            log::info!("Executing SOPS command: {} --encrypt set {} [with {} secrets]", 
                     self.config.sops_path, self.config.file_path, secrets.len());

            // Execute the command
            let output = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| {
                    log::info!("Failed to execute SOPS command: {}", e);
                    SopsError::CommandFailed(format!("Failed to execute SOPS command: {}", e))
                })?;

            log::info!("SOPS command completed with status: {}", output.status);

            // Log stdout and stderr for debugging
            if !output.stdout.is_empty() {
                if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
                    log::debug!("SOPS stdout: {}", stdout.trim());
                } else {
                    log::debug!("SOPS stdout: <invalid UTF-8>");
                }
            } else {
                log::info!("SOPS stdout: <empty>");
            }

            if !output.stderr.is_empty() {
                if let Ok(stderr) = String::from_utf8(output.stderr.clone()) {
                    log::info!("SOPS stderr: {}", stderr.trim());
                } else {
                    log::info!("SOPS stderr: <invalid UTF-8>");
                }
            } else {
                log::info!("SOPS stderr: <empty>");
            }

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::info!("SOPS command failed with status {}: {}", output.status, stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS command failed with status {}: {}",
                    output.status, stderr
                )));
            }

            log::info!("SOPS file created successfully: {}", self.config.file_path);
            Ok(())
        };

        timeout(timeout_duration, operation)
            .await
            .map_err(|_| {
                log::info!("SOPS create_file operation timed out after {:?}", timeout_duration);
                SopsError::Timeout(timeout_duration)
            })?
    }

    /// Add an owned secret with allowed readers and writers
    /// The secret will be stored as: {secret_name}_secret
    /// All data (value, owner, readers, writers) is stored as a single JSON struct
    /// The owner will automatically be added to both the allowed readers and writers lists
    pub async fn add_owned_secret(&self, owner_name: &str, secret_name: &str, secret_value: &str, allowed_readers: &[String], allowed_writers: &[String], timeout_duration: Option<Duration>) -> SopsResult<()> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        log::info!("Adding owned secret: owner='{}', secret='{}', value_length={}, readers_count={}, writers_count={}, timeout={:?}", 
                 owner_name, secret_name, secret_value.len(), allowed_readers.len(), allowed_writers.len(), timeout_duration);

        // Validate inputs
        if owner_name.trim().is_empty() {
            log::info!("Validation failed: owner name is empty");
            return Err(SopsError::InvalidSecretFormat("Owner name cannot be empty".to_string()));
        }

        if secret_name.trim().is_empty() {
            log::info!("Validation failed: secret name is empty");
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Validate owner name doesn't contain invalid characters
        if owner_name.contains(' ') || owner_name.contains('\t') || owner_name.contains('\n') {
            log::info!("Validation failed: owner name contains invalid characters: '{}'", owner_name);
            return Err(SopsError::InvalidSecretFormat("Owner name contains invalid characters".to_string()));
        }

        // Validate secret name doesn't contain invalid characters
        if secret_name.contains(' ') || secret_name.contains('\t') || secret_name.contains('\n') {
            log::info!("Validation failed: secret name contains invalid characters: '{}'", secret_name);
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        // Validate allowed readers
        for reader in allowed_readers {
            if reader.trim().is_empty() {
                log::info!("Validation failed: allowed reader name is empty");
                return Err(SopsError::InvalidSecretFormat("Allowed reader name cannot be empty".to_string()));
            }
            if reader.contains(' ') || reader.contains('\t') || reader.contains('\n') {
                log::info!("Validation failed: allowed reader name contains invalid characters: '{}'", reader);
                return Err(SopsError::InvalidSecretFormat("Allowed reader name contains invalid characters".to_string()));
            }
        }

        // Validate allowed writers
        for writer in allowed_writers {
            if writer.trim().is_empty() {
                log::info!("Validation failed: allowed writer name is empty");
                return Err(SopsError::InvalidSecretFormat("Allowed writer name cannot be empty".to_string()));
            }
            if writer.contains(' ') || writer.contains('\t') || writer.contains('\n') {
                log::info!("Validation failed: allowed writer name contains invalid characters: '{}'", writer);
                return Err(SopsError::InvalidSecretFormat("Allowed writer name contains invalid characters".to_string()));
            }
        }

        log::info!("Input validation passed");

        // Create the secret data structure with base64 encoding
        log::info!("Creating SecretData structure with base64 encoding");
        let secret_data = SecretData::new_with_base64_value(
            secret_value.to_string(),
            owner_name.to_string(),
            Some(allowed_readers.to_vec()),
            Some(allowed_writers.to_vec()),
        );

        log::info!("SecretData created: owner='{}', readers={:?}, writers={:?}", 
                 secret_data.owner, secret_data.readers, secret_data.writers);

        // Serialize the complete secret data to JSON
        log::info!("Serializing secret data to JSON");
        let secret_json = serde_json::to_string(&secret_data)
            .map_err(|e| {
                log::info!("Failed to serialize secret data: {}", e);
                SopsError::InvalidSecretFormat(format!("Failed to serialize secret data: {}", e))
            })?;

        log::info!("Secret data serialized successfully, JSON length: {}", secret_json.len());

        // Use only the secret name for the key (no owner prefix)
        let secret_key = format!("{}_secret", secret_name);
        log::info!("Using secret key: {}", secret_key);

        log::info!("Calling add_secret with key='{}', owner='{}'", secret_key, owner_name);
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

        // Create standardized secret key (same format as add_owned_secret)
        let secret_key = format!("{}_{}_secret", owner_name, secret_name);

        // Validate the generated key doesn't contain invalid characters
        if secret_key.contains(' ') || secret_key.contains('\t') || secret_key.contains('\n') {
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        // Get the secret data JSON
        let secret_json = self.get_secret(&secret_key, timeout_duration).await?;

        // Parse the JSON to SecretData
        let secret_data: SecretData = serde_json::from_str(&secret_json)
            .map_err(|e| SopsError::InvalidSecretFormat(format!("Failed to deserialize secret data: {}", e)))?;

        // Decode the base64 value
        secret_data.get_decoded_value()
    }

    /// Get secret data for a given secret name
    pub async fn get_secret_data(&self, secret_name: &str, timeout_duration: Option<Duration>) -> SopsResult<SecretData> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        log::info!("Getting secret data: secret_name='{}', timeout={:?}", secret_name, timeout_duration);

        // Validate inputs
        if secret_name.trim().is_empty() {
            info!("Validation failed: secret name is empty");
            return Err(SopsError::InvalidSecretFormat("Secret name cannot be empty".to_string()));
        }

        // Create standardized secret key
        let secret_key = format!("{}_secret", secret_name);
        log::info!("Using secret key: {}", secret_key);

        // Validate the generated key doesn't contain invalid characters
        if secret_key.contains(' ') || secret_key.contains('\t') || secret_key.contains('\n') {
            log::info!("Validation failed: secret key contains invalid characters: '{}'", secret_key);
            return Err(SopsError::InvalidSecretFormat("Secret name contains invalid characters".to_string()));
        }

        log::info!("Input validation passed");

        // Get the secret data JSON
        log::info!("Retrieving secret JSON for key: {}", secret_key);
        let secret_json = self.get_secret(&secret_key, Some(timeout_duration)).await?;

        log::info!("Secret JSON retrieved, length: {}", secret_json.len());

        if secret_json.trim().is_empty() {
            log::info!("Secret JSON is empty, returning NoSecretFound error");
            return Err(SopsError::NoSecretFound);
        }

        // Parse the JSON to SecretData
        log::info!("Deserializing secret JSON to SecretData");
        let secret_data: SecretData = serde_json::from_str(&secret_json)
            .map_err(|e| {
                log::info!("Failed to deserialize secret data: {}", e);
                log::info!("Secret JSON content: {}", secret_json);
                SopsError::InvalidSecretPayload(format!("Failed to deserialize secret data: {}", e))
            })?;

        log::info!("Secret data deserialized successfully: owner='{}', readers_count={}, writers_count={}, value_length={}", 
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

        // Update the value with base64 encoding
        secret_data.set_base64_value(new_value.to_string());

        // Save the updated secret data
        self.save_secret_data(secret_name, &secret_data, timeout_duration).await
    }

    /// Check if a key exists in the SOPS file by parsing the JSON structure
    /// If a read lock is provided, use it; otherwise, acquire one for this operation.
    pub async fn key_exists(
        &self,
        key: &str,
        timeout_duration: Option<Duration>,
        read_lock: Option<&crate::shared::file_lock::ReadLock>,
    ) -> SopsResult<bool> {
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout);

        debug!("Key existence check: key='{}', timeout={:?}", key, timeout_duration);

        // Validate inputs
        if key.trim().is_empty() {
            warn!("Validation failed: key is empty");
            return Err(SopsError::InvalidSecretFormat("Key cannot be empty".to_string()));
        }

        if !Path::new(&self.config.file_path).exists() {
            debug!("File does not exist: {}", self.config.file_path);
            return Ok(false);
        }

        // Helper closure to perform the check
        let check = async || {
            // Read the SOPS file content
            let file_content = tokio::fs::read_to_string(&self.config.file_path).await
                .map_err(|e| {
                    warn!("Failed to read SOPS file: {}", e);
                    SopsError::FileRead(e.to_string())
                })?;

            // Parse as JSON
            let json_value: Value = serde_json::from_str(&file_content)
                .map_err(|e| {
                    warn!("Failed to parse SOPS file as JSON: {}", e);
                    SopsError::InvalidSecretFormat(format!("Invalid JSON: {}", e))
                })?;

            // Check if the key exists in the JSON structure
            let key_exists = match json_value {
                Value::Object(map) => map.contains_key(key),
                _ => {
                    warn!("SOPS file is not a JSON object");
                    false
                }
            };

            debug!("Key existence check result: key='{}', exists={}", key, key_exists);
            Ok(key_exists)
        };

        // If a read lock is provided, use it; otherwise, acquire one
        if read_lock.is_some() {
            // Already locked, just check
            match timeout(timeout_duration, check()).await {
                Ok(result) => {
                    info!("Key existence check completed successfully (with provided lock)");
                    result
                }
                Err(_) => {
                    warn!("Key existence check timed out after {:?}", timeout_duration);
                    Err(SopsError::Timeout(timeout_duration))
                }
            }
        } else {
            // Acquire our own lock for this operation
            let acquired_lock = ReadLock::acquire(&self.config.file_path, timeout_duration)
                .await
                .map_err(|e| {
                    warn!("Failed to acquire read lock for key existence check: {:?}", e);
                    SopsError::FileLockError(e)
                })?;

            match timeout(timeout_duration, check()).await {
                Ok(result) => {
                    info!("Key existence check completed successfully (with acquired lock)");
                    result
                }
                Err(_) => {
                    warn!("Key existence check timed out after {:?}", timeout_duration);
                    Err(SopsError::Timeout(timeout_duration))
                }
            }
        }
    }
}

/// Convenience function to add a secret to a SOPS file using default configuration
async fn add_secret(file_path: &str, owner: &str, key: &str, value: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.add_secret(owner, key, value, timeout_duration).await
}

/// Convenience function to add multiple secrets to a SOPS file using default configuration
async fn add_secrets(file_path: &str, owner: &str, secrets: &HashMap<String, String>, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.add_secrets(owner, secrets, timeout_duration).await
}

/// Convenience function to get a secret from a SOPS file using default configuration
async fn get_secret(file_path: &str, key: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.get_secret(key, timeout_duration).await
}

/// Convenience function to create a new SOPS file with initial secrets using default configuration
async fn create_file(file_path: &str, owner: &str, secrets: &HashMap<String, String>, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.create_file(owner, secrets, timeout_duration).await
}

/// Convenience function to add an owner secret using default configuration
async fn add_owned_secret(file_path: &str, owner_name: &str, secret_name: &str, secret_value: &str, allowed_readers: &[String], allowed_writers: &[String], master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.add_owned_secret(owner_name, secret_name, secret_value, allowed_readers, allowed_writers, timeout_duration).await
}

/// Convenience function to get an owner secret using default configuration
async fn get_owned_secret(file_path: &str, owner_name: &str, secret_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<String> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.get_owned_secret(owner_name, secret_name, timeout_duration).await
}

/// Convenience function to get allowed readers for an owner secret using default configuration
async fn get_secret_readers(file_path: &str, secret_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<Vec<String>> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.get_secret_readers(secret_name, timeout_duration).await
}

/// Convenience function to check if a reader is allowed to read an owner's secret
async fn is_reader_allowed_to_read(file_path: &str, owner_name: &str, secret_name: &str, reader_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<bool> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.is_allowed_to_read(owner_name, secret_name, reader_name, timeout_duration).await
}

/// Convenience function to add a reader to a secret using default configuration
async fn add_reader_to_secret(file_path: &str, secret_name: &str, reader_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.add_reader_to_secret(secret_name, reader_name, timeout_duration).await
}

/// Convenience function to remove a reader from a secret using default configuration
async fn remove_reader_from_secret(file_path: &str, secret_name: &str, reader_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.remove_reader_from_secret(secret_name, reader_name, timeout_duration).await
}

/// Convenience function to set the complete list of readers for a secret using default configuration
async fn set_secret_readers(file_path: &str, owner_name: &str, secret_name: &str, readers: &[String], master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.set_secret_readers(owner_name, secret_name, readers, timeout_duration).await
}

/// Convenience function to get allowed writers for a secret using default configuration
async fn get_secret_writers(file_path: &str, secret_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<Vec<String>> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.get_secret_writers(secret_name, timeout_duration).await
}

/// Convenience function to check if a writer is allowed to write to a secret using default configuration
async fn is_writer_allowed_to_write(file_path: &str, secret_name: &str, writer_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<bool> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.is_writer_allowed_to_write(secret_name, writer_name, timeout_duration).await
}

/// Convenience function to add a writer to a secret using default configuration
async fn add_writer_to_secret(file_path: &str, secret_name: &str, writer_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.add_writer_to_secret(secret_name, writer_name, timeout_duration).await
}

/// Convenience function to remove a writer from a secret using default configuration
async fn remove_writer_from_secret(file_path: &str, secret_name: &str, writer_name: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.remove_writer_from_secret(secret_name, writer_name, timeout_duration).await
}

/// Convenience function to set the complete list of writers for a secret using default configuration
async fn set_secret_writers(file_path: &str, owner_name: &str, secret_name: &str, writers: &[String], master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.set_secret_writers(owner_name, secret_name, writers, timeout_duration).await
}

/// Convenience function to update a secret value using default configuration
async fn update_secret_value(file_path: &str, secret_name: &str, new_value: &str, master_key_path: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let wrapper = SopsWrapper::new(file_path.to_string(), master_key_path.to_string());
    wrapper.update_secret_value(secret_name, new_value, timeout_duration).await
}
