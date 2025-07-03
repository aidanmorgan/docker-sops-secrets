use chrono;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command as TokioCommand;

use crate::shared::file_lock::{FileLockError, ReadLock, WriteLock};

/// JSON structure representing a complete secret with access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretData {
    /// The secret value (plain string)
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
        let mut final_readers = readers.unwrap_or_default();
        let mut final_writers = writers.unwrap_or_default();

        // Ensure owner is always included in readers and writers
        if !final_readers.contains(&owner) {
            final_readers.push(owner.to_string());
        }
        if !final_writers.contains(&owner) {
            final_writers.push(owner.to_string());
        }

        Self {
            value,
            owner,
            readers: final_readers,
            writers: final_writers,
        }
    }

    /// Create a new SecretData with plain string value (no base64 encoding)
    pub fn new_with_value(value: String, owner: String, readers: Option<Vec<String>>, writers: Option<Vec<String>>) -> Self {
        Self::new(value, owner, readers, writers)
    }

    /// Get the value as a string (no decoding needed)
    pub fn get_value(&self) -> &str {
        &self.value
    }

    /// Set the value as a plain string
    pub fn set_value(&mut self, value: String) {
        self.value = value;
    }

    /// Check if a user can read this secret
    pub fn can_read(&self, user: &str) -> bool {
        self.readers.contains(&user.to_string()) || self.owner == user.to_string()
    }

    /// Check if a user can write this secret
    pub fn can_write(&self, user: &str) -> bool {
        self.writers.contains(&user.to_string()) || self.owner == user.to_string()
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
    #[error("Invalid secret input: {0}")]
    InvalidSecretInput(String),
    #[error("Invalid secret data: {0}")]
    InvalidSecretData(String),
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),
    #[error("File lock acquisition timed out after {0:?}")]
    LockTimeout(Duration),
    #[error("Failed to load private key from file: {0}")]
    KeyLoadError(String),
    #[error("No secret with key found")]
    NoSecretFound,
    #[error("Secret already exists: {0}")]
    SecretAlreadyExists(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("File lock error: {0}")]
    FileLockError(#[from] FileLockError),
    #[error("Command timeout")]
    CommandTimeout,
    #[error("Command execution failed: {0}")]
    CommandExecutionFailed(String),
    #[error("Invalid output: {0}")]
    InvalidOutput(String),
}

/// Result type for SOPS operations
pub type SopsResult<T> = Result<T, SopsError>;

/// Configuration for SOPS operations
#[derive(Debug, Clone)]
pub struct SopsConfig {
    sops_executable_path: PathBuf,
    working_dir: Option<PathBuf>,
    env_vars: HashMap<String, String>,
    default_timeout: Duration,
    file_path: PathBuf,
    master_key_path: PathBuf,
    lock_timeout: Duration,
}

impl SopsConfig {
    pub fn sops_executable_path(&self) -> &PathBuf { &self.sops_executable_path }
    pub fn working_dir(&self) -> &Option<PathBuf> { &self.working_dir }
    pub fn env_vars(&self) -> &HashMap<String, String> { &self.env_vars }
    pub fn default_timeout(&self) -> Duration { self.default_timeout }
    pub fn sops_file_path(&self) -> &PathBuf { &self.file_path }
    pub fn master_key_file_path(&self) -> &PathBuf { &self.master_key_path }
    pub fn lock_timeout(&self) -> Duration { self.lock_timeout }

    /// Create a new SOPS configuration
    pub fn new(file_path: PathBuf, master_key_path: PathBuf) -> Self {
        Self {
            sops_executable_path: "/usr/local/bin/sops".into(),
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path,
            master_key_path,
            lock_timeout: Duration::from_secs(30),
        }
    }

    /// Create a new SOPS configuration with custom SOPS path
    pub fn with_sops_path(file_path: PathBuf, master_key_path: PathBuf, sops_path: PathBuf) -> Self {
        Self {
            sops_executable_path: sops_path,
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path,
            master_key_path,
            lock_timeout: Duration::from_secs(30),
        }
    }

    /// Set the working directory for SOPS operations
    pub fn with_working_dir(mut self, working_dir: PathBuf) -> Self {
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
            sops_executable_path: "/usr/local/bin/sops".into(),
            working_dir: None,
            env_vars: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            file_path: "secrets.json".into(),
            master_key_path: "secrets.age".into(),
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
    pub config: SopsConfig,
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
    pub fn new(file_path: PathBuf, master_key_path: PathBuf) -> Self {
        Self {
            config: SopsConfig::new(file_path, master_key_path),
        }
    }
    
    // ============================================================================
    // Internal SOPS command execution functions
    // ============================================================================

    /// Helper method to create a command with common configuration
    async fn create_command(&self, arg: &str) -> SopsResult<TokioCommand> {
        let mut command = TokioCommand::new(&self.config.sops_executable_path());

        // Set up environment variables - avoid cloning by building directly
        let mut env_vars = HashMap::new();
        for (key, value) in self.config.env_vars() {
            env_vars.insert(key.clone(), value.clone());
        }

        let master_key_path_str = self.get_master_key_path_string();
        if !env_vars.contains_key("SOPS_AGE_KEY_FILE") {
            debug!("Setting SOPS_AGE_KEY_FILE environment variable to: {}", self.config.master_key_file_path().display());
            env_vars.insert("SOPS_AGE_KEY_FILE".to_string(), master_key_path_str);
        } else {
            debug!("SOPS_AGE_KEY_FILE already set in environment");
        }
        command.envs(env_vars);

        // Set working directory if specified
        if let Some(working_dir) = self.config.working_dir() {
            debug!("Setting working directory to: {}", working_dir.display());
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

    /// Helper method to get master key path as string, avoiding repeated cloning
    fn get_master_key_path_string(&self) -> String {
        match self.config.master_key_file_path().canonicalize() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => self.config.master_key_file_path().to_string_lossy().to_string(),
        }
    }

    /// Helper method to build environment variables with master key, avoiding cloning
    fn build_env_vars_with_master_key(&self) -> HashMap<String, String> {
        let mut env_vars = HashMap::new();
        for (key, value) in self.config.env_vars() {
            env_vars.insert(key.to_string(), value.to_string());
        }

        let master_key_path_str = self.get_master_key_path_string();
        if !env_vars.contains_key("SOPS_AGE_KEY_FILE") {
            env_vars.insert("SOPS_AGE_KEY_FILE".to_string(), master_key_path_str);
        }
        env_vars
    }

    /// Helper method to run a command and log the results
    async fn run_and_log_command(mut command: TokioCommand) -> SopsResult<std::process::Output> {
        // Extract command details for detailed logging
        let program = command.as_std().get_program().to_string_lossy().to_string();
        let args: Vec<String> = command.as_std().get_args().map(|arg| arg.to_string_lossy().to_string()).collect();
        
        let output = command.output().await
            .map_err(|e| {
                error!("Failed to execute command: {}", e);
                SopsError::CommandFailed(format!("Command execution failed: {}", e))
            })?;

        debug!("Command completed with status: {}", output.status);

        // Log stdout and stderr for debugging
        if !output.stdout.is_empty() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            debug!("Command stdout: {}", stdout.trim());
        } else {
            debug!("Command stdout: <empty>");
        }

        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("Command stderr: {}", stderr.trim());
        } else {
            debug!("Command stderr: <empty>");
        }

        Ok(output)
    }

    
    /// Check if a key exists in the SOPS file by parsing the JSON structure
    /// If a read lock or write lock is provided, use it; otherwise, acquire one for this operation.
    pub async fn key_exists(
        &self,
        key: &str,
        read_lock: Option<&crate::shared::file_lock::ReadLock>,
        write_lock: Option<&crate::shared::file_lock::WriteLock>,
    ) -> SopsResult<bool> {
        debug!("Key existence check: key='{}'", key);

        // Validate inputs
        if key.trim().is_empty() {
            warn!("Validation failed: key is empty");
            return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
        }

        if !self.config.sops_file_path().exists() {
            debug!("File does not exist: {}", canonicalize_path(&self.config.sops_file_path()));
            return Ok(false);
        }

        // Helper closure to perform the check
        let check = async || {
            // Read the SOPS file content
            let file_content = tokio::fs::read_to_string(&self.config.sops_file_path()).await
                .map_err(|e| {
                    warn!("Failed to read SOPS file: {}", e);
                    SopsError::IoError(e)
                })?;

            // Parse as JSON
            let json_value: Value = serde_json::from_str(&file_content)
                .map_err(|e| {
                    warn!("Failed to parse SOPS file as JSON: {}", e);
                    SopsError::InvalidSecretData(format!("Invalid JSON: {}", e))
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

        // If a read lock or write lock is provided, use it; otherwise, acquire one
        if read_lock.is_some() || write_lock.is_some() {
            // Already locked, just check
            check().await
        } else {
            // Acquire our own lock for this operation
            let _acquired_lock = ReadLock::acquire(&self.config.sops_file_path(), self.config.lock_timeout())
                .await
                .map_err(|e| {
                    warn!("Failed to acquire read lock for key existence check: {:?}", e);
                    SopsError::FileLockError(e)
                })?;

            check().await
        }
    }

    /// Internal function to create a SOPS file with initial SecretData content
    pub(crate) async fn create_sops_file(&self, secrets: &HashMap<String, SecretData>) -> SopsResult<()> {
        debug!("Creating SOPS file: {}", self.config.sops_file_path().display());
        
        // Acquire write lock
        let _write_lock = WriteLock::acquire(&self.config.sops_file_path(), self.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;
        
        // Create JSON object with created_at timestamp in milliseconds
        let current_timestamp_ms = chrono::Utc::now().timestamp_millis();
        let initial_json = format!("{{\"created_at\": {}}}", current_timestamp_ms);
        
        // Write initial content to file
        tokio::fs::write(&self.config.sops_file_path(), initial_json).await
            .map_err(|e| SopsError::IoError(e))?;
        
        // Encrypt the file with SOPS
        let mut command = TokioCommand::new(&self.config.sops_executable_path());
        
        // Set up environment variables using helper method
        let env_vars = self.build_env_vars_with_master_key();
        command.envs(env_vars);
        
        // Set working directory if specified
        if let Some(working_dir) = self.config.working_dir() {
            command.current_dir(working_dir);
        }
        
        command
            .arg("--encrypt")
            .arg(canonicalize_path(&self.config.sops_file_path()));
        
        let output = Self::run_and_log_command(command).await?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SopsError::CommandFailed(format!(
                "Failed to encrypt SOPS file: {}",
                stderr
            )));
        }
        
        // Now add each secret individually using SOPS set commands
        for (key, secret_data) in secrets {
            // Serialize the SecretData to JSON
            let json_value = serde_json::to_string(secret_data)
                .map_err(|e| SopsError::InvalidSecretData(format!("Failed to serialize SecretData for key {}: {}", key, e)))?;
            
            // Build SOPS set command
            let mut set_command = TokioCommand::new(&self.config.sops_executable_path());
            
            // Set up environment variables using helper method
            let set_env_vars = self.build_env_vars_with_master_key();
            set_command.envs(set_env_vars);
            
            // Set working directory if specified
            if let Some(working_dir) = self.config.working_dir() {
                set_command.current_dir(working_dir);
            }
            
            // Set the JSON value for the key
            set_command
                .arg("set")
                .arg(canonicalize_path(&self.config.sops_file_path()))
                .arg(&format!("[\"{}\"]", key))
                .arg(&json_value);
            
            let set_output = Self::run_and_log_command(set_command).await?;
            
            if !set_output.status.success() {
                let stderr = String::from_utf8_lossy(&set_output.stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS set command failed for key {}: {}",
                    key, stderr
                )));
            }
            
            debug!("Successfully added secret for key: {}", key);
        }
        
        Ok(())
    }

    /// Internal function to get SecretData from a SOPS file for a given key
    /// Can accept either a ReadLock or WriteLock if already acquired elsewhere
    pub async fn get_secret_data_for_key(&self, key: &str, read_lock: Option<&crate::shared::file_lock::ReadLock>, write_lock: Option<&crate::shared::file_lock::WriteLock>) -> SopsResult<SecretData> {
        debug!("Getting SecretData for key: {}", key);
        
        // Validate inputs
        if key.trim().is_empty() {
            return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
        }
        
        // Check if file exists
        if !self.config.sops_file_path().exists() {
            return Err(SopsError::InvalidPath(format!("File does not exist: {}", canonicalize_path(&self.config.sops_file_path()))));
        }
        
        // Acquire read lock if not provided
        let _read_lock = if read_lock.is_some() || write_lock.is_some() {
            None // Use the provided lock
        } else {
            Some(ReadLock::acquire(&self.config.sops_file_path(), self.config.lock_timeout())
                .await
                .map_err(|e| SopsError::FileLockError(e))?)
        };
        
        // Build SOPS extract command
        let mut command = TokioCommand::new(&self.config.sops_executable_path());
        
        // Set up environment variables using helper method
        let env_vars = self.build_env_vars_with_master_key();
        command.envs(env_vars);
        
        // Set working directory if specified
        if let Some(working_dir) = self.config.working_dir() {
            command.current_dir(working_dir);
        }
        
        // Extract the JSON value for the key
        command
            .arg("--decrypt")
            .arg("--extract")
            .arg(&format!("[\"{}\"]", key))
            .arg(canonicalize_path(&self.config.sops_file_path()));
        
        let output = Self::run_and_log_command(command).await?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SopsError::CommandFailed(format!(
                "SOPS extract command failed: {}",
                stderr
            )));
        }
        
        // Parse the output as JSON SecretData
        let json_str = String::from_utf8(output.stdout)
            .map_err(|e| SopsError::CommandFailed(format!("Invalid UTF-8 in SOPS output: {}", e)))?;
        
        let trimmed_json = json_str.trim();
        if trimmed_json.is_empty() {
            return Err(SopsError::NoSecretFound);
        }
        
        let secret_data: SecretData = serde_json::from_str(trimmed_json)
            .map_err(|e| SopsError::InvalidSecretData(format!("Failed to parse SecretData: {}", e)))?;
        
        debug!("Successfully extracted SecretData for key: {}", key);
        Ok(secret_data)
    }

    /// Internal function to update SecretData values in a SOPS file for multiple keys
    pub async fn update_secrets(&self, secrets: &HashMap<String, SecretData>, write_lock: Option<&crate::shared::file_lock::WriteLock>) -> SopsResult<()> {
        debug!("Updating SecretData for {} keys", secrets.len());
        
        // Validate inputs
        if secrets.is_empty() {
            return Err(SopsError::InvalidSecretInput("No secrets provided".to_string()));
        }
        
        for key in secrets.keys() {
            if key.trim().is_empty() {
                return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
            }
        }
        
        // Acquire write lock if not provided
        let _write_lock = if write_lock.is_some() {
            None // Use the provided lock
        } else {
            Some(WriteLock::acquire(&self.config.sops_file_path(), self.config.lock_timeout())
                .await
                .map_err(|e| SopsError::FileLockError(e))?)
        };
        
        // Process each secret in the HashMap
        for (key, secret_data) in secrets {
            // Serialize SecretData to JSON
            let json_value = serde_json::to_string(secret_data)
                .map_err(|e| SopsError::InvalidSecretData(format!("Failed to serialize SecretData for key {}: {}", key, e)))?;
            
            // Build SOPS set command
            let mut command = TokioCommand::new(&self.config.sops_executable_path());
            
            // Set up environment variables using helper method
            let env_vars = self.build_env_vars_with_master_key();
            command.envs(env_vars);
            
            // Set working directory if specified
            if let Some(working_dir) = self.config.working_dir() {
                command.current_dir(working_dir);
            }
            
            // Set the JSON value for the key
            command
                .arg("set")
                .arg(canonicalize_path(&self.config.sops_file_path()))
                .arg(&format!("[\"{}\"]", key))
                .arg(&json_value);
            
            let output = Self::run_and_log_command(command).await?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SopsError::CommandFailed(format!(
                    "SOPS set command failed for key {}: {}",
                    key, stderr
                )));
            }
            
            debug!("Successfully updated SecretData for key: {}", key);
        }
        
        info!("Successfully updated {} secrets", secrets.len());
        Ok(())
    }


    /// Validate that SOPS executable exists and is accessible
    /// Runs 'sops --version' to verify SOPS is working correctly
    pub async fn validate_sops(&self, timeout_duration: Option<Duration>) -> SopsResult<()> {
        debug!("Validating SOPS executable: {}", self.config.sops_executable_path().display());
        
        let timeout_duration = timeout_duration.unwrap_or(self.config.default_timeout());
        
        let mut command = TokioCommand::new(&self.config.sops_executable_path());
        
        // Set up environment variables using helper method
        let env_vars = self.build_env_vars_with_master_key();
        command.envs(env_vars);
        
        // Set working directory if specified
        if let Some(working_dir) = self.config.working_dir() {
            command.current_dir(working_dir);
        }
        
        command.arg("--version");
        
        let output = tokio::time::timeout(timeout_duration, command.output()).await
            .map_err(|_| SopsError::CommandTimeout)?;

        let output = output.map_err(|e| SopsError::CommandExecutionFailed(e.to_string()))?;

        if output.status.success() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                debug!("SOPS version: {}", stdout.trim());
                info!("SOPS validation successful");
                Ok(())
            } else {
                Err(SopsError::InvalidOutput("Failed to parse stdout as UTF-8".to_string()))
            }
        } else {
            let stderr = if let Ok(stderr) = String::from_utf8(output.stderr) {
                stderr
            } else {
                "Failed to parse stderr as UTF-8".to_string()
            };
            Err(SopsError::CommandFailed(stderr))
        }
    }
}

// Helper for canonicalizing a path for use
fn canonicalize_path(path: &PathBuf) -> String {
    path.canonicalize().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| path.to_string_lossy().to_string())
}