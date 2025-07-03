use std::collections::HashMap;
use std::time::Duration;
use log::{debug, error, info, warn};
use tokio::time::timeout;
use crate::shared::file_lock::{ReadLock, WriteLock};
use crate::shared::secure_secret::SecureSecret;
use crate::sops::private::{SecretData, SopsError, SopsResult, SopsWrapper};

/// Insert or update a secret in the SOPS file
/// If the secret exists, it will be updated (if client has permission)
/// If the secret doesn't exist, it will be created with client as owner
pub async fn upsert_secret(sops: &SopsWrapper, key: &str, value: &str, client: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    // Validate inputs
    if key.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if value.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Value cannot be empty".to_string()));
    }
    if client.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }

    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());

    let operation = async {
        let write_lock = WriteLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;

        // Check if the secret already exists
        let secret_exists = sops.key_exists(key, None, Some(&write_lock)).await?;

        if secret_exists {
            // Secret exists - read existing data and update if client has permission
            debug!("Secret '{}' exists, checking permissions for client '{}'", key, client);

            let mut existing_data = sops.get_secret_data_for_key(key, None, Some(&write_lock)).await?;

            // Check if client is owner or in writers list
            if existing_data.owner != client && !existing_data.writers.contains(&client.to_string()) {
                return Err(SopsError::PermissionDenied(
                    format!("Client '{}' does not have permission to update secret '{}'", client, key)
                ));
            }

            // Create updated SecretData with new value but same owner, readers, and writers
            existing_data.set_value(value.to_string());

            // Update the secret
            let secrets_to_update = {
                let mut map = HashMap::new();
                map.insert(key.to_string(), existing_data);
                map
            };

            sops.update_secrets(&secrets_to_update, Some(&write_lock)).await?;

            info!("Successfully updated existing secret '{}' for client '{}'", key, client);
        } else {
            // Secret doesn't exist - create new SecretData with client as owner
            debug!("Secret '{}' does not exist, creating new secret with client '{}' as owner", key, client);

            // Create the secret
            let secrets_to_create = {
                let mut map = HashMap::new();
                map.insert(key.to_string(), SecretData::new(
                    value.to_string(),
                    client.to_string(),
                    Some(vec![]),
                    Some(vec![])
                ));
                map
            };

            sops.update_secrets(&secrets_to_create, Some(&write_lock)).await?;

            info!("Successfully created new secret '{}' with client '{}' as owner", key, client);
        }

        Ok(())
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Get a secret value from the SOPS file
/// Returns an owned SecureSecret if the client has permission to read it
pub async fn get_secret(sops: &SopsWrapper, key: &str, client: &str, timeout_duration: Option<Duration>) -> SopsResult<SecureSecret> {
    debug!("Getting secret: key='{}', client='{}', timeout={:?}", key, client, timeout_duration);
    
    // Validate inputs
    if key.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if client.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }

    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());

    let operation = async {
        let read_lock = ReadLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;

        // Check if secret exists
        let exists = sops.key_exists(key, Some(&read_lock), None).await?;
        if !exists {
            return Err(SopsError::NoSecretFound);
        }

        let secret_data = sops.get_secret_data_for_key(key, Some(&read_lock), None).await?;
        
        // Check authorization
        if !secret_data.can_read(client) {
            return Err(SopsError::PermissionDenied(
                format!("Client '{}' does not have permission to read secret '{}'", client, key)
            ));
        }
        
        info!("Successfully retrieved secret '{}' for client '{}'", key, client);
        Ok(secret_data)
    };

    let secret_data = timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?;
    
    // Create and return an owned SecureSecret
    Ok(SecureSecret::new(secret_data?.get_value().to_string()))
}

/// Add a reader to a secret
/// Requires the client to be the owner or a writer of the secret
pub async fn add_reader(sops: &SopsWrapper, key: &str, client: &str, new_reader: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    debug!("Adding reader to secret: key='{}', client='{}', new_reader='{}', timeout={:?}", key, client, new_reader, timeout_duration);

    // Validate inputs
    if key.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if client.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }
    if new_reader.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("New reader cannot be empty".to_string()));
    }

    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());

    let operation = async {
        let write_lock = WriteLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;

        // Get the current SecretData
        let mut secret_data = sops.get_secret_data_for_key(key, None, Some(&write_lock)).await?;

        if secret_data.readers.iter().any(|r| r == new_reader) {
            return Err(SopsError::InvalidSecretInput(
                format!("Reader '{}' already exists in secret '{}'", new_reader, key)
            ));
        }

        // Add the new reader
        secret_data.add_reader(new_reader.to_string());

        // Update the secret
        let secrets_to_update = {
            let mut map = HashMap::new();
            map.insert(key.to_string(), secret_data);
            map
        };

        sops.update_secrets(&secrets_to_update, Some(&write_lock)).await?;

        info!("Successfully added reader '{}' to secret '{}' by client '{}'", new_reader, key, client);
        Ok(())
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Add a writer to a secret
/// Requires the client to be the owner of the secret
pub async fn add_writer(sops: &SopsWrapper, key: &str, client: &str, new_writer: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    debug!("Adding writer to secret: key='{}', client='{}', new_writer='{}', timeout={:?}", key, client, new_writer, timeout_duration);

    // Validate inputs
    if key.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if client.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }
    if new_writer.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("New writer cannot be empty".to_string()));
    }

    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());

    let operation = async {
        let write_lock = WriteLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;

        // Get the current SecretData
        let mut secret_data = sops.get_secret_data_for_key(key, None, Some(&write_lock)).await?;

        if secret_data.writers.iter().any(|w| w == new_writer) {
            return Err(SopsError::InvalidSecretInput(
                format!("Writer '{}' already exists in secret '{}'", new_writer, key)
            ));
        }

        // Add the new writer
        secret_data.add_writer(new_writer.to_string());

        // Update the secret
        let secrets_to_update = {
            let mut map = HashMap::new();
            map.insert(key.to_string(), secret_data);
            map
        };

        sops.update_secrets(&secrets_to_update, Some(&write_lock)).await?;

        info!("Successfully added writer '{}' to secret '{}' by client '{}'", new_writer, key, client);
        Ok(())
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Remove a reader from a secret
/// Requires the client to be the owner or a writer of the secret
pub async fn remove_reader(sops: &SopsWrapper, key: &str, client: &str, reader_to_remove: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());

    debug!("Removing reader from secret: key='{}', client='{}', reader_to_remove='{}', timeout={:?}", key, client, reader_to_remove, timeout_duration);

    // Validate inputs
    if key.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if client.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }
    if reader_to_remove.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Reader to remove cannot be empty".to_string()));
    }

    let operation = async {
        let write_lock = WriteLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;

        // Get the current SecretData
        let mut secret_data = sops.get_secret_data_for_key(key, None, Some(&write_lock)).await?;

        if !secret_data.readers.contains(&reader_to_remove.to_string()) {
            return Err(SopsError::InvalidSecretInput(
                format!("Reader '{}' does not exist in secret '{}'", reader_to_remove, key)
            ));
        }

        // Remove the reader
        secret_data.remove_reader(reader_to_remove);

        // Update the secret
        let secrets_to_update = {
            let mut map = HashMap::new();
            map.insert(key.to_string(), secret_data);
            map
        };

        sops.update_secrets(&secrets_to_update, Some(&write_lock)).await?;

        info!("Successfully removed reader '{}' from secret '{}' by client '{}'", reader_to_remove, key, client);
        Ok(())
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Remove a writer from a secret
/// Requires the client to be the owner of the secret
pub async fn remove_writer(sops: &SopsWrapper, key: &str, client: &str, writer_to_remove: &str, timeout_duration: Option<Duration>) -> SopsResult<()> {
    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());

    debug!("Removing writer from secret: key='{}', client='{}', writer_to_remove='{}', timeout={:?}", key, client, writer_to_remove, timeout_duration);

    // Validate inputs
    if key.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if client.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }
    if writer_to_remove.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Writer to remove cannot be empty".to_string()));
    }

    let operation = async {
        let write_lock = WriteLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;

        // Get the current SecretData
        let mut secret_data = sops.get_secret_data_for_key(key, None, Some(&write_lock)).await?;
        
        if !secret_data.writers.contains(&writer_to_remove.to_string()) {
            return Err(SopsError::InvalidSecretInput(
                format!("Writer '{}' does not exist in secret '{}'", writer_to_remove, key)
            ));
        }

        // Remove the writer
        secret_data.remove_writer(writer_to_remove);

        // Update the secret
        let secrets_to_update = {
            let mut map = HashMap::new();
            map.insert(key.to_string(), secret_data);
            map
        };

        sops.update_secrets(&secrets_to_update, Some(&write_lock)).await?;

        info!("Successfully removed writer '{}' from secret '{}' by client '{}'", writer_to_remove, key, client);
        Ok(())
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Check if a secret exists using the public API
pub async fn secret_exists(
    sops_client: &SopsWrapper,
    secret_name: &str,
    timeout_duration: Option<Duration>,
) -> Result<bool, SopsError> {
    debug!("Checking if secret exists: secret_name='{}', timeout={:?}", secret_name, timeout_duration);
    let timeout_duration = timeout_duration.unwrap_or(sops_client.config.default_timeout());
    
    let operation = async {
        let read_lock = ReadLock::acquire(&sops_client.config.sops_file_path(), sops_client.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;

        let result = sops_client.key_exists(secret_name, Some(&read_lock), None).await;
        match result {
            Ok(exists) => {
                if exists {
                    debug!("Secret '{}' exists", secret_name);
                } else {
                    debug!("Secret '{}' does not exist", secret_name);
                }
                Ok(exists)
            },
            Err(e) => {
                error!("Failed to check if secret '{}' exists: {:?}", secret_name, e);
                Err(e)
            }
        }
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Check read permission using the public API
pub async fn can_read(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    timeout_duration: Option<Duration>,
) -> Result<bool, SopsError> {
    info!("Checking read permission for client '{}' on secret '{}'", client_name, secret_name);
    let timeout_duration = timeout_duration.unwrap_or(sops_client.config.default_timeout());
    
    let operation = async {
        let read_lock = ReadLock::acquire(&sops_client.config.sops_file_path(), sops_client.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;
            
        // make sure to call the version from the private module, otherwise we run the risk of a deadlock as the public module
        // will create a read lock whenever we check for existence.
        let exists = sops_client.key_exists(secret_name, Some(&read_lock), None).await?;
        if !exists {
            return Err(SopsError::NoSecretFound);
        }
        
        let result = sops_client.get_secret_data_for_key(secret_name, Some(&read_lock), None).await?;
        Ok(result.can_read(client_name))
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Check write permission using the public API
pub async fn can_write(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    timeout_duration: Option<Duration>,
) -> Result<bool, SopsError> {
    info!("Checking write permission for client '{}' on secret '{}'", client_name, secret_name);
    let timeout_duration = timeout_duration.unwrap_or(sops_client.config.default_timeout());

    let operation = async {
        // create one read lock to cascade through the operation
        let read_lock = ReadLock::acquire(&sops_client.config.sops_file_path(), sops_client.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;
            
        let exists = sops_client.key_exists(secret_name, Some(&read_lock), None).await?;
        if !exists {
            return Err(SopsError::NoSecretFound);
        }

        let current_secret = sops_client.get_secret_data_for_key(secret_name, Some(&read_lock), None).await?;
        Ok(current_secret.can_write(client_name))
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Set a secret value in the SOPS file (create or update)
/// Handles all input validation, existence checks, and permission checks
pub async fn set_secret(
    sops: &SopsWrapper,
    secret_name: &str,
    secret_value: &str,
    client_name: &str,
    timeout_duration: Option<Duration>,
) -> Result<(), SopsError> {
    debug!("Setting secret '{}' for client '{}' with timeout {:?}", secret_name, client_name, timeout_duration);
    // Validate inputs
    if secret_name.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if client_name.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }
    if secret_value.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Value cannot be empty".to_string()));
    }

    let write_lock = WriteLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
        .await
        .map_err(|e| SopsError::FileLockError(e))?;

    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());
    let operation = async {
        // Check if secret exists - pass the write lock to avoid deadlock
        let exists = sops.key_exists(secret_name, None, Some(&write_lock)).await?;
        let mut secret_data = if exists {
            // Secret exists - check write permission, pass the write lock to avoid deadlock
            let current_secret = sops.get_secret_data_for_key(secret_name, None, Some(&write_lock)).await?;
            if !current_secret.can_write(client_name) {
                return Err(SopsError::PermissionDenied(
                    format!("Client '{}' does not have permission to write secret '{}'", client_name, secret_name)
                ));
            }

            info!("Updating existing secret '{}' for client '{}'", secret_name, client_name);
            current_secret
        } else {
            // Secret doesn't exist - client will become owner
            info!("Creating new secret '{}' for client '{}'", secret_name, client_name);
            SecretData::new(secret_value.to_string(), client_name.to_string(), None, None)
        };

        secret_data.set_value(secret_value.to_string());

        let secrets_to_update = {
            let mut map = HashMap::new();
            map.insert(secret_name.to_string(), secret_data);
            map
        };

        sops.update_secrets(&secrets_to_update, Some(&write_lock)).await?;

        info!("Successfully {} secret '{}' for client '{}'",
              if exists { "updated" } else { "created" }, secret_name, client_name);

        Ok(())
    };

    // the private API intentionally does not provide timeouts only locks, that way we get the timeout for the operation
    // as a whole rather than individual steps.
    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Create new secret using the public API with timeout
pub async fn create_secret(
    sops_client: &SopsWrapper,
    client_name: &str,
    secret_name: &str,
    secret_value: &str,
    timeout_duration: Option<Duration>,
) -> Result<(), SopsError> {
    debug!("Creating new secret '{}' for client '{}' with timeout {:?}", secret_name, client_name, timeout_duration);
    let timeout_duration = timeout_duration.unwrap_or(sops_client.config.default_timeout());
    
    let operation = async {
        let result = upsert_secret(sops_client, secret_name, secret_value, client_name, Some(timeout_duration))
            .await
            .map_err(|e| {
                error!("Failed to create secret '{}' for client '{}': {:?}", secret_name, client_name, e);
                e
            });
        match &result {
            Ok(_) => { info!("Successfully created secret '{}' for client '{}'", secret_name, client_name); }
            Err(_) => { warn!("Failed to create secret '{}' for client '{}'", secret_name, client_name); }
        }
        result
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Check if client can write to secret with full validation
pub async fn can_write_with_validation(
    sops: &SopsWrapper,
    client: &str,
    key: &str,
    timeout_duration: Option<Duration>
) -> SopsResult<bool> {
    debug!("Checking write permission with validation: client='{}', key='{}', timeout={:?}", client, key, timeout_duration);
    
    // Validate inputs
    if key.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Key cannot be empty".to_string()));
    }
    if client.trim().is_empty() {
        return Err(SopsError::InvalidSecretInput("Client cannot be empty".to_string()));
    }

    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());

    let operation = async {
        let read_lock = ReadLock::acquire(&sops.config.sops_file_path(), sops.config.lock_timeout())
            .await
            .map_err(|e| SopsError::FileLockError(e))?;
            
        // Check if secret exists
        let exists = sops.key_exists(key, Some(&read_lock), None).await?;
        if !exists {
            return Err(SopsError::NoSecretFound);
        }

        let current_secret = sops.get_secret_data_for_key(key, Some(&read_lock), None).await?;
        Ok(current_secret.can_write(client))
    };

    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

/// Create an empty SOPS file if it doesn't exist
/// This function will create a new SOPS file with just a created_at timestamp
pub async fn initialize_sops_file_if_not_exists(sops: &SopsWrapper, timeout_duration: Option<Duration>) -> SopsResult<()> {
    debug!("Checking if SOPS file exists: {}", canonical_display(&sops.config.sops_file_path()));
    
    // Check if file already exists
    let file_path_buf = sops.config.sops_file_path();
    let file_path = std::path::Path::new(&file_path_buf);
    if file_path.exists() {
        debug!("SOPS file already exists, skipping initialization");
        return Ok(());
    }
    
    info!("SOPS file does not exist, creating empty file: {}", canonical_display(&sops.config.sops_file_path()));
    
    let timeout_duration = timeout_duration.unwrap_or(sops.config.default_timeout());
    
    let operation = async {
        // Create an empty HashMap (no secrets) to initialize the file
        let empty_secrets: HashMap<String, SecretData> = HashMap::new();
        
        // Use the private create_sops_file method with empty secrets
        sops.create_sops_file(&empty_secrets).await?;
        
        info!("Successfully created empty SOPS file: {}", canonical_display(&sops.config.sops_file_path()));
        Ok(())
    };
    
    timeout(timeout_duration, operation).await
        .map_err(|_| SopsError::Timeout(timeout_duration))?
}

// Helper for canonicalized display
fn canonical_display(path: &std::path::PathBuf) -> String {
    path.canonicalize().map(|p| p.display().to_string()).unwrap_or_else(|_| path.display().to_string())
}
