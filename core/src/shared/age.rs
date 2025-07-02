use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use age::{Decryptor, Encryptor};
use log::{debug, error, info, warn};
use std::io::{Read, Write};
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum AgeError {
    #[error("Timeout")]
    Timeout,
    #[error("Key generation error: {0}")]
    KeyGen(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Unsupported age file format")]
    UnsupportedFormat,
    #[error("Task join error: {0}")]
    TaskJoin(String),
}

/// Temporary key pair for write operations
#[derive(Debug, Clone)]
pub struct TempKeyPair {
    pub private_key: String,
    pub public_key: String,
}

impl Drop for TempKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.public_key.zeroize();
    }
}

/// Generate a temporary age key pair for write operations with timeout (using age crate)
pub async fn generate_temp_age_key_pair(
    timeout_duration: Duration,
) -> Result<TempKeyPair, AgeError> {
    debug!("Generating temporary age key pair with timeout: {:?}", timeout_duration);
    let operation = async move {
        let identity = Identity::generate();
        let private_key = identity.to_string().expose_secret().to_string();
        let public_key = identity.to_public().to_string();
        debug!("Temporary age key pair generated (public key length: {})", public_key.len());
        Ok(TempKeyPair { private_key, public_key })
    };

    match timeout(timeout_duration, operation).await {
        Ok(result) => {
            info!("Temporary age key pair generation completed successfully");
            result
        }
        Err(_) => {
            warn!("Temporary age key pair generation timed out after {:?}", timeout_duration);
            Err(AgeError::Timeout)
        }
    }
}

/// Encrypt data with age public key with timeout (using age crate, ASCII armor)
pub async fn encrypt_with_age_public_key(
    public_key: &str,
    data: &str,
    timeout_duration: Duration,
) -> Result<Vec<u8>, AgeError> {
    debug!("Encrypting data with age public key (public key length: {}, data length: {}, timeout: {:?})", 
           public_key.len(), data.len(), timeout_duration);

    let public_key = public_key.to_string();
    let data = data.to_owned();

    let operation = move || {
        // Parse the recipient
        let recipient = public_key.parse::<Recipient>()
            .map_err(|e| {
                error!("Failed to parse age public key: {}", e);
                AgeError::Parse(e.to_string())
            })?;

        // Create the encryptor
        let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| {
                error!("Failed to create age encryptor: {}", e);
                AgeError::Encryption(e.to_string())
            })?;

        // Set up the encryption pipeline
        let mut encrypted = vec![];
        let mut armor = ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor)
            .map_err(|e| {
                error!("Failed to create armored writer: {}", e);
                AgeError::Encryption(e.to_string())
            })?;

        let mut writer = encryptor.wrap_output(&mut armor)
            .map_err(|e| {
                error!("Failed to wrap encryptor output: {}", e);
                AgeError::Encryption(e.to_string())
            })?;

        // Write the data and finalize
        writer.write_all(data.as_bytes())
            .map_err(|e| {
                error!("Failed to write data to encryptor: {}", e);
                AgeError::Encryption(e.to_string())
            })?;

        writer.finish()
            .map_err(|e| {
                error!("Failed to finish encryptor writer: {}", e);
                AgeError::Encryption(e.to_string())
            })?;

        armor.finish()
            .map_err(|e| {
                error!("Failed to finish armored writer: {}", e);
                AgeError::Encryption(e.to_string())
            })?;

        info!("Data encrypted successfully (encrypted length: {})", encrypted.len());
        Ok(encrypted)
    };

    // Run the operation with a timeout
    execute_with_timeout(timeout_duration, operation, "encryption").await
}

/// Helper function to execute an operation with timeout
async fn execute_with_timeout<T, F>(timeout_duration: Duration, operation: F, operation_name: &str) 
    -> Result<T, AgeError> 
where
    F: FnOnce() -> Result<T, AgeError> + Send + 'static,
    T: Send + 'static,
{
    match timeout(timeout_duration, tokio::task::spawn_blocking(operation)).await {
        Ok(join_result) => join_result.unwrap_or_else(|e| {
            error!("Task join error during {}: {}", operation_name, e);
            Err(AgeError::TaskJoin(e.to_string()))
        }),
        Err(_) => {
            warn!("Age {} timed out after {:?}", operation_name, timeout_duration);
            Err(AgeError::Timeout)
        }
    }
}

/// Decrypt data with age private key with timeout (using age crate, ASCII armor)
pub async fn decrypt_with_age_private_key(
    private_key: &str,
    encrypted_data: &[u8],
    timeout_duration: Duration,
) -> Result<String, AgeError> {
    debug!("Decrypting data with age private key (private key length: {}, encrypted data length: {}, timeout: {:?})", 
           private_key.len(), encrypted_data.len(), timeout_duration);

    let private_key = private_key.to_string();
    let encrypted_data = encrypted_data.to_vec();

    let operation = move || {
        // Parse the identity
        let identity = private_key.parse::<Identity>()
            .map_err(|e| {
                error!("Failed to parse age private key: {}", e);
                AgeError::Parse(e.to_string())
            })?;

        // Set up the decryption pipeline
        let armor = ArmoredReader::new(&encrypted_data[..]);
        let decryptor = Decryptor::new(armor)
            .map_err(|e| {
                error!("Failed to create age decryptor: {}", e);
                AgeError::Decryption(e.to_string())
            })?;

        let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| {
                error!("Failed to decrypt with age identity: {}", e);
                AgeError::Decryption(e.to_string())
            })?;

        // Read the decrypted data
        let mut decrypted = String::new();
        reader.read_to_string(&mut decrypted)
            .map_err(|e| {
                error!("Failed to read decrypted data: {}", e);
                AgeError::Decryption(e.to_string())
            })?;

        info!("Data decrypted successfully (decrypted length: {})", decrypted.len());
        Ok(decrypted)
    };

    // Run the operation with a timeout
    execute_with_timeout(timeout_duration, operation, "decryption").await
}
