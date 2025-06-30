use std::io::{Read, Write};
use std::time::Duration;
use age::x25519::{Identity, Recipient};
use age::{Encryptor, Decryptor};
use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::ExposeSecret;
use tokio::time::timeout;
use zeroize::Zeroize;
use thiserror::Error;

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
    let operation = async move {
        let identity = Identity::generate();
        let private_key = identity.to_string().expose_secret().to_string();
        let public_key = identity.to_public().to_string();

        Ok(TempKeyPair { private_key, public_key })
    };

    timeout(timeout_duration, operation)
        .await
        .map_err(|_| AgeError::Timeout)?
}

/// Encrypt data with age public key with timeout (using age crate, ASCII armor)
pub async fn encrypt_with_age_public_key(
    public_key: &str,
    data: &str,
    timeout_duration: Duration,
) -> Result<Vec<u8>, AgeError> {
    let public_key = public_key.to_string();
    let data = data.to_owned();
    let operation = move || {
        let recipient = public_key.parse::<Recipient>().map_err(|e| AgeError::Parse(e.to_string()))?;
        let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient)).map_err(|e| AgeError::Encryption(e.to_string()))?;
        let mut encrypted = vec![];
        let mut armor = ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor).map_err(|e| AgeError::Encryption(e.to_string()))?;
        let mut writer = encryptor.wrap_output(&mut armor).map_err(|e| AgeError::Encryption(e.to_string()))?;
        writer.write_all(data.as_bytes()).map_err(|e| AgeError::Encryption(e.to_string()))?;
        writer.finish().map_err(|e| AgeError::Encryption(e.to_string()))?;
        armor.finish().map_err(|e| AgeError::Encryption(e.to_string()))?;
        Ok(encrypted)
    };
    timeout(timeout_duration, tokio::task::spawn_blocking(operation)).await
        .map_err(|_| AgeError::Timeout)?
        .map_err(|e| AgeError::TaskJoin(e.to_string()))?
}

/// Decrypt data with age private key with timeout (using age crate, ASCII armor)
pub async fn decrypt_with_age_private_key(
    private_key: &str,
    encrypted_data: &[u8],
    timeout_duration: Duration,
) -> Result<String, AgeError> {
    let private_key = private_key.to_string();
    let encrypted_data = encrypted_data.to_vec();

    let operation = move || {
        let identity = private_key.parse::<Identity>().map_err(|e| AgeError::Parse(e.to_string()))?;
        let armor = ArmoredReader::new(&encrypted_data[..]);
        let decryptor = Decryptor::new(armor).map_err(|e| AgeError::Decryption(e.to_string()))?;
        
        let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)).map_err(|e| AgeError::Decryption(e.to_string()))?;
        let mut decrypted = String::new();

        reader.read_to_string(&mut decrypted).map_err(|e| AgeError::Decryption(e.to_string()))?;

        Ok(decrypted)
    };
    
    timeout(timeout_duration, tokio::task::spawn_blocking(operation)).await
        .map_err(|_| AgeError::Timeout)?
        .map_err(|e| AgeError::TaskJoin(e.to_string()))?
} 