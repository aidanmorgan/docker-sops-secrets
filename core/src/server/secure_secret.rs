use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Secure wrapper for sensitive data that automatically zeroizes on drop
#[derive(Debug)]
pub struct SecureSecret {
    value: Secret<String>,
    hash: [u8; 32],
}

impl SecureSecret {
    pub fn new(value: String) -> Self {
        let hash = Self::calculate_hash(&value);
        Self {
            value: Secret::new(value),
            hash,
        }
    }

    pub fn calculate_hash(value: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hasher.finalize().into()
    }

    pub fn expose_secret(&self) -> &str {
        self.value.expose_secret()
    }

    pub fn verify_hash(&self, expected_hash: &str) -> bool {
        let expected_bytes = hex::decode(expected_hash).unwrap_or_default();
        if expected_bytes.len() != 32 {
            return false;
        }
        self.hash.ct_eq(&expected_bytes).into()
    }
}

impl Drop for SecureSecret {
    fn drop(&mut self) {
        let mut secret = self.value.expose_secret().to_string();
        secret.zeroize();
    }
} 