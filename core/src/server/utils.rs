use sha2::{Digest, Sha256};


/// Calculate SHA256 hash of secret value
pub fn calculate_secret_hash(secret_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret_value.as_bytes());
    hex::encode(hasher.finalize())
}

