use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use zeroize::Zeroize;

/// Request body for secret retrieval
#[derive(Debug, Deserialize)]
pub struct GetSecretRequest {
    /// Client's public key for encrypting the secret
    pub public_key: String,
}

/// Request body for write secret initiation
#[derive(Debug, Deserialize)]
pub struct WriteSecretInitRequest {
    /// Secret name
    pub secret_name: String,
    /// Secret hash for validation
    pub secret_hash: String,
}

impl Drop for WriteSecretInitRequest {
    fn drop(&mut self) {
        self.secret_hash.zeroize();
    }
}

/// Response for write secret initiation
#[derive(Debug, Serialize)]
pub struct WriteSecretInitResponse {
    pub public_key: String,
    pub file_path: String,
    pub expires_at: String,
}

impl Drop for WriteSecretInitResponse {
    fn drop(&mut self) {
        self.public_key.zeroize();
    }
}

/// Response for write secret completion
#[derive(Debug, Serialize)]
pub struct WriteSecretCompleteResponse {
    pub status: String,
    pub message: String,
}

/// Write operation state
#[derive(Debug, Clone)]
pub struct WriteOperation {
    pub secret_name: String,
    pub client_ip: IpAddr,
    pub expires_at: u64,
    pub public_key: String,
    pub private_key: String,
    pub secret_hash: String,
    pub file_path: String,
}

impl Drop for WriteOperation {
    fn drop(&mut self) {
        self.public_key.zeroize();
        self.private_key.zeroize();
        self.secret_hash.zeroize();
    }
}

/// Response structure for secret retrieval (minimal data)
#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub file_path: String,
    pub timeout_seconds: u64,
    pub secret_hash: String,
}

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub timestamp: String,
    pub checks: HealthChecks,
}

/// Detailed health check results
#[derive(Debug, Serialize)]
pub struct HealthChecks {
    pub sops_wrapper: bool,
    pub master_key: bool,
    pub docker_api: bool,
    pub age_executable: bool,
    pub secrets_directory: bool,
    pub sops_file: bool,
} 