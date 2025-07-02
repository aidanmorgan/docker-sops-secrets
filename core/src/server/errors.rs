use crate::server::ErrorResponse;
use crate::shared::sops::SopsError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Custom error type for server operations
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Docker API error: {0}")]
    DockerApi(String),
    #[error("Docker API timeout")]
    DockerTimeout,
    #[error("SOPS error: {0}")]
    Sops(#[from] SopsError),
    #[error("SOPS timeout")]
    SopsTimeout,
    #[error("Age encryption error: {0}")]
    AgeEncryption(String),
    #[error("Age encryption timeout")]
    AgeTimeout,
    #[error("File system error: {0}")]
    FileSystem(String),
    #[error("Invalid age public key")]
    InvalidPublicKey,
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Write operation not found")]
    WriteOperationNotFound,
    #[error("Write operation expired")]
    WriteOperationExpired,
    #[error("Hash mismatch")]
    HashMismatch,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

impl ServerError {
    /// Convert to HTTP status code and error response
    pub fn into_response(self) -> Response {
        match self {
            ServerError::DockerApi(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Docker API Error".to_string(),
                    message: msg,
                })
            ).into_response(),
            ServerError::DockerTimeout => (
                StatusCode::REQUEST_TIMEOUT,
                Json(ErrorResponse {
                    error: "Docker API Timeout".to_string(),
                    message: "Timeout while querying Docker API".to_string(),
                })
            ).into_response(),
            ServerError::Sops(SopsError::InvalidSecretFormat(msg)) => (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Invalid Secret".to_string(),
                    message: msg,
                })
            ).into_response(),
            ServerError::Sops(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "SOPS Error".to_string(),
                    message: e.to_string(),
                })
            ).into_response(),
            ServerError::SopsTimeout => (
                StatusCode::REQUEST_TIMEOUT,
                Json(ErrorResponse {
                    error: "SOPS Timeout".to_string(),
                    message: "Timeout while performing SOPS operation".to_string(),
                })
            ).into_response(),
            ServerError::AgeEncryption(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Encryption Failed".to_string(),
                    message: msg,
                })
            ).into_response(),
            ServerError::AgeTimeout => (
                StatusCode::REQUEST_TIMEOUT,
                Json(ErrorResponse {
                    error: "Encryption Timeout".to_string(),
                    message: "Timeout while encrypting secret with age".to_string(),
                })
            ).into_response(),
            ServerError::FileSystem(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "File System Error".to_string(),
                    message: msg,
                })
            ).into_response(),
            ServerError::InvalidPublicKey => (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid Public Key".to_string(),
                    message: "The provided age public key is invalid".to_string(),
                })
            ).into_response(),
            ServerError::AccessDenied(msg) => (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Access Denied".to_string(),
                    message: msg,
                })
            ).into_response(),
            ServerError::WriteOperationNotFound => (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Write Operation Not Found".to_string(),
                    message: "No active write operation found for this client and secret".to_string(),
                })
            ).into_response(),
            ServerError::WriteOperationExpired => (
                StatusCode::REQUEST_TIMEOUT,
                Json(ErrorResponse {
                    error: "Write Operation Expired".to_string(),
                    message: "The write operation has expired".to_string(),
                })
            ).into_response(),
            ServerError::HashMismatch => (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Hash Mismatch".to_string(),
                    message: "The provided secret hash does not match the calculated hash".to_string(),
                })
            ).into_response(),
            ServerError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Rate Limit Exceeded".to_string(),
                    message: "Too many requests from this IP".to_string(),
                })
            ).into_response(),
        }
    }
} 