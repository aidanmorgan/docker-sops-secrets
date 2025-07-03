use bollard::Docker;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::server::config::ServerConfig;
use crate::server::docker::ContainerCache;
use crate::server::file_cleaner::FileCleanupManager;
use crate::server::models::WriteOperation;
use crate::server::rate_limiter::RateLimiter;
use crate::sops::SopsWrapper;

/// Application state shared across all request handlers
pub struct AppState {
    /// SOPS client for secret operations. Thread-safe due to immutable design.
    /// Wrapped in Arc to avoid unnecessary cloning.
    pub sops_client: Arc<SopsWrapper>,
    /// Docker client for container operations. Thread-safe by design.
    /// Wrapped in Arc to avoid unnecessary cloning.
    pub docker_client: Arc<Docker>,
    /// Server configuration. Thread-safe due to read-only, owned types.
    /// Wrapped in Arc to avoid unnecessary cloning.
    pub server_config: Arc<ServerConfig>,
    /// Cache for IP to container mapping to avoid repeated Docker API calls.
    /// Thread-safe through `Arc<RwLock<...>>` - multiple readers, exclusive writers.
    pub ip_cache: ContainerCache,
    /// Active write operations cache.
    /// Thread-safe through `Arc<RwLock<...>>` - multiple readers, exclusive writers.
    pub write_operations: Arc<RwLock<HashMap<String, WriteOperation>>>,
    /// File cleanup manager for automatic deletion of temporary secret files.
    /// Thread-safe through internal `Arc<Mutex<...>>` and `Arc<Notify>`.
    pub file_cleanup: Arc<FileCleanupManager>,
    /// Rate limiter for preventing DoS attacks.
    /// Thread-safe through `Arc<RwLock<...>>`.
    pub rate_limiter: Arc<RateLimiter>,
}
