use std::collections::BinaryHeap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
use std::io;
use xattr::{get, set};
use chrono::Utc;

/// Represents a file that will be automatically deleted at a specific time.
/// 
/// # Thread Safety
/// 
/// This struct is `Clone`, `Eq`, `PartialEq`, `Ord`, and `PartialOrd`, making it safe to use
/// in concurrent data structures. The `PathBuf` and `Instant` are both thread-safe types.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExpiringFile {
    /// Full path to the file that will be deleted
    pub path: PathBuf,
    /// The instant when the file should be deleted
    pub expires_at: Instant,
    /// Number of deletion attempts
    pub retries: u32,
}

impl Ord for ExpiringFile {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse for min-heap (soonest expiry first)
        other.expires_at.cmp(&self.expires_at)
    }
}

impl PartialOrd for ExpiringFile {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Manages automatic cleanup of temporary files using a priority queue and background task.
/// 
/// # Thread Safety
/// 
/// This struct is designed to be shared across multiple async tasks:
/// 
/// - **`queue: Arc<Mutex<BinaryHeap<ExpiringFile>>>`** - Thread-safe through `Arc<Mutex<...>>`.
///   The `Arc` provides shared ownership, and the `Mutex` ensures exclusive access to the
///   priority queue. Multiple tasks can safely call `add_file()` concurrently.
/// 
/// - **`notify: Arc<Notify>`** - Thread-safe signaling mechanism. The `Notify` allows the
///   background task to be woken up when new files are added to the queue, ensuring timely
///   processing of new entries.
/// 
/// - **Background Task** - Runs in its own tokio task and safely accesses the queue through
///   the `Arc<Mutex<...>>`. It sleeps until the next file expires and can be woken early
///   by the `Notify` when new files are added.
/// 
/// # Usage
/// 
/// 1. Create a `FileCleanupManager` with `new()`
/// 2. Spawn the background task with `spawn_background_task()`
/// 3. Add files for cleanup with `add_file()`
/// 
/// The background task will automatically delete files when they expire and can be
/// efficiently woken up when new files are added to the queue.
#[derive(Debug)]
pub struct FileCleanupManager {
    /// Priority queue of files to be deleted, ordered by expiry time.
    /// Thread-safe through `Arc<Mutex<...>>`.
    queue: Arc<Mutex<BinaryHeap<ExpiringFile>>>,
    /// Notification mechanism to wake the background task when new files are added.
    /// Thread-safe through `Arc<Notify>`.
    notify: Arc<Notify>,
    /// Maximum number of retries for file deletion
    max_retries: u32,
    /// Delay between retry attempts
    retry_delay: Duration,
}

impl FileCleanupManager {
    pub fn new(max_retries: u32, retry_delay_seconds: u64) -> Self {
        Self {
            queue: Arc::new(Mutex::new(BinaryHeap::new())),
            notify: Arc::new(Notify::new()),
            max_retries,
            retry_delay: Duration::from_secs(retry_delay_seconds),
        }
    }

    /// Attempts to delete a file. Returns Ok(true) if deleted or not found, Ok(false) if failed, Err if unrecoverable.
    async fn try_delete_file(path: &PathBuf) -> Result<bool, io::Error> {
        match std::fs::remove_file(path) {
            Ok(_) => {
                eprintln!("🧹 Successfully deleted file: {}", path.display());
                Ok(true)
            }
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::NotFound => {
                        eprintln!("🧹 File already deleted (external process): {}", path.display());
                        Ok(true)
                    }
                    _ => {
                        eprintln!("⚠️  Error deleting file: {} - {}", path.display(), e);
                        Ok(false)
                    }
                }
            }
        }
    }

    pub fn spawn_background_task(self: Arc<Self>) {
        let queue = self.queue.clone();
        let notify = self.notify.clone();
        let max_retries = self.max_retries;
        let retry_delay = self.retry_delay;
        
        tokio::spawn(async move {
            loop {
                if let Err(e) = Self::run_cleanup_loop(&queue, &notify, max_retries, retry_delay).await {
                    eprintln!("⚠️  File cleanup loop error: {}, restarting...", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        });
    }

    /// Runs the main cleanup loop with proper error handling.
    async fn run_cleanup_loop(
        queue: &Arc<Mutex<BinaryHeap<ExpiringFile>>>,
        notify: &Arc<Notify>,
        max_retries: u32,
        retry_delay: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let mut to_retry = Vec::new();
            let next_expiry = {
                let mut queue = queue.lock().await;
                let now = Instant::now();

                while let Some(file) = queue.peek().cloned() {
                    if file.expires_at <= now {
                        let file = queue.pop().ok_or("Queue unexpectedly empty")?;
                        
                        // Check if file is still managed by us before attempting deletion
                        if let Some(is_managed) = Self::is_file_managed(&file.path) {
                            if !is_managed {
                                continue;
                            }
                        } else {
                            continue;
                        }
                        
                        match Self::try_delete_file(&file.path).await {
                            Ok(true) => {
                                // File deleted successfully
                            }
                            Ok(false) => {
                                if file.retries + 1 >= max_retries {
                                    eprintln!("❌ Max retries exceeded for file: {}", file.path.display());
                                } else {
                                    // Schedule retry
                                    let mut retry_file = file.clone();
                                    retry_file.retries += 1;
                                    retry_file.expires_at = now + retry_delay;
                                    to_retry.push(retry_file);
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Unrecoverable error deleting file {}: {}", file.path.display(), e);
                            }
                        }
                    } else {
                        break;
                    }
                }
                // Re-insert files to retry
                for retry_file in to_retry {
                    queue.push(retry_file);
                }
                if let Some(file) = queue.peek() {
                    Some(file.expires_at - now)
                } else {
                    None
                }
            };
            match next_expiry {
                Some(duration) => {
                    tokio::select! {
                        _ = tokio::time::sleep(duration) => {},
                        _ = notify.notified() => {},
                    }
                }
                None => {
                    notify.notified().await;
                }
            }
        }
    }

    /// Helper to mark a file as managed by the file cleaner (set xattr with expiry time)
    pub fn mark_file_managed(path: &PathBuf, expires_at: Instant) {
        // Calculate expiry as UNIX timestamp (seconds since epoch)
        let now = Instant::now();
        let duration_until_expiry = expires_at.duration_since(now);
        let expiry_time = Utc::now() + chrono::Duration::from_std(duration_until_expiry)
            .unwrap_or_else(|_| chrono::Duration::seconds(0));
        let expiry_timestamp = expiry_time.timestamp().to_string();
        
        // Set both the managed flag and expiry time
        if let Err(e) = set(path, "user.sops_cleaner_managed", b"1") {
            eprintln!("⚠️  Failed to set managed flag xattr on {}: {}", path.display(), e);
        }
        if let Err(e) = set(path, "user.sops_cleaner_expires", expiry_timestamp.as_bytes()) {
            eprintln!("⚠️  Failed to set expiry xattr on {}: {}", path.display(), e);
        }
    }

    /// Helper to check if a file is managed and get its expiry time
    fn is_file_managed_and_expired(path: &PathBuf) -> Option<bool> {
        // Check if file is managed by us
        let managed = get(path, "user.sops_cleaner_managed").ok()??;
        if managed != b"1" {
            return None; // Not managed by us
        }
        
        // Get expiry time
        let expiry_bytes = get(path, "user.sops_cleaner_expires").ok()??;
        let expiry_str = String::from_utf8(expiry_bytes).ok()?;
        let expiry_timestamp: i64 = expiry_str.parse().ok()?;
        
        // Check if expired
        let now = Utc::now().timestamp();
        Some(now > expiry_timestamp)
    }

    /// Helper to check if a file is managed by us
    fn is_file_managed(path: &PathBuf) -> Option<bool> {
        let managed = get(path, "user.sops_cleaner_managed").ok()??;
        Some(managed == b"1")
    }

    /// Cleans up any files in the secrets directory that might have been orphaned
    /// due to process restarts or other issues. This is a safety mechanism.
    /// 
    /// This method should be called periodically or on startup to ensure
    /// no temporary files are left behind.
    pub async fn cleanup_orphaned_files(secrets_dir: &PathBuf, _max_age_seconds: u64) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if !secrets_dir.exists() {
            return Ok(0);
        }

        let mut cleaned_count = 0;

        match std::fs::read_dir(secrets_dir) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => {
                            let path = entry.path();
                            
                            // Check if file is managed and expired using xattr metadata
                            if let Some(is_expired) = Self::is_file_managed_and_expired(&path) {
                                if is_expired {
                                    // File is managed by us and has expired, safe to delete
                                    if Self::try_delete_file(&path).await? {
                                        cleaned_count += 1;
                                        eprintln!("🧹 Cleaned up orphaned file: {}", path.display());
                                    }
                                }
                            }
                            // If not managed by us or not expired, skip silently
                        }
                        Err(e) => {
                            eprintln!("⚠️  Error reading directory entry: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!("Failed to read secrets directory: {}", e).into());
            }
        }

        if cleaned_count > 0 {
            eprintln!("🧹 Cleanup summary: {} orphaned files removed", cleaned_count);
        }

        Ok(cleaned_count)
    }

    pub async fn add_file(&self, path: PathBuf, expires_in: Duration) {
        if !path.is_absolute() {
            eprintln!("⚠️  Attempted to add relative path to cleanup queue: {}", path.display());
            return;
        }
        
        let expires_at = Instant::now() + expires_in;
        
        // Mark the file as managed by the file cleaner with expiry time
        Self::mark_file_managed(&path, expires_at);
        
        let mut queue = self.queue.lock().await;
        queue.push(ExpiringFile { path, expires_at, retries: 0 });
        drop(queue);
        self.notify.notify_one();
    }

    /// Gracefully shuts down the file cleanup manager and processes all remaining files.
    /// This should be called during server shutdown to ensure no files are left behind.
    #[allow(dead_code)]
    pub async fn shutdown(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("🔄 Shutting down file cleanup manager...");
        
        let mut queue = self.queue.lock().await;
        let mut processed_count = 0;
        
        // Process all remaining files in the queue
        while let Some(file) = queue.pop() {
            if let Ok(true) = Self::try_delete_file(&file.path).await {
                processed_count += 1;
                eprintln!("🧹 Cleaned up file during shutdown: {}", file.path.display());
            }
        }
        
        if processed_count > 0 {
            eprintln!("🧹 Shutdown cleanup summary: {} files processed", processed_count);
        }
        
        Ok(processed_count)
    }
} 