use log::{debug, error, info, trace, warn};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::sleep;

/// Error types for file locking operations
#[derive(Debug, Error)]
pub enum FileLockError {
    #[error("Failed to acquire lock: {0}")]
    LockAcquisitionFailed(String),
    #[error("Lock timeout after {0:?}")]
    LockTimeout(Duration),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Invalid lock file path: {0}")]
    InvalidPath(String),
}

/// Result type for file locking operations
pub type FileLockResult<T> = Result<T, FileLockError>;

/// PID-based file lock for cross-process and cross-container compatibility.
/// Each read lock creates a .read.lock.<pid> file.
/// Write lock creates a .write.lock file.
/// Write lock is exclusive if no read or write locks exist.
/// Read lock is allowed if no write lock exists.
///
/// # Note
/// This approach cannot be fully unit tested in a single process. 
pub struct FileLock {
    lock_file: Option<File>,
    lock_path: String,
    is_write_lock: bool,
}

impl FileLock {
    /// Try to acquire a read lock on the specified file
    pub async fn acquire_read_lock(
        file_path: &PathBuf,
        timeout: Duration,
    ) -> FileLockResult<Self> {
        info!("Attempting to acquire read lock for file: {}", canonical_display(file_path));
        debug!("Read lock timeout set to: {:?}", timeout);
        Self::acquire_lock(file_path, false, timeout).await
    }

    /// Try to acquire a write lock on the specified file
    pub async fn acquire_write_lock(
        file_path: &PathBuf,
        timeout: Duration,
    ) -> FileLockResult<Self> {
        info!("FileLock: Attempting to acquire write lock for file: {}", canonical_display(file_path));
        debug!("FileLock: Write lock timeout set to: {:?}", timeout);
        Self::acquire_lock(file_path, true, timeout).await
    }

    /// Internal method to acquire either a read or write lock
    async fn acquire_lock(
        file_path: &PathBuf,
        is_write_lock: bool,
        timeout: Duration,
    ) -> FileLockResult<Self> {
        debug!("FileLock: Starting lock acquisition - type: {}, file: {}", 
                 if is_write_lock { "write" } else { "read" }, canonical_display(file_path));

        let file_dir = Path::new(file_path).parent().unwrap_or_else(|| Path::new("."));
        let pid = std::process::id();
        let start_time = Instant::now();
        let write_lock_path = Self::get_write_lock_path(file_path);
        let read_lock_path = Self::get_read_lock_path(file_path, pid);

        trace!("FileLock: Lock paths - write: {}, read: {}", write_lock_path, read_lock_path);
        trace!("FileLock: Process ID: {}", pid);

        let mut attempt_count = 0;
        loop {
            attempt_count += 1;
            let elapsed = start_time.elapsed();

            if elapsed > timeout {
                warn!("FileLock: Lock acquisition timed out after {:?} (attempts: {})", elapsed, attempt_count);
                return Err(FileLockError::LockTimeout(timeout));
            }

            debug!("FileLock: Lock attempt #{} (elapsed: {:?})", attempt_count, elapsed);

            // Check for write lock
            if Path::new(&write_lock_path).exists() {
                debug!("FileLock: Write lock exists, waiting 100ms before retry");
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            if is_write_lock {
                debug!("FileLock: Attempting write lock acquisition");
                // For write lock, check for any read locks
                let pattern = format!("{}.read.lock.", Path::new(file_path).file_name().unwrap().to_string_lossy());
                trace!("FileLock: Checking for read locks with pattern: {}", pattern);

                let has_read_locks = match std::fs::read_dir(file_dir) {
                    Ok(entries) => {
                        let count = entries
                            .filter_map(Result::ok)
                            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&pattern))
                            .count();
                        debug!("FileLock: Found {} existing read locks", count);
                        count > 0
                    }
                    Err(e) => {
                        warn!("FileLock: Error reading directory: {:?}", e);
                        return Err(FileLockError::IoError(e));
                    }
                };

                if has_read_locks {
                    debug!("FileLock: Read locks exist, waiting 100ms before retry");
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }

                debug!("FileLock: No read locks found, attempting to create write lock");
                // Try to create the write lock file
                match Self::try_create_lock_file(&write_lock_path) {
                    Ok(lock_file) => {
                        info!("FileLock: Write lock acquired successfully: {}", write_lock_path);
                        return Ok(FileLock {
                            lock_file: Some(lock_file),
                            lock_path: write_lock_path,
                            is_write_lock: true,
                        });
                    }
                    Err(FileLockError::LockAcquisitionFailed(_)) => {
                        debug!("FileLock: Write lock acquisition failed, retrying in 100ms");
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => {
                        warn!("FileLock: Write lock acquisition error: {:?}", e);
                        return Err(e);
                    }
                }
            } else {
                debug!("FileLock: Attempting read lock acquisition");
                // For read lock, create a unique .read.lock.<pid> file
                // Only allowed if no write lock exists (already checked above)
                match Self::try_create_lock_file(&read_lock_path) {
                    Ok(lock_file) => {
                        info!("FileLock: Read lock acquired successfully: {}", read_lock_path);
                        return Ok(FileLock {
                            lock_file: Some(lock_file),
                            lock_path: read_lock_path,
                            is_write_lock: false,
                        });
                    }
                    Err(FileLockError::LockAcquisitionFailed(_)) => {
                        debug!("FileLock: Read lock acquisition failed, retrying in 100ms");
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => {
                        warn!("FileLock: Read lock acquisition error: {:?}", e);
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Get the write lock file path
    fn get_write_lock_path(file_path: &PathBuf) -> String {
        Self::get_lock_path(file_path, "write.lock", None)
    }

    /// Get the read lock file path for this PID
    fn get_read_lock_path(file_path: &PathBuf, pid: u32) -> String {
        Self::get_lock_path(file_path, "read.lock", Some(pid))
    }

    /// Common helper for generating lock file paths
    fn get_lock_path(file_path: &PathBuf, suffix: &str, pid: Option<u32>) -> String {
        let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
        let filename = file_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("unknown"));

        let lock_name = match pid {
            Some(pid) => format!("{}.{}.{}", filename.to_string_lossy(), suffix, pid),
            None => format!("{}.{}", filename.to_string_lossy(), suffix),
        };

        parent.join(lock_name).to_string_lossy().to_string()
    }

    /// Try to create a lock file
    fn try_create_lock_file(lock_path: &str) -> FileLockResult<File> {
        info!("FileLock: Attempting to create lock file: {}", lock_path);

        // Try to create the lock file
        let lock_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(lock_path)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    debug!("FileLock: Lock file already exists: {}", lock_path);
                    FileLockError::LockAcquisitionFailed("Lock file already exists".to_string())
                } else {
                    warn!("FileLock: Error creating lock file: {:?}", e);
                    FileLockError::IoError(e)
                }
            })?;

        debug!("FileLock: Successfully created lock file: {}", lock_path);

        // Write process information to the lock file
        let pid = std::process::id();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let lock_type = if lock_path.ends_with("write.lock") { "write" } else { "read" };
        let lock_info = format!("pid={}, type={}, timestamp={}\n", pid, lock_type, timestamp);

        trace!("FileLock: Writing lock info to file: {}", lock_info.trim());

        // Clone the file handle for writing
        let mut file_for_writing = lock_file.try_clone().map_err(FileLockError::IoError)?;

        // Write the lock info
        file_for_writing.write_all(lock_info.as_bytes()).map_err(|e| {
            warn!("FileLock: Error writing lock info: {:?}", e);
            FileLockError::IoError(e)
        })?;

        trace!("FileLock: Successfully wrote lock info to file");
        Ok(lock_file)
    }

    /// Get the lock file path
    pub fn lock_path(&self) -> &str {
        &self.lock_path
    }

    /// Check if this is a write lock
    pub fn is_write_lock(&self) -> bool {
        self.is_write_lock
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        info!("FileLock: Dropping lock: {} (type: {})", 
                 self.lock_path, if self.is_write_lock { "write" } else { "read" });

        // Remove the lock file when the lock is dropped
        match std::fs::remove_file(&self.lock_path) {
            Ok(_) => {
                debug!("FileLock: Successfully removed lock file: {}", self.lock_path);
            }
            Err(e) => {
                warn!("FileLock: Error removing lock file {}: {:?}", self.lock_path, e);
            }
        }
    }
}

/// RAII wrapper for read locks
pub struct ReadLock(FileLock);

impl ReadLock {
    /// Acquire a read lock
    pub async fn acquire(file_path: &PathBuf, timeout: Duration) -> FileLockResult<Self> {
        info!("ReadLock: Acquiring read lock for file: {}", canonical_display(file_path));
        FileLock::acquire_read_lock(file_path, timeout)
            .await
            .map(ReadLock)
    }
}

impl Drop for ReadLock {
    fn drop(&mut self) {
        info!("ReadLock: Dropping read lock");
        // FileLock's Drop implementation will handle cleanup automatically
    }
}

/// RAII wrapper for write locks
pub struct WriteLock(FileLock);

impl WriteLock {
    /// Acquire a write lock
    pub async fn acquire(file_path: &PathBuf, timeout: Duration) -> FileLockResult<Self> {
        info!("WriteLock: Acquiring write lock for file: {}", canonical_display(file_path));
        FileLock::acquire_write_lock(file_path, timeout)
            .await
            .map(WriteLock)
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        info!("WriteLock: Dropping write lock");
        // FileLock's Drop implementation will handle cleanup automatically
    }
}

// Helper for canonicalized display
fn canonical_display(path: &std::path::PathBuf) -> String {
    path.canonicalize().map(|p| p.display().to_string()).unwrap_or_else(|_| path.display().to_string())
}
