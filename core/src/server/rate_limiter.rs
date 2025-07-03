use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::server::errors::ServerError;

/// Rate limiter for preventing DoS attacks
#[derive(Debug)]
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with optional parameters
    /// 
    /// # Arguments
    /// * `max_requests` - Maximum number of requests allowed in the time window (default: 20)
    /// * `window_seconds` - Time window in seconds (default: 1)
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// // Use defaults (20 requests per second)
    /// let rate_limiter = RateLimiter::new(None, None);
    /// 
    /// // Custom rate limit (10 requests per 5 seconds)
    /// let rate_limiter = RateLimiter::new(Some(10), Some(5));
    /// ```
    pub fn new(max_requests: Option<usize>, window_seconds: Option<u64>) -> Self {
        let max_requests = max_requests.unwrap_or(20);
        let window_seconds = window_seconds.unwrap_or(1);
        
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_seconds),
        }
    }

    /// Create a new rate limiter with explicit parameters (backward compatibility)
    pub fn with_limits(max_requests: usize, window_seconds: u64) -> Self {
        Self::new(Some(max_requests), Some(window_seconds))
    }

    pub async fn check_rate_limit(&self, ip: IpAddr) -> Result<(), ServerError> {
        let now = Instant::now();
        let mut requests = self.requests.write().await;

        // Clean old requests outside the window
        if let Some(timestamps) = requests.get_mut(&ip) {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);

            if timestamps.len() >= self.max_requests {
                return Err(ServerError::RateLimitExceeded);
            }

            timestamps.push(now);
        } else {
            requests.insert(ip, vec![now]);
        }

        Ok(())
    }
} 