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
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_seconds),
        }
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