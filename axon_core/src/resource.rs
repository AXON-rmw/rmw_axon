//! Resource management utilities.
//!
//! Provides a leaky bucket rate limiter for controlling outbound bandwidth.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Token-based rate limiter using a leaky bucket algorithm.
///
/// Tokens refill at `max_tokens` per second. Sends are rejected when
/// the requested byte count exceeds available tokens.
pub struct LeakyBucket {
    max_tokens: usize,
    tokens: AtomicU64,
    last_refill: AtomicU64,
    start: Arc<Instant>,
}

impl LeakyBucket {
    /// Create a new bucket with the given maximum token count (tokens/sec refill rate).
    pub fn new(max_tokens: usize) -> Self {
        let start = Arc::new(Instant::now());
        Self {
            max_tokens,
            tokens: AtomicU64::new(max_tokens as u64),
            last_refill: AtomicU64::new(0),
            start,
        }
    }

    /// Current elapsed time in milliseconds since creation.
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Attempt to send `bytes` tokens, refilling based on elapsed time.
    ///
    /// Returns `true` if enough tokens are available, `false` otherwise.
    pub fn try_send(&self, bytes: usize) -> bool {
        loop {
            let last = self.last_refill.load(Ordering::Relaxed);
            let now_ms = self.now_ms();
            let elapsed = now_ms.saturating_sub(last);
            let added = if elapsed > 0 {
                (elapsed as usize).saturating_mul(self.max_tokens) / 1000
            } else {
                0
            };

            let cur_tokens = self.tokens.load(Ordering::Acquire);
            let refilled = (cur_tokens as usize)
                .saturating_add(added)
                .min(self.max_tokens);

            if refilled < bytes {
                return false;
            }

            match self.tokens.compare_exchange(
                cur_tokens,
                (refilled - bytes) as u64,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let _ = self.last_refill.compare_exchange(
                        last,
                        now_ms,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                    return true;
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_leaky_bucket_allows_under_budget() {
        let bucket = LeakyBucket::new(1000);
        assert!(bucket.try_send(500));
        assert!(bucket.try_send(400));
        assert!(bucket.try_send(100));
    }

    #[test]
    fn test_leaky_bucket_drops_over_budget() {
        let bucket = LeakyBucket::new(1000);
        assert!(bucket.try_send(600));
        assert!(bucket.try_send(400));
        assert!(!bucket.try_send(1));
    }

    #[test]
    fn test_leaky_bucket_refills_over_time() {
        let bucket = LeakyBucket::new(1000);
        assert!(bucket.try_send(1000));
        assert!(!bucket.try_send(1));

        thread::sleep(Duration::from_millis(1100));
        assert!(bucket.try_send(500));
    }

    #[test]
    fn test_leaky_bucket_does_not_exceed_max() {
        let bucket = LeakyBucket::new(100);
        thread::sleep(Duration::from_millis(2000));
        assert!(!bucket.try_send(101));
        assert!(bucket.try_send(100));
    }
}
