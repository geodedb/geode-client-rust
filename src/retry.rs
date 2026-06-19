//! Retry policy and helper (port of Go retry.go).

use std::future::Future;

use tokio::time::{Duration, sleep};

use crate::error::Result;

/// Retry policy: exponential backoff with a maximum number of attempts.
/// Defaults match the Go reference driver: 3 attempts, 1s initial backoff,
/// 30s max backoff, multiplier 2.0. No jitter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryPolicy {
    /// Maximum number of attempts, including the first call. Values < 1 are
    /// treated as 1.
    pub max_attempts: u32,
    /// Backoff before the first retry.
    pub initial_backoff: Duration,
    /// Maximum backoff (clamp ceiling).
    pub max_backoff: Duration,
    /// Exponential multiplier per attempt.
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// Compute the backoff for a 1-indexed attempt:
    /// `initial_backoff * multiplier^(attempt-1)`, clamped to `max_backoff`.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let attempt = attempt.max(1);
        let factor = self.multiplier.powi((attempt - 1) as i32);
        let nanos = self.initial_backoff.as_nanos() as f64 * factor;
        if nanos > self.max_backoff.as_nanos() as f64 {
            return self.max_backoff;
        }
        // nanos is finite and within max_backoff (<= u64 nanos range in practice).
        Duration::from_nanos(nanos as u64)
    }
}

/// Run `op` with retries according to `policy`. Retries only errors for which
/// [`crate::error::Error::is_retryable`] is true. Returns the last error after
/// exhausting attempts, or immediately on success / non-retryable error.
pub async fn retry<F, Fut, T>(policy: RetryPolicy, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let max_attempts = policy.max_attempts.max(1);
    let mut last_err = None;

    for attempt in 1..=max_attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !e.is_retryable() {
                    return Err(e);
                }
                if attempt == max_attempts {
                    last_err = Some(e);
                    break;
                }
                last_err = Some(e);
                sleep(policy.backoff(attempt)).await;
            }
        }
    }

    Err(last_err.expect("retry loop always records an error before breaking"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, Result};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_default_policy() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.initial_backoff, Duration::from_secs(1));
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.multiplier, 2.0);
    }

    #[test]
    fn test_backoff_exponential_and_clamped() {
        let p = RetryPolicy::default();
        assert_eq!(p.backoff(1), Duration::from_secs(1));
        assert_eq!(p.backoff(2), Duration::from_secs(2));
        assert_eq!(p.backoff(3), Duration::from_secs(4));
        // clamp test
        let p2 = RetryPolicy {
            max_attempts: 5,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5),
            multiplier: 10.0,
        };
        assert_eq!(p2.backoff(3), Duration::from_secs(5)); // 1*100 clamped to 5
    }

    fn fast_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            multiplier: 2.0,
        }
    }

    #[tokio::test]
    async fn test_retry_succeeds_first_attempt() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            }
        })
        .await;
        assert_eq!(r.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_retries_until_success() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(Error::Connection("transient".into()))
                } else {
                    Ok(7)
                }
            }
        })
        .await;
        assert_eq!(r.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_stops_on_non_retryable() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(Error::Query {
                    code: "42000".into(),
                    message: "syntax".into(),
                })
            }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_exhausts_attempts() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(Error::Timeout)
            }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
