//! Retry policy with exponential backoff for transient errors.
//!
//! Mirrors the Go reference client's `RetryPolicy`/`Retry`: a closure is
//! re-invoked up to [`RetryPolicy::max_attempts`] times, but only when the
//! returned error is [`Error::is_retryable`]. Non-retryable errors are
//! returned immediately.

use std::time::Duration;

use crate::error::{Error, Result};

/// Default maximum number of attempts (including the initial call).
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// Default delay before the first retry.
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Default upper bound on the backoff duration.
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Default exponential backoff multiplier.
const DEFAULT_MULTIPLIER: f64 = 2.0;

/// Configures retry behavior for transient (retryable) errors.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryPolicy {
    /// Maximum number of attempts, including the initial call. Values less
    /// than 1 are treated as 1.
    pub max_attempts: u32,
    /// Delay before the first retry.
    pub initial_backoff: Duration,
    /// Maximum backoff duration; the exponential backoff is clamped to this.
    pub max_backoff: Duration,
    /// Exponential backoff multiplier applied on each retry.
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    /// Returns a policy with sensible defaults: 3 max attempts, 1s initial
    /// backoff, 30s max backoff, and a 2.0 multiplier.
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
            multiplier: DEFAULT_MULTIPLIER,
        }
    }
}

impl RetryPolicy {
    /// Calculate the backoff duration for the given 1-indexed attempt,
    /// clamped to [`RetryPolicy::max_backoff`].
    fn backoff(&self, attempt: u32) -> Duration {
        let attempt = attempt.max(1);
        // initial_backoff * multiplier^(attempt-1)
        let factor = self.multiplier.powi((attempt - 1) as i32);
        let nanos = self.initial_backoff.as_secs_f64() * factor;
        let max_secs = self.max_backoff.as_secs_f64();
        if !nanos.is_finite() || nanos >= max_secs {
            return self.max_backoff;
        }
        Duration::from_secs_f64(nanos)
    }
}

/// Execute `f` up to `policy.max_attempts` times, retrying only when the
/// returned error is [`Error::is_retryable`].
///
/// Non-retryable errors (e.g. authentication, validation, syntax) are
/// returned immediately without further attempts. Between attempts the
/// future sleeps for an exponentially increasing backoff capped at
/// [`RetryPolicy::max_backoff`].
///
/// # Example
///
/// ```no_run
/// use geode_client::{retry, RetryPolicy, Error};
///
/// # async fn example() -> geode_client::Result<()> {
/// let result = retry(RetryPolicy::default(), || async {
///     // ... perform a fallible operation ...
///     Ok::<i32, Error>(42)
/// })
/// .await?;
/// assert_eq!(result, 42);
/// # Ok(())
/// # }
/// ```
pub async fn retry<F, Fut, T>(policy: RetryPolicy, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let max_attempts = policy.max_attempts.max(1);
    let mut last_err: Option<Error> = None;

    for attempt in 1..=max_attempts {
        match f().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                // Only retry errors that are explicitly retryable.
                if !err.is_retryable() {
                    return Err(err);
                }
                last_err = Some(err);
                // No more attempts remaining.
                if attempt == max_attempts {
                    break;
                }
                let delay = policy.backoff(attempt);
                tokio::time::sleep(delay).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| Error::Other("retry: no attempts made".to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn fast_policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            multiplier: 2.0,
        }
    }

    #[tokio::test]
    async fn test_succeeds_first_try() {
        let calls = Cell::new(0);
        let result: Result<i32> = retry(fast_policy(3), || {
            calls.set(calls.get() + 1);
            async { Ok(7) }
        })
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn test_retries_then_succeeds() {
        let calls = Cell::new(0);
        let result: Result<i32> = retry(fast_policy(3), || {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n < 3 {
                    // Retryable error (connection).
                    Err(Error::connection("transient"))
                } else {
                    Ok(99)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 99);
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn test_gives_up_after_max_attempts() {
        let calls = Cell::new(0);
        let result: Result<i32> = retry(fast_policy(3), || {
            calls.set(calls.get() + 1);
            async { Err(Error::timeout()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 3, "should attempt exactly max_attempts times");
    }

    #[tokio::test]
    async fn test_does_not_retry_non_retryable_auth() {
        let calls = Cell::new(0);
        let result: Result<i32> = retry(fast_policy(5), || {
            calls.set(calls.get() + 1);
            async { Err(Error::auth("bad credentials")) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 1, "non-retryable error must not be retried");
    }

    #[tokio::test]
    async fn test_does_not_retry_non_retryable_validation() {
        let calls = Cell::new(0);
        let result: Result<i32> = retry(fast_policy(5), || {
            calls.set(calls.get() + 1);
            async { Err(Error::validation("bad input")) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn test_max_attempts_zero_treated_as_one() {
        let calls = Cell::new(0);
        let result: Result<i32> = retry(fast_policy(0), || {
            calls.set(calls.get() + 1);
            async { Err(Error::connection("transient")) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn test_default_policy_values() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.initial_backoff, Duration::from_secs(1));
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.multiplier, 2.0);
    }

    #[test]
    fn test_backoff_exponential_and_clamped() {
        let p = RetryPolicy {
            max_attempts: 10,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(10),
            multiplier: 2.0,
        };
        assert_eq!(p.backoff(1), Duration::from_secs(1)); // 1 * 2^0
        assert_eq!(p.backoff(2), Duration::from_secs(2)); // 1 * 2^1
        assert_eq!(p.backoff(3), Duration::from_secs(4)); // 1 * 2^2
        assert_eq!(p.backoff(4), Duration::from_secs(8)); // 1 * 2^3
        // 1 * 2^4 = 16 > 10, clamped.
        assert_eq!(p.backoff(5), Duration::from_secs(10));
        assert_eq!(p.backoff(100), Duration::from_secs(10));
    }
}
