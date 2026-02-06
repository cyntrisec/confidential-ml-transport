use std::time::Duration;

use rand::Rng;

/// Policy for retrying failed connection attempts with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (excludes the initial attempt).
    pub max_retries: u32,
    /// Initial delay before the first retry.
    pub initial_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Multiplier applied to the delay after each attempt.
    pub backoff_multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// A policy that performs no retries (single attempt only).
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Compute the delay for the given attempt number (0-indexed).
    ///
    /// Applies exponential backoff with random jitter in [0.5x, 1.0x] of the
    /// computed delay, capped at `max_delay`.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.initial_delay.as_secs_f64()
            * self.backoff_multiplier.powi(attempt as i32);
        let capped = base.min(self.max_delay.as_secs_f64());
        let jitter = rand::thread_rng().gen_range(0.5..=1.0);
        Duration::from_secs_f64(capped * jitter)
    }
}

/// Execute a closure with retry logic according to the given policy.
///
/// Calls `f` up to `policy.max_retries + 1` times. On failure, sleeps with
/// exponential backoff before the next attempt. Returns the first success or
/// the last error.
pub async fn with_retry<F, Fut, T, E>(
    policy: &RetryPolicy,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_err = None;

    for attempt in 0..=policy.max_retries {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if attempt < policy.max_retries {
                    let delay = policy.delay_for_attempt(attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = policy.max_retries + 1,
                        delay_ms = delay.as_millis() as u64,
                        error = %e,
                        "connection attempt failed, retrying"
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    tracing::warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "final connection attempt failed"
                    );
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap())
}
