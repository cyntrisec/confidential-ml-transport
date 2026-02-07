pub mod channel;
pub mod handshake;
pub mod retry;

use std::time::Duration;

use crate::attestation::types::ExpectedMeasurements;
use crate::error::Error;

use self::retry::RetryPolicy;

/// Configuration for a secure session.
///
/// The cipher suite is always X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
/// Multi-suite negotiation may be added in a future version.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum payload size in bytes (default: 32 MiB).
    pub max_payload_size: u32,

    /// Maximum time allowed for the handshake to complete (default: 30s).
    pub handshake_timeout: Duration,

    /// Optional retry policy for connection attempts.
    pub retry_policy: Option<RetryPolicy>,

    /// Optional expected measurements to verify against the peer's attestation.
    pub expected_measurements: Option<ExpectedMeasurements>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_payload_size: crate::frame::MAX_PAYLOAD_SIZE,
            handshake_timeout: Duration::from_secs(30),
            retry_policy: None,
            expected_measurements: None,
        }
    }
}

impl SessionConfig {
    /// Create a builder for constructing a `SessionConfig`.
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder::default()
    }
}

/// Builder for [`SessionConfig`].
#[derive(Debug, Clone)]
pub struct SessionConfigBuilder {
    max_payload_size: u32,
    handshake_timeout: Duration,
    retry_policy: Option<RetryPolicy>,
    expected_measurements: Option<ExpectedMeasurements>,
}

impl Default for SessionConfigBuilder {
    fn default() -> Self {
        let defaults = SessionConfig::default();
        Self {
            max_payload_size: defaults.max_payload_size,
            handshake_timeout: defaults.handshake_timeout,
            retry_policy: None,
            expected_measurements: None,
        }
    }
}

impl SessionConfigBuilder {
    pub fn max_payload_size(mut self, size: u32) -> Self {
        self.max_payload_size = size;
        self
    }

    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    pub fn expected_measurements(mut self, measurements: ExpectedMeasurements) -> Self {
        self.expected_measurements = Some(measurements);
        self
    }

    /// Build the `SessionConfig`, validating that all values are sensible.
    pub fn build(self) -> Result<SessionConfig, Error> {
        if self.max_payload_size == 0 {
            return Err(Error::Session(crate::error::SessionError::HandshakeFailed(
                "max_payload_size must be > 0".into(),
            )));
        }
        if self.handshake_timeout.is_zero() {
            return Err(Error::Session(crate::error::SessionError::HandshakeFailed(
                "handshake_timeout must be > 0".into(),
            )));
        }
        Ok(SessionConfig {
            max_payload_size: self.max_payload_size,
            handshake_timeout: self.handshake_timeout,
            retry_policy: self.retry_policy,
            expected_measurements: self.expected_measurements,
        })
    }
}
