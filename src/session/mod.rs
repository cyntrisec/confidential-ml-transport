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

    /// When `true`, the session will refuse to complete the handshake unless
    /// `expected_measurements` is `Some`. This prevents accidental deployment
    /// without measurement pinning.
    pub require_measurements: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_payload_size: crate::frame::MAX_PAYLOAD_SIZE,
            handshake_timeout: Duration::from_secs(30),
            retry_policy: None,
            expected_measurements: None,
            require_measurements: false,
        }
    }
}

impl SessionConfig {
    /// Validate that measurement requirements are satisfied.
    ///
    /// Returns an error if `require_measurements` is `true` but
    /// `expected_measurements` is `None`.
    pub fn validate_measurements(&self) -> Result<(), Error> {
        if self.require_measurements && self.expected_measurements.is_none() {
            return Err(Error::Session(crate::error::SessionError::HandshakeFailed(
                "require_measurements is set but expected_measurements is None".into(),
            )));
        }
        Ok(())
    }

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
    require_measurements: bool,
}

impl Default for SessionConfigBuilder {
    fn default() -> Self {
        let defaults = SessionConfig::default();
        Self {
            max_payload_size: defaults.max_payload_size,
            handshake_timeout: defaults.handshake_timeout,
            retry_policy: None,
            expected_measurements: None,
            require_measurements: false,
        }
    }
}

impl SessionConfigBuilder {
    /// Set the maximum frame payload size in bytes (default: 32 MiB).
    pub fn max_payload_size(mut self, size: u32) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Set the handshake timeout duration (default: 30s).
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set the connection retry policy.
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Set expected PCR/measurement values to verify against the peer's attestation.
    pub fn expected_measurements(mut self, measurements: ExpectedMeasurements) -> Self {
        self.expected_measurements = Some(measurements);
        self
    }

    /// Require that `expected_measurements` is set before the handshake begins.
    ///
    /// When enabled, `connect_with_attestation` and `accept_with_attestation`
    /// will return an error if `expected_measurements` is `None`.
    pub fn require_measurements(mut self) -> Self {
        self.require_measurements = true;
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
            require_measurements: self.require_measurements,
        })
    }
}
