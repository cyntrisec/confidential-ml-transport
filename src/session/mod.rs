pub mod channel;
pub mod handshake;
pub mod retry;

use std::time::Duration;

use crate::attestation::types::ExpectedMeasurements;
use crate::crypto::CipherSuite;
use crate::error::Error;

use self::retry::RetryPolicy;

/// Configuration for a secure session.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// The cipher suite to use.
    pub cipher_suite: CipherSuite,

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
            cipher_suite: CipherSuite::X25519ChaChaPoly,
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
    cipher_suite: CipherSuite,
    max_payload_size: u32,
    handshake_timeout: Duration,
    retry_policy: Option<RetryPolicy>,
    expected_measurements: Option<ExpectedMeasurements>,
}

impl Default for SessionConfigBuilder {
    fn default() -> Self {
        let defaults = SessionConfig::default();
        Self {
            cipher_suite: defaults.cipher_suite,
            max_payload_size: defaults.max_payload_size,
            handshake_timeout: defaults.handshake_timeout,
            retry_policy: None,
            expected_measurements: None,
        }
    }
}

impl SessionConfigBuilder {
    pub fn cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

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
            return Err(Error::Session(
                crate::error::SessionError::HandshakeFailed(
                    "max_payload_size must be > 0".into(),
                ),
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(Error::Session(
                crate::error::SessionError::HandshakeFailed(
                    "handshake_timeout must be > 0".into(),
                ),
            ));
        }
        Ok(SessionConfig {
            cipher_suite: self.cipher_suite,
            max_payload_size: self.max_payload_size,
            handshake_timeout: self.handshake_timeout,
            retry_policy: self.retry_policy,
            expected_measurements: self.expected_measurements,
        })
    }
}
