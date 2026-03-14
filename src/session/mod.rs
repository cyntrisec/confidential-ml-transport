pub mod channel;
pub mod handshake;
pub mod retry;

use std::time::Duration;

use crate::attestation::types::ExpectedMeasurements;
use crate::error::Error;

use self::retry::RetryPolicy;

/// Security profile controlling whether empty measurements are allowed.
///
/// # Security implications
///
/// In `Production` mode (the default), the session will refuse to complete the
/// handshake unless `expected_measurements` is populated. This prevents
/// accidental deployment without measurement pinning — a configuration error
/// that would silently skip attestation verification.
///
/// In `Development` mode, empty measurements are allowed with a warning log.
/// This is intended **only** for local testing, CI, and development environments
/// where real TEE attestation is not available.
///
/// # Migration guide
///
/// If your code previously relied on `SessionConfig::default()` with no
/// measurements, you now need to explicitly opt into `Development` mode:
///
/// ```rust
/// use confidential_ml_transport::session::{SessionConfig, SecurityProfile};
/// let config = SessionConfig::builder()
///     .security_profile(SecurityProfile::Development)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Production mode (default): requires non-empty `expected_measurements`.
    /// Returns an error if measurements are missing.
    Production,
    /// Development mode: allows empty measurements with a warning.
    /// Intended for local testing and CI only.
    Development,
}

/// Configuration for a secure session.
///
/// The cipher suite is always X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
/// Multi-suite negotiation may be added in a future version.
///
/// # Security profile
///
/// The default `SecurityProfile` is `Production`, which requires
/// `expected_measurements` to be set. Use `SecurityProfile::Development`
/// for test/dev environments where TEE attestation is unavailable.
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
    ///
    /// **Deprecated:** Prefer using `security_profile` instead. This field is
    /// retained for backward compatibility. When `security_profile` is
    /// `Production`, this is implicitly `true`. Setting this to `true`
    /// explicitly is redundant but harmless.
    pub require_measurements: bool,

    /// Controls whether empty measurements are treated as an error or a warning.
    ///
    /// - `Production` (default): `expected_measurements` must be `Some` or
    ///   the handshake is rejected.
    /// - `Development`: empty measurements emit a warning but proceed.
    pub security_profile: SecurityProfile,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_payload_size: crate::frame::MAX_PAYLOAD_SIZE,
            handshake_timeout: Duration::from_secs(30),
            retry_policy: None,
            expected_measurements: None,
            require_measurements: true,
            security_profile: SecurityProfile::Production,
        }
    }
}

impl SessionConfig {
    /// Validate that measurement requirements are satisfied.
    ///
    /// In `Production` mode, returns an error if `expected_measurements` is
    /// `None`. In `Development` mode, logs a warning but allows the handshake
    /// to proceed.
    ///
    /// The legacy `require_measurements` field is also checked: if it is `true`
    /// and `expected_measurements` is `None`, an error is returned regardless
    /// of security profile.
    pub fn validate_measurements(&self) -> Result<(), Error> {
        let measurements_missing = self.expected_measurements.is_none();

        if !measurements_missing {
            return Ok(());
        }

        // Legacy field: always enforced when explicitly set.
        if self.require_measurements && self.security_profile == SecurityProfile::Development {
            // In Development mode, require_measurements being true means the
            // caller explicitly opted in — respect it.
            return Err(Error::Session(crate::error::SessionError::HandshakeFailed(
                "require_measurements is set but expected_measurements is None".into(),
            )));
        }

        match self.security_profile {
            SecurityProfile::Production => {
                Err(Error::Session(crate::error::SessionError::HandshakeFailed(
                    "production security profile requires expected_measurements to be set; \
                     use SecurityProfile::Development for test/dev environments"
                        .into(),
                )))
            }
            SecurityProfile::Development => {
                tracing::warn!(
                    "expected_measurements is None in Development security profile — \
                     attestation will not verify enclave identity. \
                     Do NOT use Development profile in production."
                );
                Ok(())
            }
        }
    }

    /// Create a builder for constructing a `SessionConfig`.
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder::default()
    }

    /// Create a `SessionConfig` suitable for development and testing.
    ///
    /// This sets the security profile to `Development`, allowing empty
    /// measurements. All other fields use their defaults.
    ///
    /// # Security warning
    ///
    /// Do **not** use this in production. It disables measurement enforcement.
    pub fn development() -> Self {
        Self {
            security_profile: SecurityProfile::Development,
            require_measurements: false,
            ..Self::default()
        }
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
    security_profile: SecurityProfile,
}

impl Default for SessionConfigBuilder {
    fn default() -> Self {
        let defaults = SessionConfig::default();
        Self {
            max_payload_size: defaults.max_payload_size,
            handshake_timeout: defaults.handshake_timeout,
            retry_policy: None,
            expected_measurements: None,
            require_measurements: defaults.require_measurements,
            security_profile: defaults.security_profile,
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
    ///
    /// **Note:** In `Production` profile this is already the default behavior.
    /// This method is retained for backward compatibility.
    pub fn require_measurements(mut self) -> Self {
        self.require_measurements = true;
        self
    }

    /// Set the security profile.
    ///
    /// - `Production` (default): requires `expected_measurements` to be set.
    /// - `Development`: allows empty measurements with a warning.
    pub fn security_profile(mut self, profile: SecurityProfile) -> Self {
        self.security_profile = profile;
        // Sync require_measurements with profile for backward compat.
        match profile {
            SecurityProfile::Production => self.require_measurements = true,
            SecurityProfile::Development => self.require_measurements = false,
        }
        self
    }

    /// Convenience: set `Development` security profile.
    ///
    /// Equivalent to `.security_profile(SecurityProfile::Development)`.
    ///
    /// # Security warning
    ///
    /// Do **not** use this in production. It disables measurement enforcement.
    pub fn allow_empty_measurements(self) -> Self {
        self.security_profile(SecurityProfile::Development)
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
            security_profile: self.security_profile,
        })
    }
}
