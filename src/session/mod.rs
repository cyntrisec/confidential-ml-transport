pub mod channel;
pub mod handshake;

use std::time::Duration;

use crate::crypto::CipherSuite;

/// Configuration for a secure session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// The cipher suite to use.
    pub cipher_suite: CipherSuite,

    /// Maximum payload size in bytes (default: 32 MiB).
    pub max_payload_size: u32,

    /// Maximum time allowed for the handshake to complete (default: 30s).
    pub handshake_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuite::X25519ChaChaPoly,
            max_payload_size: crate::frame::MAX_PAYLOAD_SIZE,
            handshake_timeout: Duration::from_secs(30),
        }
    }
}
