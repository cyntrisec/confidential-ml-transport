//! Attestation-bound encrypted tensor transport for confidential ML inference.
//!
//! This crate provides a secure channel built on X25519 + HKDF-SHA256 +
//! ChaCha20-Poly1305 with pluggable TEE attestation (Nitro, SEV-SNP, mock).
//! It includes binary tensor framing, transparent proxy helpers, and
//! transport backends for TCP and VSock.

/// TEE attestation providers and verifiers (mock, Nitro).
pub mod attestation;
/// Cryptographic primitives: key exchange, AEAD sealing, transcript hashing.
pub mod crypto;
/// Error types for every layer of the stack.
pub mod error;
/// Binary wire framing and tensor sub-protocol.
pub mod frame;
/// Secure session: handshake, encrypted channel, retry policy.
pub mod session;
/// Pluggable transport backends (TCP, VSock).
pub mod transport;

/// Transparent encryption/decryption proxies (client and server).
#[cfg(feature = "tcp")]
pub mod proxy;

// Re-export key types at crate root for convenience.
pub use error::{Error, Result};
pub use frame::tensor::{DType, OwnedTensor, TensorRef};
pub use frame::{Flags, Frame, FrameType};
pub use session::channel::{Message, SecureChannel};
pub use session::retry::RetryPolicy;
pub use session::{SessionConfig, SessionConfigBuilder};

pub use attestation::types::ExpectedMeasurements;
pub use attestation::{AttestationProvider, AttestationVerifier};

#[cfg(feature = "mock")]
pub use attestation::mock::{MockProvider, MockVerifier, MockVerifierWithMeasurements};

#[cfg(feature = "nitro")]
pub use attestation::nitro::{NitroProvider, NitroVerifier};

#[cfg(feature = "sev-snp")]
pub use attestation::sev::{SevSnpProvider, SevSnpVerifier};

#[cfg(feature = "tdx")]
pub use attestation::tdx::{TdxProvider, TdxVerifier};
