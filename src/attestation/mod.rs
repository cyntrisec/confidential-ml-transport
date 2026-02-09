pub mod types;

#[cfg(feature = "mock")]
pub mod mock;

#[cfg(feature = "nitro")]
pub mod nitro;

#[cfg(feature = "sev-snp")]
pub mod sev;

#[cfg(feature = "tdx")]
pub mod tdx;

use async_trait::async_trait;

use crate::error::AttestError;
use types::{AttestationDocument, VerifiedAttestation};

/// Provider that generates attestation documents (runs inside a TEE).
#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Generate an attestation document, optionally binding user data, a nonce,
    /// and a public key into the attestation.
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError>;
}

/// Verifier that validates attestation documents (runs on the client side).
#[async_trait]
pub trait AttestationVerifier: Send + Sync {
    /// Verify an attestation document and return the verified attestation
    /// containing the extracted claims.
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError>;
}
