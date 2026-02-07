use std::collections::BTreeMap;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::types::{AttestationDocument, VerifiedAttestation};
use super::{AttestationProvider, AttestationVerifier};
use crate::error::AttestError;

/// Mock attestation provider for testing. Produces a simple document
/// containing the concatenation of user_data, nonce, and public_key.
///
/// # Security Warning
///
/// This provider performs **zero cryptographic verification** and must
/// never be used in production. Enable it only via `features = ["mock"]`
/// for development and testing.
pub struct MockProvider;

impl MockProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationProvider for MockProvider {
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        // Simple encoding: length-prefixed fields.
        let mut raw = Vec::new();

        // Marker for mock documents.
        raw.extend_from_slice(b"MOCK_ATT_V1\0");

        for field in [user_data, nonce, public_key] {
            match field {
                Some(data) => {
                    raw.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    raw.extend_from_slice(data);
                }
                None => {
                    raw.extend_from_slice(&0u32.to_le_bytes());
                }
            }
        }

        Ok(AttestationDocument::new(raw))
    }
}

/// Mock attestation verifier for testing. Accepts any document produced
/// by `MockProvider`.
pub struct MockVerifier;

impl MockVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationVerifier for MockVerifier {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        let raw = &doc.raw;

        if !raw.starts_with(b"MOCK_ATT_V1\0") {
            return Err(AttestError::VerificationFailed(
                "not a mock attestation document".to_string(),
            ));
        }

        let mut offset = 12; // skip marker

        let mut fields = Vec::new();
        for _ in 0..3 {
            if offset + 4 > raw.len() {
                return Err(AttestError::VerificationFailed(
                    "truncated mock document".to_string(),
                ));
            }
            let len = u32::from_le_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]) as usize;
            offset += 4;
            if len > 0 {
                if offset + len > raw.len() {
                    return Err(AttestError::VerificationFailed(
                        "truncated mock document".to_string(),
                    ));
                }
                fields.push(Some(raw[offset..offset + len].to_vec()));
                offset += len;
            } else {
                fields.push(None);
            }
        }

        let document_hash: [u8; 32] = Sha256::digest(&doc.raw).into();

        Ok(VerifiedAttestation {
            document_hash,
            user_data: fields[0].clone(),
            nonce: fields[1].clone(),
            public_key: fields[2].clone(),
            measurements: BTreeMap::new(),
        })
    }
}

/// Mock verifier that returns configurable measurement values.
///
/// Delegates basic parsing to [`MockVerifier`], then overrides the
/// `measurements` field with the configured values. This enables testing
/// measurement verification without a real TEE.
pub struct MockVerifierWithMeasurements {
    measurements: BTreeMap<usize, Vec<u8>>,
}

impl MockVerifierWithMeasurements {
    pub fn new(measurements: BTreeMap<usize, Vec<u8>>) -> Self {
        Self { measurements }
    }
}

#[async_trait]
impl AttestationVerifier for MockVerifierWithMeasurements {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        let mut result = MockVerifier.verify(doc).await?;
        result.measurements = self.measurements.clone();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_roundtrip() {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();

        let doc = provider
            .attest(Some(b"user-data"), Some(b"test-nonce"), Some(&[1u8; 32]))
            .await
            .unwrap();

        let verified = verifier.verify(&doc).await.unwrap();
        assert_eq!(verified.user_data.as_deref(), Some(b"user-data".as_ref()));
        assert_eq!(verified.nonce.as_deref(), Some(b"test-nonce".as_ref()));
        assert_eq!(verified.public_key.as_deref(), Some([1u8; 32].as_ref()));
    }

    #[tokio::test]
    async fn mock_empty_fields() {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();

        let doc = provider.attest(None, None, None).await.unwrap();
        let verified = verifier.verify(&doc).await.unwrap();
        assert!(verified.user_data.is_none());
        assert!(verified.nonce.is_none());
        assert!(verified.public_key.is_none());
    }

    #[tokio::test]
    async fn mock_rejects_invalid() {
        let verifier = MockVerifier::new();
        let doc = AttestationDocument::new(b"INVALID".to_vec());
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
    }
}
