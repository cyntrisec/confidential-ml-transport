use std::collections::BTreeMap;

use crate::error::AttestError;

/// Raw attestation document bytes (opaque to the transport layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationDocument {
    /// Raw document bytes (COSE_Sign1 for Nitro, report for SEV-SNP, etc.).
    pub raw: Vec<u8>,
}

impl AttestationDocument {
    pub fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }
}

/// Expected measurement values to verify against an attestation document.
///
/// Maps measurement register indices to their expected byte values.
/// Only the indices present in this map are checked; other registers are ignored.
#[derive(Debug, Clone)]
pub struct ExpectedMeasurements {
    pub values: BTreeMap<usize, Vec<u8>>,
}

impl ExpectedMeasurements {
    pub fn new(values: BTreeMap<usize, Vec<u8>>) -> Self {
        Self { values }
    }

    /// Verify that all expected measurements match the actual values.
    pub fn verify(&self, actual: &[Vec<u8>]) -> Result<(), AttestError> {
        for (&idx, expected) in &self.values {
            match actual.get(idx) {
                Some(actual_val) => {
                    if actual_val != expected {
                        return Err(AttestError::VerificationFailed(format!(
                            "measurement[{idx}] mismatch: expected {}, got {}",
                            hex::encode(expected),
                            hex::encode(actual_val),
                        )));
                    }
                }
                None => {
                    return Err(AttestError::MissingField(format!("measurement[{idx}]")));
                }
            }
        }
        Ok(())
    }
}

/// The result of a successful attestation verification.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    /// Hash of the attestation document for transcript binding.
    pub document_hash: [u8; 32],

    /// Public key extracted from the attestation (if bound).
    pub public_key: Option<Vec<u8>>,

    /// User data extracted from the attestation (if present).
    pub user_data: Option<Vec<u8>>,

    /// Nonce extracted from the attestation (if present).
    pub nonce: Option<Vec<u8>>,

    /// PCR values or measurement registers (platform-specific).
    pub measurements: Vec<Vec<u8>>,
}
