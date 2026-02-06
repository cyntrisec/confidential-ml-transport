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
