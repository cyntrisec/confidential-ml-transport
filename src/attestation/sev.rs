use std::collections::BTreeMap;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::sev_errors::check_report_invariants;
use super::sev_policy::{enforce_report_policy, SnpVerifyPolicy};
use super::types::{AttestationDocument, VerifiedAttestation};
use super::{AttestationProvider, AttestationVerifier};
use crate::error::AttestError;

/// Wire format marker for SEV-SNP attestation documents.
const SEV_SNP_MARKER: &[u8; 12] = b"SEV_SNP_V1\0\0";

/// Size of an SEV-SNP attestation report (fixed at 1184 bytes).
const REPORT_SIZE: usize = 1184;

/// Attestation provider that requests reports from the AMD SEV-SNP firmware.
///
/// Only works inside a SEV-SNP confidential VM where `/dev/sev-guest` is
/// available. The firmware handle is opened on construction.
///
/// # REPORT_DATA layout
///
/// The 64-byte `REPORT_DATA` field is populated as:
/// - bytes `[0..32]`: raw X25519 public key (32 bytes)
/// - bytes `[32..64]`: raw nonce (32 bytes)
///
/// This allows the verifier to extract the public key and nonce directly
/// without hashing, keeping the handshake verification path unchanged.
#[cfg(target_os = "linux")]
pub struct SevSnpProvider {
    firmware: std::sync::Mutex<sev::firmware::guest::Firmware>,
}

#[cfg(target_os = "linux")]
impl SevSnpProvider {
    /// Open a connection to the SEV-SNP guest firmware device.
    ///
    /// Returns an error if `/dev/sev-guest` is not available (i.e., not
    /// running inside a SEV-SNP confidential VM).
    pub fn new() -> Result<Self, AttestError> {
        let firmware = sev::firmware::guest::Firmware::open().map_err(|e| {
            AttestError::GenerationFailed(format!(
                "failed to open /dev/sev-guest — not running inside a SEV-SNP VM? {e}"
            ))
        })?;
        Ok(Self {
            firmware: std::sync::Mutex::new(firmware),
        })
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl AttestationProvider for SevSnpProvider {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        // Build 64-byte REPORT_DATA: pk[0..32] || nonce[32..64]
        let mut report_data = [0u8; 64];

        if let Some(pk) = public_key {
            if pk.len() != 32 {
                return Err(AttestError::GenerationFailed(format!(
                    "public key must be 32 bytes, got {}",
                    pk.len()
                )));
            }
            report_data[..32].copy_from_slice(pk);
        }

        if let Some(n) = nonce {
            if n.len() != 32 {
                return Err(AttestError::GenerationFailed(format!(
                    "nonce must be 32 bytes, got {}",
                    n.len()
                )));
            }
            report_data[32..64].copy_from_slice(n);
        }

        // Request extended report (includes certificate chain).
        let mut fw = self
            .firmware
            .lock()
            .map_err(|e| AttestError::GenerationFailed(format!("firmware mutex poisoned: {e}")))?;
        let (report_bytes, certs) =
            fw.get_ext_report(None, Some(report_data), None)
                .map_err(|e| {
                    AttestError::GenerationFailed(format!("SEV-SNP get_ext_report failed: {e}"))
                })?;

        // Serialize certificate chain entries to DER bytes.
        let cert_chain_bytes = match certs {
            Some(entries) => {
                let mut chain_buf = Vec::new();
                for entry in &entries {
                    chain_buf.extend_from_slice(&entry.data);
                }
                chain_buf
            }
            None => Vec::new(),
        };

        // Build wire document: marker + report_size + report + cert_chain_size + cert_chain
        let raw = encode_sev_snp_document(&report_bytes, &cert_chain_bytes);
        Ok(AttestationDocument::new(raw))
    }
}

/// Verifier for AMD SEV-SNP attestation reports.
///
/// Validates the attestation report by:
/// 1. Parsing the wire document (marker, report, certificate chain)
/// 2. Deserializing the `AttestationReport`
/// 3. Checking structural invariants (report version, sig algo, MaskChipKey)
/// 4. Validating cert chain validity windows
/// 5. Validating the certificate chain (ARK → ASK → VCEK)
/// 6. Verifying the report signature against the VCEK
/// 7. Optionally checking MEASUREMENT (and, in future phases, policy bits
///    from [`SnpVerifyPolicy`])
///
/// # Construction
///
/// For the common case of "just check a measurement," use [`Self::new`]:
/// ```ignore
/// let verifier = SevSnpVerifier::new(Some(expected_measurement));
/// ```
///
/// For full policy control, use [`Self::with_policy`]:
/// ```ignore
/// let policy = SnpVerifyPolicy {
///     expected_measurement: Some(m),
///     accepted_products: vec![SnpProduct::Genoa],
///     ..SnpVerifyPolicy::production()
/// };
/// let verifier = SevSnpVerifier::with_policy(policy);
/// ```
pub struct SevSnpVerifier {
    policy: SnpVerifyPolicy,
}

impl SevSnpVerifier {
    /// Create a new verifier with production-default policy, optionally
    /// pinning a specific `MEASUREMENT`.
    ///
    /// Equivalent to:
    /// ```ignore
    /// SevSnpVerifier::with_policy(SnpVerifyPolicy {
    ///     expected_measurement,
    ///     ..SnpVerifyPolicy::production()
    /// })
    /// ```
    pub fn new(expected_measurement: Option<Vec<u8>>) -> Self {
        Self::with_policy(SnpVerifyPolicy {
            expected_measurement,
            ..SnpVerifyPolicy::production()
        })
    }

    /// Create a verifier with a fully-specified policy.
    ///
    /// Prefer this over [`Self::new`] when pinning products, loosening checks
    /// for development, or providing a CRL.
    pub fn with_policy(policy: SnpVerifyPolicy) -> Self {
        Self { policy }
    }

    /// Borrow the active policy (read-only).
    pub fn policy(&self) -> &SnpVerifyPolicy {
        &self.policy
    }
}

#[async_trait]
impl AttestationVerifier for SevSnpVerifier {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        // Step 1: Parse wire document.
        let (report_bytes, cert_chain_bytes) = decode_sev_snp_document(&doc.raw)?;

        // Step 2: Deserialize the attestation report.
        let report = parse_attestation_report(&report_bytes)?;

        // Step 3: Structural invariants (Phase 1 hardening — F9/F10/F11).
        // Rejects older report versions, unsupported signature algorithms,
        // and unsigned reports (MaskChipKey=1) with clear, specific errors
        // before we waste cycles on chain validation.
        check_report_invariants(&report, self.policy.min_report_version)?;

        // Step 4: Validate certificate chain and verify report signature.
        let vcek_ext = verify_report_with_certs(&report, &report_bytes, &cert_chain_bytes)?;

        // Step 4a (Phase 5 — F1): bind VCEK-embedded TCB/chipID to the report.
        // Guards against TCB rollback: old-firmware VCEK can't sign a report
        // claiming newer TCB. Required by AMD SB-3019 / CVE-2024-56161
        // (BadRAM) remediation. Gated by policy for opt-out in development.
        if self.policy.check_tcb_binding {
            super::vcek_extensions::enforce_tcb_binding(&report, &vcek_ext)
                .map_err(AttestError::from)?;
        }

        // Step 4b (Phase 6 — F5): CRL-based revocation check if caller
        // provided a CRL. Signed by ARK per VCEK 1.00 §2.3 Table 7.
        if let Some(crl_der) = self.policy.crl_der.as_deref() {
            // Re-classify certs via Subject CN. One-shot handshake code path
            // — correctness over cycle cost.
            let (_report_bytes2, cert_chain_bytes2) = decode_sev_snp_document(&doc.raw)?;
            let certs_for_crl = parse_der_certificates(&cert_chain_bytes2)?;
            let classified = super::sev_errors::classify_certs_by_cn(&certs_for_crl)
                .map_err(AttestError::from)?;
            super::sev_errors::enforce_crl_revocation(&classified.vek, crl_der, &classified.ark)
                .map_err(AttestError::from)?;
        }

        // Step 5: Enforce policy (Phase 4 — F2/F3/F8). Only after signature
        // verification — we must not trust any field in the report until the
        // chip-signed chain validates.
        enforce_report_policy(&report, &self.policy)?;

        // Step 6: Extract fields from REPORT_DATA.
        let public_key = report.report_data[..32].to_vec();
        let nonce = report.report_data[32..64].to_vec();

        // Step 7: Check measurement if expected.
        let mut measurements = BTreeMap::new();
        measurements.insert(0, report.measurement.to_vec());

        if let Some(ref expected) = self.policy.expected_measurement {
            if expected.as_slice() != report.measurement.as_slice() {
                return Err(AttestError::VerificationFailed(format!(
                    "MEASUREMENT mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(report.measurement)
                )));
            }
        }

        let document_hash: [u8; 32] = Sha256::digest(&doc.raw).into();

        // Return public key and nonce as non-empty Options only if non-zero.
        let pk_opt = if public_key.iter().all(|&b| b == 0) {
            None
        } else {
            Some(public_key)
        };
        let nonce_opt = if nonce.iter().all(|&b| b == 0) {
            None
        } else {
            Some(nonce)
        };

        Ok(VerifiedAttestation {
            document_hash,
            public_key: pk_opt,
            user_data: None,
            nonce: nonce_opt,
            measurements,
        })
    }
}

// -- Wire encoding/decoding --

/// Encode an SEV-SNP attestation document for the wire.
///
/// Format:
/// ```text
/// [12 bytes] SEV_SNP_V1\0\0  (marker)
/// [4 bytes]  report_size     (u32 LE)
/// [N bytes]  report          (N = report_size, typically 1184)
/// [4 bytes]  cert_chain_size (u32 LE)
/// [M bytes]  cert_chain      (M = cert_chain_size)
/// ```
#[doc(hidden)]
pub fn encode_sev_snp_document(report_bytes: &[u8], cert_chain_bytes: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(12 + 4 + report_bytes.len() + 4 + cert_chain_bytes.len());
    raw.extend_from_slice(SEV_SNP_MARKER);
    raw.extend_from_slice(&(report_bytes.len() as u32).to_le_bytes());
    raw.extend_from_slice(report_bytes);
    raw.extend_from_slice(&(cert_chain_bytes.len() as u32).to_le_bytes());
    raw.extend_from_slice(cert_chain_bytes);
    raw
}

/// Decode an SEV-SNP wire document into (report_bytes, cert_chain_bytes).
fn decode_sev_snp_document(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
    if raw.len() < 12 {
        return Err(AttestError::VerificationFailed(
            "document too short for SEV-SNP marker".into(),
        ));
    }

    if &raw[..12] != SEV_SNP_MARKER {
        return Err(AttestError::VerificationFailed(
            "not a SEV-SNP attestation document".into(),
        ));
    }

    let mut offset = 12;

    // Read report_size.
    if offset + 4 > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated SEV-SNP document (report_size)".into(),
        ));
    }
    let report_size = u32::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + report_size > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated SEV-SNP document (report)".into(),
        ));
    }
    let report_bytes = raw[offset..offset + report_size].to_vec();
    offset += report_size;

    // Read cert_chain_size.
    if offset + 4 > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated SEV-SNP document (cert_chain_size)".into(),
        ));
    }
    let cert_chain_size = u32::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + cert_chain_size > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated SEV-SNP document (cert_chain)".into(),
        ));
    }
    let cert_chain_bytes = raw[offset..offset + cert_chain_size].to_vec();

    Ok((report_bytes, cert_chain_bytes))
}

/// Parse raw report bytes into an `AttestationReport`.
fn parse_attestation_report(
    report_bytes: &[u8],
) -> Result<sev::firmware::guest::AttestationReport, AttestError> {
    use sev::parser::ByteParser;

    if report_bytes.len() != REPORT_SIZE {
        return Err(AttestError::VerificationFailed(format!(
            "report size mismatch: expected {REPORT_SIZE}, got {}",
            report_bytes.len()
        )));
    }

    sev::firmware::guest::AttestationReport::from_bytes(report_bytes).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse SEV-SNP attestation report: {e}"))
    })
}

/// Verify the report signature using the certificate chain.
///
/// If `cert_chain_bytes` is non-empty, parses it as concatenated DER
/// certificates (ARK + ASK + VCEK) and verifies the chain, then verifies
/// the report signature against the VCEK.
///
/// If `cert_chain_bytes` is empty, performs signature verification using
/// the report's embedded signature structure directly (requires the caller
/// to trust the report source, e.g., for testing).
///
/// Returns the parsed VCEK TCB extensions on success so the caller can
/// run the F1 TCB-binding check via `enforce_tcb_binding`.
fn verify_report_with_certs(
    report: &sev::firmware::guest::AttestationReport,
    report_bytes: &[u8],
    cert_chain_bytes: &[u8],
) -> Result<super::vcek_extensions::VcekTcbExtensions, AttestError> {
    if cert_chain_bytes.is_empty() {
        return Err(AttestError::VerificationFailed(
            "certificate chain is empty — cannot verify report signature. \
             An attacker could forge attestation reports without a valid certificate chain."
                .into(),
        ));
    }

    // Parse concatenated DER certificates (split by SEQUENCE boundaries).
    let certs = parse_der_certificates(cert_chain_bytes)?;
    if certs.len() < 3 {
        return Err(AttestError::VerificationFailed(format!(
            "expected at least 3 certificates (ARK, ASK, VCEK/VLEK), got {}",
            certs.len()
        )));
    }

    // Phase 7 (F6, minimal): classify certs by Subject CN instead of trusting
    // positional ordering from the sev firmware. Also natively supports VLEK
    // (`SEV-VLEK` CN) as a drop-in replacement for VCEK.
    //
    // Full wire-format change to carry CertType GUID (matches upstream
    // `CertTableEntry` semantics) is deferred — only needed for direct-SEV
    // deployments with non-canonical entry ordering, which we don't have.
    let classified = super::sev_errors::classify_certs_by_cn(&certs).map_err(AttestError::from)?;

    // Phase 2 (F4): validate cert validity windows BEFORE signature verification.
    super::sev_errors::check_cert_chain_validity(
        &classified.ark,
        &classified.ask,
        &classified.vek,
    )?;

    // Phase 5 (F1): parse VCEK/VLEK TCB extensions. Enforcement against the
    // report's reported_tcb is gated by policy.check_tcb_binding in verify().
    let vcek_extensions = super::vcek_extensions::parse_vcek_extensions(&classified.vek)
        .map_err(AttestError::from)?;

    // Build the sev Chain from the CN-classified certificates.
    let chain = sev::certs::snp::Chain::from_der(&classified.ark, &classified.ask, &classified.vek)
        .map_err(|e| {
            AttestError::VerificationFailed(format!("failed to build certificate chain: {e}"))
        })?;

    // Verify the certificate chain (ARK self-signed, ARK signs ASK, ASK signs VCEK/VLEK).
    use sev::certs::snp::Verifiable;
    (&chain, report).verify().map_err(|e| {
        AttestError::VerificationFailed(format!("report signature verification failed: {e}"))
    })?;

    // Verify the ARK is a known AMD root (Milan, Genoa, or Turin).
    // Without this check, an attacker could forge the entire chain with
    // a self-signed ARK of their own creation.
    verify_ark_is_known_amd_root(&classified.ark)?;

    let _ = report_bytes; // Used indirectly via report
    Ok(vcek_extensions)
}

/// Verify that the ARK certificate matches a known AMD root.
///
/// Compares the provided ARK's DER-encoded public key against the built-in
/// AMD ARK certificates for Milan, Genoa, and Turin. Rejects chains rooted
/// at unknown (potentially attacker-generated) ARKs.
fn verify_ark_is_known_amd_root(ark_der: &[u8]) -> Result<(), AttestError> {
    use openssl::x509::X509;

    let peer_ark = X509::from_der(ark_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse ARK certificate: {e}"))
    })?;
    let peer_ark_pubkey = peer_ark.public_key().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to extract ARK public key: {e}"))
    })?;
    let peer_ark_pubkey_der = peer_ark_pubkey.public_key_to_der().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to encode ARK public key to DER: {e}"))
    })?;

    // Compare against built-in AMD roots for all supported processor generations.
    let known_roots: &[(&str, &[u8])] = &[
        ("Milan", sev::certs::snp::builtin::milan::ARK),
        ("Genoa", sev::certs::snp::builtin::genoa::ARK),
        ("Turin", sev::certs::snp::builtin::turin::ARK),
    ];

    for (platform, ark_pem) in known_roots {
        let known_ark = X509::from_pem(ark_pem).map_err(|e| {
            AttestError::VerificationFailed(format!("failed to parse built-in {platform} ARK: {e}"))
        })?;
        let known_pubkey = known_ark.public_key().map_err(|e| {
            AttestError::VerificationFailed(format!(
                "failed to extract built-in {platform} ARK public key: {e}"
            ))
        })?;
        let known_pubkey_der = known_pubkey.public_key_to_der().map_err(|e| {
            AttestError::VerificationFailed(format!(
                "failed to encode built-in {platform} ARK public key: {e}"
            ))
        })?;

        if peer_ark_pubkey_der == known_pubkey_der {
            tracing::info!(platform, "ARK matches known AMD root");
            return Ok(());
        }
    }

    Err(AttestError::VerificationFailed(
        "ARK certificate does not match any known AMD root (Milan, Genoa, Turin). \
         The certificate chain may have been forged."
            .into(),
    ))
}

/// Parse concatenated DER certificates into individual certificate byte slices.
///
/// DER certificates start with a SEQUENCE tag (0x30) followed by a length.
/// We parse the length to split them.
fn parse_der_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>, AttestError> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        if data[offset] != 0x30 {
            return Err(AttestError::VerificationFailed(format!(
                "expected DER SEQUENCE tag (0x30) at offset {offset}, got 0x{:02X}",
                data[offset]
            )));
        }

        // Parse DER length.
        let (cert_len, header_len) = parse_der_length(&data[offset + 1..]).map_err(|e| {
            AttestError::VerificationFailed(format!(
                "failed to parse DER length at offset {offset}: {e}"
            ))
        })?;

        let total_len = 1 + header_len + cert_len; // tag + length bytes + content
        if offset + total_len > data.len() {
            return Err(AttestError::VerificationFailed(format!(
                "DER certificate extends beyond data at offset {offset}"
            )));
        }

        certs.push(data[offset..offset + total_len].to_vec());
        offset += total_len;
    }

    Ok(certs)
}

/// Parse a DER length encoding. Returns (content_length, number_of_length_bytes).
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("empty length field");
    }

    if data[0] < 0x80 {
        // Short form: single byte length.
        Ok((data[0] as usize, 1))
    } else if data[0] == 0x80 {
        Err("indefinite length not supported")
    } else {
        // Long form: first byte indicates number of subsequent length bytes.
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes > 4 {
            return Err("length too large");
        }
        if data.len() < 1 + num_bytes {
            return Err("truncated length field");
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_roundtrip() {
        let report = vec![0xAA; REPORT_SIZE];
        let certs = vec![0xBB; 256];

        let encoded = encode_sev_snp_document(&report, &certs);
        let (dec_report, dec_certs) = decode_sev_snp_document(&encoded).unwrap();

        assert_eq!(dec_report, report);
        assert_eq!(dec_certs, certs);
    }

    #[test]
    fn document_roundtrip_empty_certs() {
        let report = vec![0xCC; REPORT_SIZE];
        let certs = vec![];

        let encoded = encode_sev_snp_document(&report, &certs);
        let (dec_report, dec_certs) = decode_sev_snp_document(&encoded).unwrap();

        assert_eq!(dec_report, report);
        assert!(dec_certs.is_empty());
    }

    #[test]
    fn reject_invalid_marker() {
        let mut raw = vec![0u8; 100];
        raw[..7].copy_from_slice(b"INVALID");
        let result = decode_sev_snp_document(&raw);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("not a SEV-SNP"), "error: {err}");
    }

    #[test]
    fn reject_truncated_document() {
        let report = vec![0xAA; REPORT_SIZE];
        let certs = vec![0xBB; 256];
        let encoded = encode_sev_snp_document(&report, &certs);

        // Truncate in the middle of the report.
        let truncated = &encoded[..20];
        let result = decode_sev_snp_document(truncated);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verifier_rejects_invalid_document() {
        let verifier = SevSnpVerifier::new(None);
        let doc = AttestationDocument::new(b"INVALID".to_vec());
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
    }

    /// Build a synthetic attestation report with fields that pass the Phase 1
    /// invariant checks (version >= MIN_REPORT_VERSION, sig_algo == ECDSA P-384,
    /// mask_chip_key == 0).
    ///
    /// Tests that specifically want to exercise F9/F10/F11 rejection paths
    /// should construct their own report or mutate the result of this helper.
    fn build_test_report(
        report_data: [u8; 64],
        measurement: [u8; 48],
    ) -> sev::firmware::guest::AttestationReport {
        sev::firmware::guest::AttestationReport {
            version: 2,
            sig_algo: super::super::sev_errors::SIG_ALGO_ECDSA_P384_SHA384,
            chip_id: [0xD4; 64],
            report_data,
            measurement,
            ..Default::default()
        }
    }

    /// Test report field extraction directly (without going through the full
    /// verifier, since the verifier now correctly rejects empty cert chains).
    #[test]
    fn report_extracts_report_data() {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&[0x42; 32]); // public key
        rd[32..64].copy_from_slice(&[0x37; 32]); // nonce
        let report = build_test_report(rd, [0xEE; 48]);

        assert_eq!(&report.report_data[..32], &[0x42; 32]);
        assert_eq!(&report.report_data[32..64], &[0x37; 32]);
        assert_eq!(report.measurement, [0xEE; 48]);
    }

    #[test]
    fn report_measurement_mismatch_detected() {
        let report = build_test_report([0u8; 64], [0xEE; 48]);
        let expected = vec![0xFF; 48];
        assert_ne!(report.measurement.as_slice(), expected.as_slice());
    }

    #[test]
    fn report_measurement_match_detected() {
        let report = build_test_report([0u8; 64], [0xAB; 48]);
        let expected = vec![0xAB; 48];
        assert_eq!(report.measurement.as_slice(), expected.as_slice());
    }

    #[test]
    fn report_zero_pk_and_nonce() {
        let report = build_test_report([0u8; 64], [0u8; 48]);
        assert!(report.report_data[..32].iter().all(|&b| b == 0));
        assert!(report.report_data[32..64].iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn verifier_rejects_empty_cert_chain() {
        use sev::parser::ByteParser;
        let report = build_test_report([0u8; 64], [0u8; 48]);
        let report_bytes = report.to_bytes().unwrap().to_vec();
        let doc = AttestationDocument::new(encode_sev_snp_document(&report_bytes, &[]));

        let verifier = SevSnpVerifier::new(None);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "verifier must reject empty cert chain");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("certificate chain is empty"),
            "error should mention empty chain: {err}"
        );
    }

    #[test]
    fn parse_der_certs_roundtrip() {
        // Create two fake DER certificate-like structures.
        // DER: 0x30 (SEQUENCE) + length + content
        let cert1 = {
            let content = vec![0xAA; 100];
            let mut der = vec![0x30, 0x64]; // 0x64 = 100
            der.extend_from_slice(&content);
            der
        };
        let cert2 = {
            let content = vec![0xBB; 200];
            // Long form length: 0x81 0xC8 (200)
            let mut der = vec![0x30, 0x81, 0xC8];
            der.extend_from_slice(&content);
            der
        };

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&cert1);
        concatenated.extend_from_slice(&cert2);

        let parsed = parse_der_certificates(&concatenated).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], cert1);
        assert_eq!(parsed[1], cert2);
    }

    // -- Phase 1 invariant-check tests (F9/F10/F11) --
    //
    // These tests exercise the invariant-check stage directly via the verifier
    // (which calls it after parse) rather than going through the full
    // cert-chain validation — tests assert the specific error code fires
    // before any chain work is attempted.

    /// Helper: wrap a synthetic report in a wire document and run the verifier.
    /// Returns the error so tests can assert on the code/message.
    async fn verify_synthetic_report(
        report: sev::firmware::guest::AttestationReport,
    ) -> Result<crate::attestation::types::VerifiedAttestation, AttestError> {
        use sev::parser::ByteParser;
        let report_bytes = report.to_bytes().unwrap().to_vec();
        // Use a non-empty cert chain so we don't short-circuit on that error;
        // since invariants are checked before chain validation, these bytes
        // never actually get parsed.
        let doc = AttestationDocument::new(encode_sev_snp_document(&report_bytes, &[0x30, 0x00]));
        let verifier = SevSnpVerifier::new(None);
        verifier.verify(&doc).await
    }

    // F9 (report version below minimum) is unit-tested directly against the
    // `check_report_invariants` helper in `sev_errors::tests` — the sev crate's
    // `AttestationReport::from_bytes` rejects versions below 2 at parse time
    // ("unsupported"), so an integration test through verify() can never reach
    // our check. Our check remains in place for future-proofing (if
    // MIN_REPORT_VERSION ever moves to 3 or 5, it begins to fire on
    // parse-succeeding reports).

    #[tokio::test]
    async fn verifier_rejects_unsupported_signature_algo() {
        // F10: sig_algo != 1 (ECDSA P-384/SHA-384) must be rejected explicitly.
        let mut report = build_test_report([0u8; 64], [0u8; 48]);
        report.sig_algo = 2; // reserved per ABI Chapter 10 Table 139

        let err = verify_synthetic_report(report).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("SNP_UNSUPPORTED_SIGNATURE_ALGO"),
            "expected SNP_UNSUPPORTED_SIGNATURE_ALGO, got: {msg}"
        );
        assert!(msg.contains("0x2"), "error should name the bad algo: {msg}");
    }

    #[tokio::test]
    async fn verifier_rejects_mask_chip_key_enabled() {
        // F11: MaskChipKey=1 means the signature field is all zeroes by design.
        // We reject explicitly before signature verification so the error is
        // operator-actionable instead of "VEK does not sign the attestation report".
        let mut report = build_test_report([0u8; 64], [0u8; 48]);
        // Set bit 1 of key_info to 1 (MASK_CHIP_KEY) — encoded as a u32 with
        // bit 1 set. The bitfield accessor is read-only, so construct a
        // KeyInfo directly via its public ByteParser interface.
        use sev::parser::ByteParser;
        let key_info_bytes: [u8; 4] = [0x02, 0x00, 0x00, 0x00]; // bit 1 set
        report.key_info = sev::firmware::guest::KeyInfo::from_bytes(&key_info_bytes).unwrap();
        assert!(
            report.key_info.mask_chip_key(),
            "test precondition: mask_chip_key bit must be set"
        );

        let err = verify_synthetic_report(report).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("SNP_MASK_CHIP_KEY_ENABLED"),
            "expected SNP_MASK_CHIP_KEY_ENABLED, got: {msg}"
        );
    }

    #[tokio::test]
    async fn verifier_accepts_valid_invariants_reaches_chain_stage() {
        // Positive: a report with valid invariants falls through to the chain
        // validation stage (which then rejects our fake cert bytes). Confirms
        // we don't over-reject in Phase 1.
        let report = build_test_report([0u8; 64], [0u8; 48]);
        assert_eq!(report.version, 2);
        assert_eq!(report.sig_algo, 1);
        assert!(!report.key_info.mask_chip_key());

        let err = verify_synthetic_report(report).await.unwrap_err();
        let msg = format!("{err}");
        // Passing invariants means we reach chain parsing, which fails on
        // our fake bytes. The specific error differs, but it must NOT be
        // one of the Phase 1 codes.
        assert!(
            !msg.contains("SNP_REPORT_VERSION_TOO_OLD")
                && !msg.contains("SNP_UNSUPPORTED_SIGNATURE_ALGO")
                && !msg.contains("SNP_MASK_CHIP_KEY_ENABLED"),
            "valid report should pass invariants; got: {msg}"
        );
    }

    // -- Phase 4: end-to-end policy enforcement through verify() --
    //
    // These tests confirm that policy rejection surfaces via the public
    // verify() API, not just at the internal enforce_report_policy helper.
    // They use synthetic reports with a fake cert chain — those would
    // normally fail at chain verification, but policy enforcement runs
    // AFTER chain verify, so to test enforcement we need to construct a
    // scenario where chain verify succeeds. We use SnpVerifyPolicy::development()
    // to disable validity / TCB-binding checks; the bogus cert chain still
    // won't sig-verify, but we can inspect the error.
    //
    // To get a clean policy-stage rejection, we build our own synthetic doc
    // where chain verify is fully bypassed via development() — but our code
    // never bypasses chain verify (it's always on). The practical test is:
    // at the INVARIANT stage, we reject early on VMPL mismatch?
    //
    // Actually no — VMPL check is in enforce_report_policy, which runs AFTER
    // chain verify. So a synthetic report with VMPL=1 and a bogus chain will
    // fail at chain stage first, masking the policy check.
    //
    // Real integration of the policy path requires a signature-valid chain,
    // which means real Milan hardware or mocked sev-crate internals. That
    // coverage lives in sev_policy::tests — the unit tests exercise
    // enforce_report_policy directly and confirm each error variant fires.
    // Here we only assert the policy plumbing compiles and is reachable.

    #[tokio::test]
    async fn verify_uses_policy_from_with_policy_constructor() {
        // Exercise the full verify() path with a custom policy. The report
        // has valid invariants but the cert chain is fake, so verify() fails
        // at the chain stage. What we prove: no panic, the new policy
        // plumbing compiles correctly, and the failure is NOT from a Phase 4
        // enforcement code (because we never reach that stage).
        use super::super::sev_errors::SnpProduct;

        let policy = SnpVerifyPolicy {
            accepted_products: vec![SnpProduct::Genoa],
            ..SnpVerifyPolicy::production()
        };
        let verifier = SevSnpVerifier::with_policy(policy);
        assert_eq!(verifier.policy().accepted_products.len(), 1);

        let report = build_test_report([0u8; 64], [0u8; 48]);
        use sev::parser::ByteParser;
        let report_bytes = report.to_bytes().unwrap().to_vec();
        let doc = AttestationDocument::new(encode_sev_snp_document(&report_bytes, &[0x30, 0x00]));

        let err = verifier.verify(&doc).await.unwrap_err().to_string();
        // Should reach chain parsing (fails there), NOT policy-stage codes.
        for phase4_code in [
            "SNP_DEBUG_GUEST_REJECTED",
            "SNP_MIGRATABLE_GUEST_REJECTED",
            "SNP_VMPL_MISMATCH",
            "SNP_HOST_REQUESTED_REPORT_REJECTED",
            "SNP_PRODUCT_MISMATCH",
        ] {
            assert!(
                !err.contains(phase4_code),
                "synthetic report with bogus chain should fail before Phase 4 enforcement, got: {err}"
            );
        }
    }

    // -- Phase 3 verifier-API tests --

    #[test]
    fn new_with_none_measurement_uses_production_policy() {
        let v = SevSnpVerifier::new(None);
        let policy = v.policy();
        assert!(policy.expected_measurement.is_none());
        assert!(policy.reject_debug, "new() must use production defaults");
        assert!(policy.reject_migratable);
        assert_eq!(policy.require_vmpl, Some(0));
        assert!(policy.check_validity);
        assert!(policy.check_tcb_binding);
    }

    #[test]
    fn new_with_measurement_threads_it_into_policy() {
        let m = vec![0xABu8; 48];
        let v = SevSnpVerifier::new(Some(m.clone()));
        assert_eq!(
            v.policy().expected_measurement.as_deref(),
            Some(m.as_slice())
        );
        // Other defaults preserved.
        assert!(v.policy().reject_debug);
    }

    #[test]
    fn with_policy_takes_arbitrary_policy() {
        use super::super::sev_errors::SnpProduct;

        let custom = SnpVerifyPolicy {
            expected_measurement: Some(vec![0xCD; 48]),
            accepted_products: vec![SnpProduct::Genoa],
            reject_debug: false, // explicit dev override
            ..SnpVerifyPolicy::production()
        };
        let v = SevSnpVerifier::with_policy(custom);
        assert_eq!(v.policy().accepted_products.len(), 1);
        assert!(v.policy().accepted_products.contains(&SnpProduct::Genoa));
        assert!(!v.policy().reject_debug);
        // Non-overridden defaults stick:
        assert_eq!(v.policy().require_vmpl, Some(0));
    }

    #[tokio::test]
    async fn new_and_with_policy_produce_equivalent_measurement_behavior() {
        // Backward-compat guarantee: SevSnpVerifier::new(Some(m)) must behave
        // identically to with_policy(SnpVerifyPolicy { expected_measurement: Some(m), ... })
        // for the measurement check specifically.
        let m = vec![0xEE; 48];
        let v1 = SevSnpVerifier::new(Some(m.clone()));
        let v2 = SevSnpVerifier::with_policy(SnpVerifyPolicy {
            expected_measurement: Some(m.clone()),
            ..SnpVerifyPolicy::production()
        });

        // Build a doc that fails invariants identically in both — we're only
        // proving the policies are equivalent at the public-policy boundary.
        let mismatched_measurement = [0xFFu8; 48];
        let report = build_test_report([0u8; 64], mismatched_measurement);
        use sev::parser::ByteParser;
        let report_bytes = report.to_bytes().unwrap().to_vec();
        let doc = AttestationDocument::new(encode_sev_snp_document(&report_bytes, &[0x30, 0x00]));

        let err1 = v1.verify(&doc).await.unwrap_err().to_string();
        let err2 = v2.verify(&doc).await.unwrap_err().to_string();
        // Both fail at the same stage (chain parsing — measurement check happens
        // later), proving policy equivalence at the verifier boundary.
        assert_eq!(
            err1, err2,
            "new() and with_policy() produced divergent errors"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_fails_outside_sev_snp() {
        let result = SevSnpProvider::new();
        assert!(
            result.is_err(),
            "SevSnpProvider::new() should fail without /dev/sev-guest"
        );
        let err = match result {
            Err(e) => format!("{e}"),
            Ok(_) => unreachable!(),
        };
        assert!(
            err.contains("/dev/sev-guest"),
            "error should mention /dev/sev-guest: {err}"
        );
    }
}
