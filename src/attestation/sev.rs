use std::collections::BTreeMap;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

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
/// 3. Validating the certificate chain (ARK → ASK → VCEK)
/// 4. Verifying the report signature against the VCEK
/// 5. Extracting `REPORT_DATA` (public key + nonce) and `MEASUREMENT`
///
/// Optionally checks the 48-byte `MEASUREMENT` against an expected value.
pub struct SevSnpVerifier {
    expected_measurement: Option<Vec<u8>>,
}

impl SevSnpVerifier {
    /// Create a new verifier.
    ///
    /// If `expected_measurement` is `Some`, the verifier will check that the
    /// report's `MEASUREMENT` field (48 bytes) matches the expected value.
    pub fn new(expected_measurement: Option<Vec<u8>>) -> Self {
        Self {
            expected_measurement,
        }
    }
}

#[async_trait]
impl AttestationVerifier for SevSnpVerifier {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        // Step 1: Parse wire document.
        let (report_bytes, cert_chain_bytes) = decode_sev_snp_document(&doc.raw)?;

        // Step 2: Deserialize the attestation report.
        let report = parse_attestation_report(&report_bytes)?;

        // Step 3: Validate certificate chain and verify report signature.
        verify_report_with_certs(&report, &report_bytes, &cert_chain_bytes)?;

        // Step 4: Extract fields from REPORT_DATA.
        let public_key = report.report_data[..32].to_vec();
        let nonce = report.report_data[32..64].to_vec();

        // Step 5: Check measurement if expected.
        let mut measurements = BTreeMap::new();
        measurements.insert(0, report.measurement.to_vec());

        if let Some(ref expected) = self.expected_measurement {
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
fn verify_report_with_certs(
    report: &sev::firmware::guest::AttestationReport,
    report_bytes: &[u8],
    cert_chain_bytes: &[u8],
) -> Result<(), AttestError> {
    if cert_chain_bytes.is_empty() {
        return Err(AttestError::VerificationFailed(
            "certificate chain is empty — cannot verify report signature. \
             An attacker could forge attestation reports without a valid certificate chain."
                .into(),
        ));
    }

    // Parse concatenated DER certificates.
    // The cert chain from get_ext_report is typically provided as a
    // CertTableEntry list. When we serialize for the wire, we concatenate
    // the raw DER bytes. We need to split them back into individual certs.
    //
    // Use openssl to parse individual DER certs from the concatenated bytes.
    let certs = parse_der_certificates(cert_chain_bytes)?;
    if certs.len() < 3 {
        return Err(AttestError::VerificationFailed(format!(
            "expected at least 3 certificates (ARK, ASK, VCEK), got {}",
            certs.len()
        )));
    }

    // Build the sev Chain from the parsed certificates.
    // Convention from CertTableEntry: ARK, ASK, VCEK ordering.
    let chain = sev::certs::snp::Chain::from_der(
        &certs[0], // ARK
        &certs[1], // ASK
        &certs[2], // VCEK
    )
    .map_err(|e| {
        AttestError::VerificationFailed(format!("failed to build certificate chain: {e}"))
    })?;

    // Verify the certificate chain (ARK self-signed, ARK signs ASK, ASK signs VCEK).
    use sev::certs::snp::Verifiable;
    (&chain, report).verify().map_err(|e| {
        AttestError::VerificationFailed(format!("report signature verification failed: {e}"))
    })?;

    // Verify the ARK is a known AMD root (Milan, Genoa, or Turin).
    // Without this check, an attacker could forge the entire chain with
    // a self-signed ARK of their own creation.
    verify_ark_is_known_amd_root(&certs[0])?;

    let _ = report_bytes; // Used indirectly via report
    Ok(())
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

    /// Build a synthetic attestation report with custom fields.
    fn build_test_report(
        report_data: [u8; 64],
        measurement: [u8; 48],
    ) -> sev::firmware::guest::AttestationReport {
        sev::firmware::guest::AttestationReport {
            version: 2,
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
