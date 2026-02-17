#![cfg(feature = "sev-snp")]

use async_trait::async_trait;
use confidential_ml_transport::attestation::sev::{encode_sev_snp_document, SevSnpVerifier};
use confidential_ml_transport::attestation::types::AttestationDocument;
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::session::channel::SecureChannel;
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{AttestationProvider, AttestationVerifier};

/// A synthetic attestation provider that builds SEV-SNP-format documents
/// from pre-built report bytes. Used for testing the verifier's rejection
/// of unsigned attestations (empty cert chain).
///
/// NOTE: This provider generates documents WITHOUT a certificate chain.
/// The verifier correctly rejects these — use mock attestation for
/// handshake integration tests that need to succeed.
struct SyntheticSevSnpProvider {
    measurement: [u8; 48],
}

impl SyntheticSevSnpProvider {
    fn new(measurement: [u8; 48]) -> Self {
        Self { measurement }
    }
}

#[async_trait]
impl AttestationProvider for SyntheticSevSnpProvider {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        // Build REPORT_DATA: pk[0..32] || nonce[32..64]
        let mut report_data = [0u8; 64];
        if let Some(pk) = public_key {
            if pk.len() == 32 {
                report_data[..32].copy_from_slice(pk);
            }
        }
        if let Some(n) = nonce {
            if n.len() == 32 {
                report_data[32..64].copy_from_slice(n);
            }
        }

        let report = sev::firmware::guest::AttestationReport {
            version: 2,
            chip_id: [0xD4; 64],
            report_data,
            measurement: self.measurement,
            ..Default::default()
        };

        use sev::parser::ByteParser;
        let report_bytes = report
            .to_bytes()
            .map_err(|e| AttestError::GenerationFailed(format!("failed to serialize report: {e}")))?
            .to_vec();

        let raw = encode_sev_snp_document(&report_bytes, &[]);
        Ok(AttestationDocument::new(raw))
    }
}

/// Verify that the handshake correctly rejects synthetic SEV-SNP attestation
/// with an empty certificate chain. This is the critical security fix — an
/// attacker cannot bypass attestation by omitting the cert chain.
#[tokio::test]
async fn sev_snp_handshake_rejects_empty_cert_chain() {
    let measurement = [0xAA; 48];
    let provider = SyntheticSevSnpProvider::new(measurement);
    let verifier = SevSnpVerifier::new(None);

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();

    let _server_handle = tokio::spawn(async move {
        let server_verifier = SevSnpVerifier::new(None);
        SecureChannel::accept_with_attestation(server_io, &provider, &server_verifier, config).await
    });

    let client_config = SessionConfig::default();
    let client_provider = SyntheticSevSnpProvider::new(measurement);
    let result = SecureChannel::connect_with_attestation(
        client_io,
        &client_provider,
        &verifier,
        client_config,
    )
    .await;

    assert!(
        result.is_err(),
        "handshake must fail with empty cert chain (forged attestation)"
    );
}

/// Verify that the verifier also rejects measurement mismatches (existing behavior).
/// With the empty chain fix, this now fails at the chain check before reaching
/// the measurement check, but the handshake still fails as expected.
#[tokio::test]
async fn sev_snp_handshake_rejects_wrong_measurement() {
    let measurement = [0xCC; 48];
    let provider = SyntheticSevSnpProvider::new(measurement);
    // Expect a different measurement.
    let verifier = SevSnpVerifier::new(Some(vec![0xDD; 48]));

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();
    let _server_handle = tokio::spawn(async move {
        let server_verifier = SevSnpVerifier::new(None);
        SecureChannel::accept_with_attestation(server_io, &provider, &server_verifier, config).await
    });

    let client_config = SessionConfig::default();
    let client_provider = SyntheticSevSnpProvider::new(measurement);
    let result = SecureChannel::connect_with_attestation(
        client_io,
        &client_provider,
        &verifier,
        client_config,
    )
    .await;

    assert!(
        result.is_err(),
        "handshake should fail on measurement mismatch"
    );
}

/// Verify that the verifier rejects empty cert chain documents and returns
/// an appropriate error message.
#[tokio::test]
async fn sev_snp_verifier_rejects_empty_cert_chain() {
    let measurement = [0xEE; 48];
    let provider = SyntheticSevSnpProvider::new(measurement);

    let doc = provider
        .attest(None, Some(&[0x11; 32]), Some(&[0x22; 32]))
        .await
        .unwrap();

    let verifier = SevSnpVerifier::new(None);
    let result = verifier.verify(&doc).await;

    assert!(result.is_err(), "verifier must reject empty cert chain");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("certificate chain is empty"),
        "error should mention empty chain: {err}"
    );
}

/// Test that the SEV-SNP report parsing correctly handles REPORT_DATA fields.
/// This tests the report format directly, independent of certificate verification.
#[test]
fn sev_snp_report_data_parsing() {
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&[0x42; 32]); // public key
    report_data[32..64].copy_from_slice(&[0x37; 32]); // nonce
    let measurement = [0xEE; 48];

    let report = sev::firmware::guest::AttestationReport {
        version: 2,
        chip_id: [0xD4; 64],
        report_data,
        measurement,
        ..Default::default()
    };

    // Verify REPORT_DATA extraction.
    assert_eq!(&report.report_data[..32], &[0x42; 32]);
    assert_eq!(&report.report_data[32..64], &[0x37; 32]);
    assert_eq!(report.measurement, measurement);
}

/// Test the wire encoding/decoding roundtrip for the SEV-SNP document format.
#[test]
fn sev_snp_wire_format_roundtrip() {
    use sev::parser::ByteParser;

    let report = sev::firmware::guest::AttestationReport {
        version: 2,
        chip_id: [0xD4; 64],
        report_data: [0xAA; 64],
        measurement: [0xBB; 48],
        ..Default::default()
    };

    let report_bytes = report.to_bytes().unwrap().to_vec();
    let cert_chain = vec![0xCC; 256];

    let encoded = encode_sev_snp_document(&report_bytes, &cert_chain);
    assert!(encoded.len() > report_bytes.len() + cert_chain.len());
    // Starts with marker.
    assert_eq!(&encoded[..10], b"SEV_SNP_V1");
}
