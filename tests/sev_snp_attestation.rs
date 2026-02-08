#![cfg(feature = "sev-snp")]

use async_trait::async_trait;
use bytes::Bytes;
use confidential_ml_transport::attestation::sev::{encode_sev_snp_document, SevSnpVerifier};
use confidential_ml_transport::attestation::types::AttestationDocument;
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{AttestationProvider, AttestationVerifier};

/// A synthetic attestation provider that builds SEV-SNP-format documents
/// from pre-built report bytes. Used for testing the verifier and handshake
/// integration without real SEV-SNP hardware.
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

#[tokio::test]
async fn sev_snp_handshake_integration() {
    let measurement = [0xAA; 48];
    let provider = SyntheticSevSnpProvider::new(measurement);
    let verifier = SevSnpVerifier::new(None);

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();

    let server_handle = tokio::spawn(async move {
        SecureChannel::accept_with_attestation(server_io, &provider, config).await
    });

    let client_config = SessionConfig::default();
    let mut client = SecureChannel::connect_with_attestation(client_io, &verifier, client_config)
        .await
        .expect("client handshake should succeed");

    let mut server = server_handle
        .await
        .expect("server task should not panic")
        .expect("server handshake should succeed");

    // Exchange data over the attested channel.
    client
        .send(Bytes::from_static(b"hello from sev-snp client"))
        .await
        .unwrap();

    match server.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"hello from sev-snp client"),
        other => panic!("expected Data, got {:?}", other),
    }

    server
        .send(Bytes::from_static(b"hello from sev-snp server"))
        .await
        .unwrap();

    match client.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"hello from sev-snp server"),
        other => panic!("expected Data, got {:?}", other),
    }
}

#[tokio::test]
async fn sev_snp_handshake_with_measurement_verification() {
    let measurement = [0xBB; 48];
    let provider = SyntheticSevSnpProvider::new(measurement);
    let verifier = SevSnpVerifier::new(Some(measurement.to_vec()));

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();
    let server_handle = tokio::spawn(async move {
        SecureChannel::accept_with_attestation(server_io, &provider, config).await
    });

    let client_config = SessionConfig::default();
    let mut client = SecureChannel::connect_with_attestation(client_io, &verifier, client_config)
        .await
        .expect("handshake with correct measurement should succeed");

    let mut server = server_handle.await.unwrap().unwrap();

    // Verify bidirectional communication works.
    client.send(Bytes::from_static(b"ping")).await.unwrap();
    match server.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"ping"),
        other => panic!("expected Data, got {:?}", other),
    }
}

#[tokio::test]
async fn sev_snp_handshake_rejects_wrong_measurement() {
    let measurement = [0xCC; 48];
    let provider = SyntheticSevSnpProvider::new(measurement);
    // Expect a different measurement.
    let verifier = SevSnpVerifier::new(Some(vec![0xDD; 48]));

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();
    let _server_handle = tokio::spawn(async move {
        SecureChannel::accept_with_attestation(server_io, &provider, config).await
    });

    let client_config = SessionConfig::default();
    let result =
        SecureChannel::connect_with_attestation(client_io, &verifier, client_config).await;

    assert!(result.is_err(), "handshake should fail on measurement mismatch");
}

#[tokio::test]
async fn sev_snp_measurement_extracted_by_verifier() {
    // Verify that the verifier correctly maps MEASUREMENT to measurements[0].
    let measurement = [0xEE; 48];
    let provider = SyntheticSevSnpProvider::new(measurement);

    let doc = provider
        .attest(None, Some(&[0x11; 32]), Some(&[0x22; 32]))
        .await
        .unwrap();

    let verifier = SevSnpVerifier::new(None);
    let verified = verifier.verify(&doc).await.unwrap();

    assert_eq!(verified.measurements.len(), 1);
    assert!(verified.measurements.contains_key(&0));
    assert_eq!(verified.measurements[&0], measurement.to_vec());
    assert_eq!(verified.public_key.as_deref(), Some([0x22; 32].as_ref()));
    assert_eq!(verified.nonce.as_deref(), Some([0x11; 32].as_ref()));
}
