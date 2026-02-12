#![cfg(feature = "tdx")]

use async_trait::async_trait;
use bytes::Bytes;
use confidential_ml_transport::attestation::tdx::{
    build_synthetic_tdx_quote, encode_tdx_document, TdxVerifier,
};
use confidential_ml_transport::attestation::types::AttestationDocument;
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{AttestationProvider, AttestationVerifier};

/// A synthetic attestation provider that builds TDX-format documents
/// from pre-built quote bytes. Used for testing the verifier and handshake
/// integration without real TDX hardware.
struct SyntheticTdxProvider {
    mrtd: [u8; 48],
    rtmrs: [[u8; 48]; 4],
}

impl SyntheticTdxProvider {
    fn new(mrtd: [u8; 48]) -> Self {
        Self {
            mrtd,
            rtmrs: [[0u8; 48]; 4],
        }
    }
}

#[async_trait]
impl AttestationProvider for SyntheticTdxProvider {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        // Build REPORTDATA: pk[0..32] || nonce[32..64]
        let mut reportdata = [0u8; 64];
        if let Some(pk) = public_key {
            if pk.len() == 32 {
                reportdata[..32].copy_from_slice(pk);
            }
        }
        if let Some(n) = nonce {
            if n.len() == 32 {
                reportdata[32..64].copy_from_slice(n);
            }
        }

        let quote = build_synthetic_tdx_quote(reportdata, self.mrtd, self.rtmrs);
        let raw = encode_tdx_document(&quote);
        Ok(AttestationDocument::new(raw))
    }
}

#[tokio::test]
async fn tdx_handshake_integration() {
    let mrtd = [0xAA; 48];
    let provider = SyntheticTdxProvider::new(mrtd);
    let verifier = TdxVerifier::new(None);

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();

    let server_provider = SyntheticTdxProvider::new(mrtd);
    let server_verifier = TdxVerifier::new(None);
    let server_handle = tokio::spawn(async move {
        SecureChannel::accept_with_attestation(server_io, &server_provider, &server_verifier, config).await
    });

    let client_config = SessionConfig::default();
    let mut client = SecureChannel::connect_with_attestation(client_io, &provider, &verifier, client_config)
        .await
        .expect("client handshake should succeed");

    let mut server = server_handle
        .await
        .expect("server task should not panic")
        .expect("server handshake should succeed");

    // Exchange data over the attested channel.
    client
        .send(Bytes::from_static(b"hello from tdx client"))
        .await
        .unwrap();

    match server.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"hello from tdx client"),
        other => panic!("expected Data, got {:?}", other),
    }

    server
        .send(Bytes::from_static(b"hello from tdx server"))
        .await
        .unwrap();

    match client.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"hello from tdx server"),
        other => panic!("expected Data, got {:?}", other),
    }
}

#[tokio::test]
async fn tdx_handshake_with_measurement_verification() {
    let mrtd = [0xBB; 48];
    let provider = SyntheticTdxProvider::new(mrtd);
    let verifier = TdxVerifier::new(Some(mrtd.to_vec()));

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();
    let server_provider = SyntheticTdxProvider::new(mrtd);
    let server_verifier = TdxVerifier::new(Some(mrtd.to_vec()));
    let server_handle = tokio::spawn(async move {
        SecureChannel::accept_with_attestation(server_io, &server_provider, &server_verifier, config).await
    });

    let client_config = SessionConfig::default();
    let mut client = SecureChannel::connect_with_attestation(client_io, &provider, &verifier, client_config)
        .await
        .expect("handshake with correct MRTD should succeed");

    let mut server = server_handle.await.unwrap().unwrap();

    // Verify bidirectional communication works.
    client.send(Bytes::from_static(b"ping")).await.unwrap();
    match server.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"ping"),
        other => panic!("expected Data, got {:?}", other),
    }
}

#[tokio::test]
async fn tdx_handshake_rejects_wrong_measurement() {
    let mrtd = [0xCC; 48];
    let provider = SyntheticTdxProvider::new(mrtd);
    // Expect a different MRTD.
    let verifier = TdxVerifier::new(Some(vec![0xDD; 48]));

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();
    let server_provider = SyntheticTdxProvider::new(mrtd);
    let server_verifier = TdxVerifier::new(Some(vec![0xDD; 48]));
    let _server_handle = tokio::spawn(async move {
        SecureChannel::accept_with_attestation(server_io, &server_provider, &server_verifier, config).await
    });

    let client_config = SessionConfig::default();
    let result = SecureChannel::connect_with_attestation(client_io, &provider, &verifier, client_config).await;

    assert!(result.is_err(), "handshake should fail on MRTD mismatch");
}

#[tokio::test]
async fn tdx_measurement_extracted_by_verifier() {
    let mrtd = [0xEE; 48];
    let provider = SyntheticTdxProvider::new(mrtd);

    let doc = provider
        .attest(None, Some(&[0x11; 32]), Some(&[0x22; 32]))
        .await
        .unwrap();

    let verifier = TdxVerifier::new(None);
    let verified = verifier.verify(&doc).await.unwrap();

    assert_eq!(verified.measurements.len(), 5); // MRTD + 4 RTMRs
    assert!(verified.measurements.contains_key(&0));
    assert_eq!(verified.measurements[&0], mrtd.to_vec());
    assert_eq!(verified.public_key.as_deref(), Some([0x22; 32].as_ref()));
    assert_eq!(verified.nonce.as_deref(), Some([0x11; 32].as_ref()));
}
