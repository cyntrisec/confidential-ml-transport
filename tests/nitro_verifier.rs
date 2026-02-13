#![cfg(feature = "nitro")]

use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use confidential_ml_transport::attestation::nitro::{encode_attestation_doc, sign_cose_with_key};
use confidential_ml_transport::attestation::types::AttestationDocument;
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{AttestationProvider, MockProvider, MockVerifier, NitroVerifier};
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509};

/// Generate a self-signed P-384 CA certificate.
fn generate_test_ca() -> (EcKey<openssl::pkey::Private>, X509) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Nitro CA").unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    let bc = BasicConstraints::new().critical().ca().build().unwrap();
    builder.append_extension(bc).unwrap();
    let ku = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    builder.append_extension(ku).unwrap();

    builder.sign(&pkey, MessageDigest::sha384()).unwrap();
    (ec_key, builder.build())
}

/// Generate a leaf certificate signed by the given CA.
fn generate_test_leaf(
    ca_key: &EcKey<openssl::pkey::Private>,
    ca_cert: &X509,
) -> (EcKey<openssl::pkey::Private>, X509) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Nitro Leaf").unwrap();
    let name = name.build();

    let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    let ku = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .unwrap();
    builder.append_extension(ku).unwrap();

    builder.sign(&ca_pkey, MessageDigest::sha384()).unwrap();
    (ec_key, builder.build())
}

/// A mock attestation provider that returns pre-built COSE_Sign1 documents
/// signed with a synthetic P-384 key, for testing NitroVerifier integration
/// with the SecureChannel handshake.
struct SyntheticNitroProvider {
    ca_cert: X509,
    leaf_key: EcKey<openssl::pkey::Private>,
    leaf_cert: X509,
    pcrs: BTreeMap<usize, Vec<u8>>,
}

impl SyntheticNitroProvider {
    fn new(
        ca_cert: X509,
        leaf_key: EcKey<openssl::pkey::Private>,
        leaf_cert: X509,
        pcrs: BTreeMap<usize, Vec<u8>>,
    ) -> Self {
        Self {
            ca_cert,
            leaf_key,
            leaf_cert,
            pcrs,
        }
    }
}

#[async_trait]
impl AttestationProvider for SyntheticNitroProvider {
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        let leaf_der = self.leaf_cert.to_der().map_err(|e| {
            AttestError::GenerationFailed(format!("failed to encode leaf cert: {e}"))
        })?;
        let ca_der = self
            .ca_cert
            .to_der()
            .map_err(|e| AttestError::GenerationFailed(format!("failed to encode CA cert: {e}")))?;

        let payload = encode_attestation_doc(
            "i-integration-test",
            "SHA384",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            &self.pcrs,
            &leaf_der,
            &[ca_der],
            public_key,
            user_data,
            nonce,
        );

        let raw = sign_cose_with_key(&self.leaf_key, &payload);
        Ok(AttestationDocument::new(raw))
    }
}

#[tokio::test]
async fn nitro_verifier_handshake_integration() {
    let (ca_key, ca_cert) = generate_test_ca();
    let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);

    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0xAA; 48]);
    pcrs.insert(1, vec![0xBB; 48]);
    pcrs.insert(2, vec![0xCC; 48]);

    let provider = SyntheticNitroProvider::new(ca_cert.clone(), leaf_key, leaf_cert, pcrs.clone());

    let ca_pem = ca_cert.to_pem().unwrap();
    let verifier = NitroVerifier::with_root_ca(&ca_pem, pcrs).unwrap();

    let (client_io, server_io) = tokio::io::duplex(32 * 1024);

    let config = SessionConfig::default();

    let server_handle = tokio::spawn(async move {
        let server_verifier = MockVerifier::new();
        SecureChannel::accept_with_attestation(server_io, &provider, &server_verifier, config).await
    });

    let client_provider = MockProvider::new();
    let client_config = SessionConfig::default();
    let mut client = SecureChannel::connect_with_attestation(
        client_io,
        &client_provider,
        &verifier,
        client_config,
    )
    .await
    .expect("client handshake should succeed");

    let mut server = server_handle
        .await
        .expect("server task should not panic")
        .expect("server handshake should succeed");

    // Exchange data over the attested channel.
    client
        .send(Bytes::from_static(b"hello from client"))
        .await
        .unwrap();

    match server.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"hello from client"),
        other => panic!("expected Data, got {:?}", other),
    }

    server
        .send(Bytes::from_static(b"hello from server"))
        .await
        .unwrap();

    match client.recv().await.unwrap() {
        Message::Data(data) => assert_eq!(&data[..], b"hello from server"),
        other => panic!("expected Data, got {:?}", other),
    }
}
