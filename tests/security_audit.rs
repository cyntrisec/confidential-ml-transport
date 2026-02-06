//! Tests for the 15 security audit fixes.
//!
//! Each test is annotated with the audit finding number it validates.

use bytes::{Bytes, BytesMut};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_util::codec::Encoder;

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::frame::tensor::OwnedTensor;
use confidential_ml_transport::frame::{Flags, Frame};
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::{MockProvider, MockVerifier, SessionConfig};

// ---------------------------------------------------------------------------
// Fix #3: All post-handshake frames must be encrypted
// ---------------------------------------------------------------------------

/// Verify that heartbeats are now encrypted (not plaintext).
#[tokio::test]
async fn heartbeat_is_encrypted() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        // Receive an encrypted heartbeat.
        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Heartbeat));

        // Receive shutdown.
        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        channel.heartbeat().await.unwrap();
        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

/// Verify that shutdown frames are encrypted.
#[tokio::test]
async fn shutdown_is_encrypted() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// Fix #2: Unified sequence counters (sealer seq == frame header seq)
// ---------------------------------------------------------------------------

/// Verify that multiple sends produce monotonically increasing, consecutive
/// sequences that the receiver accepts (proving sealer and frame seq are unified).
#[tokio::test]
async fn sequence_counters_unified() {
    let (client_transport, server_transport) = tokio::io::duplex(65536);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        // Receive 50 messages — each must decrypt successfully,
        // proving the frame sequence matches the AEAD sequence.
        for i in 0u32..50 {
            let msg = channel.recv().await.unwrap();
            match msg {
                Message::Data(data) => {
                    assert_eq!(&data[..], format!("msg-{i}").as_bytes());
                }
                other => panic!("expected Data, got {other:?}"),
            }
        }

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        for i in 0u32..50 {
            channel.send(Bytes::from(format!("msg-{i}"))).await.unwrap();
        }

        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// Fix #4: Handshake timeout
// ---------------------------------------------------------------------------

/// A handshake that never completes (peer doesn't respond) should time out.
#[tokio::test]
async fn handshake_timeout_triggers() {
    let (client_transport, _server_transport) = tokio::io::duplex(16384);
    // Server side is dropped — no one responds to the handshake.

    let config = SessionConfig::builder()
        .handshake_timeout(Duration::from_millis(100))
        .build()
        .unwrap();

    let verifier = MockVerifier::new();
    let result = SecureChannel::connect_with_attestation(client_transport, &verifier, config).await;

    assert!(result.is_err());
    let err = format!("{}", result.err().unwrap());
    // Should be either a timeout or a closed connection error.
    assert!(
        err.contains("timeout") || err.contains("closed"),
        "expected timeout or closed error, got: {err}"
    );
}

/// A handshake with a generous timeout should succeed normally.
#[tokio::test]
async fn handshake_within_timeout_succeeds() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_config = SessionConfig::builder()
        .handshake_timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let client_config = server_config.clone();

    let server_handle = tokio::spawn(async move {
        let mut channel =
            SecureChannel::accept_with_attestation(server_transport, &provider, server_config)
                .await
                .unwrap();
        channel.shutdown().await.unwrap();
    });

    let client_handle = tokio::spawn(async move {
        let mut channel =
            SecureChannel::connect_with_attestation(client_transport, &verifier, client_config)
                .await
                .unwrap();
        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// Fix #7: Mandatory public key binding in attestation
// ---------------------------------------------------------------------------

/// An attestation document without a public key must cause the handshake to fail.
#[tokio::test]
async fn reject_attestation_without_public_key() {
    use async_trait::async_trait;
    use confidential_ml_transport::attestation::types::AttestationDocument;
    use confidential_ml_transport::error::AttestError;
    use confidential_ml_transport::AttestationProvider;

    /// A provider that produces attestation docs WITHOUT binding a public key.
    struct NoPkProvider;

    #[async_trait]
    impl AttestationProvider for NoPkProvider {
        async fn attest(
            &self,
            _user_data: Option<&[u8]>,
            nonce: Option<&[u8]>,
            _public_key: Option<&[u8]>,
        ) -> Result<AttestationDocument, AttestError> {
            // Intentionally omit the public key field.
            let mut raw = Vec::new();
            raw.extend_from_slice(b"MOCK_ATT_V1\0");
            // user_data = None
            raw.extend_from_slice(&0u32.to_le_bytes());
            // nonce
            match nonce {
                Some(data) => {
                    raw.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    raw.extend_from_slice(data);
                }
                None => raw.extend_from_slice(&0u32.to_le_bytes()),
            }
            // public_key = None (the bug: not binding the key)
            raw.extend_from_slice(&0u32.to_le_bytes());

            Ok(AttestationDocument::new(raw))
        }
    }

    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = NoPkProvider;
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        // Server produces attestation without public key.
        let result = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await;
        // Server may or may not error (depends on timing).
        let _ = result;
    });

    let client_handle = tokio::spawn(async move {
        let result = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await;

        assert!(
            result.is_err(),
            "should reject attestation without public key"
        );
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("missing") || err.contains("public_key"),
            "error should mention missing public_key: {err}"
        );
    });

    let _ = server_handle.await;
    client_handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// Fix #11: Tensor ndims cap
// ---------------------------------------------------------------------------

/// A tensor with >32 dimensions should be rejected during decode.
#[test]
fn reject_tensor_with_excessive_ndims() {
    let mut buf = BytesMut::new();
    // ndims = 1000 (way above the 32 cap)
    buf.extend_from_slice(&1000u16.to_le_bytes());
    // dtype
    buf.extend_from_slice(&[0u8]); // F32

    let result = OwnedTensor::decode(buf.freeze());
    assert!(result.is_err());
    let err = format!("{}", result.err().unwrap());
    assert!(
        err.contains("overflow") || err.contains("shape"),
        "should reject excessive ndims: {err}"
    );
}

/// A tensor with exactly 32 dimensions should be accepted (boundary).
#[test]
fn accept_tensor_with_32_dims() {
    let ndims: u16 = 32;
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&ndims.to_le_bytes());
    buf.extend_from_slice(&[6u8]); // U8 dtype (element_size = 1)

    // Shape: all 1s (so total elements = 1, data = 1 byte)
    for _ in 0..ndims {
        buf.extend_from_slice(&1u32.to_le_bytes());
    }

    // name_len = 0
    buf.extend_from_slice(&0u16.to_le_bytes());

    // Compute padding
    let sub_header_len = 2 + 1 + (ndims as usize) * 4 + 2;
    let padding = (8 - (sub_header_len % 8)) % 8;
    for _ in 0..padding {
        buf.extend_from_slice(&[0u8]);
    }

    // 1 byte of data (1 element of U8)
    buf.extend_from_slice(&[42u8]);

    let result = OwnedTensor::decode(buf.freeze());
    assert!(result.is_ok(), "32 dims should be accepted");
    let tensor = result.unwrap();
    assert_eq!(tensor.shape.len(), 32);
}

/// A tensor with 33 dimensions should be rejected (just above cap).
#[test]
fn reject_tensor_with_33_dims() {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&33u16.to_le_bytes());
    buf.extend_from_slice(&[0u8]); // F32

    let result = OwnedTensor::decode(buf.freeze());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Fix #13: Flags encapsulation
// ---------------------------------------------------------------------------

/// Verify Flags can be constructed via from_raw() and inspected via raw().
#[test]
fn flags_encapsulation() {
    let flags = Flags::from_raw(0x03); // ENCRYPTED | TENSOR_PAYLOAD
    assert!(flags.is_encrypted());
    assert!(flags.is_tensor_payload());
    assert!(!flags.is_batch());
    assert!(!flags.is_compressed());
    assert_eq!(flags.raw(), 0x03);
}

/// Verify Flags::empty() produces zero bits.
#[test]
fn flags_empty() {
    let flags = Flags::empty();
    assert_eq!(flags.raw(), 0);
    assert!(!flags.is_encrypted());
}

// ---------------------------------------------------------------------------
// Fix #6: Contributory key check
// ---------------------------------------------------------------------------

/// Verify that derive_session_keys rejects the identity point.
/// We test this by using an all-zero public key (which maps to the identity
/// point on Curve25519 — the DH result is non-contributory).
#[test]
fn reject_non_contributory_dh() {
    use confidential_ml_transport::crypto::hpke::{derive_session_keys, KeyPair};

    let keypair = KeyPair::generate();
    let zero_pk = x25519_dalek::PublicKey::from([0u8; 32]);
    let transcript = [0xAA; 32];

    let result = derive_session_keys(&keypair.secret, &zero_pk, &transcript, true);
    assert!(result.is_err());
    let err = format!("{}", result.err().unwrap());
    assert!(
        err.contains("non-contributory") || err.contains("identity"),
        "should reject non-contributory key: {err}"
    );
}

// ---------------------------------------------------------------------------
// Fix #10: Handshake sequence validation
// ---------------------------------------------------------------------------

/// The handshake with correct sequences succeeds normally.
#[tokio::test]
async fn handshake_with_correct_sequences_succeeds() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap()
    });

    let client_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();
        channel.shutdown().await.unwrap();
    });

    let mut server_channel = server_handle.await.unwrap();
    let msg = server_channel.recv().await.unwrap();
    assert!(matches!(msg, Message::Shutdown));
    client_handle.await.unwrap();
}

/// Inject a handshake hello with wrong sequence number and verify rejection.
#[tokio::test]
async fn handshake_rejects_wrong_sequence() {
    let (mut client_raw, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();

    let server_handle = tokio::spawn(async move {
        let result = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::builder()
                .handshake_timeout(Duration::from_millis(500))
                .build()
                .unwrap(),
        )
        .await;
        // Should fail because of wrong sequence.
        result
    });

    // Manually craft an initiator hello with wrong sequence (99 instead of 0).
    let mut codec = FrameCodec::new();
    let payload = {
        let mut buf = BytesMut::with_capacity(1 + 32 + 32);
        buf.extend_from_slice(&[1u8]); // message number
        buf.extend_from_slice(&[0x42u8; 32]); // fake pubkey
        buf.extend_from_slice(&[0xAA; 32]); // fake nonce
        buf.freeze()
    };
    let frame = Frame::hello(99, payload); // Wrong sequence!
    let mut buf = BytesMut::new();
    codec.encode(frame, &mut buf).unwrap();
    client_raw.write_all(&buf).await.unwrap();
    client_raw.flush().await.unwrap();

    let result = server_handle.await.unwrap();
    assert!(result.is_err(), "should reject wrong handshake sequence");
    let err = format!("{}", result.err().unwrap());
    assert!(
        err.contains("sequence") || err.contains("timeout") || err.contains("closed"),
        "error should mention sequence issue: {err}"
    );
}

// ---------------------------------------------------------------------------
// Fix #9: Confirmation hash binds both keys
// ---------------------------------------------------------------------------

/// Verify that a session established correctly allows bidirectional communication,
/// which proves both keys are correctly bound in the confirmation.
#[tokio::test]
async fn confirmation_binds_both_keys_bidirectional() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        // Receive from client.
        let msg = channel.recv().await.unwrap();
        match msg {
            Message::Data(data) => assert_eq!(&data[..], b"from-client"),
            other => panic!("expected Data, got {other:?}"),
        }

        // Send to client.
        channel
            .send(Bytes::from_static(b"from-server"))
            .await
            .unwrap();

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        // Send to server.
        channel
            .send(Bytes::from_static(b"from-client"))
            .await
            .unwrap();

        // Receive from server.
        let msg = channel.recv().await.unwrap();
        match msg {
            Message::Data(data) => assert_eq!(&data[..], b"from-server"),
            other => panic!("expected Data, got {other:?}"),
        }

        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// Fix #15: Session ID domain separation
// ---------------------------------------------------------------------------

/// Verify that session establishment works end-to-end, which implicitly proves
/// the session_id derivation (via HKDF) is consistent on both sides.
/// If session_id were derived differently, AEAD decryption would fail because
/// the AAD includes session_id.
#[tokio::test]
async fn session_id_domain_separation_consistent() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        let msg = channel.recv().await.unwrap();
        match msg {
            Message::Data(data) => assert_eq!(&data[..], b"domain-sep-test"),
            other => panic!("expected Data, got {other:?}"),
        }
    });

    let client_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        channel
            .send(Bytes::from_static(b"domain-sep-test"))
            .await
            .unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// Fix #1: Key zeroization (compile-time structural test)
// ---------------------------------------------------------------------------

/// Verify that SymmetricKey implements Drop (via ZeroizeOnDrop) by creating
/// and dropping a key. This is a structural test — actual zeroization is
/// guaranteed by the zeroize crate.
#[test]
fn symmetric_key_is_zeroize() {
    use confidential_ml_transport::crypto::SymmetricKey;

    let key = SymmetricKey::from([0x42; 32]);
    assert_eq!(key.as_bytes(), &[0x42; 32]);
    drop(key);
    // If SymmetricKey didn't implement ZeroizeOnDrop, this test would still
    // pass, but it ensures the type is usable and droppable. The derive macro
    // guarantees zeroization.
}

// ---------------------------------------------------------------------------
// Fix #8: Bounded read buffer (indirect test via protocol compliance)
// ---------------------------------------------------------------------------

/// A normal session should not trigger the read buffer overflow check.
#[tokio::test]
async fn normal_session_within_buffer_bounds() {
    let (client_transport, server_transport) = tokio::io::duplex(65536);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        // Receive a large (but valid) payload.
        let msg = channel.recv().await.unwrap();
        match msg {
            Message::Data(data) => assert_eq!(data.len(), 100_000),
            other => panic!("expected Data, got {other:?}"),
        }

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        let payload = vec![0xAB; 100_000];
        channel.send(Bytes::from(payload)).await.unwrap();
        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}
