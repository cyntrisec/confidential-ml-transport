#![cfg(feature = "mock")]

use bytes::Bytes;

use confidential_ml_transport::frame::tensor::{DType, TensorRef};
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::{MockProvider, MockVerifier, SessionConfig};

/// Full handshake + encrypted data exchange over in-memory duplex.
#[tokio::test]
async fn full_session_data_exchange() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let config = SessionConfig::development();

    // Run client and server handshakes concurrently.
    let server_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel =
            SecureChannel::accept_with_attestation(server_transport, &provider, &verifier, config)
                .await
                .expect("server handshake failed");

        // Receive a message.
        let msg = channel.recv().await.expect("server recv failed");
        match msg {
            Message::Data(data) => {
                assert_eq!(&data[..], b"hello from client");
            }
            other => panic!("expected Data, got {:?}", other),
        }

        // Send a response.
        channel
            .send(Bytes::from_static(b"hello from server"))
            .await
            .expect("server send failed");

        // Receive shutdown.
        let msg = channel.recv().await.expect("server recv shutdown failed");
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let config = SessionConfig::development();
        let mut channel =
            SecureChannel::connect_with_attestation(client_transport, &provider, &verifier, config)
                .await
                .expect("client handshake failed");

        // Send a message.
        channel
            .send(Bytes::from_static(b"hello from client"))
            .await
            .expect("client send failed");

        // Receive response.
        let msg = channel.recv().await.expect("client recv failed");
        match msg {
            Message::Data(data) => {
                assert_eq!(&data[..], b"hello from server");
            }
            other => panic!("expected Data, got {:?}", other),
        }

        // Send shutdown.
        channel.shutdown().await.expect("client shutdown failed");
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

/// Test sending tensors through an encrypted session.
#[tokio::test]
async fn session_tensor_exchange() {
    let (client_transport, server_transport) = tokio::io::duplex(65536);

    let server_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        let msg = channel.recv().await.unwrap();
        match msg {
            Message::Tensor(tensor) => {
                assert_eq!(tensor.name, "embedding");
                assert_eq!(tensor.dtype, DType::F32);
                assert_eq!(tensor.shape, vec![2, 4]);
                assert_eq!(tensor.data.len(), 32); // 2*4*4 bytes
            }
            other => panic!("expected Tensor, got {:?}", other),
        }

        channel.shutdown().await.unwrap();
    });

    let client_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        let data = vec![0u8; 32]; // [2, 4] f32
        let tensor = TensorRef {
            name: "embedding",
            dtype: DType::F32,
            shape: &[2, 4],
            data: &data,
        };
        channel.send_tensor(tensor).await.unwrap();

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

/// Test heartbeat exchange.
#[tokio::test]
async fn session_heartbeat() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let server_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Heartbeat));

        channel.heartbeat().await.unwrap();

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        channel.heartbeat().await.unwrap();

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Heartbeat));

        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

/// Test that production profile rejects handshake when measurements are None.
#[tokio::test]
async fn production_profile_rejects_empty_measurements() {
    // Default builder is Production profile — no measurements set.
    let config = SessionConfig::builder().build().unwrap();

    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let verifier = MockVerifier::new();
    let provider = MockProvider::new();

    // Initiator should fail before even starting the handshake.
    let result = SecureChannel::connect_with_attestation(
        client_transport,
        &provider,
        &verifier,
        config.clone(),
    )
    .await;
    assert!(
        result.is_err(),
        "expected connect to fail in production profile without measurements"
    );
    let err = result.err().unwrap();
    assert!(
        format!("{err}").contains("production security profile"),
        "expected production profile error, got: {err}"
    );

    // Responder should also fail.
    let result =
        SecureChannel::accept_with_attestation(server_transport, &provider, &verifier, config)
            .await;
    assert!(
        result.is_err(),
        "expected accept to fail in production profile without measurements"
    );
    let err = result.err().unwrap();
    assert!(
        format!("{err}").contains("production security profile"),
        "expected production profile error, got: {err}"
    );
}

/// Test that the legacy require_measurements flag still works in Development mode.
#[tokio::test]
async fn legacy_require_measurements_in_dev_mode_rejects() {
    // Development profile + explicit require_measurements = true should still reject.
    let config = SessionConfig::builder()
        .security_profile(confidential_ml_transport::SecurityProfile::Development)
        .build()
        .unwrap();

    // After security_profile(Development), require_measurements is false.
    // Now set it back to true explicitly.
    let mut config = config;
    config.require_measurements = true;

    let (client_transport, _server_transport) = tokio::io::duplex(16384);

    let verifier = MockVerifier::new();
    let provider = MockProvider::new();

    let result = SecureChannel::connect_with_attestation(
        client_transport,
        &provider,
        &verifier,
        config,
    )
    .await;
    assert!(
        result.is_err(),
        "expected connect to fail with require_measurements in dev mode"
    );
    let err = result.err().unwrap();
    assert!(
        format!("{err}").contains("require_measurements"),
        "expected require_measurements error, got: {err}"
    );
}

/// Test that Development profile allows empty measurements.
#[tokio::test]
async fn development_profile_allows_empty_measurements() {
    let config = SessionConfig::development();

    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let server_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .expect("server handshake should succeed in dev mode")
    });

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let _channel = SecureChannel::connect_with_attestation(
        client_transport,
        &provider,
        &verifier,
        config,
    )
    .await
    .expect("client handshake should succeed in dev mode");

    let _server_channel = server_handle.await.unwrap();
}

/// Test that Production profile with measurements succeeds.
#[tokio::test]
async fn production_profile_with_measurements_succeeds() {
    use std::collections::BTreeMap;
    use confidential_ml_transport::attestation::types::ExpectedMeasurements;

    let verifier = confidential_ml_transport::MockVerifierWithMeasurements::new(
        BTreeMap::from([(0, vec![0xAA; 32])]),
    );

    let mut expected = BTreeMap::new();
    expected.insert(0, vec![0xAA; 32]);

    // Production profile with measurements provided.
    let config = SessionConfig::builder()
        .expected_measurements(ExpectedMeasurements::new(expected))
        .build()
        .unwrap();

    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let server_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let server_verifier = MockVerifier::new();
        SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            &server_verifier,
            SessionConfig::development(),
        )
        .await
        .expect("server handshake should succeed")
    });

    let provider = MockProvider::new();
    let _channel = SecureChannel::connect_with_attestation(
        client_transport,
        &provider,
        &verifier,
        config,
    )
    .await
    .expect("client handshake should succeed in production mode with measurements");

    let _server_channel = server_handle.await.unwrap();
}

/// Test multiple data messages in sequence.
#[tokio::test]
async fn session_multiple_messages() {
    let (client_transport, server_transport) = tokio::io::duplex(65536);

    let n_messages = 100;

    let server_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        for i in 0..n_messages {
            let msg = channel.recv().await.unwrap();
            match msg {
                Message::Data(data) => {
                    let expected = format!("message-{i}");
                    assert_eq!(&data[..], expected.as_bytes());
                }
                other => panic!("expected Data, got {:?}", other),
            }
        }

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let client_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        for i in 0..n_messages {
            let payload = format!("message-{i}");
            channel.send(Bytes::from(payload)).await.unwrap();
        }

        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

/// Mutual attestation: both sides receive peer_attestation.
#[tokio::test]
async fn mutual_attestation_both_sides_receive_attestation() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let server_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        // Responder should have initiator's attestation.
        let peer_att = channel.peer_attestation();
        assert!(
            peer_att.is_some(),
            "responder should receive initiator attestation"
        );
        let att = peer_att.unwrap();
        assert!(
            att.public_key.is_some(),
            "attestation should contain public key"
        );

        channel
    });

    let client_handle = tokio::spawn(async move {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let channel = SecureChannel::connect_with_attestation(
            client_transport,
            &provider,
            &verifier,
            SessionConfig::development(),
        )
        .await
        .unwrap();

        // Initiator should have responder's attestation.
        let peer_att = channel.peer_attestation();
        assert!(
            peer_att.is_some(),
            "initiator should receive responder attestation"
        );
        let att = peer_att.unwrap();
        assert!(
            att.public_key.is_some(),
            "attestation should contain public key"
        );

        channel
    });

    let _server_ch = server_handle.await.unwrap();
    let _client_ch = client_handle.await.unwrap();
}
