use bytes::Bytes;

use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::frame::tensor::{DType, TensorRef};
use confidential_ml_transport::{MockProvider, MockVerifier, SessionConfig};

/// Full handshake + encrypted data exchange over in-memory duplex.
#[tokio::test]
async fn full_session_data_exchange() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let config = SessionConfig::default();

    // Run client and server handshakes concurrently.
    let server_handle = tokio::spawn(async move {
        let mut channel =
            SecureChannel::accept_with_attestation(server_transport, &provider, config)
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
        let config = SessionConfig::default();
        let mut channel =
            SecureChannel::connect_with_attestation(client_transport, &verifier, config)
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
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
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
        assert!(matches!(msg, Message::Heartbeat));

        channel.heartbeat().await.unwrap();

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

        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Heartbeat));

        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

/// Test multiple data messages in sequence.
#[tokio::test]
async fn session_multiple_messages() {
    let (client_transport, server_transport) = tokio::io::duplex(65536);

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let n_messages = 100;

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
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
        let mut channel = SecureChannel::connect_with_attestation(
            client_transport,
            &verifier,
            SessionConfig::default(),
        )
        .await
        .unwrap();

        for i in 0..n_messages {
            let payload = format!("message-{i}");
            channel
                .send(Bytes::from(payload))
                .await
                .unwrap();
        }

        channel.shutdown().await.unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}
