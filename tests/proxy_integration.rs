#![cfg(all(feature = "mock", feature = "tcp"))]
//! End-to-end integration test for the transparent proxy.
//!
//! Test flow:
//! 1. Start a plain TCP echo backend
//! 2. Start the server proxy (connects encrypted clients to the echo backend)
//! 3. Start the client proxy (accepts plain TCP and establishes encrypted channel)
//! 4. Connect a plain TCP client to the client proxy
//! 5. Send data and verify the echo response

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use confidential_ml_transport::proxy::client::{run_client_proxy, ClientProxyConfig};
use confidential_ml_transport::proxy::server::{run_server_proxy, ServerProxyConfig};
use confidential_ml_transport::{MockProvider, MockVerifier, SessionConfig};

/// Simple TCP echo server: reads data and writes it back.
async fn run_echo_backend(listener: TcpListener) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        stream.write_all(&buf[..n]).await.ok();
                        stream.flush().await.ok();
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

#[tokio::test]
async fn proxy_end_to_end_echo() {
    // 1. Start echo backend.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(run_echo_backend(echo_listener));

    // 2. Start server proxy.
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    drop(server_listener); // free the port for the proxy to bind

    let server_config = ServerProxyConfig {
        listen_addr: server_addr,
        backend_addr: echo_addr,
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let server_verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_server_proxy(server_config, provider, server_verifier));

    // Small delay for server proxy to start listening.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Start client proxy.
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_proxy_addr = client_listener.local_addr().unwrap();
    drop(client_listener); // free the port for the proxy to bind

    let client_config = ClientProxyConfig {
        listen_addr: client_proxy_addr,
        enclave_addr: server_addr,
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let client_provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_client_proxy(client_config, client_provider, verifier));

    // Small delay for client proxy to start listening.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Connect a plain TCP client.
    let mut client = tokio::net::TcpStream::connect(client_proxy_addr)
        .await
        .unwrap();
    client.set_nodelay(true).unwrap();

    // 5. Send and receive.
    let test_data = b"hello from plain TCP through encrypted tunnel";
    client.write_all(test_data).await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("timed out waiting for echo response")
        .unwrap();

    assert_eq!(&buf[..n], test_data);
}

#[tokio::test]
async fn proxy_client_disconnect_is_clean() {
    // Same setup as above but disconnect the client early.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(run_echo_backend(echo_listener));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    drop(server_listener);

    let server_config = ServerProxyConfig {
        listen_addr: server_addr,
        backend_addr: echo_addr,
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let server_verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_server_proxy(server_config, provider, server_verifier));

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_proxy_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let client_config = ClientProxyConfig {
        listen_addr: client_proxy_addr,
        enclave_addr: server_addr,
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let client_provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_client_proxy(client_config, client_provider, verifier));

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and immediately drop.
    {
        let mut client = tokio::net::TcpStream::connect(client_proxy_addr)
            .await
            .unwrap();
        client.write_all(b"hello").await.unwrap();
        // client dropped here
    }

    // Give the proxy time to handle disconnection without panicking.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// When the backend is unreachable, the server proxy should log an error
/// and not crash. The client proxy should still accept the connection
/// (the handshake will succeed) but the relay will fail when the server
/// proxy cannot connect to the backend.
#[tokio::test]
async fn proxy_backend_unreachable_does_not_crash() {
    // Pick a port that nobody is listening on.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    drop(server_listener);

    let server_config = ServerProxyConfig {
        listen_addr: server_addr,
        backend_addr: dead_addr, // unreachable
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let server_verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_server_proxy(server_config, provider, server_verifier));

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_proxy_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let client_config = ClientProxyConfig {
        listen_addr: client_proxy_addr,
        enclave_addr: server_addr,
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let client_provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_client_proxy(client_config, client_provider, verifier));

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect — the handshake should succeed but the relay should fail
    // when the server proxy can't reach the backend. The client should
    // see the connection close or error, not hang.
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = tokio::net::TcpStream::connect(client_proxy_addr)
            .await
            .unwrap();
        client.write_all(b"data").await.unwrap();
        let mut buf = vec![0u8; 256];
        // Expect either 0 bytes (connection closed) or error.
        let n = client.read(&mut buf).await.unwrap_or(0);
        n
    })
    .await;

    // Should complete within the timeout (not hang forever).
    assert!(result.is_ok());
}

/// Multiple concurrent connections through the proxy should all succeed.
#[tokio::test]
async fn proxy_concurrent_connections() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(run_echo_backend(echo_listener));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    drop(server_listener);

    let server_config = ServerProxyConfig {
        listen_addr: server_addr,
        backend_addr: echo_addr,
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let server_verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_server_proxy(server_config, provider, server_verifier));

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_proxy_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let client_config = ClientProxyConfig {
        listen_addr: client_proxy_addr,
        enclave_addr: server_addr,
        session_config: SessionConfig::default(),
        max_connections: 0,
    };
    let client_provider: Arc<dyn confidential_ml_transport::AttestationProvider> =
        Arc::new(MockProvider::new());
    let verifier: Arc<dyn confidential_ml_transport::AttestationVerifier> =
        Arc::new(MockVerifier::new());
    tokio::spawn(run_client_proxy(client_config, client_provider, verifier));

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn 5 concurrent connections.
    let mut handles = vec![];
    for i in 0..5u8 {
        let addr = client_proxy_addr;
        handles.push(tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            client.set_nodelay(true).unwrap();
            let msg = format!("hello-{i}");
            client.write_all(msg.as_bytes()).await.unwrap();
            client.flush().await.unwrap();

            let mut buf = vec![0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
                .await
                .expect("timed out")
                .unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
