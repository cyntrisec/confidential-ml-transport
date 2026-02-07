#![cfg(feature = "tcp")]
//! Tests for the `transport::tcp` helper functions.

use confidential_ml_transport::transport::tcp;

#[tokio::test]
async fn listen_and_accept() {
    let listener = tcp::listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_handle = tokio::spawn(async move {
        tcp::connect(addr).await.unwrap()
    });

    let (server_stream, peer_addr) = tcp::accept(&listener).await.unwrap();
    let client_stream = client_handle.await.unwrap();

    // Both sides should have nodelay set.
    assert!(server_stream.nodelay().unwrap());
    assert!(client_stream.nodelay().unwrap());

    // Peer address should be loopback.
    assert!(peer_addr.ip().is_loopback());
}

#[tokio::test]
async fn connect_to_unbound_port_fails() {
    // Bind and immediately drop to get a port that is not listening.
    let listener = tcp::listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let result = tcp::connect(addr).await;
    assert!(result.is_err());
}
