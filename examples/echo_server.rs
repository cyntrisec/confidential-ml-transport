use bytes::Bytes;
use std::net::SocketAddr;

use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::{MockProvider, MockVerifier, SessionConfig};

/// Encrypted echo server over TCP with mock attestation.
///
/// Run with: `cargo run --example echo_server --features mock`
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:9876".parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("echo server listening on {addr}");

    // Spawn a client that connects after the server is ready.
    let client_handle = tokio::spawn(async move {
        // Small delay to let the server start accepting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();

        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        let mut channel =
            SecureChannel::connect_with_attestation(stream, &provider, &verifier, SessionConfig::default())
                .await
                .unwrap();

        println!("[client] connected and handshake complete");

        // Send a few messages.
        for i in 0..3 {
            let msg = format!("echo request #{i}");
            println!("[client] sending: {msg}");
            channel.send(Bytes::from(msg)).await.unwrap();

            match channel.recv().await.unwrap() {
                Message::Data(data) => {
                    println!("[client] received: {}", String::from_utf8_lossy(&data));
                }
                other => println!("[client] unexpected: {other:?}"),
            }
        }

        println!("[client] sending shutdown");
        channel.shutdown().await.unwrap();
    });

    // Accept one connection.
    let (stream, peer_addr) = listener.accept().await?;
    stream.set_nodelay(true)?;
    println!("accepted connection from {peer_addr}");

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let mut channel =
        SecureChannel::accept_with_attestation(stream, &provider, &verifier, SessionConfig::default()).await?;

    println!("[server] handshake complete");

    loop {
        match channel.recv().await? {
            Message::Data(data) => {
                let text = String::from_utf8_lossy(&data);
                println!("[server] echoing: {text}");
                channel.send(data).await?;
            }
            Message::Shutdown => {
                println!("[server] client sent shutdown, exiting");
                break;
            }
            other => {
                println!("[server] unexpected: {other:?}");
            }
        }
    }

    client_handle.await?;
    println!("done!");

    Ok(())
}
