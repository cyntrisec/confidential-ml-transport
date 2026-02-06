use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::attestation::AttestationVerifier;
use crate::error::Error;
use crate::session::channel::{Message, SecureChannel};
use crate::session::SessionConfig;

/// Configuration for the client-side (host) transparent proxy.
#[derive(Debug, Clone)]
pub struct ClientProxyConfig {
    /// Address to listen on for incoming plaintext TCP connections.
    pub listen_addr: SocketAddr,
    /// Address of the enclave's server proxy to connect to.
    pub enclave_addr: SocketAddr,
    /// Session configuration for the secure channel.
    pub session_config: SessionConfig,
}

/// Run the client-side transparent proxy (on the host).
///
/// Accepts plaintext TCP connections from local applications, establishes
/// an encrypted SecureChannel to the enclave, then relays traffic
/// bidirectionally.
pub async fn run_client_proxy(
    config: ClientProxyConfig,
    verifier: Arc<dyn AttestationVerifier>,
) -> Result<(), Error> {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .map_err(Error::Io)?;

    tracing::info!(addr = %config.listen_addr, "client proxy listening");

    loop {
        let (stream, peer_addr) = listener.accept().await.map_err(Error::Io)?;
        stream.set_nodelay(true).ok();

        let verifier = Arc::clone(&verifier);
        let enclave_addr = config.enclave_addr;
        let session_config = config.session_config.clone();

        tokio::spawn(async move {
            tracing::debug!(%peer_addr, "accepted plaintext connection");
            if let Err(e) =
                handle_client_connection(stream, verifier.as_ref(), enclave_addr, session_config)
                    .await
            {
                tracing::warn!(%peer_addr, error = %e, "connection handler error");
            }
        });
    }
}

async fn handle_client_connection(
    mut local: TcpStream,
    verifier: &dyn AttestationVerifier,
    enclave_addr: SocketAddr,
    config: SessionConfig,
) -> Result<(), Error> {
    // Connect to the enclave and perform handshake.
    let enclave_stream = TcpStream::connect(enclave_addr).await.map_err(Error::Io)?;
    enclave_stream.set_nodelay(true).ok();

    let mut channel =
        SecureChannel::connect_with_attestation(enclave_stream, verifier, config).await?;

    let (mut local_read, mut local_write) = local.split();

    // Bidirectional relay.
    let mut buf = vec![0u8; 8192];
    loop {
        tokio::select! {
            // Data from local plaintext → encrypted channel.
            n = local_read.read(&mut buf) => {
                match n {
                    Ok(0) => {
                        tracing::debug!("local client disconnected");
                        channel.shutdown().await.ok();
                        break;
                    }
                    Ok(n) => {
                        channel.send(Bytes::copy_from_slice(&buf[..n])).await?;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "local read error");
                        break;
                    }
                }
            }
            // Data from encrypted channel → local plaintext.
            msg = channel.recv() => {
                match msg {
                    Ok(Message::Data(data)) => {
                        local_write.write_all(&data).await.map_err(Error::Io)?;
                        local_write.flush().await.map_err(Error::Io)?;
                    }
                    Ok(Message::Shutdown) => {
                        tracing::debug!("enclave sent shutdown");
                        break;
                    }
                    Ok(_) => {} // ignore heartbeats, etc.
                    Err(e) => {
                        tracing::debug!(error = %e, "channel recv error");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
