use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::attestation::AttestationProvider;
use crate::error::Error;
use crate::session::channel::{Message, SecureChannel};
use crate::session::SessionConfig;

/// Default maximum number of concurrent connections.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Configuration for the server-side (enclave) transparent proxy.
#[derive(Debug, Clone)]
pub struct ServerProxyConfig {
    /// Address to listen on for incoming SecureChannel connections.
    pub listen_addr: SocketAddr,
    /// Address of the local backend service to relay traffic to.
    pub backend_addr: SocketAddr,
    /// Session configuration for the secure channel.
    pub session_config: SessionConfig,
    /// Maximum number of concurrent connections (default: 256).
    /// Excess connections are held at accept until a slot opens.
    pub max_connections: usize,
}

/// Run the server-side transparent proxy (inside the enclave).
///
/// Accepts encrypted SecureChannel connections, performs the handshake,
/// then relays decrypted traffic bidirectionally to a local backend TCP service.
/// Limits concurrency to `max_connections`.
pub async fn run_server_proxy(
    config: ServerProxyConfig,
    provider: Arc<dyn AttestationProvider>,
) -> Result<(), Error> {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .map_err(Error::Io)?;

    let max_conns = if config.max_connections == 0 {
        DEFAULT_MAX_CONNECTIONS
    } else {
        config.max_connections
    };
    let semaphore = Arc::new(Semaphore::new(max_conns));

    tracing::info!(addr = %config.listen_addr, max_connections = max_conns, "server proxy listening");

    loop {
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .map_err(|_| Error::Io(std::io::Error::other("semaphore closed")))?;

        let (stream, peer_addr) = listener.accept().await.map_err(Error::Io)?;
        stream.set_nodelay(true).ok();

        let provider = Arc::clone(&provider);
        let backend_addr = config.backend_addr;
        let session_config = config.session_config.clone();

        tokio::spawn(async move {
            tracing::debug!(%peer_addr, "accepted connection");
            if let Err(e) =
                handle_server_connection(stream, provider.as_ref(), backend_addr, session_config)
                    .await
            {
                tracing::warn!(%peer_addr, error = %e, "connection handler error");
            }
            drop(permit);
        });
    }
}

async fn handle_server_connection(
    stream: TcpStream,
    provider: &dyn AttestationProvider,
    backend_addr: SocketAddr,
    config: SessionConfig,
) -> Result<(), Error> {
    // Perform handshake with the client.
    let mut channel = SecureChannel::accept_with_attestation(stream, provider, config).await?;

    // Connect to the local backend.
    let mut backend = TcpStream::connect(backend_addr).await.map_err(Error::Io)?;
    backend.set_nodelay(true).ok();

    let (mut backend_read, mut backend_write) = backend.split();

    // Bidirectional relay.
    let mut buf = vec![0u8; 8192];
    loop {
        tokio::select! {
            // Data from encrypted channel → backend.
            msg = channel.recv() => {
                match msg {
                    Ok(Message::Data(data)) => {
                        backend_write.write_all(&data).await.map_err(Error::Io)?;
                        backend_write.flush().await.map_err(Error::Io)?;
                    }
                    Ok(Message::Shutdown) => {
                        tracing::debug!("client sent shutdown");
                        break;
                    }
                    Ok(_) => {} // ignore heartbeats, etc.
                    Err(e) => {
                        tracing::debug!(error = %e, "channel recv error");
                        break;
                    }
                }
            }
            // Data from backend → encrypted channel.
            n = backend_read.read(&mut buf) => {
                match n {
                    Ok(0) => {
                        tracing::debug!("backend closed");
                        channel.shutdown().await.ok();
                        break;
                    }
                    Ok(n) => {
                        channel.send(Bytes::copy_from_slice(&buf[..n])).await?;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "backend read error");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
