use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::attestation::{AttestationProvider, AttestationVerifier};
use crate::error::Error;
use crate::session::channel::{Message, SecureChannel};
use crate::session::SessionConfig;

/// Default maximum number of concurrent connections.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Configuration for the client-side (host) transparent proxy.
#[derive(Debug, Clone)]
pub struct ClientProxyConfig {
    /// Address to listen on for incoming plaintext TCP connections.
    pub listen_addr: SocketAddr,
    /// Address of the enclave's server proxy to connect to.
    pub enclave_addr: SocketAddr,
    /// Session configuration for the secure channel.
    pub session_config: SessionConfig,
    /// Maximum number of concurrent connections (default: 256).
    /// Excess connections are held at accept until a slot opens.
    pub max_connections: usize,
}

/// Run the client-side transparent proxy (on the host).
///
/// Accepts plaintext TCP connections from local applications, establishes
/// an encrypted SecureChannel to the enclave, then relays traffic
/// bidirectionally. Limits concurrency to `max_connections`.
pub async fn run_client_proxy(
    config: ClientProxyConfig,
    provider: Arc<dyn AttestationProvider>,
    verifier: Arc<dyn AttestationVerifier>,
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

    tracing::info!(addr = %config.listen_addr, max_connections = max_conns, "client proxy listening");

    loop {
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .map_err(|_| Error::Io(std::io::Error::other("semaphore closed")))?;

        let (stream, peer_addr) = listener.accept().await.map_err(Error::Io)?;
        stream.set_nodelay(true).ok();

        let provider = Arc::clone(&provider);
        let verifier = Arc::clone(&verifier);
        let enclave_addr = config.enclave_addr;
        let session_config = config.session_config.clone();

        tokio::spawn(async move {
            // Hold permit as `_permit` so it is released when this task exits,
            // including on panic (no explicit drop needed).
            let _permit = permit;
            tracing::debug!(%peer_addr, "accepted plaintext connection");
            if let Err(e) = handle_client_connection(
                stream,
                provider.as_ref(),
                verifier.as_ref(),
                enclave_addr,
                session_config,
            )
            .await
            {
                tracing::warn!(%peer_addr, error = %e, "connection handler error");
            }
        });
    }
}

async fn handle_client_connection(
    mut local: TcpStream,
    provider: &dyn AttestationProvider,
    verifier: &dyn AttestationVerifier,
    enclave_addr: SocketAddr,
    config: SessionConfig,
) -> Result<(), Error> {
    // Connect to the enclave and perform handshake (mutual attestation).
    let enclave_stream = TcpStream::connect(enclave_addr).await.map_err(Error::Io)?;
    enclave_stream.set_nodelay(true).ok();

    let mut channel =
        SecureChannel::connect_with_attestation(enclave_stream, provider, verifier, config).await?;

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
