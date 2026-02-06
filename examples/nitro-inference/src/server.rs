mod model;

use std::path::PathBuf;

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::{DType, SessionConfig, TensorRef};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "enclave-server", about = "Confidential ML inference server")]
struct Args {
    /// Path to model directory (containing model.safetensors, tokenizer.json, config.json)
    #[arg(long, default_value = "/model")]
    model_dir: PathBuf,

    /// Port to listen on
    #[arg(long, default_value_t = 5555)]
    port: u32,
}

#[cfg(feature = "tcp-mock")]
fn create_provider() -> Box<dyn confidential_ml_transport::AttestationProvider> {
    Box::new(confidential_ml_transport::MockProvider::new())
}

#[cfg(feature = "vsock-nitro")]
fn create_provider() -> Result<Box<dyn confidential_ml_transport::AttestationProvider>> {
    Ok(Box::new(confidential_ml_transport::NitroProvider::new()?))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    tracing::info!("loading model from {}", args.model_dir.display());
    let embedding_model = model::EmbeddingModel::load(&args.model_dir)?;
    tracing::info!("model loaded (dim={})", embedding_model.dim());

    #[cfg(feature = "tcp-mock")]
    let provider = create_provider();

    #[cfg(feature = "vsock-nitro")]
    let provider = create_provider()?;

    let config = SessionConfig::default();

    #[cfg(feature = "tcp-mock")]
    {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", args.port).parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("listening on {addr} (tcp-mock)");

        loop {
            let (stream, peer) = listener.accept().await?;
            stream.set_nodelay(true)?;
            tracing::info!("accepted connection from {peer}");

            handle_connection(stream, provider.as_ref(), config.clone(), &embedding_model).await?;
        }
    }

    #[cfg(feature = "vsock-nitro")]
    {
        let mut listener = confidential_ml_transport::transport::vsock::listen(args.port)?;
        tracing::info!("listening on vsock port {} (vsock-nitro)", args.port);

        loop {
            let (stream, peer) =
                confidential_ml_transport::transport::vsock::accept(&mut listener).await?;
            tracing::info!("accepted vsock connection from {:?}", peer);

            handle_connection(stream, provider.as_ref(), config.clone(), &embedding_model).await?;
        }
    }
}

async fn handle_connection<T>(
    transport: T,
    provider: &dyn confidential_ml_transport::AttestationProvider,
    config: SessionConfig,
    embedding_model: &model::EmbeddingModel,
) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut channel = SecureChannel::accept_with_attestation(transport, provider, config).await?;
    tracing::info!("handshake complete");

    loop {
        match channel.recv().await {
            Ok(Message::Data(data)) => {
                let text = String::from_utf8_lossy(&data);
                tracing::info!("inference request: \"{}\"", text);

                match embedding_model.encode(&text) {
                    Ok(embedding) => {
                        let data_bytes: Vec<u8> =
                            embedding.iter().flat_map(|f| f.to_le_bytes()).collect();

                        let tensor = TensorRef {
                            name: "embedding",
                            dtype: DType::F32,
                            shape: &[1, embedding_model.dim() as u32],
                            data: &data_bytes,
                        };

                        channel.send_tensor(tensor).await?;
                        tracing::info!("sent embedding ({} dims)", embedding.len());
                    }
                    Err(e) => {
                        tracing::error!("inference failed: {e}");
                        channel.send(Bytes::from(format!("ERROR: {e}"))).await?;
                    }
                }
            }
            Ok(Message::Shutdown) => {
                tracing::info!("client sent shutdown");
                break;
            }
            Ok(other) => {
                tracing::warn!("unexpected message: {other:?}");
            }
            Err(e) => {
                tracing::error!("recv error: {e}");
                break;
            }
        }
    }

    Ok(())
}
