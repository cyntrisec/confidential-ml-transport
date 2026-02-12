#[cfg(feature = "vsock-nitro")]
use std::collections::BTreeMap;

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::SessionConfig;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "host-client", about = "Confidential ML inference client")]
struct Args {
    /// Text to encode (can be repeated)
    #[arg(long, required = true)]
    text: Vec<String>,

    /// Server port
    #[arg(long, default_value_t = 5555)]
    port: u32,

    /// Enclave CID (vsock-nitro only)
    #[cfg(feature = "vsock-nitro")]
    #[arg(long)]
    cid: u32,
}

#[cfg(feature = "tcp-mock")]
fn create_provider() -> Box<dyn confidential_ml_transport::AttestationProvider> {
    Box::new(confidential_ml_transport::MockProvider::new())
}

#[cfg(feature = "tcp-mock")]
fn create_verifier() -> Box<dyn confidential_ml_transport::AttestationVerifier> {
    Box::new(confidential_ml_transport::MockVerifier::new())
}

#[cfg(feature = "vsock-nitro")]
fn create_verifier() -> Result<Box<dyn confidential_ml_transport::AttestationVerifier>> {
    let mut expected_pcrs = BTreeMap::new();

    // Load expected PCR values from environment variables.
    // Set EXPECTED_PCR0, EXPECTED_PCR1, EXPECTED_PCR2 from `nitro-cli build-enclave` output.
    // If none are set, verification is skipped with a warning — NOT safe for production.
    for (env_key, pcr_idx) in [
        ("EXPECTED_PCR0", 0u8),
        ("EXPECTED_PCR1", 1),
        ("EXPECTED_PCR2", 2),
    ] {
        if let Ok(hex_val) = std::env::var(env_key) {
            if !hex_val.is_empty() {
                let bytes = hex::decode(&hex_val)
                    .map_err(|e| anyhow::anyhow!("{env_key} is not valid hex: {e}"))?;
                expected_pcrs.insert(pcr_idx, bytes);
            }
        }
    }

    if expected_pcrs.is_empty() {
        eprintln!("WARNING: No EXPECTED_PCR0/1/2 set — accepting ANY enclave measurement.");
        eprintln!("         This is insecure. Set PCR env vars for production use.");
    }

    Ok(Box::new(confidential_ml_transport::NitroVerifier::new(
        expected_pcrs,
    )?))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    #[cfg(feature = "tcp-mock")]
    let provider = create_provider();
    #[cfg(feature = "tcp-mock")]
    let verifier = create_verifier();
    #[cfg(feature = "vsock-nitro")]
    let provider: Box<dyn confidential_ml_transport::AttestationProvider> =
        Box::new(confidential_ml_transport::MockProvider::new());
    #[cfg(feature = "vsock-nitro")]
    let verifier = create_verifier()?;

    let config = SessionConfig::default();

    #[cfg(feature = "tcp-mock")]
    let transport = {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", args.port).parse()?;
        tracing::info!("connecting to {addr} (tcp-mock)");
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        stream
    };

    #[cfg(feature = "vsock-nitro")]
    let transport = {
        tracing::info!(
            "connecting to vsock cid={} port={} (vsock-nitro)",
            args.cid,
            args.port
        );
        confidential_ml_transport::transport::vsock::connect(args.cid, args.port).await?
    };

    let mut channel =
        SecureChannel::connect_with_attestation(transport, provider.as_ref(), verifier.as_ref(), config).await?;
    tracing::info!("handshake complete");

    for text in &args.text {
        println!("Input: \"{text}\"");
        channel.send(Bytes::from(text.clone())).await?;

        match channel.recv().await? {
            Message::Tensor(tensor) => {
                println!("  Tensor: name={:?}", tensor.name);
                println!("  Shape:  {:?}", tensor.shape);
                println!("  DType:  {:?}", tensor.dtype);

                // Decode f32 values from raw bytes
                let floats: Vec<f32> = tensor
                    .data
                    .chunks_exact(4)
                    .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();

                // Print first 5 and last 5 values
                let n = floats.len();
                if n <= 10 {
                    println!("  Values: {:?}", floats);
                } else {
                    println!(
                        "  Values: [{:.6}, {:.6}, {:.6}, {:.6}, {:.6}, ... {:.6}, {:.6}, {:.6}, {:.6}, {:.6}]",
                        floats[0], floats[1], floats[2], floats[3], floats[4],
                        floats[n-5], floats[n-4], floats[n-3], floats[n-2], floats[n-1]
                    );
                }
                println!("  Dims:   {n}");
                println!();
            }
            Message::Data(data) => {
                let msg = String::from_utf8_lossy(&data);
                eprintln!("  Server response: {msg}");
            }
            other => {
                eprintln!("  Unexpected message: {other:?}");
            }
        }
    }

    channel.shutdown().await?;
    tracing::info!("done");

    Ok(())
}
