#[cfg(feature = "vsock-nitro")]
use std::collections::BTreeMap;

use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::SessionConfig;

#[derive(Parser)]
#[command(name = "bench-client", about = "Isolated Nitro enclave benchmarks")]
struct Args {
    /// Server port
    #[arg(long, default_value_t = 5555)]
    port: u32,

    /// Enclave CID (vsock-nitro only)
    #[cfg(feature = "vsock-nitro")]
    #[arg(long)]
    cid: u32,

    /// Number of connect+handshake iterations
    #[arg(long, default_value_t = 50)]
    handshake_rounds: usize,

    /// Number of echo RTT iterations
    #[arg(long, default_value_t = 200)]
    rtt_rounds: usize,

    /// Number of inference iterations
    #[arg(long, default_value_t = 50)]
    inference_rounds: usize,

    /// Output JSON to this path
    #[arg(long)]
    output: Option<String>,
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
    }
    Ok(Box::new(confidential_ml_transport::NitroVerifier::new(
        expected_pcrs,
    )?))
}

struct Stats {
    min: Duration,
    max: Duration,
    mean: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
}

fn compute_stats(times: &[Duration]) -> Stats {
    let mut sorted: Vec<Duration> = times.to_vec();
    sorted.sort();
    let n = sorted.len();
    let sum: Duration = sorted.iter().sum();
    Stats {
        min: sorted[0],
        max: sorted[n - 1],
        mean: sum / n as u32,
        p50: sorted[n / 2],
        p95: sorted[((n as f64) * 0.95) as usize],
        p99: sorted[((n as f64) * 0.99).min((n - 1) as f64) as usize],
    }
}

fn print_stats(label: &str, times: &[Duration]) {
    let s = compute_stats(times);
    println!("  {label}:");
    println!(
        "    n={}, min={:.3}ms, max={:.3}ms",
        times.len(),
        dur_ms(s.min),
        dur_ms(s.max)
    );
    println!(
        "    mean={:.3}ms, p50={:.3}ms, p95={:.3}ms, p99={:.3}ms",
        dur_ms(s.mean),
        dur_ms(s.p50),
        dur_ms(s.p95),
        dur_ms(s.p99)
    );
}

fn dur_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn stats_to_json(label: &str, times: &[Duration]) -> serde_json::Value {
    let s = compute_stats(times);
    serde_json::json!({
        "label": label,
        "n": times.len(),
        "min_ms": dur_ms(s.min),
        "max_ms": dur_ms(s.max),
        "mean_ms": dur_ms(s.mean),
        "p50_ms": dur_ms(s.p50),
        "p95_ms": dur_ms(s.p95),
        "p99_ms": dur_ms(s.p99),
        "raw_ms": times.iter().map(|d| dur_ms(*d)).collect::<Vec<f64>>(),
    })
}

#[cfg(feature = "tcp-mock")]
async fn connect(port: u32) -> Result<tokio::net::TcpStream> {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

#[cfg(feature = "vsock-nitro")]
async fn connect(cid: u32, port: u32) -> Result<tokio_vsock::VsockStream> {
    Ok(confidential_ml_transport::transport::vsock::connect(cid, port).await?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    anyhow::ensure!(args.handshake_rounds > 0, "--handshake-rounds must be > 0");
    anyhow::ensure!(args.rtt_rounds > 0, "--rtt-rounds must be > 0");
    anyhow::ensure!(args.inference_rounds > 0, "--inference-rounds must be > 0");

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

    // Warmup: one full connection to ensure server is ready
    {
        #[cfg(feature = "tcp-mock")]
        let transport = connect(args.port).await?;
        #[cfg(feature = "vsock-nitro")]
        let transport = connect(args.cid, args.port).await?;

        let mut ch =
            SecureChannel::connect_with_attestation(transport, provider.as_ref(), verifier.as_ref(), config.clone())
                .await?;
        ch.send(Bytes::from_static(b"ECHO:warmup")).await?;
        let _ = ch.recv().await?;
        ch.shutdown().await.ok();
        // Small delay to let server loop back to accept
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("Warmup done\n");

    // === Phase 1: Connect + Handshake ===
    eprintln!("Phase 1: Connect + Handshake (n={})", args.handshake_rounds);
    let mut handshake_times = Vec::with_capacity(args.handshake_rounds);
    for i in 0..args.handshake_rounds {
        let start = Instant::now();

        #[cfg(feature = "tcp-mock")]
        let transport = connect(args.port).await?;
        #[cfg(feature = "vsock-nitro")]
        let transport = connect(args.cid, args.port).await?;

        let mut ch =
            SecureChannel::connect_with_attestation(transport, provider.as_ref(), verifier.as_ref(), config.clone())
                .await?;
        let elapsed = start.elapsed();
        handshake_times.push(elapsed);

        ch.shutdown().await.ok();
        // Let server loop back to accept
        tokio::time::sleep(Duration::from_millis(20)).await;

        if (i + 1) % 10 == 0 {
            eprintln!("  {}/{}", i + 1, args.handshake_rounds);
        }
    }
    print_stats("connect+handshake", &handshake_times);
    println!();

    // === Phase 2: Transport RTT (ECHO, single connection) ===
    eprintln!("Phase 2: Transport RTT via ECHO (n={})", args.rtt_rounds);
    let mut rtt_times = Vec::with_capacity(args.rtt_rounds);
    {
        #[cfg(feature = "tcp-mock")]
        let transport = connect(args.port).await?;
        #[cfg(feature = "vsock-nitro")]
        let transport = connect(args.cid, args.port).await?;

        let mut ch =
            SecureChannel::connect_with_attestation(transport, provider.as_ref(), verifier.as_ref(), config.clone())
                .await?;

        let payload = "ECHO:".to_string() + &"x".repeat(64); // 64-byte echo payload
        for i in 0..args.rtt_rounds {
            let start = Instant::now();
            ch.send(Bytes::from(payload.clone())).await?;
            let msg = ch.recv().await?;
            let elapsed = start.elapsed();
            rtt_times.push(elapsed);

            // Verify we got echo back
            if let Message::Data(data) = msg {
                assert_eq!(data.len(), 64, "echo payload size mismatch");
            }

            if (i + 1) % 50 == 0 {
                eprintln!("  {}/{}", i + 1, args.rtt_rounds);
            }
        }
        ch.shutdown().await.ok();
    }
    print_stats("transport RTT (64B echo)", &rtt_times);
    println!();

    // === Phase 3: Inference RTT (single connection) ===
    eprintln!("Phase 3: Inference RTT (n={})", args.inference_rounds);
    let mut inference_times = Vec::with_capacity(args.inference_rounds);
    {
        // Let server accept
        tokio::time::sleep(Duration::from_millis(50)).await;

        #[cfg(feature = "tcp-mock")]
        let transport = connect(args.port).await?;
        #[cfg(feature = "vsock-nitro")]
        let transport = connect(args.cid, args.port).await?;

        let mut ch =
            SecureChannel::connect_with_attestation(transport, provider.as_ref(), verifier.as_ref(), config.clone())
                .await?;

        let text = "The quick brown fox jumps over the lazy dog";
        for i in 0..args.inference_rounds {
            let start = Instant::now();
            ch.send(Bytes::from(text)).await?;
            let msg = ch.recv().await?;
            let elapsed = start.elapsed();
            inference_times.push(elapsed);

            if let Message::Tensor(t) = msg {
                assert_eq!(t.shape, vec![1, 384], "unexpected embedding shape");
            } else {
                anyhow::bail!("expected tensor, got {:?}", msg);
            }

            if (i + 1) % 10 == 0 {
                eprintln!("  {}/{}", i + 1, args.inference_rounds);
            }
        }
        ch.shutdown().await.ok();
    }
    print_stats("inference RTT", &inference_times);
    println!();

    // === Derived: inference-only estimate ===
    let rtt_mean = compute_stats(&rtt_times).mean;
    let inf_mean = compute_stats(&inference_times).mean;
    let inference_only = inf_mean.saturating_sub(rtt_mean);
    println!(
        "  Derived: inference-only (mean) = {:.3}ms",
        dur_ms(inference_only)
    );
    println!(
        "    (inference RTT mean - transport RTT mean = {:.3}ms - {:.3}ms)",
        dur_ms(inf_mean),
        dur_ms(rtt_mean)
    );
    println!();

    // === JSON output ===
    let json = serde_json::json!({
        "test_date": format_date(),
        "crate_version": "0.1.1",
        "benchmark_type": "isolated_nitro_phases",
        "phases": {
            "connect_handshake": stats_to_json("connect+handshake (VSock + Nitro attestation)", &handshake_times),
            "transport_rtt": stats_to_json("transport RTT (64B echo, encrypted channel)", &rtt_times),
            "inference_rtt": stats_to_json("inference RTT (MiniLM-L6-v2, 384-dim F32)", &inference_times),
        },
        "derived": {
            "inference_only_mean_ms": dur_ms(inference_only),
            "transport_overhead_per_msg_ms": dur_ms(rtt_mean),
        },
    });

    let json_str = serde_json::to_string_pretty(&json)?;
    println!("{json_str}");

    if let Some(path) = args.output {
        std::fs::write(&path, &json_str)?;
        eprintln!("Results written to {path}");
    }

    Ok(())
}

fn format_date() -> String {
    // UTC date without chrono dependency: days since epoch → Y-M-D
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = (secs / 86400) as i64;
    // Algorithm from Howard Hinnant's civil_from_days
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}
