use bytes::{Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;
use tokio_util::codec::{Encoder, FramedRead};

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::frame::Frame;
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{MockProvider, MockVerifier, SecureChannel};

/// 2MB duplex buffer — creates realistic backpressure for large payloads.
const DUPLEX_SIZE: usize = 2 * 1024 * 1024;

const PAYLOADS: &[(&str, usize)] = &[
    ("1536b_embedding", 1_536), // 384-dim F32 (MiniLM-L6-v2 output)
    ("4k_activation", 4_096),   // Small activation tensor
    ("384k_hidden", 393_216),   // [128, 768] F32 hidden state
    ("1m_large", 1_048_576),    // 1MB payload for throughput saturation
];

/// Target ~4MB of data per iteration so large payloads get enough samples.
fn burst_count(payload_size: usize) -> usize {
    (4 * 1_048_576 / payload_size).max(1)
}

fn bench_throughput_plaintext(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/plaintext");

    for &(label, size) in PAYLOADS {
        let burst = burst_count(size);
        let payload = Bytes::from(vec![0xABu8; size]);
        group.throughput(Throughput::Bytes((size * burst) as u64));

        group.bench_with_input(BenchmarkId::new("send", label), &payload, |b, payload| {
            let rt = Runtime::new().unwrap();

            // Establish duplex + drain server once, reuse across iterations.
            let client_w = rt.block_on(async {
                let (client, server) = tokio::io::duplex(DUPLEX_SIZE);

                // Server: decode frames (matches SecureChannel's decode cost).
                tokio::spawn(async move {
                    use futures::StreamExt;
                    let mut framed = FramedRead::new(server, FrameCodec::new());
                    while framed.next().await.is_some() {}
                });

                client
            });

            let client_w = std::sync::Arc::new(tokio::sync::Mutex::new(client_w));

            b.iter(|| {
                let w = client_w.clone();
                let p = payload.clone();
                rt.block_on(async {
                    use tokio::io::AsyncWriteExt;
                    let mut w = w.lock().await;
                    let mut codec = FrameCodec::new();
                    // Match SecureChannel's per-frame write_all + flush pattern.
                    for _ in 0..burst {
                        let frame = Frame::data(0, p.clone(), false);
                        let mut buf = BytesMut::new();
                        codec.encode(frame, &mut buf).unwrap();
                        w.write_all(&buf).await.unwrap();
                        w.flush().await.unwrap();
                    }
                });
            });
        });
    }

    group.finish();
}

fn bench_throughput_secure(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/secure_channel");

    for &(label, size) in PAYLOADS {
        let burst = burst_count(size);
        let payload = Bytes::from(vec![0xABu8; size]);
        group.throughput(Throughput::Bytes((size * burst) as u64));

        group.bench_with_input(BenchmarkId::new("send", label), &payload, |b, payload| {
            let rt = Runtime::new().unwrap();

            // Establish SecureChannel + drain server once.
            let client_ch = rt.block_on(async {
                let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                let provider = MockProvider::new();
                let verifier = MockVerifier::new();
                let config = SessionConfig::default();

                let (server_ch, client_ch) = tokio::join!(
                    SecureChannel::accept_with_attestation(server, &provider, config.clone()),
                    SecureChannel::connect_with_attestation(client, &verifier, config),
                );
                let mut server_ch = server_ch.unwrap();

                // Server: drain all incoming messages.
                tokio::spawn(async move { while server_ch.recv().await.is_ok() {} });

                client_ch.unwrap()
            });

            let client_ch = std::sync::Arc::new(tokio::sync::Mutex::new(client_ch));

            b.iter(|| {
                let ch = client_ch.clone();
                let p = payload.clone();
                rt.block_on(async {
                    let mut ch = ch.lock().await;
                    for _ in 0..burst {
                        ch.send(p.clone()).await.unwrap();
                    }
                });
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_throughput_plaintext, bench_throughput_secure);
criterion_main!(benches);
