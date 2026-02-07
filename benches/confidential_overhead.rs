use bytes::{Bytes, BytesMut};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;
use tokio_util::codec::{Decoder, Encoder};

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::frame::Frame;
use confidential_ml_transport::session::channel::Message;
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{MockProvider, MockVerifier, SecureChannel};

/// Payload sizes matching real ML tensor workloads.
const PAYLOADS: &[(&str, usize)] = &[
    ("1536b_embedding", 1_536), // 384-dim F32 (MiniLM-L6-v2 output)
    ("4k_activation", 4_096),   // Small activation tensor
    ("384k_hidden", 393_216),   // [128, 768] F32 hidden state
];

/// Duplex buffer size — large enough for handshake + largest payload.
const DUPLEX_SIZE: usize = 1024 * 1024;

fn bench_plaintext(c: &mut Criterion) {
    let mut group = c.benchmark_group("confidential_overhead/plaintext");

    for &(label, size) in PAYLOADS {
        let payload = Bytes::from(vec![0xABu8; size]);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("send_recv", label),
            &payload,
            |b, payload| {
                let mut codec = FrameCodec::new();

                // Pure encode + decode — no I/O, no crypto.
                b.iter(|| {
                    let frame = Frame::data(0, payload.clone(), false);
                    let mut buf = BytesMut::with_capacity(size + 13);
                    codec.encode(frame, &mut buf).unwrap();
                    let decoded = codec.decode(&mut buf).unwrap().unwrap();
                    black_box(decoded);
                });
            },
        );
    }

    group.finish();
}

fn bench_plaintext_duplex(c: &mut Criterion) {
    let mut group = c.benchmark_group("confidential_overhead/plaintext_duplex");

    for &(label, size) in PAYLOADS {
        let payload = Bytes::from(vec![0xABu8; size]);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("send_recv", label),
            &payload,
            |b, payload| {
                let rt = Runtime::new().unwrap();

                // Establish duplex + echo server once, reuse across iterations.
                let (client_w, client_r) = rt.block_on(async {
                    let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                    let (server_r, server_w) = tokio::io::split(server);

                    // Echo server: decode frame, re-encode, send back.
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut r = server_r;
                        let mut w = server_w;
                        let mut read_buf = BytesMut::with_capacity(DUPLEX_SIZE);
                        let mut codec = FrameCodec::new();
                        loop {
                            // Try to decode a frame from what we have.
                            match codec.decode(&mut read_buf) {
                                Ok(Some(frame)) => {
                                    let mut out = BytesMut::new();
                                    codec.encode(frame, &mut out).unwrap();
                                    if w.write_all(&out).await.is_err() {
                                        break;
                                    }
                                    let _ = w.flush().await;
                                }
                                Ok(None) => {
                                    // Need more data.
                                    match r.read_buf(&mut read_buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(_) => continue,
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });

                    let (cr, cw) = tokio::io::split(client);
                    (cw, cr)
                });

                let client_w = std::sync::Arc::new(tokio::sync::Mutex::new(client_w));
                let client_r = std::sync::Arc::new(tokio::sync::Mutex::new(client_r));

                b.iter(|| {
                    let cw = client_w.clone();
                    let cr = client_r.clone();
                    let p = payload.clone();
                    rt.block_on(async {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};

                        let frame = Frame::data(0, p, false);
                        let mut codec = FrameCodec::new();
                        let mut buf = BytesMut::new();
                        codec.encode(frame, &mut buf).unwrap();

                        let mut w = cw.lock().await;
                        w.write_all(&buf).await.unwrap();
                        w.flush().await.unwrap();
                        drop(w);

                        let mut r = cr.lock().await;
                        let mut read_buf = BytesMut::with_capacity(buf.len() + 64);
                        loop {
                            match codec.decode(&mut read_buf) {
                                Ok(Some(frame)) => {
                                    black_box(frame);
                                    break;
                                }
                                Ok(None) => {
                                    r.read_buf(&mut read_buf).await.unwrap();
                                }
                                Err(e) => panic!("decode error: {e}"),
                            }
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_secure_channel(c: &mut Criterion) {
    let mut group = c.benchmark_group("confidential_overhead/secure_channel");

    for &(label, size) in PAYLOADS {
        let payload = Bytes::from(vec![0xABu8; size]);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("send_recv", label),
            &payload,
            |b, payload| {
                let rt = Runtime::new().unwrap();

                // Establish handshake once, reuse the SecureChannel across iterations.
                let (client_ch, server_rx) = rt.block_on(async {
                    let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                    let provider = MockProvider::new();
                    let verifier = MockVerifier::new();
                    let config = SessionConfig::default();

                    let (server_ch, client_ch) = tokio::join!(
                        SecureChannel::accept_with_attestation(server, &provider, config.clone()),
                        SecureChannel::connect_with_attestation(client, &verifier, config),
                    );
                    let mut server_ch = server_ch.unwrap();

                    // Echo server: recv decrypted message, send it back encrypted.
                    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                    tokio::spawn(async move {
                        // We drop `tx` when we exit so the parent knows.
                        let _tx = tx;
                        while let Ok(Message::Data(data)) = server_ch.recv().await {
                            if server_ch.send(data).await.is_err() {
                                break;
                            }
                        }
                    });

                    (client_ch.unwrap(), rx)
                });

                let client_ch = std::sync::Arc::new(tokio::sync::Mutex::new(client_ch));

                b.iter(|| {
                    let ch = client_ch.clone();
                    let p = payload.clone();
                    rt.block_on(async {
                        let mut ch = ch.lock().await;
                        ch.send(p).await.unwrap();
                        let msg = ch.recv().await.unwrap();
                        match msg {
                            Message::Data(data) => {
                                black_box(data);
                            }
                            other => panic!("unexpected message: {other:?}"),
                        }
                    });
                });

                // Drop to close the channel and let server exit.
                drop(server_rx);
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_plaintext,
    bench_plaintext_duplex,
    bench_secure_channel,
);
criterion_main!(benches);
