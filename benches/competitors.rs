//! Side-by-side benchmark: raw TCP vs TLS 1.3 (rustls) vs confidential-ml-transport.
//!
//! All measurements over tokio::io::duplex (in-process, no network).
//! This isolates protocol overhead from network latency.
//!
//! Round-trip benchmarks use length-prefixed framing on ALL paths (raw, TLS, CMT)
//! so the comparison is apples-to-apples: all paths pay encode/decode cost.

use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

use confidential_ml_transport::session::channel::Message;
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{MockProvider, MockVerifier, SecureChannel};

const DUPLEX_SIZE: usize = 1024 * 1024;

const PAYLOADS: &[(&str, usize)] = &[
    ("1536b_embedding", 1_536),
    ("4k_activation", 4_096),
    ("384k_hidden", 393_216),
];

// ---------------------------------------------------------------------------
// Framing helpers (4-byte big-endian length prefix)
// ---------------------------------------------------------------------------

/// Write a length-prefixed frame: [u32 BE length][payload].
async fn write_framed<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(payload).await?;
    w.flush().await
}

/// Read a length-prefixed frame. Returns the payload.
async fn read_framed<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// TLS setup helpers
// ---------------------------------------------------------------------------

fn make_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    // Generate self-signed cert via rcgen.
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = cert_params.self_signed(&key_pair).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

    // Server config.
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    // Client config: trust the self-signed cert.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (Arc::new(server_config), Arc::new(client_config))
}

// ---------------------------------------------------------------------------
// Handshake / session-establishment benchmarks
// ---------------------------------------------------------------------------

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitors/handshake");

    // Baseline: duplex creation only (no protocol handshake).
    // Included to show the floor; this is NOT a handshake.
    group.bench_function("duplex_creation_baseline", |b| {
        let rt = Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                black_box((client, server));
            });
        });
    });

    // TLS 1.3 (rustls): full handshake over duplex.
    // Cipher suite is whatever rustls negotiates by default (typically AES-128-GCM
    // or AES-256-GCM with AES-NI, or ChaCha20-Poly1305 without AES-NI).
    let (server_config, client_config) = make_tls_configs();
    group.bench_function("tls13_rustls", |b| {
        let rt = Runtime::new().unwrap();
        let sc = server_config.clone();
        let cc = client_config.clone();

        b.iter(|| {
            let sc = sc.clone();
            let cc = cc.clone();
            rt.block_on(async {
                let (client_io, server_io) = tokio::io::duplex(DUPLEX_SIZE);
                let acceptor = tokio_rustls::TlsAcceptor::from(sc);
                let connector = tokio_rustls::TlsConnector::from(cc);

                let (server_tls, client_tls) = tokio::join!(
                    acceptor.accept(server_io),
                    connector.connect("localhost".try_into().unwrap(), client_io),
                );
                black_box((server_tls.unwrap(), client_tls.unwrap()));
            });
        });
    });

    // confidential-ml-transport: full 3-message handshake + key derivation.
    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    group.bench_function("cmt_attestation", |b| {
        let rt = Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                let config = SessionConfig::default();

                let (s, c) = tokio::join!(
                    SecureChannel::accept_with_attestation(server, &provider, config.clone()),
                    SecureChannel::connect_with_attestation(client, &verifier, config),
                );
                black_box((s.unwrap(), c.unwrap()));
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Round-trip latency benchmarks (established session)
//
// All paths use length-prefixed framing so the comparison is fair:
// - Raw TCP: 4-byte length prefix + payload
// - TLS 1.3: 4-byte length prefix + payload (over TLS record layer)
// - CMT: CMT frame header + AEAD-encrypted payload
// ---------------------------------------------------------------------------

fn bench_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitors/round_trip");

    for &(label, size) in PAYLOADS {
        let payload = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Raw TCP with length-prefixed framing.
        group.bench_with_input(
            BenchmarkId::new("raw_tcp_framed", label),
            &payload,
            |b, payload| {
                let rt = Runtime::new().unwrap();

                let (client_w, client_r) = rt.block_on(async {
                    let (client, server) = tokio::io::duplex(DUPLEX_SIZE);

                    // Framed echo server.
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(server);
                        while let Ok(data) = read_framed(&mut r).await {
                            if write_framed(&mut w, &data).await.is_err() {
                                break;
                            }
                        }
                    });

                    let (r, w) = tokio::io::split(client);
                    (
                        Arc::new(tokio::sync::Mutex::new(w)),
                        Arc::new(tokio::sync::Mutex::new(r)),
                    )
                });

                b.iter(|| {
                    let w = client_w.clone();
                    let r = client_r.clone();
                    let p = payload.clone();
                    rt.block_on(async {
                        let mut w = w.lock().await;
                        write_framed(&mut *w, &p).await.unwrap();
                        drop(w);

                        let mut r = r.lock().await;
                        let buf = read_framed(&mut *r).await.unwrap();
                        black_box(buf);
                    });
                });
            },
        );

        // TLS 1.3 with length-prefixed framing.
        let (server_config, client_config) = make_tls_configs();
        group.bench_with_input(
            BenchmarkId::new("tls13_rustls_framed", label),
            &payload,
            |b, payload| {
                let rt = Runtime::new().unwrap();

                let (client_w, client_r) = rt.block_on(async {
                    let (client_io, server_io) = tokio::io::duplex(DUPLEX_SIZE);
                    let acceptor = tokio_rustls::TlsAcceptor::from(server_config.clone());
                    let connector = tokio_rustls::TlsConnector::from(client_config.clone());

                    let (server_tls, client_tls) = tokio::join!(
                        acceptor.accept(server_io),
                        connector.connect("localhost".try_into().unwrap(), client_io),
                    );

                    let server_tls = server_tls.unwrap();
                    // Framed echo server on TLS.
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(server_tls);
                        while let Ok(data) = read_framed(&mut r).await {
                            if write_framed(&mut w, &data).await.is_err() {
                                break;
                            }
                        }
                    });

                    let client_tls = client_tls.unwrap();
                    let (r, w) = tokio::io::split(client_tls);
                    (
                        Arc::new(tokio::sync::Mutex::new(w)),
                        Arc::new(tokio::sync::Mutex::new(r)),
                    )
                });

                b.iter(|| {
                    let w = client_w.clone();
                    let r = client_r.clone();
                    let p = payload.clone();
                    rt.block_on(async {
                        let mut w = w.lock().await;
                        write_framed(&mut *w, &p).await.unwrap();
                        drop(w);

                        let mut r = r.lock().await;
                        let buf = read_framed(&mut *r).await.unwrap();
                        black_box(buf);
                    });
                });
            },
        );

        // confidential-ml-transport: send + recv on established SecureChannel.
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();
        group.bench_with_input(
            BenchmarkId::new("cmt_secure_channel", label),
            &payload,
            |b, payload| {
                let rt = Runtime::new().unwrap();
                let payload = Bytes::copy_from_slice(payload);

                let (client_ch, _rx) = rt.block_on(async {
                    let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                    let config = SessionConfig::default();

                    let (s, c) = tokio::join!(
                        SecureChannel::accept_with_attestation(server, &provider, config.clone()),
                        SecureChannel::connect_with_attestation(client, &verifier, config),
                    );

                    let mut server_ch = s.unwrap();
                    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

                    // Echo server.
                    tokio::spawn(async move {
                        let _tx = tx;
                        while let Ok(Message::Data(data)) = server_ch.recv().await {
                            if server_ch.send(data).await.is_err() {
                                break;
                            }
                        }
                    });

                    (c.unwrap(), rx)
                });

                let client_ch = Arc::new(tokio::sync::Mutex::new(client_ch));

                b.iter(|| {
                    let ch = client_ch.clone();
                    let p = payload.clone();
                    rt.block_on(async {
                        let mut ch = ch.lock().await;
                        ch.send(p).await.unwrap();
                        let msg = ch.recv().await.unwrap();
                        black_box(msg);
                    });
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_handshake, bench_round_trip);
criterion_main!(benches);
