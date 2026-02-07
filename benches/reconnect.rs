use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

use confidential_ml_transport::session::channel::Message;
use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{MockProvider, MockVerifier, SecureChannel};

/// 64 KB duplex buffer — sufficient for handshake + a small payload.
const DUPLEX_SIZE: usize = 64 * 1024;

/// Small payload for measuring transport latency (not throughput).
const PAYLOAD_SIZE: usize = 1_536; // 384-dim F32 embedding

fn bench_reconnect(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconnect");

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let payload = Bytes::from(vec![0xAB; PAYLOAD_SIZE]);

    // -----------------------------------------------------------------------
    // fresh_handshake_plus_first_message: Full session establishment + one
    // send/recv round-trip. This is the "cold path" cost a client pays when
    // connecting for the first time or after a session drop.
    // -----------------------------------------------------------------------
    group.bench_function("fresh_handshake_plus_first_msg", |b| {
        let rt = Runtime::new().unwrap();

        b.iter(|| {
            let p = payload.clone();
            rt.block_on(async {
                let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                let config = SessionConfig::default();

                let (server_ch, client_ch) = tokio::join!(
                    SecureChannel::accept_with_attestation(server, &provider, config.clone()),
                    SecureChannel::connect_with_attestation(client, &verifier, config),
                );

                let mut server_ch = server_ch.unwrap();
                let mut client_ch = client_ch.unwrap();

                // First message round-trip.
                let srv = tokio::spawn(async move {
                    let msg = server_ch.recv().await.unwrap();
                    match msg {
                        Message::Data(data) => {
                            server_ch.send(data).await.unwrap();
                        }
                        _ => panic!("expected Data"),
                    }
                    server_ch
                });

                client_ch.send(p).await.unwrap();
                let msg = client_ch.recv().await.unwrap();
                black_box(msg);
                black_box(srv.await.unwrap());
            });
        });
    });

    // -----------------------------------------------------------------------
    // steady_state_rtt: Send/recv latency on an already-established session.
    // This is the "warm path" — what most requests experience after the
    // initial handshake is amortized.
    // -----------------------------------------------------------------------
    group.bench_function("steady_state_rtt", |b| {
        let rt = Runtime::new().unwrap();

        // Establish session once, reuse across iterations.
        let (client_ch, _server_rx) = rt.block_on(async {
            let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
            let config = SessionConfig::default();

            let (server_ch, client_ch) = tokio::join!(
                SecureChannel::accept_with_attestation(server, &provider, config.clone()),
                SecureChannel::connect_with_attestation(client, &verifier, config),
            );

            let mut server_ch = server_ch.unwrap();
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
                black_box(msg);
            });
        });
    });

    // -----------------------------------------------------------------------
    // session_teardown_and_reconnect: Measures the cost of tearing down an
    // existing session and establishing a new one. This is the reconnect
    // penalty after a network disruption or session rotation.
    // -----------------------------------------------------------------------
    group.bench_function("teardown_and_reconnect", |b| {
        let rt = Runtime::new().unwrap();

        b.iter(|| {
            rt.block_on(async {
                // First session.
                let (client1, server1) = tokio::io::duplex(DUPLEX_SIZE);
                let config = SessionConfig::default();

                let (server_ch1, client_ch1) = tokio::join!(
                    SecureChannel::accept_with_attestation(server1, &provider, config.clone()),
                    SecureChannel::connect_with_attestation(client1, &verifier, config.clone()),
                );

                let mut server_ch1 = server_ch1.unwrap();
                let mut client_ch1 = client_ch1.unwrap();

                // Graceful shutdown.
                client_ch1.shutdown().await.unwrap();
                let msg = server_ch1.recv().await.unwrap();
                assert!(matches!(msg, Message::Shutdown));
                drop(client_ch1);
                drop(server_ch1);

                // Second session (reconnect).
                let (client2, server2) = tokio::io::duplex(DUPLEX_SIZE);

                let (server_ch2, client_ch2) = tokio::join!(
                    SecureChannel::accept_with_attestation(server2, &provider, config.clone()),
                    SecureChannel::connect_with_attestation(client2, &verifier, config),
                );

                black_box((server_ch2.unwrap(), client_ch2.unwrap()));
            });
        });
    });

    group.finish();
}

criterion_group!(benches, bench_reconnect);
criterion_main!(benches);
