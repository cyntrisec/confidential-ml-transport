use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

use confidential_ml_transport::session::SessionConfig;
use confidential_ml_transport::{MockProvider, MockVerifier, SecureChannel};

/// 64KB duplex buffer — sufficient for the 3-message handshake.
const DUPLEX_SIZE: usize = 64 * 1024;

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    // Each iteration performs a full 3-message handshake over a fresh duplex.
    // This measures per-session handshake cost on a warmed process (after
    // criterion warmup). True first-ever-process cold start is higher due to
    // one-time allocations and CPU cache misses.
    group.bench_function("fresh_session", |b| {
        let rt = Runtime::new().unwrap();

        b.iter(|| {
            rt.block_on(async {
                let (client, server) = tokio::io::duplex(DUPLEX_SIZE);
                let config = SessionConfig::default();

                let (server_ch, client_ch) = tokio::join!(
                    SecureChannel::accept_with_attestation(
                        server,
                        &provider,
                        &verifier,
                        config.clone()
                    ),
                    SecureChannel::connect_with_attestation(client, &provider, &verifier, config),
                );
                black_box((server_ch.unwrap(), client_ch.unwrap()));
            });
        });
    });

    group.finish();
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
