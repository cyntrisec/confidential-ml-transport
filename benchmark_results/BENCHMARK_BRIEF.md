# Benchmark Brief: confidential-ml-transport

One-page summary of transport layer performance across tested environments.

## Environments Tested

| Environment | CPU | vCPUs | RAM | Security | Commit |
|-------------|-----|-------|-----|----------|--------|
| AWS m6i.xlarge | Intel Xeon Platinum 8375C @ 2.90 GHz | 4 | 16 GiB | Standard (no TEE) | `63d7cc2` |
| Azure DC4ads_v5 | AMD EPYC 7763 Milan (SEV-SNP masked) | 4 | 14 GiB | ConfidentialVM (AMD SEV-SNP) | `9e68c25` |
| Local dev | Intel Core i7-8565U @ 1.80 GHz | 8 | varies | None | `1e4164d` |

All runs: Rust 1.93.0, `tokio::io::duplex` (in-process), MockProvider/MockVerifier, ChaCha20-Poly1305, X25519+HKDF-SHA256, 100 criterion samples.

## Key Numbers

### Handshake (fresh session, 3-message, mock attestation)

| Environment | p50 | p95 |
|-------------|-----|-----|
| AWS m6i.xlarge | 139 µs | 140 µs |
| Azure DC4ads_v5 | 168 µs | 175 µs |
| Local dev | 249 µs | — |

Real attestation (Nitro/SEV-SNP) adds ~1-5 ms to the handshake.

### Reconnect KPIs (local dev)

| Metric | Latency | Ratio |
|--------|---------|-------|
| Fresh handshake + first message | 282 µs | 1.0x (baseline) |
| Steady-state RTT (established session) | 29 µs | 9.7x faster |
| Teardown + reconnect | 465 µs | 1.6x slower |

After the initial handshake, ongoing requests pay only AEAD seal/open cost (~29 µs RTT for a 1536-byte embedding).

### Steady-State AEAD Latency (send/recv round-trip, established session)

| Payload | AWS p50 | Azure p50 | Overhead vs plaintext (AWS) |
|---------|---------|-----------|---------------------------|
| 1536 B (384-dim F32 embedding) | 33 µs | 124 µs | 64% |
| 4 KB (activation tensor) | 42 µs | 140 µs | 101% |
| 384 KB (128×768 hidden state) | 1.85 ms | 1.62 ms | 1148% |

Note: "overhead" = SecureChannel vs plaintext-duplex (frame encode/decode only). The 384 KB overhead is dominated by AEAD processing time on the payload, not protocol overhead.

### Sustained Throughput (unidirectional, burst send)

| Payload | AWS plaintext | AWS secure | Azure secure | Overhead (AWS) |
|---------|--------------|------------|-------------|----------------|
| 1536 B | 2.62 GB/s | 488 MB/s | 411 MB/s | 81% |
| 4 KB | 4.25 GB/s | 751 MB/s | 618 MB/s | 82% |
| 384 KB | 7.04 GB/s | 825 MB/s | 760 MB/s | 88% |
| 1 MB | 6.34 GB/s | 765 MB/s | 756 MB/s | 88% |

### Frame Codec (pure encode/decode, no I/O, no crypto)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Encode 4 KB | 211 ns | 18 GiB/s |
| Decode 4 KB | 200 ns | 19 GiB/s |
| Roundtrip 4 KB | 320 ns | 12 GiB/s |
| Tensor decode 384 KB | 139 ns | 2.6 TiB/s (zero-copy) |

### Crypto Primitives

| Operation | Latency | Throughput |
|-----------|---------|------------|
| ChaCha20-Poly1305 seal 4 KB | 6.2 µs | 630 MB/s |

## Real-World Impact

For MiniLM-L6-v2 inference (~100 ms per sentence):

| Component | Cost | % of inference |
|-----------|------|----------------|
| Handshake (once per session) | ~168 µs | 0.17% |
| AEAD round-trip per request | ~33 µs | 0.03% |
| **Steady-state overhead** | **~33 µs** | **~0.03%** |

For a session serving 1000 requests, the amortized handshake cost is <0.001% per request.

## Reproducing

```bash
# Full run (100 samples, ~5 min)
bash scripts/bench_transport_performance.sh

# Quick smoke test (10 samples, ~1 min)
bash scripts/bench_transport_performance.sh --quick

# Individual benchmarks
cargo bench --bench handshake
cargo bench --bench confidential_overhead
cargo bench --bench throughput
cargo bench --bench reconnect
cargo bench --bench frame_codec

# On a cloud VM (see CLAUDE.md "Running Cloud Benchmarks" for full setup)
# AWS:
#   Instance: m6i.xlarge (4 vCPU, 16 GiB)
#   AMI: Amazon Linux 2023
#   Setup: install rustup + build-essential, clone repo, run script
#
# Azure:
#   VM: Standard_DC4ads_v5 (4 vCPU, 14 GiB, SEV-SNP)
#   Image: Ubuntu 24.04 CVM
#   Setup: install rustup + build-essential + libssl-dev, clone repo, run script
```

## Raw Data

| File | Description |
|------|-------------|
| `transport_performance_aws_m6i.json` | AWS m6i.xlarge full results (machine-readable) |
| `transport_performance_aws_m6i.md` | AWS m6i.xlarge full results (human-readable) |
| `transport_performance_azure_dc4ads_v5.json` | Azure DC4ads_v5 full results (machine-readable) |
| `transport_performance_azure_dc4ads_v5.md` | Azure DC4ads_v5 full results (human-readable) |
| `transport_performance.json` | Latest local run (machine-readable) |
| `transport_performance.md` | Latest local run (human-readable) |
| `target/criterion/` | Raw criterion data (not committed) |

## Competitor Comparison (local dev, tokio::io::duplex 1MB, 20 samples)

Side-by-side: raw TCP (unencrypted duplex), TLS 1.3 (rustls 0.23, AES-256-GCM), CMT SecureChannel (ChaCha20-Poly1305 + X25519 + mock attestation).

### Handshake Latency

| Transport | p50 | vs TLS 1.3 |
|-----------|-----|------------|
| Raw TCP (duplex creation only) | 247 ns | — |
| TLS 1.3 (rustls, full handshake) | 535 µs | 1.0x |
| **CMT (3-msg, mock attestation)** | **182 µs** | **2.9x faster** |

CMT's 3-message handshake is significantly faster than TLS 1.3 because it avoids X.509 certificate chain validation. Real attestation (Nitro/SEV-SNP) would add 1-5 ms.

### Round-Trip Latency (established session, echo server)

| Payload | Raw TCP | TLS 1.3 | CMT | CMT overhead vs raw |
|---------|---------|---------|-----|---------------------|
| 1536 B (embedding) | 13.2 µs | 14.3 µs | 23.5 µs | 1.78x |
| 4 KB (activation) | 14.9 µs | 20.3 µs | 35.4 µs | 2.38x |
| 384 KB (hidden state) | 100 µs | 439 µs | 1,610 µs | 16.1x |

### Round-Trip Throughput

| Payload | Raw TCP | TLS 1.3 | CMT |
|---------|---------|---------|-----|
| 1536 B | 119 MiB/s | 102 MiB/s | 62 MiB/s |
| 4 KB | 262 MiB/s | 193 MiB/s | 110 MiB/s |
| 384 KB | 3.65 GiB/s | 855 MiB/s | 233 MiB/s |

**Analysis:** For small payloads (1.5-4 KB, typical ML embeddings), CMT adds ~10-20 µs vs raw TCP — negligible against model inference latency (~100 ms). For large payloads (384 KB), CMT's per-frame AEAD dominates. TLS 1.3 benefits from AES-NI hardware acceleration on Intel CPUs while CMT uses software ChaCha20.

**Reproduce:** `cargo bench --bench competitors`

## SLO Targets

Based on measured p50/p95 values with 2x headroom:

| Metric | SLO | Measured (worst env) |
|--------|-----|---------------------|
| Handshake p50 | < 500 µs | 249 µs (local) |
| Steady-state RTT p50 (1536 B) | < 200 µs | 124 µs (Azure) |
| Reconnect p95 | < 1 ms | 465 µs (local) |
| Throughput (4 KB, secure) | > 200 MB/s | 501 MB/s (local) |

CI checks these thresholds nightly via `scripts/check_bench_slo.sh`.
