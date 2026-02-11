# Transport Performance Report

Generated: 2026-02-11T12:59:45Z

## Methodology

| Parameter | Value |
|-----------|-------|
| CPU | Intel Sapphire Rapids (4th Gen Xeon) [TDX confidential VM] |
| VM SKU | c3-standard-4 |
| Cloud | GCP |
| Region | us-central1-a |
| Security | Intel TDX Confidential VM |
| Kernel | 6.14.0-1021-gcp |
| Rust | rustc 1.93.0 (254b59607 2026-01-19) |
| CPUs | 4 |
| CPU governor | unknown |
| Memory | 14Gi |
| Transport | tokio::io::duplex (in-process, no network) |
| Attestation | MockProvider / MockVerifier |
| Cipher | ChaCha20-Poly1305 (AEAD) |
| Key agreement | X25519 + HKDF-SHA256 |
| Criterion samples | 100 (default) |

## 1. Handshake Latency

| Metric | p50 | p95 | p99 | 95% CI |
|--------|-----|-----|-----|--------|
| Fresh session | 142.9 us | 148.0 us | 155.2 us | [142.7 us .. 143.0 us] |

Full 3-message handshake: X25519 keygen, mock attestation, HKDF derivation.
Measured on a warmed process (after criterion warmup). True first-process cold
start is higher. No session resumption — every reconnect repeats the handshake.

## 2. Steady-State AEAD Latency (per send/recv round-trip)

Handshake excluded — measured on an established channel.

| Payload | Plaintext | SC p50 | SC p95 | SC p99 | 95% CI | Overhead |
|---------|-----------|--------|--------|--------|--------|----------|
| 1536b_embedding (1536 B) | 84.4 us | 108.0 us | 121.2 us | 126.5 us | [104.5 us .. 109.5 us] | 27.9% |
| 4k_activation (4096 B) | 85.4 us | 124.8 us | 139.9 us | 150.3 us | [122.2 us .. 125.8 us] | 46.1% |
| 384k_hidden (393216 B) | 214.3 us | 1.86 ms | 1.87 ms | 2.07 ms | [1.85 ms .. 1.86 ms] | 765.7% |

## 3. Sustained Throughput (unidirectional send)

Client sends burst of messages, server drains in background. No echo.
Both plaintext and SecureChannel servers decode frames; overhead = crypto (AEAD seal/open) only.

| Payload | Burst | Plaintext | SecureChannel | 95% CI | Overhead |
|---------|-------|-----------|---------------|--------|----------|
| 1536b_embedding (1536 B) | 2730x | 3.04 GB/s | 403.3 MB/s | [395.5 MB/s .. 406.3 MB/s] | 86.8% |
| 4k_activation (4096 B) | 1024x | 4.58 GB/s | 604.2 MB/s | [600.6 MB/s .. 610.3 MB/s] | 86.8% |
| 384k_hidden (393216 B) | 10x | 5.17 GB/s | 918.3 MB/s | [859.2 MB/s .. 928.1 MB/s] | 82.3% |
| 1m_large (1048576 B) | 4x | 4.70 GB/s | 784.9 MB/s | [772.1 MB/s .. 831.3 MB/s] | 83.3% |

## 4. Real-World Impact

Transport crypto overhead in the context of end-to-end ML inference:

| Component | Latency | % of inference |
|-----------|---------|----------------|
| MiniLM-L6-v2 inference (estimated) | ~100 ms | 100% |
| Handshake (amortized over session) | 142.9 us | 0.14% |
| AEAD send+recv 384-dim embedding (1536 B) | 108.0 us | 0.11% |
| **Total transport overhead per request** | **0.25 ms** | **0.25%** |

The handshake is a one-time cost per session (not per request). For a session
serving 1000 requests, the amortized handshake cost is <0.001% per request.
**Steady-state transport overhead is ~0.1% of model inference time.**

## Notes

- All measurements over `tokio::io::duplex` (in-process, no network latency)
- Mock attestation (real Nitro/SEV-SNP attestation adds ~1-5ms to handshake)
- CPU governor `powersave` may increase variance; `performance` recommended for reproducibility
- 95% CI = criterion confidence interval on median estimate
- p50/p95/p99 = percentiles over criterion sample-level iteration means
- Reconnect = another cold handshake (no session resumption)
