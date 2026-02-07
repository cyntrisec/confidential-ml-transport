# Transport Performance Report

Generated: 2026-02-07T14:04:51Z

## Methodology

| Parameter | Value |
|-----------|-------|
| CPU | Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz |
| Kernel | 6.1.159-182.297.amzn2023.x86_64 |
| Rust | rustc 1.93.0 (254b59607 2026-01-19) |
| CPUs | 4 |
| CPU governor | unknown |
| Memory | 15Gi |
| Transport | tokio::io::duplex (in-process, no network) |
| Attestation | MockProvider / MockVerifier |
| Cipher | ChaCha20-Poly1305 (AEAD) |
| Key agreement | X25519 + HKDF-SHA256 |
| Criterion samples | 100 (default) |

## 1. Handshake Latency

| Metric | p50 | p95 | p99 | 95% CI |
|--------|-----|-----|-----|--------|
| Cold connect | 139.0 us | 139.7 us | 143.0 us | [138.9 us .. 139.1 us] |

Full 3-message handshake: X25519 keygen, mock attestation, HKDF derivation.
No session resumption — reconnect = another cold handshake.

## 2. Steady-State AEAD Latency (per send/recv round-trip)

Handshake excluded — measured on an established channel.

| Payload | Plaintext | SC p50 | SC p95 | SC p99 | 95% CI | Overhead |
|---------|-----------|--------|--------|--------|--------|----------|
| 1536b_embedding (1536 B) | 20.2 us | 33.2 us | 36.8 us | 37.9 us | [32.4 us .. 33.5 us] | 64.1% |
| 4k_activation (4096 B) | 20.9 us | 42.1 us | 46.3 us | 48.2 us | [41.1 us .. 42.8 us] | 100.8% |
| 384k_hidden (393216 B) | 148.4 us | 1.85 ms | 2.20 ms | 2.47 ms | [1.73 ms .. 1.94 ms] | 1147.9% |

## 3. Sustained Throughput (unidirectional send)

Client sends burst of messages, server drains in background. No echo.

| Payload | Burst | Plaintext | SecureChannel | 95% CI | Overhead |
|---------|-------|-----------|---------------|--------|----------|
| 1536b_embedding (1536 B) | 682x | 2.62 GB/s | 488.4 MB/s | [486.3 MB/s .. 490.0 MB/s] | 81.4% |
| 4k_activation (4096 B) | 256x | 4.25 GB/s | 750.8 MB/s | [749.5 MB/s .. 752.0 MB/s] | 82.3% |
| 384k_hidden (393216 B) | 2x | 7.04 GB/s | 825.1 MB/s | [785.0 MB/s .. 867.6 MB/s] | 88.3% |
| 1m_large (1048576 B) | 1x | 6.34 GB/s | 765.2 MB/s | [699.8 MB/s .. 966.5 MB/s] | 87.9% |

## 4. Real-World Impact

Transport crypto overhead in the context of end-to-end ML inference:

| Component | Latency | % of inference |
|-----------|---------|----------------|
| MiniLM-L6-v2 inference (representative) | ~100 ms | 100% |
| Handshake (amortized over session) | 139.0 us | 0.14% |
| AEAD send+recv 384-dim embedding (1536 B) | 33.2 us | 0.03% |
| **Total transport overhead per request** | **0.17 ms** | **0.17%** |

The handshake is a one-time cost per session (not per request). For a session
serving 1000 requests, the amortized handshake cost is <0.001% per request.
**Steady-state transport overhead is <0.1% of model inference time.**

## Notes

- All measurements over `tokio::io::duplex` (in-process, no network latency)
- Mock attestation (real Nitro/SEV-SNP attestation adds ~1-5ms to handshake)
- CPU governor `powersave` may increase variance; `performance` recommended for reproducibility
- 95% CI = criterion confidence interval on median estimate
- p50/p95/p99 = percentiles over criterion sample-level iteration means
- Reconnect = another cold handshake (no session resumption)
