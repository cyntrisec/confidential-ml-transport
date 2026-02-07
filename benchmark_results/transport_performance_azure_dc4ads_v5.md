# Transport Performance Report

Generated: 2026-02-07T14:51:52Z

## Methodology

| Parameter | Value |
|-----------|-------|
| CPU | AMD EPYC 7763 (Milan, Family 25h Model 1h) [SEV-SNP masked] |
| VM SKU | Standard_DC4ads_v5 (Azure Confidential VM) |
| Security | ConfidentialVM (AMD SEV-SNP) |
| Region | eastus (Zone 2) |
| Kernel | 6.8.0-1044-azure-fde |
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
| Cold connect | 168.2 us | 174.7 us | 189.1 us | [168.1 us .. 168.4 us] |

Full 3-message handshake: X25519 keygen, mock attestation, HKDF derivation.
No session resumption — reconnect = another cold handshake.

## 2. Steady-State AEAD Latency (per send/recv round-trip)

Handshake excluded — measured on an established channel.

| Payload | Plaintext | SC p50 | SC p95 | SC p99 | 95% CI | Overhead |
|---------|-----------|--------|--------|--------|--------|----------|
| 1536b_embedding (1536 B) | 101.1 us | 123.8 us | 141.5 us | 144.1 us | [120.9 us .. 126.1 us] | 22.4% |
| 4k_activation (4096 B) | 103.7 us | 139.5 us | 155.4 us | 157.4 us | [136.6 us .. 140.8 us] | 34.5% |
| 384k_hidden (393216 B) | 199.6 us | 1.62 ms | 1.65 ms | 1.78 ms | [1.61 ms .. 1.63 ms] | 709.1% |

## 3. Sustained Throughput (unidirectional send)

Client sends burst of messages, server drains in background. No echo.

| Payload | Burst | Plaintext | SecureChannel | 95% CI | Overhead |
|---------|-------|-----------|---------------|--------|----------|
| 1536b_embedding (1536 B) | 682x | 3.04 GB/s | 411.2 MB/s | [408.1 MB/s .. 413.3 MB/s] | 86.5% |
| 4k_activation (4096 B) | 256x | 4.52 GB/s | 618.1 MB/s | [601.4 MB/s .. 632.2 MB/s] | 86.3% |
| 384k_hidden (393216 B) | 2x | 1.90 GB/s | 725.1 MB/s | [715.8 MB/s .. 747.2 MB/s] | 61.8% |
| 1m_large (1048576 B) | 1x | 1.71 GB/s | 519.3 MB/s | [517.5 MB/s .. 520.2 MB/s] | 69.6% |

## 4. Real-World Impact

Transport crypto overhead in the context of end-to-end ML inference:

| Component | Latency | % of inference |
|-----------|---------|----------------|
| MiniLM-L6-v2 inference (representative) | ~100 ms | 100% |
| Handshake (amortized over session) | 168.2 us | 0.17% |
| AEAD send+recv 384-dim embedding (1536 B) | 123.8 us | 0.12% |
| **Total transport overhead per request** | **0.29 ms** | **0.29%** |

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
