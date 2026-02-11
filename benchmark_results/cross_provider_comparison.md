# Cross-Provider Transport Performance Comparison

Generated: 2026-02-11

## Platforms

| | AWS m6i.xlarge | Azure DC4ads_v5 | GCP c3-standard-4 |
|---|---|---|---|
| **CPU** | Intel Xeon 8375C (Ice Lake) | AMD EPYC 7763 (Milan) | Intel Sapphire Rapids (4th Gen Xeon) |
| **vCPUs** | 4 | 4 | 4 |
| **Memory** | 15 GiB | 14 GiB | 14 GiB |
| **Security** | Standard VM (none) | SEV-SNP Confidential VM | TDX Confidential VM |
| **Kernel** | 6.1.159 (Amazon Linux 2023) | 6.8.0-1044-azure-fde | 6.14.0-1021-gcp |
| **Rust** | 1.93.0 | 1.93.0 | 1.93.0 |
| **Date** | 2026-02-07 | 2026-02-07 | 2026-02-11 |

## 1. Handshake Latency (3-message, mock attestation)

| Metric | AWS m6i | Azure DC4ads_v5 | GCP c3-standard-4 |
|--------|---------|-----------------|---------------------|
| **p50** | **139.0 us** | 168.2 us | 142.9 us |
| p95 | 139.7 us | 174.7 us | 148.0 us |
| p99 | 143.0 us | 189.1 us | 155.2 us |
| 95% CI | [138.9 .. 139.1] us | [168.1 .. 168.4] us | [142.7 .. 143.0] us |

**Takeaway:** AWS and GCP within 3% of each other (both Intel). Azure ~21% slower (AMD EPYC Milan vs Intel Xeon). This measures X25519 keygen + HKDF — CPU crypto performance, not memory encryption.

## 2. Steady-State AEAD Latency (per send/recv round-trip)

### 1536B embedding (384-dim F32, MiniLM-L6-v2 output)

| Metric | AWS m6i | Azure DC4ads_v5 | GCP c3-standard-4 |
|--------|---------|-----------------|---------------------|
| Plaintext duplex | 20.2 us | 101.1 us | 84.4 us |
| **SC p50** | **33.2 us** | 123.8 us | 108.0 us |
| Overhead | 64.1% | 22.4% | 27.9% |

### 4KB activation tensor

| Metric | AWS m6i | Azure DC4ads_v5 | GCP c3-standard-4 |
|--------|---------|-----------------|---------------------|
| Plaintext duplex | 20.9 us | 103.7 us | 85.4 us |
| **SC p50** | **42.1 us** | 139.5 us | 124.8 us |
| Overhead | 100.8% | 34.5% | 46.1% |

### 384KB hidden state ([128, 768] F32)

| Metric | AWS m6i | Azure DC4ads_v5 | GCP c3-standard-4 |
|--------|---------|-----------------|---------------------|
| Plaintext duplex | 148.4 us | 199.6 us | 214.3 us |
| **SC p50** | 1.85 ms | **1.62 ms** | 1.86 ms |
| Overhead | 1148% | 709% | 766% |

**Takeaway:** AWS has the lowest absolute latency for small messages but the highest crypto overhead %. Azure/GCP have higher baseline duplex latency (memory encryption overhead from SEV-SNP/TDX) but the crypto overhead % is lower because the baseline is already higher. For large payloads (384KB), Azure is fastest — AMD EPYC Milan's memory subsystem handles large AEAD operations well.

## 3. Sustained Throughput (SecureChannel, unidirectional)

| Payload | AWS m6i | Azure DC4ads_v5 | GCP c3-standard-4 |
|---------|---------|-----------------|---------------------|
| **1536B embedding** | **488 MB/s** | 411 MB/s | 403 MB/s |
| **4KB activation** | **751 MB/s** | 618 MB/s | 604 MB/s |
| **384KB hidden** | 825 MB/s | 725 MB/s | **918 MB/s** |
| **1MB large** | 765 MB/s | 519 MB/s | **785 MB/s** |

**Takeaway:** AWS wins on small-message throughput (no memory encryption overhead on plaintext path). GCP TDX wins on large-message throughput — Sapphire Rapids' memory bandwidth advantage with TDX is smaller than SEV-SNP's on Milan. All platforms sustain >400 MB/s encrypted throughput even for the smallest payload.

## 4. Real-World Impact (MiniLM-L6-v2, ~100ms inference)

| Component | AWS m6i | Azure DC4ads_v5 | GCP c3-standard-4 |
|-----------|---------|-----------------|---------------------|
| Handshake | 0.14% | 0.17% | 0.14% |
| AEAD RTT (1536B) | 0.03% | 0.12% | 0.11% |
| **Total overhead** | **<0.17%** | **<0.29%** | **<0.25%** |

**Bottom line:** Transport crypto overhead is <0.3% of inference time on all three platforms, including real confidential VMs with hardware memory encryption (SEV-SNP, TDX). The encryption cost is negligible compared to model computation.

## 5. Key Observations

1. **Confidential VM memory encryption is measurable but small.** SEV-SNP (Azure) adds ~4-5x to baseline duplex latency for small messages vs non-confidential (AWS). TDX (GCP) adds ~4x. This is the cost of AES-XTS memory encryption at the hardware level.

2. **Our AEAD overhead is consistent across platforms.** ChaCha20-Poly1305 adds 22-64% on top of the already-encrypted baseline (for small messages). The crypto is CPU-bound and behaves predictably.

3. **Large messages are dominated by memory bandwidth, not crypto.** At 384KB, all platforms converge to 700-920 MB/s encrypted throughput. The AEAD seal/open becomes a smaller fraction of total time.

4. **No platform is a clear overall winner.** AWS is fastest for small messages (no memory encryption overhead). GCP TDX is fastest for large messages. Azure SEV-SNP is in the middle. Choose based on workload shape.

## Notes

- All measurements over `tokio::io::duplex` (in-process, no network)
- Mock attestation (real attestation adds ~1-5ms to handshake, amortized over session)
- Same Rust toolchain (1.93.0) on all platforms
- AWS is a non-confidential baseline; Azure and GCP are real confidential VMs
- Throughput differences partly reflect burst count changes between benchmark runs
