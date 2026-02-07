# Nitro Enclave Test Results

**Date:** 2026-02-07
**Crate:** confidential-ml-transport v0.1.1
**Attestation:** Real AWS Nitro (NitroProvider / NitroVerifier)

## Instance

| Parameter | Value |
|-----------|-------|
| Instance type | m5.xlarge |
| Region | us-east-1 |
| CPU | Intel Xeon Platinum 8175M @ 2.50GHz |
| Total vCPUs | 4 (2 host + 2 enclave) |
| Total memory | 16 GiB (2 GiB to enclave) |
| OS | Amazon Linux 2023 |
| Kernel | 6.1.159-182.297.amzn2023.x86_64 |
| Rust | 1.93.0 |
| Nitro CLI | 1.4.4 |

## EIF Measurements

| PCR | Value |
|-----|-------|
| PCR0 | `f5ee1e0e52547b31e533c3bc5a6091d8235e006f8dc85badccb9eeecff5ebb4fcbf1c21a67dfcf99268863602d598d9a` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `91ee3f436aa1fc381777ed015bdfb964b4bd70ae8ec6add9e8ab92a4667b96e680b34a34244aeb983bc694f4cb265cc6` |

## Attestation Verification

- **Document hash:** `40235006940aab2f5d89d9afee362e15d41b3149e63fdfd4c367bc7421c16d5c`
- **Measurement registers returned:** 16
- **Verification:** Passed (real COSE_Sign1 document, AWS root CA chain)

## Model

- **Model:** sentence-transformers/all-MiniLM-L6-v2
- **Parameters:** 22.7M
- **Embedding dimensions:** 384 (F32)

## Benchmark Results

### Sequential Requests (10x, each with fresh handshake)

Each request includes: VSock connect + Nitro attestation handshake + model inference + tensor response.

| Request | Latency (ms) |
|---------|-------------|
| 1 | 104 |
| 2 | 94 |
| 3 | 92 |
| 4 | 92 |
| 5 | 92 |
| 6 | 91 |
| 7 | 92 |
| 8 | 92 |
| 9 | 92 |
| 10 | 91 |

| Metric | Value |
|--------|-------|
| Mean | 93.2ms |
| Median (p50) | 92ms |
| p95 | 104ms |
| Min | 91ms |
| Max | 104ms |

### Burst (5 texts, single connection)

Single handshake + 5 sequential inferences:

| Metric | Value |
|--------|-------|
| Total | 415ms |
| Per inference | ~83ms |
| Handshake overhead | ~10ms (estimated) |

## Protocol

- **Cipher suite:** X25519 + HKDF-SHA256 + ChaCha20-Poly1305
- **Transport:** VSock (enclave CID 16/17)
- **Frame version:** 2 (AAD binds version + msg_type + flags + session_id + sequence)
- **Tensor framing:** Zero-copy binary with 8-byte alignment

## Key Observations

1. **Real Nitro attestation works end-to-end** — COSE_Sign1 document generation inside enclave, verification on host via AWS root CA chain
2. **First request ~12ms slower** (104ms vs 91ms) — likely due to initial allocations / TLS-like cold start
3. **Steady-state latency: 91-92ms** per request (handshake + inference combined)
4. **Amortized inference: ~83ms** when reusing a single connection (handshake overhead ~10ms)
5. **NSM module loaded** — enclave console confirms `nsm: loading out-of-tree module` and RNG seeding
