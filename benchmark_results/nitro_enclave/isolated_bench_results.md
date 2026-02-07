# Isolated Nitro Enclave Benchmarks

**Date:** 2026-02-07
**Crate:** confidential-ml-transport v0.1.1
**Attestation:** Real AWS Nitro (NitroProvider / NitroVerifier)

> **Note:** Enclave runs in `DEBUG_MODE`. PCR values differ from production
> (PCR0 is zeroed). Not representative of production security posture.

## Instance

| Parameter | Value |
|-----------|-------|
| Instance type | m5.xlarge |
| CPU | Intel Xeon Platinum 8175M @ 2.50GHz |
| vCPUs | 4 total (2 host, 2 enclave) |
| Enclave memory | 2048 MiB |
| OS | Amazon Linux 2023, kernel 6.1.159 |

## Phase 1: Connect + Handshake (n=50)

Full VSock connect + 3-message attestation handshake with real Nitro NSM call and COSE_Sign1 verification.

| Metric | Value |
|--------|-------|
| **p50** | **5.711ms** |
| p95 | 5.825ms |
| p99 | 5.890ms |
| mean | 5.718ms |
| min | 5.575ms |
| max | 5.890ms |

Very tight distribution (5.6–5.9ms). The Nitro NSM attestation call + COSE verification dominates.

## Phase 2: Transport RTT (n=200)

Round-trip of 64-byte echo payload over an established encrypted SecureChannel via VSock.
Measures: ChaCha20-Poly1305 encrypt → frame → VSock write → server echo → VSock read → deframe → decrypt.

| Metric | Value |
|--------|-------|
| **p50** | **0.244ms** |
| p95 | 0.277ms |
| p99 | 0.307ms |
| mean | 0.247ms |
| min | 0.222ms |
| max | 0.423ms |

Sub-millisecond encrypted round-trips. Extremely consistent (0.22–0.28ms for 95th percentile).

## Phase 3: Inference RTT (n=50)

Round-trip of text → MiniLM-L6-v2 inference → 384-dim F32 tensor response over established encrypted channel.

| Metric | Value |
|--------|-------|
| **p50** | **98.172ms** |
| p95 | 98.490ms |
| p99 | 99.439ms |
| mean | 98.220ms |
| min | 97.903ms |
| max | 99.439ms |

Nearly all time is model inference. Very tight distribution (97.9–98.5ms for 95th percentile).

## Derived Metrics

| Metric | Value |
|--------|-------|
| **Inference-only (mean)** | **97.973ms** |
| Transport overhead per message | 0.247ms |
| Transport overhead % of inference | 0.25% |
| Handshake amortized over 100 requests | 0.057ms/req |

## Key Findings

1. **Transport overhead is negligible**: 0.247ms RTT for encrypted channel over VSock — 0.25% of inference time
2. **Nitro attestation handshake: 5.7ms**: Includes NSM device call, COSE_Sign1 generation, X.509 chain verification, X25519 key exchange, HKDF key derivation
3. **Model inference dominates**: 97.97ms of the 98.22ms total (99.75%)
4. **Extremely consistent**: All three phases show tight distributions, no outlier spikes
5. **Handshake is amortizable**: Over a long-lived connection, the 5.7ms handshake cost vanishes

## Comparison: Local tcp-mock vs Real Nitro

| Phase | tcp-mock (localhost) | Nitro (VSock) | Overhead |
|-------|---------------------|---------------|----------|
| Handshake | ~0.8ms | 5.7ms | +4.9ms (real attestation) |
| Transport RTT | ~0.04ms | 0.25ms | +0.21ms (VSock vs loopback) |
| Inference | ~70ms | 98ms | +28ms (enclave CPU constraints) |

The 28ms inference increase is due to the enclave running on 2 vCPUs with constrained memory,
not transport overhead. Transport adds only 0.21ms per message.
