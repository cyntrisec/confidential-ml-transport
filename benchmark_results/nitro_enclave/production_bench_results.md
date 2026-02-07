# Production-Mode Nitro Enclave Benchmarks

**Date:** 2026-02-07
**Crate:** confidential-ml-transport v0.1.1
**Attestation:** Real AWS Nitro (NitroProvider / NitroVerifier)
**Enclave mode:** PRODUCTION (`Flags: "NONE"`, no debug)

## Instance

| Parameter | Value |
|-----------|-------|
| Instance type | m5.xlarge |
| CPU | Intel Xeon Platinum 8175M @ 2.50GHz |
| vCPUs | 4 total (2 host, 2 enclave) |
| Enclave memory | 2048 MiB |
| OS | Amazon Linux 2023, kernel 6.1.159 |

## EIF Measurements (Production)

| PCR | Value |
|-----|-------|
| PCR0 | `9c4a19c5e7726b1dab80c8068d46ebacd449b3a900d4402944cc5d9502d268efedc860fba625073ba444a32be5a879b1` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `7479d50ad59b5327e59d17454c01f4cf722695a6ace8c2e1b7cf2796c13b8597e3de85ece92b1cdc2ba008dc98fda4f1` |

## Results

### Phase 1: Connect + Handshake (n=50)

| Metric | Value |
|--------|-------|
| **p50** | **5.699ms** |
| p95 | 5.822ms |
| p99 | 5.957ms |
| mean | 5.699ms |
| min | 5.580ms |
| max | 5.957ms |

### Phase 2: Transport RTT (n=200)

| Metric | Value |
|--------|-------|
| **p50** | **0.263ms** |
| p95 | 0.286ms |
| p99 | 0.320ms |
| mean | 0.265ms |
| min | 0.251ms |
| max | 0.326ms |

### Phase 3: Inference RTT (n=50)

| Metric | Value |
|--------|-------|
| **p50** | **98.332ms** |
| p95 | 99.102ms |
| p99 | 99.244ms |
| mean | 98.384ms |
| min | 97.838ms |
| max | 99.244ms |

## Debug vs Production Comparison

| Phase | Debug p50 | Production p50 | Delta |
|-------|-----------|----------------|-------|
| Connect + Handshake | 5.711ms | 5.699ms | -0.012ms (-0.2%) |
| Transport RTT (64B) | 0.244ms | 0.263ms | +0.019ms (+7.8%) |
| Inference RTT | 98.172ms | 98.332ms | +0.160ms (+0.2%) |

**Conclusion:** No measurable performance difference between debug and production mode.
The ~0.02ms variations are within normal noise. Production mode adds no overhead;
it only changes PCR0 values and disables console access.

## Derived Metrics

| Metric | Value |
|--------|-------|
| **Inference-only (mean)** | **98.119ms** |
| Transport overhead per message | 0.265ms |
| Transport overhead % of inference | 0.27% |
