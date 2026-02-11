# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-02-12

### Fixed

- **Double-SHA256 bug in TDX ECDSA signature verification** — `verify_ecdsa_signature()` pre-hashed the quote data with SHA-256 before passing it to OpenSSL's `verify_oneshot()`, which hashes again internally. Real TDX hardware signs `SHA256(header+body)` once, so verification always failed on real quotes. Synthetic tests masked the bug because `build_synthetic_tdx_quote()` had the same double-hash in the signing path. Both paths now pass raw data and let OpenSSL hash once.
- **configfs-tsm entry name collision** — concurrent handshakes from the same process (e.g., control + data channels) used the same configfs-tsm entry name (`cmt_{pid}`), causing `EEXIST` on `create_dir`. Fixed with an `AtomicU64` counter for unique entry names (`cmt_{pid}_{counter}`).
- Benchmark scripts now pass `--features mock` so they work on fresh clones.

### Added

- **3-cloud transport benchmark comparison** — benchmarked on AWS m6i.xlarge (Intel Xeon, non-confidential), Azure DC4ads_v5 (AMD EPYC Milan, SEV-SNP), and GCP c3-standard-4 (Intel Sapphire Rapids, TDX). Transport crypto overhead is <0.3% of inference time on all platforms including real confidential VMs.

| Metric | AWS m6i (none) | Azure DC4ads_v5 (SEV-SNP) | GCP c3-standard-4 (TDX) |
|---|---|---|---|
| Handshake p50 | 139 us | 168 us | 143 us |
| 1536B RTT p50 | 33 us | 124 us | 108 us |
| 384KB throughput | 825 MB/s | 725 MB/s | 918 MB/s |
| Overhead vs inference | <0.17% | <0.29% | <0.25% |

- Hostile-host relay capture demo example.

## [0.2.0] - 2026-02-09

### Added

- **AMD SEV-SNP attestation backend** — `SevSnpProvider` and `SevSnpVerifier` behind the `sev-snp` feature flag. `SevSnpProvider` issues `/dev/sev-guest` attestation requests. `SevSnpVerifier` parses SEV-SNP attestation reports, verifies VCEK/VLEK ECDSA-P384 signatures via openssl, and extracts launch measurement + REPORTDATA. Depends on the `sev` crate (v7, snp + openssl features).
- **Intel TDX attestation backend** — `TdxProvider` and `TdxVerifier` behind the `tdx` feature flag. `TdxProvider` uses the Linux configfs-tsm ABI (`/sys/kernel/config/tsm/report/`, kernel 6.7+). `TdxVerifier` parses TDX v4/v5 quotes, verifies ECDSA-P256 attestation signatures, and extracts MRTD + RTMR0-3 measurements. No new dependencies (reuses existing optional `openssl`).
- SEV-SNP integration tests: handshake, measurement verification, measurement rejection, field extraction.
- TDX integration tests: handshake, measurement verification, measurement rejection, field extraction.
- TDX added to CI feature matrix.
- SEV-SNP added to CI feature matrix.
- Dependabot configuration for Cargo and GitHub Actions dependencies.
- `CODE_OF_CONDUCT.md` and expanded `SECURITY.md` disclosure policy.
- `TensorNameTooLong` error variant for tensor names exceeding 65535 bytes.

### Fixed

- Tensor encode now validates dimension count (≤32) and name length (≤65535 bytes) before u16 cast, preventing silent truncation.

### Changed

- Attestation backend count: 2 → 4 (mock, nitro, sev-snp, tdx).
- CI feature combinations: 5 → 7.

## [0.1.3] - 2026-02-08

Identical to 0.1.2 with a rustfmt fix (no API or behavior changes).
Re-released because crates.io does not allow republishing the same version.

## [0.1.2] - 2026-02-08

### Security

- **Constant-time confirmation hash comparison** — replaced `!=` with `subtle::ConstantTimeEq::ct_eq()` in the handshake confirmation step to prevent timing side-channel attacks where an attacker could incrementally learn correct hash bytes by measuring response latency.
- **Semaphore permit panic safety** — changed proxy connection handlers to bind the semaphore permit at task start (`let _permit = permit;`) instead of explicit `drop(permit)` at the end, ensuring the permit is released even if the handler panics. Prevents connection slot exhaustion under the 256-connection limit.
- **Example client hardening** — added PCR verification and input validation to the nitro-inference example client.

### Added

- `#[non_exhaustive]` on all public error enums (`Error`, `FrameError`, `CryptoError`, `AttestError`, `SessionError`) to allow adding variants in future minor versions without breaking downstream matches.
- Transport API tests (`transport::tcp::connect`, `listen`, `accept`, nodelay verification, error paths).
- Proxy error-path tests (backend unreachable, concurrent connections).
- Initiator-side handshake fuzz target (`fuzz_handshake_init`) with seed corpus.
- CI feature flag matrix testing 5 feature combinations (`--all-features`, `--no-default-features`, `mock`, `tcp`, `tcp+mock`).
- CI fuzz smoke job running all 5 fuzz targets for 30s each.
- Real Nitro Enclave benchmarks (m5.xlarge, production mode) in README and benchmark results.
- `CHANGELOG.md`.

### Fixed

- Proxy integration test now correctly gated on both `mock` and `tcp` features (was `mock`-only, failed to compile without `tcp`).
- README benchmark numbers updated to use consistent AWS criterion p50 values with cross-environment breakdown.
- `echo_server` example command corrected in documentation.
- Dockerfile Rust version bumped to 1.93 for `zip@7.4.0` compatibility.

### Changed

- `subtle` added as direct dependency (was already transitive via `x25519-dalek`, `sha2`, `chacha20poly1305`).
- Test count: 89 → 93.
- Fuzz targets: 4 → 5.

## [0.1.1] - 2026-02-07

### Added

- Doc comments on all public API items.
- Quickstart section with runnable example in README.
- Mock feature gate warning on all mock examples.

### Fixed

- Removed internal references from benchmark files.
- CONTRIBUTING.md test command corrected.

## [0.1.0] - 2026-02-07

Initial release.

### Features

- 3-message attestation-bound handshake (X25519 + HKDF-SHA256).
- ChaCha20-Poly1305 AEAD encryption with AAD binding (version, msg_type, flags, session_id, sequence).
- Binary tensor framing with zero-copy decode.
- Pluggable attestation traits (`AttestationProvider`, `AttestationVerifier`).
- Mock and Nitro attestation implementations.
- TCP and VSock transport backends.
- Transparent encryption proxy (client + server).
- Monotonic sequence enforcement with replay rejection.
- Session retry with exponential backoff.
- Measurement/PCR verification.

[0.2.1]: https://github.com/cyntrisec/confidential-ml-transport/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/cyntrisec/confidential-ml-transport/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/cyntrisec/confidential-ml-transport/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cyntrisec/confidential-ml-transport/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cyntrisec/confidential-ml-transport/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cyntrisec/confidential-ml-transport/releases/tag/v0.1.0
