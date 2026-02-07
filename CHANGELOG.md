# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.2]: https://github.com/cyntrisec/confidential-ml-transport/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cyntrisec/confidential-ml-transport/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cyntrisec/confidential-ml-transport/releases/tag/v0.1.0
