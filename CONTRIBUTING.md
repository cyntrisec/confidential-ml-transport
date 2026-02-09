# Contributing to confidential-ml-transport

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork and create a feature branch:
   ```bash
   git checkout -b my-feature
   ```
3. Make your changes
4. Run the test suite:
   ```bash
   cargo test --all-features
   cargo clippy --all-features --tests -- -D warnings
   cargo fmt --check
   ```
5. Commit and push to your fork
6. Open a pull request

## Development Requirements

- Rust stable (edition 2021)
- `libssl-dev` (for the `nitro`, `sev-snp`, and `tdx` features — `sudo apt-get install libssl-dev`)
- `tokio` runtime (tests use `#[tokio::test]`)

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy --all-features --tests -- -D warnings` and fix all warnings
- Write tests for new functionality
- Minimize `unsafe` usage; justify each use with a `// SAFETY:` comment

## Testing

```bash
# Unit + integration tests (default features)
cargo test

# All features (requires libssl-dev)
cargo test --all-features

# Property tests
cargo test --test frame_roundtrip

# Benchmarks
cargo bench

# Fuzz testing (5 targets: frame_decode, tensor_decode, handshake_resp, handshake_init, aead_open)
cargo +nightly fuzz run fuzz_frame_decode fuzz/seed_corpus/fuzz_frame_decode
```

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for bug fixes and new features
- Update the README if adding user-facing functionality
- Ensure CI passes (test, clippy, fmt, doc)

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (MIT OR Apache-2.0).
