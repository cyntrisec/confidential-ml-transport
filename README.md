# confidential-ml-transport

Attestation-bound encrypted tensor transport for confidential ML inference over VSock and TCP.

## Quickstart

Try it in 60 seconds — no project setup needed:

```bash
git clone https://github.com/cyntrisec/confidential-ml-transport.git
cd confidential-ml-transport
cargo run --example echo_server --features mock
```

This runs an encrypted echo server and client over TCP with a full attested handshake (mock attestation). You should see:

```
echo server listening on 127.0.0.1:9876
accepted connection from 127.0.0.1:...
[client] connected and handshake complete
[client] sending: echo request #0
[server] handshake complete
[server] echoing: echo request #0
[client] received: echo request #0
...
done!
```

To use in your own project:

```bash
cargo add confidential-ml-transport --features mock
```

```rust
use confidential_ml_transport::{
    MockProvider, MockVerifier, SecureChannel, SessionConfig,
};
use bytes::Bytes;

// Server: accept an attested encrypted connection
let (stream, _) = listener.accept().await?;
let mut server = SecureChannel::accept_with_attestation(
    stream, &MockProvider::new(), SessionConfig::default(),
).await?;

// Client: connect with attestation verification
let stream = tokio::net::TcpStream::connect("127.0.0.1:9876").await?;
let mut client = SecureChannel::connect_with_attestation(
    stream, &MockVerifier::new(), SessionConfig::default(),
).await?;

client.send(Bytes::from("hello")).await?;
```

> **Note:** `MockProvider`/`MockVerifier` perform no real attestation and are for **testing and development only**. For production, use `NitroProvider`/`NitroVerifier` (feature `nitro`) or implement the `AttestationProvider`/`AttestationVerifier` traits for your TEE platform.

## Overview

`confidential-ml-transport` is a Rust library that provides secure, binary-framed communication between TEE (Trusted Execution Environment) enclaves and clients. It combines a compact wire protocol with X25519+ChaCha20Poly1305 encryption and a 3-message attested handshake, designed for streaming tensor data in confidential AI inference pipelines.

**Key properties:**

- **Binary framing** — 13-byte fixed header, compact tensor sub-headers with 8-byte-aligned data, 32 MiB max payload
- **Attestation-bound sessions** — session keys are derived from attestation documents, binding the cryptographic channel to a verified TEE identity
- **Full channel encryption** — all post-handshake frames (data, tensor, heartbeat, shutdown, error) are encrypted and authenticated via AEAD
- **Key material protection** — symmetric keys zeroized on drop, contributory DH check, domain-separated session ID
- **Pluggable transports** — TCP and VSock backends via feature flags
- **Pluggable attestation** — trait-based attestation provider/verifier, with mock and Nitro implementations (SEV-SNP, TDX implementable downstream)
- **Monotonic sequence enforcement** — replay protection on every decrypted message
- **Hardened handshake** — configurable timeout, mandatory public key binding, sequence validation, confirmation binds both keys
- **Measurement verification** — verify PCR/measurement registers against expected values during handshake
- **Connection retry** — exponential backoff with jitter for resilient connection establishment
- **Transparent proxy** — encrypt-on-the-wire proxy pair for wrapping existing TCP services without code changes

## Wire Protocol

```
13-byte frame header (big-endian):

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         magic (0xCF4D)        |  version (2)  |   msg_type    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    flags      |                  sequence                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                payload_len                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |
+-+-+-+-+-+-+-+-+
```

| Message Type | Value | Description |
|---|---|---|
| Hello | `0x01` | Handshake messages |
| Data | `0x02` | Application data |
| Error | `0x03` | Error from peer |
| Heartbeat | `0x04` | Keep-alive |
| Shutdown | `0x05` | Graceful close |
| Tensor | `0x06` | Tensor payload with sub-header |

Tensor frames include a sub-header with dtype, shape, name, and 8-byte-aligned raw data. Supported dtypes: F32, F64, F16, BF16, I32, I64, U8, U32.

## Handshake

A 3-message protocol establishes an encrypted session:

```
  Initiator (client)                         Responder (server/enclave)
       |                                            |
       |--- Hello { pubkey_c, nonce_c } ----------->|
       |                                            |
       |<-- Hello { pubkey_s, nonce_s, att_doc } ---|
       |                                            |
       |--- Hello { confirmation_hash } ----------->|
       |                                            |
     [session established, encrypted data flows]
```

1. Client sends its ephemeral X25519 public key and nonce
2. Server responds with its public key, nonce, and an attestation document binding its public key
3. Client verifies the attestation, derives session keys, and sends a confirmation hash proving key agreement

Session keys are derived via HKDF-SHA256 from the X25519 shared secret, salted with a transcript hash that binds: `SHA256(attestation_hash || sorted(pk_a, pk_b) || nonce_a XOR nonce_b || protocol_version)`.

## Usage

### Basic encrypted echo (TCP + mock attestation)

> **Requires feature `mock`:** `cargo add confidential-ml-transport --features mock`
>
> `MockProvider`/`MockVerifier` skip real attestation and are for **testing only**. For production, use `NitroProvider`/`NitroVerifier` or implement your own `AttestationProvider`/`AttestationVerifier`.

```rust
use bytes::Bytes;
use confidential_ml_transport::{
    MockProvider, MockVerifier, SecureChannel, SessionConfig,
    session::channel::Message,
};

// Server side
let listener = tokio::net::TcpListener::bind("127.0.0.1:9876").await?;
let (stream, _) = listener.accept().await?;
let provider = MockProvider::new();
let mut server = SecureChannel::accept_with_attestation(
    stream, &provider, SessionConfig::default(),
).await?;

match server.recv().await? {
    Message::Data(data) => server.send(data).await?,
    _ => {}
}

// Client side
let stream = tokio::net::TcpStream::connect("127.0.0.1:9876").await?;
let verifier = MockVerifier::new();
let mut client = SecureChannel::connect_with_attestation(
    stream, &verifier, SessionConfig::default(),
).await?;

client.send(Bytes::from("hello")).await?;
let response = client.recv().await?; // Message::Data("hello")
client.shutdown().await?;
```

### SessionConfig builder

Use the builder pattern to customize session configuration:

```rust
use std::time::Duration;
use std::collections::BTreeMap;
use confidential_ml_transport::{
    SessionConfig, RetryPolicy, ExpectedMeasurements,
};

let config = SessionConfig::builder()
    .handshake_timeout(Duration::from_secs(10))
    .retry_policy(RetryPolicy {
        max_retries: 5,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        backoff_multiplier: 2.0,
    })
    .expected_measurements(ExpectedMeasurements::new({
        let mut m = BTreeMap::new();
        m.insert(0, vec![0xAA; 48]); // expected PCR0
        m
    }))
    .build()?;
```

### Connection retry with backoff

Use `connect_with_retry` to automatically retry failed connections with exponential backoff:

```rust
use confidential_ml_transport::{SecureChannel, SessionConfig, RetryPolicy};
use std::time::Duration;

let config = SessionConfig::builder()
    .retry_policy(RetryPolicy::default()) // 3 retries, 1s initial, 2x backoff
    .build()?;

let mut channel = SecureChannel::connect_with_retry(
    || async { tokio::net::TcpStream::connect("enclave:5000").await },
    &verifier,
    config,
).await?;
```

### Measurement verification

Verify PCR/measurement registers against expected values during the handshake. If any measurement mismatches, the connection is rejected before any application data flows:

```rust
use std::collections::BTreeMap;
use confidential_ml_transport::{SessionConfig, ExpectedMeasurements};

let mut expected = BTreeMap::new();
expected.insert(0, pcr0_bytes.to_vec());  // PCR0: enclave image hash
expected.insert(1, pcr1_bytes.to_vec());  // PCR1: kernel hash

let config = SessionConfig::builder()
    .expected_measurements(ExpectedMeasurements::new(expected))
    .build()?;

// Handshake will fail if the enclave's measurements don't match
let mut channel = SecureChannel::connect_with_attestation(
    stream, &verifier, config,
).await?;
```

For testing, use `MockVerifierWithMeasurements` to simulate an enclave returning specific measurement values:

```rust
use confidential_ml_transport::MockVerifierWithMeasurements;

let verifier = MockVerifierWithMeasurements::new(vec![
    vec![0xAA; 48],  // measurement[0]
    vec![0xBB; 48],  // measurement[1]
]);
```

### Transparent proxy

Wrap any existing TCP service with encryption, without modifying the service code. The server proxy runs inside the enclave and forwards decrypted traffic to a local backend; the client proxy runs on the host and accepts plaintext TCP connections.

```rust
use std::sync::Arc;
use confidential_ml_transport::proxy::server::{run_server_proxy, ServerProxyConfig};
use confidential_ml_transport::proxy::client::{run_client_proxy, ClientProxyConfig};
use confidential_ml_transport::{MockProvider, MockVerifier, SessionConfig};

// Inside the enclave: decrypt and forward to local inference server
let server_config = ServerProxyConfig {
    listen_addr: "0.0.0.0:5000".parse()?,
    backend_addr: "127.0.0.1:8080".parse()?,  // local inference server
    session_config: SessionConfig::default(),
    max_connections: 256,
};
tokio::spawn(run_server_proxy(server_config, Arc::new(provider)));

// On the host: accept plaintext, encrypt and forward to enclave
let client_config = ClientProxyConfig {
    listen_addr: "127.0.0.1:9000".parse()?,
    enclave_addr: "enclave:5000".parse()?,
    session_config: SessionConfig::default(),
    max_connections: 256,
};
tokio::spawn(run_client_proxy(client_config, Arc::new(verifier)));

// Now any TCP client connecting to localhost:9000 gets transparent encryption
```

### Sending tensors

```rust
use confidential_ml_transport::{TensorRef, DType};

let activations: Vec<f32> = vec![0.0; 128 * 768];
// Safe conversion: collect f32s into a byte vec via to_ne_bytes
let data: Vec<u8> = activations.iter().flat_map(|f| f.to_ne_bytes()).collect();

let tensor = TensorRef {
    name: "hidden_state",
    dtype: DType::F32,
    shape: &[128, 768],
    data: &data,
};

channel.send_tensor(tensor).await?;
```

### Custom attestation provider

Implement the `AttestationProvider` and `AttestationVerifier` traits for your TEE platform:

```rust
use async_trait::async_trait;
use confidential_ml_transport::{
    AttestationProvider, AttestationVerifier,
    attestation::types::{AttestationDocument, VerifiedAttestation},
    error::AttestError,
};

struct MyProvider { /* platform-specific handle */ }

#[async_trait]
impl AttestationProvider for MyProvider {
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        // Call platform API to generate attestation document
        todo!()
    }
}
```

A built-in `NitroProvider` and `NitroVerifier` are available behind the `nitro` feature flag for AWS Nitro Enclaves.

## Features

| Feature | Default | Description |
|---|---|---|
| `mock` | No | Mock attestation provider/verifier for testing |
| `tcp` | Yes | TCP transport helpers and transparent proxy |
| `vsock` | No | VSock transport via `tokio-vsock` |
| `nitro` | No | AWS Nitro Enclave attestation (NitroProvider/NitroVerifier) |

```bash
# Default (tcp only)
cargo build

# With mock attestation for testing
cargo build --features mock

# With VSock support
cargo build --features vsock

# With Nitro attestation (requires libssl-dev)
cargo build --features nitro

# All features
cargo build --all-features
```

## Testing

```bash
# All tests (unit + proptest + integration, requires mock feature)
cargo test --all-features

# Property-based tests only
cargo test --test frame_roundtrip

# Retry and measurement tests
cargo test --test session_retry

# Proxy integration tests
cargo test --test proxy_integration

# Benchmarks
cargo bench --bench frame_codec

# Fuzz the frame decoder (requires nightly)
cd fuzz && cargo +nightly fuzz run fuzz_frame_decode -- -max_total_time=60

# Run the echo server example
cargo run --example echo_server
```

## Benchmarks

Headline numbers (see [`benchmark_results/BENCHMARK_BRIEF.md`](benchmark_results/BENCHMARK_BRIEF.md) for full cross-environment results, SLO targets, and reproduction commands):

| Metric | Value | Environment |
|--------|-------|-------------|
| Handshake (3-msg, mock attestation) | **139–249 µs** p50 | AWS / Azure / local |
| Steady-state RTT (1536 B embedding) | **29 µs** | Local (established session) |
| Reconnect amortization | **9.7x** (282 µs → 29 µs) | Local |
| Throughput (4 KB, secure) | **501–751 MB/s** | Local / AWS |
| Frame codec roundtrip (4 KB) | **320 ns** (12 GiB/s) | Local |
| ChaCha20-Poly1305 seal (4 KB) | **6.2 µs** (630 MB/s) | Local |

```bash
# Run all benchmarks
bash scripts/bench_transport_performance.sh

# Quick smoke test
bash scripts/bench_transport_performance.sh --quick

# Individual: handshake, overhead, throughput, reconnect, frame_codec
cargo bench --bench reconnect
```

## Performance (Real Nitro Enclave)

Measured on m5.xlarge (Intel Xeon 8175M, 2 vCPU enclave, 2 GiB) with real Nitro attestation in **production mode** (`Flags: "NONE"`, no debug).

| Phase | p50 | p95 | n |
|-------|-----|-----|---|
| Connect + handshake (NSM + COSE + X25519) | 5.699 ms | 5.822 ms | 50 |
| Encrypted transport RTT (64 B echo) | 0.263 ms | 0.286 ms | 200 |
| Inference RTT (MiniLM-L6-v2, 384-dim F32) | 98.332 ms | 99.102 ms | 50 |

Transport overhead is 0.27% of inference time — encryption is not the bottleneck. No measurable performance difference between debug and production enclave modes.

Baseline: [`bench-baseline-v0.1.1`](https://github.com/cyntrisec/confidential-ml-transport/tree/bench-baseline-v0.1.1).
See `benchmark_results/nitro_enclave/` for full data including raw measurements and debug vs production comparison.

## Crypto Design

| Component | Algorithm | Purpose |
|---|---|---|
| Key exchange | X25519 (Diffie-Hellman) | Ephemeral shared secret |
| Key derivation | HKDF-SHA256 | Derive send/recv keys from shared secret + transcript |
| Encryption | ChaCha20Poly1305 | Per-message AEAD with AAD = `version \|\| msg_type \|\| flags \|\| session_id \|\| sequence` |
| Transcript | SHA256 | Bind session to attestation + public keys + nonces |
| Replay protection | Monotonic u64 sequence | Reject any sequence <= last accepted |

## Security Hardening

The following security measures have been applied based on a comprehensive audit:

### Key Material Protection
- **Key zeroization** — `SymmetricKey` uses `Zeroize + ZeroizeOnDrop` to clear key material from memory when no longer needed. `SealingContext` and `OpeningContext` implement `Drop` to zeroize session IDs and sequence counters.
- **Contributory key check** — `was_contributory()` rejects non-contributory DH results (small-subgroup or identity point attacks).
- **Domain-separated session ID** — Session ID is derived from the transcript hash via HKDF with label `"cmt-session-id"`, preventing reuse as HKDF salt.

### Channel Security
- **All post-handshake frames encrypted** — Heartbeat, shutdown, and error frames are encrypted via AEAD, preventing traffic analysis and injection of unauthenticated control messages. Unencrypted frames in an established session are rejected.
- **Unified sequence counters** — The AEAD sealer's internal sequence counter is used directly as the frame header sequence number, eliminating desynchronization between the wire format and cryptographic state.
- **Bounded read buffer** — The read buffer enforces a maximum size to prevent memory exhaustion from oversized or malicious frames.

### Handshake Hardening
- **Handshake timeout** — Configurable via `SessionConfig::handshake_timeout` (default: 30 seconds). Prevents resource exhaustion from stalled or slow handshakes.
- **Mandatory public key binding** — The responder's attestation document must include a public key that matches the handshake key exchange. Missing public keys are rejected.
- **Measurement verification** — Optional `ExpectedMeasurements` checked during the handshake, before any application data flows. Mismatched PCR/measurement values abort the connection.
- **Confirmation hash binds both keys** — The confirmation message includes both the send and receive keys, ensuring both parties derived identical key pairs.
- **Handshake sequence validation** — Frame sequence numbers are validated during the handshake (initiator hello=0, responder hello=0, confirmation=1).
- **Sanitized error messages** — Internal error details are logged via `tracing` but not exposed in protocol-level error messages.

### Connection Resilience
- **Exponential backoff with jitter** — `RetryPolicy` provides configurable retry with exponential delay (default: 3 retries, 1s initial, 2x multiplier, 30s cap) and random jitter in [0.5x, 1.0x] to avoid thundering herd.
- **Transport factory pattern** — `connect_with_retry` accepts a closure to create fresh transports per attempt, ensuring clean state on each retry.

### Operational Observability
- **Structured attestation logging** — `tracing::info` events emitted after successful attestation verification (document hash, measurement count) and measurement verification (expected count).
- **Debug-level measurement dumps** — Full hex-encoded measurement values logged at `tracing::debug` for forensic analysis.
- **PCR check logging** — Nitro verifier logs PCR check results at debug level.

### Frame & Tensor Validation
- **Tensor dimension cap** — `ndims` is capped at 32 in the decoder, preventing allocation amplification from maliciously crafted tensor headers.
- **Flags encapsulation** — The `Flags` inner field is `pub(crate)`, with `from_raw()` / `raw()` accessors for external use.

### Known Limitations
- **One-way attestation** — The handshake verifies the responder's (server/enclave) attestation but does not verify the initiator's identity. For mutual attestation, perform an application-level challenge-response after session establishment.
- **No transport binding** — The channel authenticates the data stream but does not bind to a specific transport address (IP, VSock CID). Perform a transport-level identity check separately if required.
- **Proxy is TCP-only** — The transparent proxy currently supports TCP backends. VSock proxy support can be added by implementing the same pattern with `tokio-vsock` listeners/streams.

## License

MIT OR Apache-2.0
