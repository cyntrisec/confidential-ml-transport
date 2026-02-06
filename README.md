# confidential-ml-transport

Attestation-bound encrypted tensor transport for confidential ML inference over VSock and TCP.

## Overview

`confidential-ml-transport` is a Rust library that provides secure, binary-framed communication between TEE (Trusted Execution Environment) enclaves and clients. It combines a compact wire protocol with X25519+ChaCha20Poly1305 encryption and a 3-message attested handshake, designed for streaming tensor data in confidential AI inference pipelines.

**Key properties:**

- **Binary framing** — 13-byte fixed header, zero-copy tensor sub-headers, 32 MiB max payload
- **Attestation-bound sessions** — session keys are derived from attestation documents, binding the cryptographic channel to a verified TEE identity
- **Pluggable transports** — TCP and VSock backends via feature flags
- **Pluggable attestation** — trait-based attestation provider/verifier, with mock implementation for testing (Nitro, SEV-SNP, TDX implementable downstream)
- **Monotonic sequence enforcement** — replay protection on every decrypted message

## Wire Protocol

```
13-byte frame header (big-endian):

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         magic (0xCF4D)        |  version (1)  |   msg_type    |
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

### Sending tensors

```rust
use confidential_ml_transport::{TensorRef, DType};

let activations = vec![0f32; 128 * 768];
let data = unsafe {
    std::slice::from_raw_parts(activations.as_ptr() as *const u8, activations.len() * 4)
};

let tensor = TensorRef {
    name: "hidden_state",
    dtype: DType::F32,
    shape: &[128, 768],
    data,
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

struct NitroProvider { /* NSM API handle */ }

#[async_trait]
impl AttestationProvider for NitroProvider {
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        // Call NSM API to generate attestation document
        todo!()
    }
}
```

## Features

| Feature | Default | Description |
|---|---|---|
| `mock` | Yes | Mock attestation provider/verifier for testing |
| `tcp` | Yes | TCP transport helpers |
| `vsock` | No | VSock transport via `tokio-vsock` |

```bash
# Default (mock + tcp)
cargo build

# With VSock support
cargo build --features vsock

# Minimal
cargo build --no-default-features --features mock,tcp
```

## Testing

```bash
# All tests (unit + proptest + integration)
cargo test

# Property-based tests only
cargo test --test frame_roundtrip

# Benchmarks
cargo bench --bench frame_codec

# Fuzz the frame decoder (requires nightly)
cd fuzz && cargo +nightly fuzz run fuzz_frame_decode -- -max_total_time=60

# Run the echo server example
cargo run --example echo_server
```

## Benchmarks

Measured on a standard development machine:

| Operation | Throughput | Latency |
|---|---|---|
| Frame encode (4 KB) | ~22 GiB/s | ~170 ns |
| Frame decode (4 KB) | ~22 GiB/s | ~170 ns |
| Tensor decode (384 KB) | ~2.2 TiB/s | ~160 ns |
| ChaCha20Poly1305 seal (4 KB) | ~530 MiB/s | ~7.2 µs |
| ChaCha20Poly1305 open (4 KB) | ~19 GiB/s | ~180 ns |

## Crypto Design

| Component | Algorithm | Purpose |
|---|---|---|
| Key exchange | X25519 (Diffie-Hellman) | Ephemeral shared secret |
| Key derivation | HKDF-SHA256 | Derive send/recv keys from shared secret + transcript |
| Encryption | ChaCha20Poly1305 | Per-message AEAD with AAD = `version \|\| session_id \|\| sequence` |
| Transcript | SHA256 | Bind session to attestation + public keys + nonces |
| Replay protection | Monotonic u64 sequence | Reject any sequence <= last accepted |

## License

MIT OR Apache-2.0
