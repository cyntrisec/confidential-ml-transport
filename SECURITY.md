# Security Design

This document describes the security-relevant design decisions in `confidential-ml-transport`, including frame-size limits, parser strictness, memory-allocation strategy, and key material protection.

## Frame-Size Limits

| Parameter | Value | Enforced In |
|-----------|-------|-------------|
| `MAX_PAYLOAD_SIZE` | 32 MiB (33,554,432 bytes) | `FrameHeader::decode()`, `FrameCodec::decode()`, frame constructors |
| `HEADER_SIZE` | 13 bytes | Fixed by wire format |
| Codec `max_payload_size` | Configurable per-codec (default: `MAX_PAYLOAD_SIZE`) | `FrameCodec::with_max_payload_size()` |
| Read buffer bound (channel) | `max_payload_size + HEADER_SIZE + 4096` | `SecureChannel::recv_frame()` |
| Read buffer bound (handshake) | `MAX_PAYLOAD_SIZE + HEADER_SIZE + 4096` | `handshake::recv_frame()` |

Frame payloads exceeding these limits are rejected before allocation. The codec enforces a configurable limit (which may be stricter than the wire-format maximum), and the channel enforces a read-buffer ceiling to prevent memory exhaustion from slow or malicious peers.

## Parser Strictness

All handshake message parsers enforce **exact-length checks** (canonical parsing):

- **Initiator hello**: Must be exactly 65 bytes (1 type + 32 pubkey + 32 nonce). Trailing bytes rejected.
- **Responder hello**: Must be exactly `69 + doc_len` bytes (1 type + 32 pubkey + 32 nonce + 4 doc_len + doc). Trailing bytes rejected.
- **Confirmation**: Must be exactly 33 bytes (1 type + 32 hash). Trailing bytes rejected.

This prevents:
- Extension attacks where an adversary appends data that a future parser version might interpret
- Padding oracle or length-confusion attacks
- Protocol confusion from non-canonical encodings

Frame constructors (`Frame::data`, `Frame::hello`, `Frame::error`, `Frame::tensor`) validate that payload length fits in `u32` and does not exceed `MAX_PAYLOAD_SIZE`, panicking on violation. This is a programming error (not an external input), so `assert!` is appropriate.

## Memory-Allocation Strategy

### Codec reserve cap

When the codec sees a valid header but the payload has not yet fully arrived, it reserves buffer space incrementally — capped at **64 KB per decode call** — rather than allocating the full `payload_len` upfront. This prevents a memory-exhaustion attack where an adversary sends many headers claiming large payloads, then stalls the connections:

```
Attacker: send header with payload_len = 32 MB, then stall
Before fix: codec allocates 32 MB immediately per connection
After fix:  codec allocates ≤64 KB, growing as data actually arrives
```

The 64 KB cap is sufficient for normal streaming while limiting the amplification factor. For a valid frame, the buffer grows organically as payload bytes arrive. For a stalled attacker, the allocation is bounded at 64 KB per connection.

### Read buffer bounds

Both the channel and handshake enforce maximum read buffer sizes. If the buffer grows beyond the limit (from fragmented or malicious data), the connection is terminated with `ReadBufferOverflow`.

### Tensor dimension cap

Tensor sub-headers cap `ndims` at 32, preventing allocation amplification from maliciously crafted tensor headers with millions of dimensions.

## Connection Limits

The transparent proxy (both client and server) limits concurrent connections via a `tokio::sync::Semaphore`. The default is 256 connections; excess connections block at `accept()` until a slot opens. This prevents file-descriptor exhaustion and unbounded task spawning from connection floods.

## Key Material Protection

| Mechanism | Implementation |
|-----------|---------------|
| Key zeroization | `SymmetricKey` derives `Zeroize + ZeroizeOnDrop`; cleared from memory on drop |
| Context cleanup | `SealingContext` and `OpeningContext` implement `Drop` to zeroize session IDs and counters |
| Contributory DH | `was_contributory()` rejects non-contributory X25519 results (identity point / small-subgroup) |
| Domain-separated session ID | Session ID derived via HKDF with label `"cmt-session-id"`, separate from key material |

## Channel Security

| Property | Mechanism |
|----------|-----------|
| Encryption | All post-handshake frames encrypted via ChaCha20-Poly1305 AEAD |
| Authentication | AAD = `version \|\| session_id \|\| sequence` binds each frame to its session and position |
| Replay protection | Monotonic u64 sequence counter; any sequence ≤ last accepted is rejected |
| Unencrypted rejection | Receiving an unencrypted frame in an established session returns `UnencryptedFrame` error |
| Unified counters | The AEAD sealer's internal sequence is used directly as the frame header sequence number |

## Handshake Security

| Property | Mechanism |
|----------|-----------|
| Timeout | Configurable via `SessionConfig::handshake_timeout` (default: 30s) |
| Public key binding | Responder's attestation must contain a public key matching the handshake DH key |
| Confirmation binding | Confirmation hash includes both send and recv keys, proving mutual key agreement |
| Sequence validation | Frame sequence numbers validated during handshake (hello=0, confirmation=1) |
| Measurement verification | Optional `ExpectedMeasurements` checked before any application data flows |

## Known Limitations

- **One-way attestation**: Only the responder (server/enclave) is attested. For mutual attestation, perform an application-level challenge-response after session establishment.
- **No transport binding**: The channel does not bind to a specific transport address (IP, VSock CID). Perform transport-level identity checks separately if required.
- **Proxy is TCP-only**: The transparent proxy supports TCP backends only.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it via [GitHub Security Advisories](https://github.com/cyntrisec/confidential-ml-transport/security/advisories/new) or email the maintainers directly. Do not open a public issue for security vulnerabilities.
