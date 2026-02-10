# Hostile Host Relay Capture Demo

A/B proof that `SecureChannel` protects tensor data from a hostile host relay.

## Terminal Recording

[![asciicast](https://asciinema.org/a/placeholder.svg)](https://asciinema.org/a/placeholder)

> To play locally: `asciinema play examples/hostile-host-demo/assets/demo.cast`

## Quick Start

```bash
cargo run --release -p hostile-host-demo
```

Runs in <1 second, zero setup, no model download.

## What It Does

```
Enclave (sender) ──> [Hostile Relay] ──> Client (receiver)
```

The relay sits between sender and receiver, copying bytes bidirectionally while recording everything that passes through. Two modes run through the same relay:

| | Mode A (baseline) | Mode B (SecureChannel) |
|---|---|---|
| Framing | Raw `Frame::tensor()` | `SecureChannel` + MockProvider |
| Encryption | None | X25519 + ChaCha20-Poly1305 |
| Tensor names visible | YES | NO |
| Tensor values visible | YES | NO |
| Prompt recoverable | YES | NO |
| Payload entropy | ~6.9 bits/byte | ~7.99 bits/byte |
| AEAD overhead | -- | ~2.2% |

## Exporting Captures

```bash
cargo run --release -p hostile-host-demo -- --dump artifacts/
```

Writes to the specified directory:

| File | Contents |
|------|----------|
| `mode_a_capture.bin` | Raw bytes captured by relay (Mode A, unidirectional) |
| `mode_b_fwd_capture.bin` | Raw forward-direction bytes (Mode B) |
| `mode_b_bwd_capture.bin` | Raw backward-direction bytes (Mode B) |
| `summary.json` | Frame inventory, entropy, overhead metrics |

Attach these to releases or audit reports. The `.bin` files can be fed into
any tool that parses the `confidential-ml-transport` wire format (magic `0xCF4D`,
13-byte frame headers).

## Running Tests

```bash
cargo test -p hostile-host-demo
```

11 tests verify fixed structural invariants for CI regression detection:

**Mode A (deterministic snapshot)**
- Exact byte count (15,475 bytes)
- Exact frame structure (2 Tensor + 1 Shutdown, all unencrypted)
- Exact payload sizes (44 bytes input_ids, 15,392 bytes hidden_states)
- Full prompt recovery ("The capital of France is")
- Activation value recovery (first 4 values within 1e-4 tolerance)

**Mode B (structural invariants, stable across random key generation)**
- Zero unencrypted tensor frames
- All encrypted payloads fail `OwnedTensor::decode()`
- Exactly 3 handshake frames (Hello seq=0/0/1)
- Shutdown frame is encrypted
- Payload entropy > 7.9 bits/byte

**Cross-mode**
- AEAD overhead < 5% and > 0%
- Encrypted entropy strictly exceeds plaintext entropy

## Threat Model

### Adversary

A **hostile host** that controls the network path between enclave and client. This
is the standard TEE threat model: the host OS, hypervisor, and all host-side
software are untrusted. The adversary can:

- **Read** all bytes transiting the relay (passive eavesdropping)
- **Record** traffic for offline analysis
- **Parse** the wire protocol (frame headers, payload boundaries)
- **Attempt tensor decoding** on captured payloads

### What SecureChannel Protects

| Property | Protected | How |
|----------|-----------|-----|
| Tensor values (weights, activations, embeddings) | Yes | ChaCha20-Poly1305 AEAD per frame |
| Tensor metadata (name, dtype, shape) | Yes | Metadata is inside the encrypted payload |
| Prompt / input token IDs | Yes | Encoded as tensor, encrypted like any other |
| Shutdown signaling | Yes | Shutdown frame payload is encrypted |
| Message integrity | Yes | Poly1305 tag on every frame (16-byte MAC) |
| Replay protection | Yes | Nonce derived from monotonic sequence counter |
| Session binding | Yes | Keys derived from X25519 + attestation-bound HKDF |

### What the Host Still Sees

The relay (host) retains visibility into **transport-level metadata** that is
not encrypted by the application-layer channel:

| Observable | Example | Why |
|------------|---------|-----|
| **Frame count** | 6 frames in Mode B | Frame headers (magic + type + flags + seq + length) are plaintext; the host knows how many messages were exchanged |
| **Frame sizes** | 60 bytes, 15,408 bytes | Payload length is in the plaintext header; the host can infer relative tensor sizes |
| **Frame types** | Hello, Tensor, Shutdown | The `msg_type` byte is plaintext; the host knows which frames are handshake vs data |
| **Direction** | Which side sent which frame | Observable from TCP/VSock socket direction |
| **Timing** | When each frame was sent | Network-level timestamp on each packet |
| **Total volume** | 15,817 bytes transferred | Sum of all frame sizes |
| **Session liveness** | Channel open/closed | Handshake and shutdown are observable events |
| **Encrypted flag** | `flags & 0x01` | The host can confirm encryption is in use |

### What This Means in Practice

A sophisticated host can infer:
- **Model architecture class** from tensor sizes (e.g., 768-dim hidden states suggests BERT-base, not GPT-2-large)
- **Batch size** from the number of tensor frames per request
- **Inference timing** from inter-frame gaps
- **Session patterns** from handshake frequency

These are **traffic analysis** side channels, not cryptographic breaks. Mitigations
(not implemented in this demo) include:
- **Padding** frames to fixed sizes to hide tensor dimensions
- **Chaff traffic** to obscure real message boundaries
- **Constant-rate sending** to hide timing
- **Batching** multiple tensors into a single frame to hide count

The demo intentionally does not implement these mitigations to keep the threat
model claims precise: SecureChannel protects **content confidentiality and integrity**,
not **traffic analysis resistance**.
