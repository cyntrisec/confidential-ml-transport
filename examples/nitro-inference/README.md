# Nitro Inference Example

End-to-end confidential ML inference using `confidential-ml-transport` with
[MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)
(22.7M params, 384-dim sentence embeddings).

Two binaries:
- **enclave-server** — loads the model, accepts attested connections, returns embeddings
- **host-client** — connects, sends text, prints the resulting embedding tensor

Transport is feature-gated:
- `tcp-mock` (default) — TCP on localhost with mock attestation, for local development
- `vsock-nitro` — VSock with AWS Nitro attestation, for real enclave deployment

## Quick Start (local, tcp-mock)

### 1. Download the model

```bash
bash scripts/build.sh
```

Or manually:

```bash
mkdir -p model
for f in model.safetensors tokenizer.json config.json; do
  curl -L "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/$f" \
    -o "model/$f"
done
```

### 2. Run the server

```bash
cargo run --bin enclave-server -- --model-dir model
```

### 3. Run the client (separate terminal)

```bash
cargo run --bin host-client -- --text "Hello world" --text "Rust is great"
```

Output:

```
Input: "Hello world"
  Tensor: name="embedding"
  Shape:  [1, 384]
  DType:  F32
  Values: [0.012345, -0.067890, ...]
  Dims:   384
```

## Nitro Enclave Deployment

Requires an EC2 instance with Nitro Enclaves enabled (e.g., m6i.xlarge) and
`nitro-cli` installed.

### 1. Build

```bash
bash scripts/build.sh
```

This downloads the model, builds the Docker image, and creates the EIF.

### 2. Run

```bash
bash scripts/run.sh
```

Or manually:

```bash
# Launch enclave
nitro-cli run-enclave \
  --eif-path nitro-inference.eif \
  --cpu-count 2 --memory 2048 --debug-mode

# Get CID
CID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')

# Run client
cargo run --release --bin host-client \
  --no-default-features --features vsock-nitro \
  -- --cid $CID --text "Hello from the host"

# Cleanup
nitro-cli terminate-enclave --enclave-id <id>
```

## Message Flow

```
Client                              Server (Enclave)
  |                                    |
  |--- [SecureChannel handshake] ----->|
  |<-- [attestation + keys] ----------|
  |--- [confirmation] --------------->|
  |                                    |
  |--- Data("Hello world") ---------->|
  |                                    | model.encode("Hello world")
  |<-- Tensor("embedding",F32,[1,384])-|
  |                                    |
  |--- Shutdown ---------------------->|
```

## Environment Variables

- `RUST_LOG` — tracing filter (e.g., `RUST_LOG=info`)
- `ENCLAVE_CPUS` — vCPUs for enclave (default: 2)
- `ENCLAVE_MEM` — memory in MiB for enclave (default: 2048)
