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

Security posture:
- `scripts/run.sh` launches production-mode enclaves by default (`Flags: NONE`, no `--debug-mode`).
- `scripts/build.sh` writes `nitro-inference.pcrs.env` from `nitro-cli build-enclave`; the host client refuses to run without PCR0/1/2 pins unless you explicitly set `ALLOW_UNPINNED_NITRO_FOR_DEV=I_UNDERSTAND`.
- This example authenticates the enclave to the host. The enclave-side server uses `MockVerifier` for the host initiator because the host is outside the enclave and does not have a Nitro attestation provider in this demo. Do not describe this example as full production mutual host identity.

### 1. Build

```bash
bash scripts/build.sh
```

This downloads the model, builds the Docker image, creates the EIF, and writes:

```
nitro-inference.measurements.json
nitro-inference.pcrs.env
```

The `.env` file contains `EXPECTED_PCR0`, `EXPECTED_PCR1`, and `EXPECTED_PCR2` for the exact EIF build.

### 2. Run

```bash
bash scripts/run.sh
```

Or manually:

```bash
# Launch enclave
nitro-cli run-enclave \
  --eif-path nitro-inference.eif \
  --cpu-count 2 --memory 2048

# Get CID
CID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')

# Load PCR pins from the build output and run client
source nitro-inference.pcrs.env
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
  |--- [keys + mock host attestation]->|
  |<-- [keys + Nitro attestation] -----|
  |--- [confirmation] ---------------->|
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
- `EXPECTED_PCR0`, `EXPECTED_PCR1`, `EXPECTED_PCR2` — production Nitro PCR pins from `nitro-cli build-enclave`
- `NITRO_DEBUG_MODE=1` — launch with `--debug-mode` for local diagnostics only
- `ALLOW_UNPINNED_NITRO_FOR_DEV=I_UNDERSTAND` — allow unpinned PCRs for dev-only runs
