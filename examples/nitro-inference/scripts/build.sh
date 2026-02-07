#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$(dirname "$EXAMPLE_DIR")")"

# 1. Download model from HuggingFace (if not already present)
MODEL_DIR="$EXAMPLE_DIR/model"
if [ ! -f "$MODEL_DIR/model.safetensors" ] || [ ! -f "$MODEL_DIR/tokenizer.json" ] || [ ! -f "$MODEL_DIR/config.json" ]; then
    echo "Downloading MiniLM-L6-v2..."
    mkdir -p "$MODEL_DIR"
    for f in model.safetensors tokenizer.json config.json; do
        echo "  $f"
        curl -L "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/$f" \
            -o "$MODEL_DIR/$f"
    done
    echo "Model downloaded to $MODEL_DIR"
else
    echo "Model already present at $MODEL_DIR"
fi

# 2. Build host client (tcp-mock for local testing)
echo ""
echo "Building host-client (tcp-mock)..."
cargo build --release --bin host-client \
    --manifest-path "$EXAMPLE_DIR/Cargo.toml"

# 3. Build enclave server (tcp-mock for local testing too)
echo ""
echo "Building enclave-server (tcp-mock)..."
cargo build --release --bin enclave-server \
    --manifest-path "$EXAMPLE_DIR/Cargo.toml"

echo ""
echo "Local build complete."
echo "  Server: $ROOT_DIR/target/release/enclave-server"
echo "  Client: $ROOT_DIR/target/release/host-client"

# 4. If nitro-cli is available, build EIF
if command -v nitro-cli &> /dev/null; then
    echo ""
    echo "Building vsock-nitro enclave-server..."
    cargo build --release --bin enclave-server \
        --manifest-path "$EXAMPLE_DIR/Cargo.toml" \
        --no-default-features --features vsock-nitro

    echo ""
    echo "Building Docker image..."
    docker build -t nitro-inference -f "$EXAMPLE_DIR/Dockerfile" "$ROOT_DIR"

    echo ""
    echo "Building EIF..."
    nitro-cli build-enclave \
        --docker-uri nitro-inference:latest \
        --output-file "$EXAMPLE_DIR/nitro-inference.eif"

    echo ""
    echo "EIF built at: $EXAMPLE_DIR/nitro-inference.eif"
else
    echo ""
    echo "nitro-cli not found — skipping EIF build."
    echo "To build for Nitro Enclaves, run on an EC2 instance with nitro-cli installed."
fi
