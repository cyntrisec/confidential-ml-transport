#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE_DIR="$(dirname "$SCRIPT_DIR")"

# Configuration
ENCLAVE_CPUS="${ENCLAVE_CPUS:-2}"
ENCLAVE_MEM="${ENCLAVE_MEM:-2048}"  # MiB (MiniLM needs ~100MB, rest for runtime)
TEXT="${TEXT:-This is a test sentence}"

if [ ! -f "$EXAMPLE_DIR/nitro-inference.eif" ]; then
    echo "EIF not found. Run build.sh first."
    exit 1
fi

# 1. Launch enclave
echo "Launching enclave (cpus=$ENCLAVE_CPUS, mem=${ENCLAVE_MEM}MiB)..."
ENCLAVE_ID=$(nitro-cli run-enclave \
    --eif-path "$EXAMPLE_DIR/nitro-inference.eif" \
    --cpu-count "$ENCLAVE_CPUS" \
    --memory "$ENCLAVE_MEM" \
    --debug-mode | jq -r '.EnclaveID')

echo "Enclave ID: $ENCLAVE_ID"

# 2. Get CID for the specific enclave we just launched
CID=$(nitro-cli describe-enclaves | jq -r --arg eid "$ENCLAVE_ID" '.[] | select(.EnclaveID == $eid) | .EnclaveCID')
echo "Enclave CID: $CID"

# 3. Wait for enclave to boot
echo "Waiting for enclave to boot..."
sleep 3

# 4. Run client
echo ""
echo "Running inference..."
cargo run --release --bin host-client \
    --manifest-path "$EXAMPLE_DIR/Cargo.toml" \
    --no-default-features --features vsock-nitro \
    -- --cid "$CID" --text "$TEXT"

# 5. Cleanup
echo ""
echo "Terminating enclave..."
nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"
echo "Done."
