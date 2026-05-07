#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE_DIR="$(dirname "$SCRIPT_DIR")"

# Configuration
ENCLAVE_CPUS="${ENCLAVE_CPUS:-2}"
ENCLAVE_MEM="${ENCLAVE_MEM:-2048}"  # MiB (MiniLM needs ~100MB, rest for runtime)
TEXT="${TEXT:-This is a test sentence}"
NITRO_DEBUG_MODE="${NITRO_DEBUG_MODE:-0}"
PCR_ENV_FILE="$EXAMPLE_DIR/nitro-inference.pcrs.env"

if [ ! -f "$EXAMPLE_DIR/nitro-inference.eif" ]; then
    echo "EIF not found. Run build.sh first."
    exit 1
fi

if [ -f "$PCR_ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$PCR_ENV_FILE"
    set +a
    echo "Loaded Nitro PCR pins from $PCR_ENV_FILE"
elif [ "${ALLOW_UNPINNED_NITRO_FOR_DEV:-}" != "I_UNDERSTAND" ]; then
    echo "PCR env file not found: $PCR_ENV_FILE"
    echo "Run build.sh first, or set EXPECTED_PCR0/1/2 manually."
    echo "For dev-only unpinned runs, set ALLOW_UNPINNED_NITRO_FOR_DEV=I_UNDERSTAND."
    exit 1
else
    echo "WARNING: running without PCR pins because ALLOW_UNPINNED_NITRO_FOR_DEV=I_UNDERSTAND"
fi

# 1. Launch enclave
echo "Launching enclave (cpus=$ENCLAVE_CPUS, mem=${ENCLAVE_MEM}MiB)..."
RUN_ARGS=(
    nitro-cli run-enclave
    --eif-path "$EXAMPLE_DIR/nitro-inference.eif"
    --cpu-count "$ENCLAVE_CPUS"
    --memory "$ENCLAVE_MEM"
)
if [ "$NITRO_DEBUG_MODE" = "1" ]; then
    echo "WARNING: NITRO_DEBUG_MODE=1, launching enclave with --debug-mode."
    RUN_ARGS+=(--debug-mode)
fi
ENCLAVE_ID=$("${RUN_ARGS[@]}" | jq -r '.EnclaveID')

echo "Enclave ID: $ENCLAVE_ID"
cleanup() {
    if [ -n "${ENCLAVE_ID:-}" ]; then
        nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

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
cleanup
trap - EXIT
echo "Done."
