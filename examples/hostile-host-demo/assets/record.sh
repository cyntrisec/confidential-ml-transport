#!/bin/bash
# Script executed inside asciinema recording.
# Paced for 60-90s so viewers can read each section.

set -e
cd /home/tsyrulb/vsock/confidential-ml-transport

type_cmd() {
    local cmd="$1"
    printf '\n$ '
    for (( i=0; i<${#cmd}; i++ )); do
        printf '%s' "${cmd:$i:1}"
        sleep 0.04
    done
    printf '\n'
    sleep 0.5
    eval "$cmd"
}

echo ""
echo "  Hostile Host Relay Capture Demo"
echo "  ================================"
echo ""
echo "  Proving SecureChannel protects tensor data"
echo "  from a man-in-the-middle host relay."
echo ""
sleep 5

# Run the demo with --dump
type_cmd "cargo run --release -p hostile-host-demo -- --dump /tmp/demo-artifacts"

# Viewers read Mode A: prompt exposed, values leaked
sleep 12

# Viewers read Mode B: all encrypted, decode fails
sleep 10

# Viewers read comparison table + artifact listing
sleep 8

# Show the machine-readable summary
type_cmd "cat /tmp/demo-artifacts/summary.json"
sleep 12

# Show artifact files
type_cmd "ls -lh /tmp/demo-artifacts/"
sleep 5

echo ""
echo "  Done. Mode A: full prompt + activations exposed."
echo "  Mode B: all tensors protected, entropy ~8 bits/byte."
echo "  AEAD overhead: 2.2% (342 bytes for 15 KB of tensor data)."
echo ""
sleep 5

rm -rf /tmp/demo-artifacts
