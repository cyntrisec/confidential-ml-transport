#!/usr/bin/env bash
# Validates that benchmark math constants stay aligned between the Rust bench
# binary and the Python report-generation script.
#
# Guards against the class of bug fixed in 77aed72 where burst_count used
# different multipliers in bench vs script, causing misreported throughput.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH="$REPO_ROOT/benches/throughput.rs"
SCRIPT="$REPO_ROOT/scripts/bench_transport_performance.sh"

fail=0

# --- burst_count multiplier ---
# Rust:   (4 * 1_048_576 / payload_size).max(1)
# Python: max(1, 4 * 1048576 // size)
#
# Extract the integer multiplier before "1048576" (or "1_048_576") from each.

rust_mult=$(grep -oP '(\d+)\s*\*\s*1_?048_?576\s*/\s*payload_size' "$BENCH" | grep -oP '^\d+' || true)
py_mult=$(grep -oP '(\d+)\s*\*\s*1048576\s*//\s*size' "$SCRIPT" | grep -oP '^\d+' || true)

if [ -z "$rust_mult" ]; then
    echo "FAIL: could not extract burst multiplier from benches/throughput.rs"
    fail=1
elif [ -z "$py_mult" ]; then
    echo "FAIL: could not extract burst multiplier from scripts/bench_transport_performance.sh"
    fail=1
elif [ "$rust_mult" != "$py_mult" ]; then
    echo "FAIL: burst_count multiplier mismatch — bench=${rust_mult}x script=${py_mult}x"
    fail=1
else
    echo "OK: burst_count multiplier aligned (${rust_mult}x 1 MiB)"
fi

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "Benchmark constants are out of sync. Fix bench and script to match."
    exit 1
fi
