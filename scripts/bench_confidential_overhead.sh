#!/usr/bin/env bash
#
# Runs the confidential overhead benchmark and generates results.
#
# Usage:
#   bash scripts/bench_confidential_overhead.sh          # full run
#   bash scripts/bench_confidential_overhead.sh --quick   # fast (fewer samples)
#
# Outputs:
#   benchmark_results/confidential_overhead.json   — machine-readable
#   benchmark_results/confidential_overhead.md     — human-readable table

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/benchmark_results"
CRITERION_DIR="$PROJECT_DIR/target/criterion"

BENCH_ARGS=()
if [[ "${1:-}" == "--quick" ]]; then
    BENCH_ARGS+=(-- --sample-size 10 --warm-up-time 1 --measurement-time 3)
    echo "Running in quick mode (reduced samples)..."
fi

echo "=== Running confidential overhead benchmark ==="
cargo bench --bench confidential_overhead -p confidential-ml-transport "${BENCH_ARGS[@]}"

echo ""
echo "=== Collecting results ==="

mkdir -p "$RESULTS_DIR"

# Helper: extract median estimate (in nanoseconds) from criterion estimates.json
# Criterion replaces '/' with '_' in directory names on the filesystem.
extract_median_ns() {
    local group="$1"
    local bench="$2"
    # Convert slashes to underscores to match criterion's directory naming
    local dir_name="${group//\//_}"
    local estimates_file="$CRITERION_DIR/$dir_name/send_recv/$bench/new/estimates.json"

    if [[ ! -f "$estimates_file" ]]; then
        echo "null"
        return
    fi

    # Extract median point_estimate (in nanoseconds)
    python3 -c "
import json, sys
with open('$estimates_file') as f:
    data = json.load(f)
print(data['median']['point_estimate'])
" 2>/dev/null || echo "null"
}

# Payload labels (must match criterion benchmark IDs)
LABELS=("1536b_embedding" "4k_activation" "384k_hidden")
SIZES=(1536 4096 393216)

# Collect results into JSON
json_entries=()

for i in "${!LABELS[@]}"; do
    label="${LABELS[$i]}"
    size="${SIZES[$i]}"

    plaintext_ns=$(extract_median_ns "confidential_overhead/plaintext" "$label")
    plaintext_duplex_ns=$(extract_median_ns "confidential_overhead/plaintext_duplex" "$label")
    secure_ns=$(extract_median_ns "confidential_overhead/secure_channel" "$label")

    # Compute overhead % vs plaintext_duplex (the fair comparison — same I/O path)
    if [[ "$plaintext_duplex_ns" != "null" && "$secure_ns" != "null" ]]; then
        overhead_pct=$(python3 -c "
pt = $plaintext_duplex_ns
sc = $secure_ns
print(round((sc - pt) / pt * 100, 2))
")
    else
        overhead_pct="null"
    fi

    json_entries+=("{\"label\": \"$label\", \"size_bytes\": $size, \"plaintext_encode_decode_ns\": $plaintext_ns, \"plaintext_duplex_ns\": $plaintext_duplex_ns, \"secure_channel_ns\": $secure_ns, \"overhead_pct\": $overhead_pct}")
done

# Write JSON
json_array=$(printf '%s\n' "${json_entries[@]}" | paste -sd ',' -)
cat > "$RESULTS_DIR/confidential_overhead.json" << JSONEOF
{
  "benchmark": "confidential_overhead",
  "description": "SecureChannel (AEAD + handshake) vs plaintext transport overhead",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "results": [$json_array]
}
JSONEOF

echo "Wrote $RESULTS_DIR/confidential_overhead.json"

# Write Markdown table
{
    echo "# Confidential Overhead Benchmark"
    echo ""
    echo "Measures the overhead of SecureChannel (AEAD encryption) vs plaintext framing."
    echo ""
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "| Payload | Plaintext (encode/decode) | Plaintext (duplex I/O) | SecureChannel (duplex I/O) | Overhead % |"
    echo "|---------|--------------------------|----------------------|--------------------------|------------|"

    for i in "${!LABELS[@]}"; do
        label="${LABELS[$i]}"
        size="${SIZES[$i]}"

        plaintext_ns=$(extract_median_ns "confidential_overhead/plaintext" "$label")
        plaintext_duplex_ns=$(extract_median_ns "confidential_overhead/plaintext_duplex" "$label")
        secure_ns=$(extract_median_ns "confidential_overhead/secure_channel" "$label")

        fmt_pt=$(python3 -c "
ns = $plaintext_ns
if ns < 1000: print(f'{ns:.0f} ns')
elif ns < 1_000_000: print(f'{ns/1000:.1f} us')
else: print(f'{ns/1_000_000:.2f} ms')
" 2>/dev/null || echo "N/A")

        fmt_pd=$(python3 -c "
ns = $plaintext_duplex_ns
if ns < 1000: print(f'{ns:.0f} ns')
elif ns < 1_000_000: print(f'{ns/1000:.1f} us')
else: print(f'{ns/1_000_000:.2f} ms')
" 2>/dev/null || echo "N/A")

        fmt_sc=$(python3 -c "
ns = $secure_ns
if ns < 1000: print(f'{ns:.0f} ns')
elif ns < 1_000_000: print(f'{ns/1000:.1f} us')
else: print(f'{ns/1_000_000:.2f} ms')
" 2>/dev/null || echo "N/A")

        if [[ "$plaintext_duplex_ns" != "null" && "$secure_ns" != "null" ]]; then
            overhead=$(python3 -c "print(f'{($secure_ns - $plaintext_duplex_ns) / $plaintext_duplex_ns * 100:.1f}%')")
        else
            overhead="N/A"
        fi

        echo "| $label ($size B) | $fmt_pt | $fmt_pd | $fmt_sc | $overhead |"
    done

    echo ""
    echo "**Overhead %** = (SecureChannel - Plaintext Duplex) / Plaintext Duplex * 100"
    echo ""
    echo "The plaintext encode/decode column shows pure framing cost (no I/O)."
    echo "The plaintext duplex column shows framing + tokio duplex I/O (no crypto)."
    echo "The SecureChannel column adds AEAD seal/open on top of duplex I/O."
} > "$RESULTS_DIR/confidential_overhead.md"

echo "Wrote $RESULTS_DIR/confidential_overhead.md"
echo ""
echo "=== Results ==="
cat "$RESULTS_DIR/confidential_overhead.md"
