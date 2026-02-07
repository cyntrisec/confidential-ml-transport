#!/usr/bin/env bash
#
# Runs all transport benchmarks and generates a unified performance report.
#
# Usage:
#   bash scripts/bench_transport_performance.sh          # full run
#   bash scripts/bench_transport_performance.sh --quick   # fast (fewer samples)
#
# Outputs:
#   benchmark_results/transport_performance.json  — machine-readable
#   benchmark_results/transport_performance.md    — human-readable report

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

# ── Run all benchmarks ──────────────────────────────────────────────────────

echo "=== Running handshake benchmark ==="
cargo bench --bench handshake -p confidential-ml-transport "${BENCH_ARGS[@]}"

echo ""
echo "=== Running confidential overhead benchmark ==="
cargo bench --bench confidential_overhead -p confidential-ml-transport "${BENCH_ARGS[@]}"

echo ""
echo "=== Running throughput benchmark ==="
cargo bench --bench throughput -p confidential-ml-transport "${BENCH_ARGS[@]}"

echo ""
echo "=== Collecting results ==="

mkdir -p "$RESULTS_DIR"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Extract percentiles from criterion sample.json.
# Args: $1 = path to sample.json
# Outputs: "p50_ns p95_ns p99_ns" on stdout.
extract_percentiles() {
    local sample_file="$1"
    python3 -c "
import json
with open('$sample_file') as f:
    data = json.load(f)
iters = data['iters']
times = data['times']
per_iter = sorted([t / i for t, i in zip(times, iters)])
n = len(per_iter)
p50 = per_iter[int(n * 0.5)]
p95 = per_iter[min(int(n * 0.95), n - 1)]
p99 = per_iter[min(int(n * 0.99), n - 1)]
print(f'{p50} {p95} {p99}')
"
}

# Extract median from criterion estimates.json.
# Args: $1 = criterion group dir (with slashes replaced by underscores)
#       $2 = bench function name
#       $3 = bench input id (optional)
extract_median_ns() {
    local dir_name="${1//\//_}"
    local bench_fn="$2"
    local bench_input="${3:-}"
    local estimates_file

    if [[ -n "$bench_input" ]]; then
        estimates_file="$CRITERION_DIR/$dir_name/$bench_fn/$bench_input/new/estimates.json"
    else
        estimates_file="$CRITERION_DIR/$dir_name/$bench_fn/new/estimates.json"
    fi

    if [[ ! -f "$estimates_file" ]]; then
        echo "null"
        return
    fi

    python3 -c "
import json
with open('$estimates_file') as f:
    data = json.load(f)
print(data['median']['point_estimate'])
"
}

# Get sample.json path for a benchmark.
sample_path() {
    local dir_name="${1//\//_}"
    local bench_fn="$2"
    local bench_input="${3:-}"

    if [[ -n "$bench_input" ]]; then
        echo "$CRITERION_DIR/$dir_name/$bench_fn/$bench_input/new/sample.json"
    else
        echo "$CRITERION_DIR/$dir_name/$bench_fn/new/sample.json"
    fi
}

# Format nanoseconds for display.
fmt_ns() {
    python3 -c "
ns = $1
if ns < 1000:
    print(f'{ns:.0f} ns')
elif ns < 1_000_000:
    print(f'{ns/1000:.1f} us')
else:
    print(f'{ns/1_000_000:.2f} ms')
" 2>/dev/null || echo "N/A"
}

# ── Validate criterion outputs exist ────────────────────────────────────────

missing=0

# Handshake
for f in "handshake/cold_connect/new/estimates.json" "handshake/cold_connect/new/sample.json"; do
    if [[ ! -f "$CRITERION_DIR/$f" ]]; then
        echo "ERROR: missing $CRITERION_DIR/$f" >&2
        missing=$((missing + 1))
    fi
done

# Confidential overhead
OVERHEAD_LABELS=("1536b_embedding" "4k_activation" "384k_hidden")
for group in "confidential_overhead_plaintext_duplex" "confidential_overhead_secure_channel"; do
    for label in "${OVERHEAD_LABELS[@]}"; do
        f="$group/send_recv/$label/new/estimates.json"
        if [[ ! -f "$CRITERION_DIR/$f" ]]; then
            echo "ERROR: missing $CRITERION_DIR/$f" >&2
            missing=$((missing + 1))
        fi
    done
done

# Throughput
THROUGHPUT_LABELS=("1536b_embedding" "4k_activation" "384k_hidden" "1m_large")
for group in "throughput_plaintext" "throughput_secure_channel"; do
    for label in "${THROUGHPUT_LABELS[@]}"; do
        f="$group/send/$label/new/estimates.json"
        if [[ ! -f "$CRITERION_DIR/$f" ]]; then
            echo "ERROR: missing $CRITERION_DIR/$f" >&2
            missing=$((missing + 1))
        fi
    done
done

if [[ $missing -gt 0 ]]; then
    echo "ERROR: $missing criterion estimate file(s) missing. Benchmark may not have run correctly." >&2
    exit 1
fi

# ── Extract data ────────────────────────────────────────────────────────────

# Handshake percentiles
hs_sample=$(sample_path "handshake" "cold_connect")
read -r hs_p50 hs_p95 hs_p99 <<< "$(extract_percentiles "$hs_sample")"

# ── Generate JSON ───────────────────────────────────────────────────────────

python3 - "$CRITERION_DIR" "$hs_p50" "$hs_p95" "$hs_p99" > "$RESULTS_DIR/transport_performance.json" << 'PYEOF'
import json, sys, os

criterion_dir = sys.argv[1]
hs_p50, hs_p95, hs_p99 = float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])

def load_estimates(group, bench_fn, bench_input=None):
    dir_name = group.replace("/", "_")
    if bench_input:
        path = os.path.join(criterion_dir, dir_name, bench_fn, bench_input, "new", "estimates.json")
    else:
        path = os.path.join(criterion_dir, dir_name, bench_fn, "new", "estimates.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def load_percentiles(group, bench_fn, bench_input=None):
    dir_name = group.replace("/", "_")
    if bench_input:
        path = os.path.join(criterion_dir, dir_name, bench_fn, bench_input, "new", "sample.json")
    else:
        path = os.path.join(criterion_dir, dir_name, bench_fn, "new", "sample.json")
    if not os.path.exists(path):
        return None, None, None
    with open(path) as f:
        data = json.load(f)
    per_iter = sorted([t / i for t, i in zip(data["times"], data["iters"])])
    n = len(per_iter)
    return per_iter[int(n * 0.5)], per_iter[min(int(n * 0.95), n - 1)], per_iter[min(int(n * 0.99), n - 1)]

overhead_labels = [("1536b_embedding", 1536), ("4k_activation", 4096), ("384k_hidden", 393216)]
throughput_labels = [("1536b_embedding", 1536), ("4k_activation", 4096), ("384k_hidden", 393216), ("1m_large", 1048576)]

def burst_count(size):
    return max(1, 1048576 // size)

overhead_results = []
for label, size in overhead_labels:
    pt = load_estimates("confidential_overhead/plaintext_duplex", "send_recv", label)
    sc = load_estimates("confidential_overhead/secure_channel", "send_recv", label)
    sc_p50, sc_p95, sc_p99 = load_percentiles("confidential_overhead/secure_channel", "send_recv", label)
    pt_med = pt["median"]["point_estimate"] if pt else None
    sc_med = sc["median"]["point_estimate"] if sc else None
    overhead_pct = round((sc_med - pt_med) / pt_med * 100, 2) if pt_med and sc_med else None
    overhead_results.append({
        "label": label, "size_bytes": size,
        "plaintext_duplex_ns": pt_med, "secure_channel_ns": sc_med,
        "overhead_pct": overhead_pct,
        "secure_channel_p50_ns": sc_p50, "secure_channel_p95_ns": sc_p95, "secure_channel_p99_ns": sc_p99,
    })

throughput_results = []
for label, size in throughput_labels:
    burst = burst_count(size)
    total_bytes = size * burst
    pt = load_estimates("throughput/plaintext", "send", label)
    sc = load_estimates("throughput/secure_channel", "send", label)
    pt_med = pt["median"]["point_estimate"] if pt else None
    sc_med = sc["median"]["point_estimate"] if sc else None
    pt_mbps = round(total_bytes / (pt_med / 1e9) / 1e6, 2) if pt_med else None
    sc_mbps = round(total_bytes / (sc_med / 1e9) / 1e6, 2) if sc_med else None
    overhead_pct = round((sc_mbps and pt_mbps and (pt_mbps - sc_mbps) / pt_mbps * 100) or 0, 1) if pt_mbps and sc_mbps else None
    throughput_results.append({
        "label": label, "size_bytes": size, "burst_count": burst,
        "plaintext_mbps": pt_mbps, "secure_channel_mbps": sc_mbps,
        "throughput_overhead_pct": overhead_pct,
    })

report = {
    "benchmark": "transport_performance",
    "description": "Comprehensive transport layer performance: handshake, steady-state latency, sustained throughput",
    "date": "",  # filled by shell
    "handshake": {
        "description": "Full 3-message handshake over tokio::io::duplex (mock attestation)",
        "p50_ns": hs_p50, "p95_ns": hs_p95, "p99_ns": hs_p99,
    },
    "steady_state_latency": overhead_results,
    "sustained_throughput": throughput_results,
}
print(json.dumps(report, indent=2))
PYEOF

# Patch the date into JSON (avoids embedding shell commands in Python)
python3 -c "
import json, datetime
with open('$RESULTS_DIR/transport_performance.json') as f:
    data = json.load(f)
data['date'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
with open('$RESULTS_DIR/transport_performance.json', 'w') as f:
    json.dump(data, f, indent=2)
"

echo "Wrote $RESULTS_DIR/transport_performance.json"

# ── Generate Markdown report ────────────────────────────────────────────────

python3 - "$RESULTS_DIR/transport_performance.json" > "$RESULTS_DIR/transport_performance.md" << 'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

def fmt_ns(ns):
    if ns is None:
        return "N/A"
    if ns < 1000:
        return f"{ns:.0f} ns"
    elif ns < 1_000_000:
        return f"{ns/1000:.1f} us"
    else:
        return f"{ns/1_000_000:.2f} ms"

def fmt_mbps(mbps):
    if mbps is None:
        return "N/A"
    if mbps >= 1000:
        return f"{mbps/1000:.2f} GB/s"
    return f"{mbps:.1f} MB/s"

print("# Transport Performance Report")
print()
print(f"Generated: {data['date']}")
print()

# Handshake
hs = data["handshake"]
print("## 1. Handshake Latency")
print()
print(f"{hs['description']}")
print()
print("| Metric | p50 | p95 | p99 |")
print("|--------|-----|-----|-----|")
print(f"| Cold connect | {fmt_ns(hs['p50_ns'])} | {fmt_ns(hs['p95_ns'])} | {fmt_ns(hs['p99_ns'])} |")
print()
print("Each iteration creates a fresh `tokio::io::duplex`, generates X25519 keypair,")
print("and completes the full 3-message handshake (mock attestation).")
print("No session resumption — every connect is a full handshake.")
print()

# Steady-state latency
print("## 2. Steady-State AEAD Latency (per send/recv round-trip)")
print()
print("Handshake excluded — measured on established channel.")
print()
print("| Payload | Plaintext (duplex) | SecureChannel p50 | p95 | p99 | AEAD Overhead |")
print("|---------|-------------------|-------------------|-----|-----|---------------|")
for r in data["steady_state_latency"]:
    pt = fmt_ns(r["plaintext_duplex_ns"])
    p50 = fmt_ns(r["secure_channel_p50_ns"])
    p95 = fmt_ns(r["secure_channel_p95_ns"])
    p99 = fmt_ns(r["secure_channel_p99_ns"])
    overhead = f"{r['overhead_pct']:.1f}%" if r["overhead_pct"] is not None else "N/A"
    print(f"| {r['label']} ({r['size_bytes']} B) | {pt} | {p50} | {p95} | {p99} | {overhead} |")
print()

# Sustained throughput
print("## 3. Sustained Throughput (unidirectional send)")
print()
print("Client sends burst of messages, server drains in background. No echo.")
print()
print("| Payload | Burst | Plaintext | SecureChannel | Overhead |")
print("|---------|-------|-----------|---------------|----------|")
for r in data["sustained_throughput"]:
    pt = fmt_mbps(r["plaintext_mbps"])
    sc = fmt_mbps(r["secure_channel_mbps"])
    overhead = f"{r['throughput_overhead_pct']:.1f}%" if r["throughput_overhead_pct"] is not None else "N/A"
    print(f"| {r['label']} ({r['size_bytes']} B) | {r['burst_count']}x | {pt} | {sc} | {overhead} |")
print()
print("**Overhead %** = (Plaintext - SecureChannel) / Plaintext * 100")
print()

# Notes
print("## Notes")
print()
print("- All measurements over `tokio::io::duplex` (in-process, no network latency)")
print("- Mock attestation provider (no real TEE hardware)")
print("- AEAD cipher: ChaCha20-Poly1305")
print("- Handshake: X25519 key agreement + HKDF key derivation + 3-message exchange")
print("- Reconnect = another cold handshake (no session resumption implemented)")
print("- p50/p95/p99 computed from criterion sample data (default 100 samples)")
PYEOF

echo "Wrote $RESULTS_DIR/transport_performance.md"
echo ""
echo "=== Transport Performance Report ==="
cat "$RESULTS_DIR/transport_performance.md"
