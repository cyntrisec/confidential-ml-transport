#!/usr/bin/env bash
#
# Checks benchmark results against SLO thresholds.
# Exits non-zero if any SLO is violated.
#
# Usage:
#   bash scripts/check_bench_slo.sh
#
# Prerequisites:
#   Run benchmarks first:
#     cargo bench --bench handshake --bench confidential_overhead --bench reconnect --bench throughput
#
# SLO thresholds (2x headroom over measured worst-case):
#   - Handshake p50:           < 500 µs
#   - Steady-state RTT p50:    < 200 µs  (1536B embedding)
#   - Reconnect p95:           < 1 ms
#   - Throughput (4KB secure): > 200 MB/s

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CRITERION_DIR="$PROJECT_DIR/target/criterion"

FAILURES=0

# ── Helpers ──────────────────────────────────────────────────────────────────

# Extract median point estimate (in nanoseconds) from criterion estimates.json.
get_median_ns() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "MISSING"
        return
    fi
    python3 -c "
import json
with open('$file') as f:
    data = json.load(f)
print(data['median']['point_estimate'])
"
}

# Extract p95 from criterion sample.json.
get_p95_ns() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "MISSING"
        return
    fi
    python3 -c "
import json
with open('$file') as f:
    data = json.load(f)
per_iter = sorted([t / i for t, i in zip(data['times'], data['iters'])])
n = len(per_iter)
p95 = per_iter[min(int(n * 0.95), n - 1)]
print(p95)
"
}

check_lt() {
    local name="$1"
    local actual="$2"
    local threshold="$3"
    local unit="$4"

    if [[ "$actual" == "MISSING" ]]; then
        echo "FAIL  $name: criterion data missing"
        FAILURES=$((FAILURES + 1))
        return
    fi

    local pass
    pass=$(python3 -c "print('yes' if float('$actual') < float('$threshold') else 'no')")
    if [[ "$pass" == "yes" ]]; then
        local actual_fmt
        actual_fmt=$(python3 -c "v=float('$actual'); print(f'{v/1000:.0f} µs' if v >= 1000 else f'{v:.0f} ns')")
        local thresh_fmt
        thresh_fmt=$(python3 -c "v=float('$threshold'); print(f'{v/1000:.0f} µs' if v >= 1000 else f'{v:.0f} ns')")
        echo "PASS  $name: $actual_fmt < $thresh_fmt"
    else
        local actual_fmt
        actual_fmt=$(python3 -c "v=float('$actual'); print(f'{v/1000:.0f} µs' if v >= 1000 else f'{v:.0f} ns')")
        local thresh_fmt
        thresh_fmt=$(python3 -c "v=float('$threshold'); print(f'{v/1000:.0f} µs' if v >= 1000 else f'{v:.0f} ns')")
        echo "FAIL  $name: $actual_fmt >= $thresh_fmt"
        FAILURES=$((FAILURES + 1))
    fi
}

check_throughput_gt() {
    local name="$1"
    local time_ns="$2"
    local total_bytes="$3"
    local min_mbps="$4"

    if [[ "$time_ns" == "MISSING" ]]; then
        echo "FAIL  $name: criterion data missing"
        FAILURES=$((FAILURES + 1))
        return
    fi

    local actual_mbps
    actual_mbps=$(python3 -c "print(round($total_bytes / (float('$time_ns') / 1e9) / 1e6, 1))")
    local pass
    pass=$(python3 -c "print('yes' if float('$actual_mbps') > float('$min_mbps') else 'no')")
    if [[ "$pass" == "yes" ]]; then
        echo "PASS  $name: ${actual_mbps} MB/s > ${min_mbps} MB/s"
    else
        echo "FAIL  $name: ${actual_mbps} MB/s <= ${min_mbps} MB/s"
        FAILURES=$((FAILURES + 1))
    fi
}

# ── SLO Checks ───────────────────────────────────────────────────────────────

echo "=== SLO Check: confidential-ml-transport ==="
echo ""

# 1. Handshake p50 < 500 µs
HS_MEDIAN=$(get_median_ns "$CRITERION_DIR/handshake/fresh_session/new/estimates.json")
check_lt "handshake/fresh_session p50" "$HS_MEDIAN" "500000" "ns"

# 2. Steady-state RTT p50 < 200 µs (1536B embedding)
RTT_MEDIAN=$(get_median_ns "$CRITERION_DIR/confidential_overhead_secure_channel/send_recv/1536b_embedding/new/estimates.json")
check_lt "secure_channel RTT p50 (1536B)" "$RTT_MEDIAN" "200000" "ns"

# 3. Reconnect p95 < 1 ms
RECONNECT_FILE="$CRITERION_DIR/reconnect/teardown_and_reconnect/new/sample.json"
if [[ -f "$RECONNECT_FILE" ]]; then
    RECONNECT_P95=$(get_p95_ns "$RECONNECT_FILE")
    check_lt "reconnect/teardown_and_reconnect p95" "$RECONNECT_P95" "1000000" "ns"
else
    # Reconnect bench may not have been run; skip gracefully.
    echo "SKIP  reconnect/teardown_and_reconnect p95: criterion data not found (run: cargo bench --bench reconnect)"
fi

# 4. Throughput (4KB, secure) > 200 MB/s
#    burst_count for 4KB = max(1, 4*1048576/4096) = 1024
THROUGHPUT_4K_NS=$(get_median_ns "$CRITERION_DIR/throughput_secure_channel/send/4k_activation/new/estimates.json")
THROUGHPUT_4K_BYTES=$((4096 * 1024))
check_throughput_gt "throughput/secure_channel (4KB)" "$THROUGHPUT_4K_NS" "$THROUGHPUT_4K_BYTES" "200"

echo ""
if [[ $FAILURES -gt 0 ]]; then
    echo "RESULT: $FAILURES SLO violation(s) detected."
    exit 1
else
    echo "RESULT: All SLO checks passed."
    exit 0
fi
