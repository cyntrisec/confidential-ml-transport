#!/usr/bin/env bash
# CI guard: every p50/p95 value in the README "## Performance" table must match
# a corresponding "p50_ms" / "p95_ms" key in a JSON file under benchmark_results/.
#
# Usage: bash scripts/check_bench_tables.sh [base_ref]
#   base_ref  optional git ref to diff against (default: HEAD~1)
#             Set to "full" to always validate, even without a diff.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
README="$REPO_ROOT/README.md"
BENCH_DIR="$REPO_ROOT/benchmark_results"
BASE_REF="${1:-HEAD~1}"

# --- Step 1: detect if benchmark tables in README changed ---

if [ "$BASE_REF" = "full" ]; then
    echo "Mode: full validation (no diff filtering)"
else
    changed_lines=$(git diff "$BASE_REF" -- README.md 2>/dev/null || true)

    if [ -z "$changed_lines" ]; then
        echo "OK: README.md unchanged — skipping benchmark table check."
        exit 0
    fi

    bench_touched=$(echo "$changed_lines" | grep -E '^\+.*\|.*ms' || true)

    if [ -z "$bench_touched" ]; then
        echo "OK: README.md changed but no benchmark tables affected."
        exit 0
    fi

    echo "Benchmark table rows changed in README:"
    echo "$bench_touched"
    echo ""
fi

# --- Step 2: extract p50 and p95 values from each data row by column position ---
# Table format: | Phase | p50 | p95 | n |
# We split on "|" and pick columns 2 (p50) and 3 (p95) by index.

perf_section=$(sed -n '/^## Performance/,/^## /p' "$README" | head -n -1)

if [ -z "$perf_section" ]; then
    echo "FAIL: No '## Performance' section found in README.md"
    exit 1
fi

# Extract data rows (skip header and separator lines)
data_rows=$(echo "$perf_section" | grep -E '^\|' | grep -v -E '^\|[-\s]+' | grep -v -E '^\| Phase')

if [ -z "$data_rows" ]; then
    echo "FAIL: No data rows found in Performance table."
    exit 1
fi

fail=0
json_files=$(find "$BENCH_DIR" -name '*.json' -type f 2>/dev/null || true)

if [ -z "$json_files" ]; then
    echo "FAIL: No JSON files found in $BENCH_DIR"
    exit 1
fi

echo "Validating README performance table values against JSON data..."
echo ""

while IFS= read -r row; do
    # Split on "|" — fields: [0]="" [1]=Phase [2]=p50 [3]=p95 [4]=n
    p50_raw=$(echo "$row" | awk -F'|' '{print $3}')
    p95_raw=$(echo "$row" | awk -F'|' '{print $4}')
    phase=$(echo "$row" | awk -F'|' '{print $2}' | sed 's/^ *//;s/ *$//')

    # Extract numeric value (strip "ms" and whitespace)
    p50=$(echo "$p50_raw" | grep -oP '[\d.]+' || true)
    p95=$(echo "$p95_raw" | grep -oP '[\d.]+' || true)

    if [ -z "$p50" ] || [ -z "$p95" ]; then
        echo "WARN: Could not parse values from row: $row"
        continue
    fi

    echo "  Row: $phase"

    # Validate p50 against "p50_ms": <value> in JSON
    p50_found=false
    for json in $json_files; do
        if grep -qE "\"p50_ms\"[[:space:]]*:[[:space:]]*$p50" "$json"; then
            p50_found=true
            break
        fi
    done

    if [ "$p50_found" = false ]; then
        echo "    FAIL: p50=${p50}ms not found as p50_ms in any benchmark JSON."
        fail=1
    else
        echo "    OK: p50=${p50}ms matches p50_ms in benchmark data."
    fi

    # Validate p95 against "p95_ms": <value> in JSON
    p95_found=false
    for json in $json_files; do
        if grep -qE "\"p95_ms\"[[:space:]]*:[[:space:]]*$p95" "$json"; then
            p95_found=true
            break
        fi
    done

    if [ "$p95_found" = false ]; then
        echo "    FAIL: p95=${p95}ms not found as p95_ms in any benchmark JSON."
        fail=1
    else
        echo "    OK: p95=${p95}ms matches p95_ms in benchmark data."
    fi
done <<< "$data_rows"

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "README benchmark values do not match raw data in benchmark_results/."
    echo "Update the JSON files first (by running benchmarks), then update the README."
    exit 1
fi

echo ""
echo "OK: All README benchmark values backed by raw JSON data (key-matched)."
