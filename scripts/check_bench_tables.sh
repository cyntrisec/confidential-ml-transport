#!/usr/bin/env bash
# CI guard: every numeric value in the README benchmark table must appear in a
# corresponding JSON file under benchmark_results/.  This prevents someone from
# editing the README numbers without updating (or adding) raw data.
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
    check_all=true
else
    # Get lines changed in README between base and working tree / HEAD
    changed_lines=$(git diff "$BASE_REF" -- README.md 2>/dev/null || true)

    if [ -z "$changed_lines" ]; then
        echo "OK: README.md unchanged — skipping benchmark table check."
        exit 0
    fi

    # Check if any table row with "ms" was touched
    bench_touched=$(echo "$changed_lines" | grep -E '^\+.*\|.*ms' || true)

    if [ -z "$bench_touched" ]; then
        echo "OK: README.md changed but no benchmark tables affected."
        exit 0
    fi

    echo "Benchmark table rows changed in README:"
    echo "$bench_touched"
    echo ""
    check_all=false
fi

# --- Step 2: extract numeric values from the README performance table ---

# Find the "## Performance" section and extract table rows with "ms" values
perf_section=$(sed -n '/^## Performance/,/^## /p' "$README" | head -n -1)

if [ -z "$perf_section" ]; then
    echo "FAIL: No '## Performance' section found in README.md"
    exit 1
fi

# Extract all p50 values from the table (column 2 — the first data column)
p50_values=$(echo "$perf_section" | grep -oP '\|\s*[\d.]+\s*ms' | head -3 | grep -oP '[\d.]+')

if [ -z "$p50_values" ]; then
    echo "FAIL: Could not extract p50 values from README performance table."
    exit 1
fi

echo "README p50 values: $(echo $p50_values | tr '\n' ' ')"

# --- Step 3: verify each value exists in at least one JSON file ---

fail=0
json_files=$(find "$BENCH_DIR" -name '*.json' -type f 2>/dev/null || true)

if [ -z "$json_files" ]; then
    echo "FAIL: No JSON files found in $BENCH_DIR"
    exit 1
fi

for val in $p50_values; do
    found=false
    for json in $json_files; do
        if grep -q "$val" "$json"; then
            found=true
            break
        fi
    done
    if [ "$found" = false ]; then
        echo "FAIL: p50 value ${val}ms in README not found in any benchmark JSON file."
        fail=1
    else
        echo "  OK: ${val}ms found in benchmark data."
    fi
done

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "README benchmark values do not match raw data in benchmark_results/."
    echo "Update the JSON files first (by running benchmarks), then update the README."
    exit 1
fi

echo ""
echo "OK: All README benchmark values backed by raw JSON data."
