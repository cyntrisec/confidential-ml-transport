#!/usr/bin/env bash
# CI guard: every p50/p95 value in README benchmark tables must match the correct
# metric in a JSON file under benchmark_results/.
#
# Validates:
#   1. "## Performance" table — each row mapped to its JSON section key by phase name,
#      then p50/p95 checked against "p50_ms"/"p95_ms" within that section only.
#   2. "## Benchmarks" table — values cross-checked against BENCHMARK_BRIEF.md
#      (which is generated from JSON data).
#
# Usage: bash scripts/check_bench_tables.sh [base_ref]
#   base_ref  optional git ref to diff against (default: HEAD~1)
#             Set to "full" to always validate, even without a diff.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
README="$REPO_ROOT/README.md"
BENCH_DIR="$REPO_ROOT/benchmark_results"
NITRO_DIR="$BENCH_DIR/nitro_enclave"
BRIEF="$BENCH_DIR/BENCHMARK_BRIEF.md"
BASE_REF="${1:-HEAD~1}"

fail=0

# --- Step 1: detect if benchmark tables in README changed ---

if [ "$BASE_REF" = "full" ]; then
    echo "Mode: full validation (no diff filtering)"
else
    changed_lines=$(git diff "$BASE_REF" -- README.md 2>/dev/null || true)

    if [ -z "$changed_lines" ]; then
        echo "OK: README.md unchanged — skipping benchmark table check."
        exit 0
    fi

    # Trigger on any unit: ms, µs, ns, MB/s, GB/s, GiB/s
    bench_touched=$(echo "$changed_lines" | grep -E '^\+.*\|.*(ms|µs|ns|MB/s|GB/s|GiB/s)' || true)

    if [ -z "$bench_touched" ]; then
        echo "OK: README.md changed but no benchmark tables affected."
        exit 0
    fi

    echo "Benchmark table rows changed in README:"
    echo "$bench_touched"
    echo ""
fi

# === Validate "## Performance (Real Nitro Enclave)" section ===

echo "=== Validating ## Performance section ==="
echo ""

perf_section=$(sed -n '/^## Performance/,/^## /p' "$README" | head -n -1)

if [ -z "$perf_section" ]; then
    echo "WARN: No '## Performance' section found in README.md — skipping."
else
    data_rows=$(echo "$perf_section" | grep -E '^\|' | grep -v -E '^\|[-\s]+' | grep -v -E '^\| Phase')

    if [ -z "$data_rows" ]; then
        echo "WARN: No data rows found in Performance table."
    else
        # Map phase name substrings to JSON section keys
        # JSON structure: phases.connect_handshake, phases.transport_rtt, phases.inference_rtt
        map_phase_to_key() {
            local phase="$1"
            if echo "$phase" | grep -qi "handshake"; then
                echo "connect_handshake"
            elif echo "$phase" | grep -qi "transport.*RTT\|echo"; then
                echo "transport_rtt"
            elif echo "$phase" | grep -qi "inference"; then
                echo "inference_rtt"
            else
                echo ""
            fi
        }

        # Find the production JSON (preferred) or isolated JSON
        nitro_json=""
        if [ -f "$NITRO_DIR/production_bench_results.json" ]; then
            nitro_json="$NITRO_DIR/production_bench_results.json"
        elif [ -f "$NITRO_DIR/isolated_bench_results.json" ]; then
            nitro_json="$NITRO_DIR/isolated_bench_results.json"
        fi

        if [ -z "$nitro_json" ]; then
            echo "FAIL: No Nitro benchmark JSON found in $NITRO_DIR"
            fail=1
        else
            echo "Using: $nitro_json"
            echo ""

            while IFS= read -r row; do
                # Split on "|" — fields: [0]="" [1]=Phase [2]=p50 [3]=p95 [4]=n
                phase=$(echo "$row" | awk -F'|' '{print $2}' | sed 's/^ *//;s/ *$//')
                p50=$(echo "$row" | awk -F'|' '{print $3}' | grep -oP '[\d.]+' || true)
                p95=$(echo "$row" | awk -F'|' '{print $4}' | grep -oP '[\d.]+' || true)

                if [ -z "$p50" ] || [ -z "$p95" ]; then
                    echo "WARN: Could not parse values from row: $row"
                    continue
                fi

                section_key=$(map_phase_to_key "$phase")
                echo "  Row: $phase → section: ${section_key:-UNKNOWN}"

                if [ -z "$section_key" ]; then
                    echo "    FAIL: Could not map phase to JSON section key."
                    fail=1
                    continue
                fi

                # Extract the JSON block for this section (between "section_key": { and next })
                # and check p50_ms / p95_ms within that block only
                section_block=$(sed -n "/\"$section_key\"/,/}/p" "$nitro_json")

                if [ -z "$section_block" ]; then
                    echo "    FAIL: Section '$section_key' not found in $nitro_json"
                    fail=1
                    continue
                fi

                # Check p50_ms
                if echo "$section_block" | grep -qE "\"p50_ms\"[[:space:]]*:[[:space:]]*$p50"; then
                    echo "    OK: p50=${p50}ms matches p50_ms in $section_key"
                else
                    echo "    FAIL: p50=${p50}ms not found as p50_ms in section '$section_key'"
                    fail=1
                fi

                # Check p95_ms
                if echo "$section_block" | grep -qE "\"p95_ms\"[[:space:]]*:[[:space:]]*$p95"; then
                    echo "    OK: p95=${p95}ms matches p95_ms in $section_key"
                else
                    echo "    FAIL: p95=${p95}ms not found as p95_ms in section '$section_key'"
                    fail=1
                fi
            done <<< "$data_rows"
        fi
    fi
fi

# === Validate "## Benchmarks" section ===

echo ""
echo "=== Validating ## Benchmarks section ==="
echo ""

bench_section=$(sed -n '/^## Benchmarks$/,/^## /p' "$README" | head -n -1)

if [ -z "$bench_section" ]; then
    echo "WARN: No '## Benchmarks' section found in README.md — skipping."
else
    bench_rows=$(echo "$bench_section" | grep -E '^\|' | grep -v -E '^\|[-\s]+' | grep -v -E '^\| Metric')

    if [ -z "$bench_rows" ]; then
        echo "WARN: No data rows in Benchmarks table."
    elif [ ! -f "$BRIEF" ]; then
        echo "WARN: $BRIEF not found — cannot cross-check Benchmarks table."
    else
        # Each Benchmarks row has: | Metric | Value | Environment |
        # Extract the numeric value and verify it appears in BENCHMARK_BRIEF.md
        while IFS= read -r row; do
            metric=$(echo "$row" | awk -F'|' '{print $2}' | sed 's/^ *//;s/ *$//')
            value_col=$(echo "$row" | awk -F'|' '{print $3}')
            # Extract all numbers with units from the value column
            numbers=$(echo "$value_col" | grep -oP '[\d.]+\s*(µs|ms|ns|MB/s|GB/s|GiB/s)' || true)

            if [ -z "$numbers" ]; then
                echo "  SKIP: No parseable value in row: $metric"
                continue
            fi

            # Check each number appears in BENCHMARK_BRIEF.md
            while IFS= read -r numval; do
                num=$(echo "$numval" | grep -oP '[\d.]+')
                if [ -z "$num" ]; then continue; fi
                if grep -q "$num" "$BRIEF"; then
                    echo "  OK: $metric — $numval found in BENCHMARK_BRIEF.md"
                else
                    echo "  FAIL: $metric — $numval NOT found in BENCHMARK_BRIEF.md"
                    fail=1
                fi
            done <<< "$numbers"
        done <<< "$bench_rows"
    fi
fi

# === Final result ===

echo ""
if [ "$fail" -ne 0 ]; then
    echo "FAIL: README benchmark values do not match raw data."
    echo "Update the JSON/BRIEF files first (by running benchmarks), then update the README."
    exit 1
fi

echo "OK: All README benchmark values backed by raw data (section-matched)."
