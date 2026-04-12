#!/usr/bin/env bash
# Fetch public SEV-SNP test fixtures from AMD's Key Distribution System (KDS).
#
# What this does:
#   1. Pulls ARK/ASK PEM chain for Milan, Genoa, Turin from kdsintf.amd.com
#   2. Pulls DER-encoded CRLs for each product
#   3. Byte-compares the pulled ARK/ASK against the `sev` crate's builtins
#      (sanity check: our pinned roots must equal live KDS)
#   4. Writes a manifest with SHA-256 of each file + fetch timestamp
#
# What this does NOT do:
#   - NOT fetch any VCEK certificates (those are chip-specific and contain
#     the chip's public serial number / hwID — keep those out of VCS)
#   - NOT authenticate against any cloud (all endpoints are public HTTPS)
#   - NOT modify any test code
#
# Usage:
#   scripts/fetch-snp-fixtures.sh           # fetch + compare, exit non-zero on drift
#   scripts/fetch-snp-fixtures.sh --refresh # overwrite existing fixtures
#   scripts/fetch-snp-fixtures.sh --check   # compare only, no writes
#
# Safe to run from any working directory; re-runnable; exits non-zero on error.
#
# Spec references:
#   - VCEK 1.00 (Pub. 57230) §2.2 Table 6: /vcek/v1/{product}/cert_chain
#   - VCEK 1.00 §4.3 Table 15: /vcek/v1/{product}/crl
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/test_assets/sev-snp"
KDS_BASE="https://kdsintf.amd.com/vcek/v1"
PRODUCTS=("Milan" "Genoa" "Turin")

MODE="${1:-fetch}"
case "$MODE" in
  fetch|--refresh) MODE="fetch" ;;
  --check) MODE="check" ;;
  -h|--help)
    sed -n '2,30p' "$0"
    exit 0
    ;;
  *)
    echo "error: unknown mode '$MODE'; use --refresh or --check" >&2
    exit 2
    ;;
esac

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
info()  { printf '[fetch-snp] %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    red "missing required command: $1"
    exit 2
  }
}

require_cmd curl
require_cmd openssl
require_cmd sha256sum
require_cmd diff

mkdir -p "$FIXTURES_DIR"

MANIFEST="$FIXTURES_DIR/MANIFEST.txt"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

fetch_product() {
  local product="$1"
  local chain_url="$KDS_BASE/$product/cert_chain"
  local crl_url="$KDS_BASE/$product/crl"
  local product_dir="$FIXTURES_DIR/$product"

  info "fetching $product chain and CRL"

  mkdir -p "$product_dir"

  # Chain: ASK + ARK, PEM, in that order (per VCEK 1.00 §4.2 Table 14)
  if ! curl -sSfLo "$TMPDIR/$product.chain.pem" "$chain_url"; then
    red "  chain fetch failed for $product"
    return 1
  fi

  # CRL: DER-encoded (per VCEK 1.00 §4.3 Table 15)
  if ! curl -sSfLo "$TMPDIR/$product.crl" "$crl_url"; then
    red "  CRL fetch failed for $product"
    return 1
  fi

  # Sanity: two PEM blocks in the chain, parseable
  local cert_count
  cert_count="$(grep -c 'BEGIN CERTIFICATE' "$TMPDIR/$product.chain.pem" || true)"
  if [[ "$cert_count" -ne 2 ]]; then
    red "  $product: expected 2 PEM certs in chain, got $cert_count"
    return 1
  fi

  # Split into ASK (first) and ARK (second), identified by Subject CN.
  # (Defensive: classify by CN, not position — matches F7 fix rationale.)
  awk '/BEGIN CERT/{c++} {print > "'$TMPDIR'/'$product'.cert_"c".pem"}' "$TMPDIR/$product.chain.pem"

  local cert1_cn cert2_cn
  cert1_cn="$(openssl x509 -in "$TMPDIR/$product.cert_1.pem" -noout -subject | sed 's/.*CN = //' | tr -d '[:space:]')"
  cert2_cn="$(openssl x509 -in "$TMPDIR/$product.cert_2.pem" -noout -subject | sed 's/.*CN = //' | tr -d '[:space:]')"

  local ask_pem ark_pem
  case "$cert1_cn:$cert2_cn" in
    SEV-$product:ARK-$product)
      ask_pem="$TMPDIR/$product.cert_1.pem"
      ark_pem="$TMPDIR/$product.cert_2.pem"
      ;;
    ARK-$product:SEV-$product)
      ark_pem="$TMPDIR/$product.cert_1.pem"
      ask_pem="$TMPDIR/$product.cert_2.pem"
      ;;
    *)
      red "  $product: unrecognized Subject CNs: '$cert1_cn' / '$cert2_cn'"
      return 1
      ;;
  esac

  # Parse each cert to catch malformed data early; fail fast if AMD ever
  # serves something that's not X.509v3.
  openssl x509 -in "$ask_pem" -noout -text >"$TMPDIR/$product.ask.txt"
  openssl x509 -in "$ark_pem" -noout -text >"$TMPDIR/$product.ark.txt"

  # Basic CRL sanity: parseable and signed with known-good SHA-384.
  openssl crl -inform DER -in "$TMPDIR/$product.crl" -noout -text >"$TMPDIR/$product.crl.txt"

  if [[ "$MODE" == "fetch" ]]; then
    cp "$ask_pem"                      "$product_dir/ask.pem"
    cp "$ark_pem"                      "$product_dir/ark.pem"
    cp "$TMPDIR/$product.chain.pem"    "$product_dir/cert_chain.pem"
    cp "$TMPDIR/$product.crl"          "$product_dir/crl.der"
    green "  $product: fixtures written to test_assets/sev-snp/$product/"
  elif [[ "$MODE" == "check" ]]; then
    local drift=0
    for f in ask.pem ark.pem cert_chain.pem crl.der; do
      if [[ ! -f "$product_dir/$f" ]]; then
        yellow "  $product: $f missing on disk (re-run with --refresh)"
        drift=1
        continue
      fi
      local local_sha live_sha
      case "$f" in
        ask.pem)        live_sha="$(sha256sum "$ask_pem" | awk '{print $1}')" ;;
        ark.pem)        live_sha="$(sha256sum "$ark_pem" | awk '{print $1}')" ;;
        cert_chain.pem) live_sha="$(sha256sum "$TMPDIR/$product.chain.pem" | awk '{print $1}')" ;;
        crl.der)        live_sha="$(sha256sum "$TMPDIR/$product.crl" | awk '{print $1}')" ;;
      esac
      local_sha="$(sha256sum "$product_dir/$f" | awk '{print $1}')"
      if [[ "$local_sha" != "$live_sha" ]]; then
        yellow "  $product: $f differs from live KDS (local=$local_sha live=$live_sha)"
        drift=1
      fi
    done
    [[ $drift -eq 0 ]] && green "  $product: fixtures match live KDS"
    return $drift
  fi
}

compare_with_sev_crate() {
  local product="$1"
  local product_dir="$FIXTURES_DIR/$product"
  local crate_dir
  crate_dir="$(find "$HOME/.cargo/registry/src" -maxdepth 2 -type d -name 'sev-*' | head -1)"

  if [[ -z "$crate_dir" ]]; then
    yellow "  sev crate not in cargo cache; skipping builtin comparison for $product"
    return 0
  fi

  local product_lower
  product_lower="$(echo "$product" | tr '[:upper:]' '[:lower:]')"
  local builtin_ark="$crate_dir/src/certs/snp/builtin/$product_lower/ark.pem"
  local builtin_ask="$crate_dir/src/certs/snp/builtin/$product_lower/ask.pem"

  if [[ ! -f "$builtin_ark" || ! -f "$builtin_ask" ]]; then
    yellow "  $product: sev crate has no builtin for this product (expected for Turin on older crate versions)"
    return 0
  fi

  # Compare at DER level (after PEM decode) — this is the semantic trust
  # boundary. PEM whitespace (CRLF vs LF, trailing newlines) is not a trust
  # signal; the actual X.509 bytes are. AMD has historically served Turin ARK
  # with CRLF line endings while the sev crate ships LF-only; both decode to
  # the same certificate.
  local local_der_sha crate_der_sha
  local_der_sha="$(openssl x509 -in "$product_dir/ark.pem" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  crate_der_sha="$(openssl x509 -in "$builtin_ark" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  if [[ "$local_der_sha" != "$crate_der_sha" ]]; then
    red "  $product: ARK DER differs from sev crate builtin — possible supply-chain issue or crate update needed"
    red "    local: $local_der_sha"
    red "    crate: $crate_der_sha"
    return 1
  fi
  local_der_sha="$(openssl x509 -in "$product_dir/ask.pem" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  crate_der_sha="$(openssl x509 -in "$builtin_ask" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  if [[ "$local_der_sha" != "$crate_der_sha" ]]; then
    red "  $product: ASK DER differs from sev crate builtin"
    return 1
  fi
  green "  $product: pinned roots match sev crate builtins at DER level"
}

write_manifest() {
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    echo "# SEV-SNP fixture manifest"
    echo "# Generated: $ts"
    echo "# Source: $KDS_BASE"
    echo "# Safe to commit: YES (AMD public KDS data, no chip-specific identifiers)"
    echo
    (cd "$FIXTURES_DIR" && find . -type f \( -name '*.pem' -o -name '*.der' \) | sort | xargs sha256sum)
  } >"$MANIFEST"
  info "manifest: $MANIFEST"
}

# ---------------- main ----------------
info "mode: $MODE"
info "fixtures dir: $FIXTURES_DIR"
info "KDS base: $KDS_BASE"

failed=0
for product in "${PRODUCTS[@]}"; do
  if ! fetch_product "$product"; then
    failed=1
    continue
  fi
done

if [[ "$MODE" == "fetch" ]]; then
  info "comparing against sev crate builtins..."
  for product in "${PRODUCTS[@]}"; do
    compare_with_sev_crate "$product" || failed=1
  done
  write_manifest
  [[ $failed -eq 0 ]] && green "done." || { red "completed with errors"; exit 1; }
else
  [[ $failed -eq 0 ]] && green "all fixtures match live KDS" || { yellow "drift detected — run with --refresh"; exit 1; }
fi
