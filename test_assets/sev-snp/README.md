# SEV-SNP test fixtures

Public data from AMD's Key Distribution System (KDS), used as test anchors for
the SEV-SNP verifier hardening work tracked in
`references/amd-sev-snp-audit-2026-04-12/findings.md`.

## Contents

For each of Milan, Genoa, Turin:

- `<product>/ark.pem` — AMD Root Key certificate (X.509, PEM). Root CA.
- `<product>/ask.pem` — AMD SEV Key certificate (X.509, PEM). Intermediate CA.
- `<product>/cert_chain.pem` — raw KDS response (ASK || ARK, PEM concatenated).
- `<product>/crl.der` — Certificate Revocation List (DER).
- `MANIFEST.txt` — SHA-256 of every file + fetch timestamp.

All files are the unmodified response from:

- `https://kdsintf.amd.com/vcek/v1/{Milan,Genoa,Turin}/cert_chain`
- `https://kdsintf.amd.com/vcek/v1/{Milan,Genoa,Turin}/crl`

## Why this is safe to commit

These fixtures contain **only AMD's product-level signing infrastructure**:

- ARK and ASK are per-product certificates issued by AMD that sign VCEKs for an
  entire processor generation (Milan / Genoa / Turin). They are not
  chip-specific.
- CRLs are per-product revocation lists; they contain serial numbers of revoked
  certificates, not identifiers of any of our systems.

No chip-specific identifiers are committed:

- No VCEK certificates. A VCEK embeds the chip's Public Serial Number
  (PSN, 64 bytes on Milan/Genoa, 8 bytes on Turin per VCEK 1.00 §3.1) as the
  `hwID` extension. Even though PSN is "public" in the AMD sense, embedding
  our test VMs' chip IDs in a public repo enables fleet fingerprinting — so
  we deliberately never commit them.
- No attestation reports. Reports carry chip ID, family/model/stepping, and
  TCB version, all of which are infrastructure identifiers we treat as
  sensitive.
- No nonces, session keys, handshake transcripts, or measurement values
  captured from live systems.

If we later need a real VCEK for a negative test case, it should be obtained
from a short-lived test VM, the hwID redacted to zeros, and the reduced
artifact documented here.

## Refresh cadence

ARK and ASK certificates are valid for 25 years (VCEK 1.00 §2.3); they rotate
rarely. CRLs are intended to be fetched regularly.

Recommended:

- **ARK / ASK**: re-fetch on every major `sev` crate version bump, to catch
  any AMD reissuance (none has ever happened for ARK/ASK in practice).
- **CRL**: re-fetch quarterly, or immediately upon any AMD Product Security
  Bulletin that touches SEV-SNP firmware.

To refresh everything:

```bash
scripts/fetch-snp-fixtures.sh --refresh
```

To verify the on-disk fixtures still match the live KDS without overwriting:

```bash
scripts/fetch-snp-fixtures.sh --check
```

CI should run `--check` on a schedule (monthly is enough) to detect drift.

## Integrity

The fetch script compares the ARK and ASK byte-for-byte at the **DER level**
(after PEM decode) against the `sev` crate's pinned builtins in
`sev-7.1.0/src/certs/snp/builtin/`. If those ever diverge, investigate —
either AMD reissued a root (unprecedented, so take seriously) or the `sev`
crate's pin is stale and needs a version bump.

Note on whitespace: AMD KDS has historically served the Turin ARK with CRLF
line endings while the `sev` crate ships it with LF only. The DER-level
comparison ignores this cosmetic difference — only the actual X.509 bytes
are the trust signal. Do not normalize the PEM on fetch; keep AMD's wire
format verbatim so future-us can audit exactly what the KDS served.

## Used by

- `src/attestation/sev_errors.rs` — error codes
- `src/attestation/sev.rs` — direct `/dev/sev-guest` path tests (planned)
- `src/attestation/azure_sev.rs` — Azure vTPM path tests (planned)
- `tests/sev_snp_hardening_test.rs` — integration tests (planned, Phase 2+)

## Spec references

- AMD SEV-SNP Firmware ABI Specification 1.58 (Pub. 56860, May 2025)
- AMD VCEK Certificate and KDS Interface Specification 1.00 (Pub. 57230, January 2025)
- AMD SEV-SNP Platform Attestation Using VirTEE/SEV 1.2 (Pub. 58217, July 2023)
