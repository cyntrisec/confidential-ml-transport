//! SEV-SNP attestation verification error codes.
//!
//! Mirrors the structure of `TdxVerifyError` in `tdx.rs` — 4-layer trust model
//! (T1_PARSE → T2_CRYPTO → T3_CHAIN → T4_POLICY) with stable string codes for
//! programmatic matching in tests and operator-facing diagnostics.
//!
//! # Layer semantics (matches M2 trust matrix)
//!
//! - **T1_PARSE**: evidence shape / wire format. "Is this a well-formed report?"
//! - **T2_CRYPTO**: signature math + binding. "Was it signed by a key we trust?"
//! - **T3_CHAIN**: certificate chain + revocation. "Does the signing key itself
//!   belong to a genuine AMD platform?"
//! - **T4_POLICY**: guest / platform posture. "Are we willing to accept this
//!   configuration?" (debug flags, VMPL, TCB rollback, measurements).
//!
//! # Spec references
//!
//! - AMD ABI 1.58 (Pub. 56860) — attestation report format, policy fields
//! - AMD VCEK 1.00 (Pub. 57230) — certificate chain and TCB extensions
//! - AMD VirTEE 1.2 (Pub. 58217) — reference verification flow
//! - AMD SB-3019 / CVE-2024-56161 — BadRAM remediation requires TCB binding

use std::fmt;

use crate::error::AttestError;

/// Minimum attestation report VERSION accepted by the verifier (Phase 1 default).
///
/// Reference: ABI 1.58 §7.3 Table 23 offset 00h — "Set to 5h for this specification";
/// `virtee/sev` crate `AttestationReport` doc still says "Set to 2h" (trails ABI);
/// known report versions in the wild: 2, 3 (PreTurin), 5 (current).
///
/// We accept `>= 2` today because that's what our existing test suite uses and
/// what virtee/sev's own documentation targets. Phase 3 will move this into a
/// configurable `SnpVerifyPolicy` so production deployments can require higher.
pub const MIN_REPORT_VERSION: u32 = 2;

/// Signature algorithm encoding for ECDSA P-384 + SHA-384 (the only defined value).
///
/// Reference: ABI 1.58 Chapter 10 Table 139 — "ECDSA P-384 with SHA-384 — 1h.
/// All other encodings are reserved."
pub const SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;

/// Sentinel VMPL value indicating a host-requested report (SNP_HV_REPORT_REQ).
///
/// Reference: ABI 1.58 §7.3 Table 23 offset 30h — "A Host requested attestation
/// report will have a value of 0xffffffff."
pub const VMPL_HOST_REQUESTED: u32 = 0xFFFF_FFFF;

/// SEV-SNP processor product family.
///
/// AMD issues a distinct ARK (root) and ASK (intermediate) for each product
/// family. Used by the verifier to:
///
/// 1. Identify which AMD root matched the incoming chain ([`classify_certs_by_cn`]
///    extracts this from the ARK's Subject CN).
/// 2. Let callers pin policy to a specific product family (Phase 4+ enforcement).
/// 3. Cross-check the report's CPUID fields against the cert (F8, Phase 4+).
///
/// # Spec reference
///
/// - VCEK 1.00 §1.5 Table 4 (Family/Extended Model → product_name mapping):
///   - Milan: Family 19h, Extended Model 0h
///   - Genoa: Family 19h, Extended Model 1h (also Siena uses Genoa roots)
///   - Turin: Family 1Ah, Extended Model 0h or 1h
/// - VCEK 1.00 §2.3 Table 7 (ARK CN = `ARK-{product_name}`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnpProduct {
    /// EPYC 7xx3 (Family 19h, Extended Model 0h).
    Milan,
    /// EPYC 9xx4 (Family 19h, Extended Model 1h). Also covers Siena.
    Genoa,
    /// EPYC 9xx5 (Family 1Ah, Extended Model 0h/1h).
    Turin,
}

impl SnpProduct {
    /// Canonical product name as used in ARK Subject CN (e.g., `"Milan"`).
    pub fn name(self) -> &'static str {
        match self {
            SnpProduct::Milan => "Milan",
            SnpProduct::Genoa => "Genoa",
            SnpProduct::Turin => "Turin",
        }
    }

    /// All supported products in canonical order.
    ///
    /// Used by policy defaults to construct `accepted_products` allowlists.
    pub fn all() -> &'static [SnpProduct] {
        &[SnpProduct::Milan, SnpProduct::Genoa, SnpProduct::Turin]
    }

    /// Parse a product from an ARK Subject CN of the form `"ARK-<Product>"`.
    ///
    /// Returns `None` for unrecognized product names.
    ///
    /// Reference: VCEK 1.00 §2.3 Table 7.
    pub fn from_ark_cn(cn: &str) -> Option<Self> {
        match cn.strip_prefix("ARK-")? {
            "Milan" => Some(SnpProduct::Milan),
            "Genoa" => Some(SnpProduct::Genoa),
            "Turin" => Some(SnpProduct::Turin),
            _ => None,
        }
    }

    /// Parse a product from the report's CPUID_FAM_ID / CPUID_MOD_ID fields
    /// (ABI 1.58 §7.3 Table 23 offsets 188h/189h).
    ///
    /// The spec presents CPUID as combined Extended Family + Family (fam_id)
    /// and combined Extended Model + Model (mod_id). Used by the F8 product-
    /// binding check in Phase 4+.
    ///
    /// Reference: VCEK 1.00 §1.5 Table 4.
    pub fn from_cpuid(fam_id: u8, mod_id: u8) -> Option<Self> {
        match (fam_id, mod_id & 0xF0) {
            (0x19, 0x00) => Some(SnpProduct::Milan),
            (0x19, 0x10) => Some(SnpProduct::Genoa),
            // Siena (Family 19h, Extended Model Ah) uses Genoa roots per VCEK §1.5 Table 4 note 2.
            (0x19, 0xA0) => Some(SnpProduct::Genoa),
            (0x1A, 0x00) | (0x1A, 0x10) => Some(SnpProduct::Turin),
            _ => None,
        }
    }
}

impl fmt::Display for SnpProduct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Certificate role in the SEV-SNP trust chain.
///
/// Used by [`check_cert_chain_validity`] and [`classify_certs_by_cn`]
/// to produce role-specific error variants when a cert is expired, not yet
/// valid, or misidentified.
///
/// Reference: VCEK 1.00 §2.1 Table 5 (ARK/ASK chain), §3 Table 9 (VCEK leaf);
/// ABI 1.58 §3.7 (VLEK is a drop-in replacement for VCEK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRole {
    /// AMD Root Key — self-signed root CA, product-specific.
    Ark,
    /// AMD SEV Key — intermediate CA, signs VCEK/VLEK.
    Ask,
    /// Versioned Endorsement Key — leaf, signs attestation reports.
    /// Covers both VCEK (chip-derived) and VLEK (CSP-derived).
    Vek,
}

impl CertRole {
    fn name(self) -> &'static str {
        match self {
            CertRole::Ark => "ARK",
            CertRole::Ask => "ASK",
            CertRole::Vek => "VEK",
        }
    }
}

/// Check that a certificate's validity window (NotBefore..NotAfter) contains
/// the current time.
///
/// Returns a role-specific error variant if the cert is expired or not yet
/// valid. Parse failures surface as [`SnpVerifyError::CertParseFailed`].
///
/// # Why this is needed
///
/// The `openssl::x509::X509::verify(&pkey)` method used by the `sev` crate's
/// chain verification checks **only the signature**. It does not inspect
/// NotBefore/NotAfter, key usage, EKU, or any other X.509 constraint. An
/// expired VCEK — which AMD no longer considers authoritative for the chip —
/// will still pass signature verification and produce a valid-looking chain.
///
/// # Spec reference
///
/// - VCEK 1.00 §3 Table 9: VCEK valid 7 years from issuance.
/// - VCEK 1.00 §2.3 Tables 7-8: ARK/ASK valid 25 years from issuance.
/// - `docs.rs` openssl `X509::verify`: "Only the signature is checked: no
///   other checks (such as certificate chain validity) are performed."
/// - Direct precedent: MSRC Case 107128 / VULN-173713 (azure-cvm-tooling,
///   Feb 2026).
///
/// # Clock skew
///
/// No slop is applied. AMD's VCEK issuance already backdates NotBefore by
/// one day (VCEK 1.00 §3 Table 9 note: "The notValidBefore date is backdated
/// one day prior to the actual issuance date to avoid false certificate
/// verification failures due to out-of-sync system clocks").
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
pub fn check_cert_chain_validity(
    ark_der: &[u8],
    ask_der: &[u8],
    vek_der: &[u8],
) -> Result<(), SnpVerifyError> {
    check_single_cert_validity(CertRole::Ark, ark_der)?;
    check_single_cert_validity(CertRole::Ask, ask_der)?;
    check_single_cert_validity(CertRole::Vek, vek_der)?;
    Ok(())
}

/// Validity check for one certificate; returns role-appropriate error on
/// expiry or not-yet-valid.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
fn check_single_cert_validity(role: CertRole, der: &[u8]) -> Result<(), SnpVerifyError> {
    use openssl::asn1::Asn1Time;
    use openssl::x509::X509;

    let cert = X509::from_der(der)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("{role}: {e}", role = role.name())))?;

    let now = Asn1Time::days_from_now(0).map_err(|e| {
        // Extremely unlikely — openssl failing to represent current time.
        SnpVerifyError::CertParseFailed(format!(
            "failed to get current time for validity check: {e}"
        ))
    })?;

    // Asn1TimeRef::compare returns Ordering relative to the argument:
    //   not_before.compare(now) == Greater  ⇒  notBefore is in the future
    //   not_after.compare(now)  == Less     ⇒  notAfter is in the past
    //
    // A compare() failure here indicates one of the two ASN.1 times is
    // malformed; treat as a parse error.
    let not_before_cmp = cert.not_before().compare(&now).map_err(|e| {
        SnpVerifyError::CertParseFailed(format!(
            "{role} notBefore compare failed: {e}",
            role = role.name()
        ))
    })?;
    if not_before_cmp == std::cmp::Ordering::Greater {
        let msg = format!(
            "{role} is not yet valid (notBefore is in the future)",
            role = role.name()
        );
        return Err(match role {
            CertRole::Ark => SnpVerifyError::ArkNotYetValid(msg),
            CertRole::Ask => SnpVerifyError::AskNotYetValid(msg),
            CertRole::Vek => SnpVerifyError::VekNotYetValid(msg),
        });
    }

    let not_after_cmp = cert.not_after().compare(&now).map_err(|e| {
        SnpVerifyError::CertParseFailed(format!(
            "{role} notAfter compare failed: {e}",
            role = role.name()
        ))
    })?;
    if not_after_cmp == std::cmp::Ordering::Less {
        let msg = format!(
            "{role} has expired (notAfter is in the past)",
            role = role.name()
        );
        return Err(match role {
            CertRole::Ark => SnpVerifyError::ArkExpired(msg),
            CertRole::Ask => SnpVerifyError::AskExpired(msg),
            CertRole::Vek => SnpVerifyError::VekExpired(msg),
        });
    }

    Ok(())
}

/// Classified SEV-SNP certificate chain, returned by [`classify_certs_by_cn`].
///
/// Each field holds the DER bytes of the cert matched to that role.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedCerts {
    /// AMD Root Key certificate (DER).
    pub ark: Vec<u8>,
    /// AMD SEV Key certificate (DER).
    pub ask: Vec<u8>,
    /// VCEK or VLEK certificate (DER).
    pub vek: Vec<u8>,
}

/// Classify a set of DER-encoded certificates into (ARK, ASK, VEK) by
/// inspecting each cert's Subject Common Name.
///
/// This replaces positional `certs[0]/certs[1]/certs[2]` indexing in the
/// Azure IMDS path (F7). Positional indexing is brittle against:
///
/// 1. Future-compatible changes to the Azure THIM response format (e.g.,
///    Microsoft prepending a TLS chain leaf).
/// 2. Whitespace variations between PEM blocks that happen to shift
///    SEQUENCE boundaries.
/// 3. Accidental duplication or reordering during cert marshaling.
///
/// # Subject CN mapping
///
/// Per VCEK 1.00 §2.3 Tables 7-8 and §3 Table 9:
///
/// | Cert role | Subject CN format | Example |
/// |---|---|---|
/// | ARK | `ARK-{product}` | `ARK-Milan`, `ARK-Genoa`, `ARK-Turin` |
/// | ASK | `SEV-{product}` | `SEV-Milan`, `SEV-Genoa`, `SEV-Turin` |
/// | VCEK | `SEV-VCEK` | `SEV-VCEK` |
/// | VLEK | `SEV-VLEK` | `SEV-VLEK` (ABI 1.58 §3.7) |
///
/// Disambiguation: `SEV-VCEK`/`SEV-VLEK` are leaf keys, everything else
/// starting with `SEV-` is an ASK.
///
/// # Returns
///
/// A [`ClassifiedCerts`] with `ark`, `ask`, `vek` fields populated from the
/// corresponding cert in the input. Missing roles, duplicates, or unrecognized
/// CNs surface as [`SnpVerifyError`] variants.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
pub fn classify_certs_by_cn(der_blocks: &[Vec<u8>]) -> Result<ClassifiedCerts, SnpVerifyError> {
    use openssl::nid::Nid;
    use openssl::x509::X509;

    let mut ark: Option<Vec<u8>> = None;
    let mut ask: Option<Vec<u8>> = None;
    let mut vek: Option<Vec<u8>> = None;

    for der in der_blocks {
        let cert = X509::from_der(der)
            .map_err(|e| SnpVerifyError::CertParseFailed(format!("DER parse: {e}")))?;

        // Extract the first CN in the Subject — AMD certs have exactly one.
        let subject = cert.subject_name();
        let cn = subject
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .ok_or_else(|| SnpVerifyError::CertParseFailed("cert missing Subject CN".into()))?
            .data()
            .as_utf8()
            .map_err(|e| SnpVerifyError::CertParseFailed(format!("CN not UTF-8: {e}")))?
            .to_string();

        // Classify by CN. Order of checks matters: SEV-VCEK/SEV-VLEK before SEV-*.
        if cn.starts_with("ARK-") {
            if ark.is_some() {
                return Err(SnpVerifyError::CertParseFailed(format!(
                    "duplicate ARK certificate (second has CN={cn})"
                )));
            }
            ark = Some(der.clone());
        } else if cn == "SEV-VCEK" || cn == "SEV-VLEK" {
            if vek.is_some() {
                return Err(SnpVerifyError::CertParseFailed(format!(
                    "duplicate VEK certificate (second has CN={cn})"
                )));
            }
            vek = Some(der.clone());
        } else if cn.starts_with("SEV-") {
            if ask.is_some() {
                return Err(SnpVerifyError::CertParseFailed(format!(
                    "duplicate ASK certificate (second has CN={cn})"
                )));
            }
            ask = Some(der.clone());
        } else {
            return Err(SnpVerifyError::CertParseFailed(format!(
                "unrecognized Subject CN: '{cn}' (expected ARK-<product>, SEV-<product>, SEV-VCEK, or SEV-VLEK)"
            )));
        }
    }

    let ark = ark.ok_or_else(|| SnpVerifyError::CertTypeMissing("ARK".into()))?;
    let ask = ask.ok_or_else(|| SnpVerifyError::CertTypeMissing("ASK".into()))?;
    let vek = vek.ok_or_else(|| SnpVerifyError::CertTypeMissing("VCEK/VLEK".into()))?;

    Ok(ClassifiedCerts { ark, ask, vek })
}

/// Enforce CRL-based revocation on a VCEK certificate (F5).
///
/// Parameters:
/// - `vcek_der` — the VCEK to check for revocation (classified from the chain)
/// - `crl_der` — a CRL, typically from `kdsintf.amd.com/vcek/v1/{product}/crl`
/// - `ark_der` — the ARK that signs the CRL (per real Milan CRL inspection:
///   issuer CN is `ARK-Milan` / `ARK-Genoa` / `ARK-Turin`)
///
/// Returns [`SnpVerifyError::VekRevoked`] on serial match, other variants on
/// CRL signature / time-window / parse failures. Mirrors the TDX CRL path in
/// `tdx.rs::verify_pck_chain_with_crl`.
///
/// # Spec references
///
/// - VCEK 1.00 §2.2 Table 6 — CRL endpoint
/// - VCEK 1.00 §4.3 Table 15 — "Returns the DER-formatted certificate
///   revocation list for the named product, including the certificate chain"
/// - VCEK 1.00 §2.3 Table 7 — ARK key usage includes "Off-line CRL Signing,
///   CRL Signing"
/// - AMD operational note (virtee/snpguest #130): VCEK/ARK revocation is not
///   expected in practice; only ASK has been revoked historically. Treat this
///   as defense-in-depth infrastructure, not a high-probability threat.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
pub fn enforce_crl_revocation(
    vcek_der: &[u8],
    crl_der: &[u8],
    ark_der: &[u8],
) -> Result<(), SnpVerifyError> {
    use openssl::asn1::Asn1Time;
    use openssl::x509::{CrlStatus, X509Crl, X509};
    use std::cmp::Ordering;

    let vcek = X509::from_der(vcek_der)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("VCEK DER parse: {e}")))?;
    let crl = X509Crl::from_der(crl_der)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("CRL DER parse: {e}")))?;
    let ark = X509::from_der(ark_der)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("ARK DER parse: {e}")))?;

    // Verify the CRL's issuer subject matches the ARK's subject. Prevents
    // feeding us a legitimately-signed CRL from a different product.
    let crl_issuer = crl.issuer_name();
    let ark_subject = ark.subject_name();
    let name_cmp = crl_issuer.try_cmp(ark_subject).map_err(|e| {
        SnpVerifyError::CrlSigInvalid(format!("failed to compare CRL issuer vs ARK subject: {e}"))
    })?;
    if name_cmp != Ordering::Equal {
        return Err(SnpVerifyError::CrlSigInvalid(
            "CRL issuer subject does not match ARK subject".into(),
        ));
    }

    // Verify the CRL signature against the ARK's public key.
    let ark_pubkey = ark
        .public_key()
        .map_err(|e| SnpVerifyError::CrlSigInvalid(format!("extract ARK pubkey: {e}")))?;
    let sig_ok = crl
        .verify(&ark_pubkey)
        .map_err(|e| SnpVerifyError::CrlSigInvalid(format!("CRL verify(): {e}")))?;
    if !sig_ok {
        return Err(SnpVerifyError::CrlSigInvalid(
            "CRL signature did not verify against ARK public key".into(),
        ));
    }

    // Time window: lastUpdate must not be in the future; nextUpdate (if present)
    // must not be in the past. AMD always emits nextUpdate for KDS CRLs — a
    // missing one indicates a malformed CRL we shouldn't trust.
    let now = Asn1Time::days_from_now(0)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("current time: {e}")))?;

    let last_cmp = crl
        .last_update()
        .compare(&now)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("compare lastUpdate: {e}")))?;
    if last_cmp == Ordering::Greater {
        return Err(SnpVerifyError::CrlSigInvalid(
            "CRL lastUpdate is in the future (clock skew or tampered CRL)".into(),
        ));
    }

    let next = crl
        .next_update()
        .ok_or_else(|| SnpVerifyError::CrlExpired("CRL missing nextUpdate".into()))?;
    let next_cmp = next
        .compare(&now)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("compare nextUpdate: {e}")))?;
    if next_cmp == Ordering::Less {
        return Err(SnpVerifyError::CrlExpired(
            "CRL nextUpdate is in the past — refetch a fresh CRL".into(),
        ));
    }

    // Revocation lookup by cert → serial match.
    match crl.get_by_cert(&vcek) {
        CrlStatus::Revoked(_) => Err(SnpVerifyError::VekRevoked(
            "VCEK serial is in CRL revoked list".into(),
        )),
        _ => Ok(()),
    }
}

/// Structural invariant checks on an `AttestationReport`.
///
/// These checks are independent of signature verification or policy — they
/// reject reports that are malformed, use an unsupported signature algorithm,
/// or were produced with `MaskChipKey=1` (unsigned by design).
///
/// Call this immediately after `AttestationReport::from_bytes(...)` in both the
/// direct SEV path and the Azure vTPM path, before chain/signature verification.
/// Early rejection here:
///
/// 1. Produces a clear, specific error code instead of the opaque
///    "VEK does not sign the attestation report" from the `sev` crate.
/// 2. Avoids wasting cycles on cert-chain parsing for reports that will fail
///    structural invariants anyway.
///
/// `min_report_version` controls the F9 minimum-version check; pass
/// `policy.min_report_version` from a [`crate::attestation::sev_policy::SnpVerifyPolicy`].
///
/// Closes audit findings F9, F10, F11.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
pub fn check_report_invariants(
    report: &sev::firmware::guest::AttestationReport,
    min_report_version: u32,
) -> Result<(), SnpVerifyError> {
    // F9: minimum report version.
    // Older versions (0/1) predate the current attestation report structure
    // and leave newer fields (LAUNCH_TCB, LAUNCH_MIT_VECTOR, etc.) as zero —
    // silent trust degradation risk if we start relying on them.
    if report.version < min_report_version {
        return Err(SnpVerifyError::ReportVersionTooOld {
            got: report.version,
            min_required: min_report_version,
        });
    }

    // F10: signature algorithm must be the one defined in ABI Chapter 10.
    // The `sev` crate unconditionally interprets `report.signature` as ECDSA
    // P-384 regardless of `sig_algo` — we assert the field explicitly so a
    // future algorithm introduction doesn't silently get misparsed.
    if report.sig_algo != SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(SnpVerifyError::UnsupportedSignatureAlgo(report.sig_algo));
    }

    // F11: reject MaskChipKey=1 with a clear operator-facing error.
    // The signature field is all-zero in this case; downstream signature
    // verification would fail with the opaque sev-crate error "VEK does not
    // sign the attestation report" — not useful for operators trying to
    // diagnose why a given SEV-SNP deployment isn't producing signed reports.
    if report.key_info.mask_chip_key() {
        return Err(SnpVerifyError::MaskChipKeyEnabled);
    }

    Ok(())
}

/// SEV-SNP verification error codes.
///
/// Each variant carries a stable string code accessible via [`SnpVerifyError::code`]
/// and a trust-layer classification via [`SnpVerifyError::layer`]. Use the string
/// code for programmatic matching in integration tests; use the enum itself for
/// in-crate error handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnpVerifyError {
    // -------------------------------------------------------------------
    // T1_PARSE: evidence shape / wire format
    // -------------------------------------------------------------------
    /// SNP-PARSE-001: Wire document marker mismatch (not an SEV-SNP attestation).
    WireMarkerMismatch(String),

    /// SNP-PARSE-002: Wire document truncated or length prefix invalid.
    WireTruncated(String),

    /// SNP-PARSE-003: Report bytes failed structural parse.
    ///
    /// Reference: ABI 1.58 §7.3 Table 23 (ATTESTATION_REPORT Structure).
    ReportParseFailed(String),

    /// SNP-PARSE-004: Report `VERSION` field below configured minimum.
    ///
    /// Older report versions lack `LAUNCH_TCB`, `LAUNCH_MIT_VECTOR`, and other
    /// fields; relying on them silently returns zero. A minimum version must be
    /// enforced by policy.
    ///
    /// Reference: ABI 1.58 §7.3 Table 23 offset 00h ("Set to 5h for this
    /// specification"); virtee/sev crate enum V2/V3(PreTurin)/V5.
    ReportVersionTooOld { got: u32, min_required: u32 },

    /// SNP-PARSE-005: Report `SIGNATURE_ALGO` field is not `1h` (ECDSA P-384 +
    /// SHA-384), the only currently defined algorithm.
    ///
    /// Reference: ABI 1.58 Chapter 10 Table 139 ("ECDSA P-384 with SHA-384 — 1h.
    /// All other encodings are reserved.").
    UnsupportedSignatureAlgo(u32),

    /// SNP-PARSE-006: HCL report wrapper (Azure vTPM path) did not contain an
    /// SNP report, or length was insufficient to hold one.
    HclReportInvalid(String),

    /// SNP-PARSE-007: Azure VarData JSON could not be parsed, or `user-data`
    /// field was missing / too short.
    VarDataInvalid(String),

    // -------------------------------------------------------------------
    // T2_CRYPTO: signature math + binding
    // -------------------------------------------------------------------
    /// SNP-CRYPTO-001: ECDSA P-384 signature over report bytes [0..0x2A0]
    /// failed verification against the VCEK/VLEK public key.
    ///
    /// Reference: ABI 1.58 §7.3 Table 23 SIGNATURE row ("Signature of bytes 0h
    /// to 29Fh inclusive of this report").
    ReportSigInvalid(String),

    /// SNP-CRYPTO-002: Public key bound into `REPORT_DATA[0..32]` does not
    /// match the expected handshake key.
    ReportdataBindingMismatch { expected: String, actual: String },

    /// SNP-CRYPTO-003: Azure HCL `REPORT_DATA[0..32]` does not equal
    /// `SHA256(VarData)` — VarData tampering detected.
    AzureVarDataBindingMismatch { expected: String, actual: String },

    /// SNP-CRYPTO-004: `MaskChipKey = 1` — firmware intentionally wrote zeroes
    /// into the SIGNATURE field; the attestation report is unsignable by design.
    ///
    /// Reference: ABI 1.58 §3.6 ("When MaskChipKey is 1, the attestation report
    /// will not be signed and will contain zeroes instead of a signature.").
    MaskChipKeyEnabled,

    // -------------------------------------------------------------------
    // T3_CHAIN: certificate chain + revocation
    // -------------------------------------------------------------------
    /// SNP-CHAIN-001: Certificate chain missing or empty — cannot verify the
    /// report signature without ARK → ASK → VCEK/VLEK.
    CertChainMissing,

    /// SNP-CHAIN-002: Fewer than 3 certificates in the chain.
    CertChainIncomplete { got: usize, expected: usize },

    /// SNP-CHAIN-003: A certificate failed DER/PEM parsing.
    CertParseFailed(String),

    /// SNP-CHAIN-004: Certificate signature chain does not validate
    /// (ARK self-sign → ASK → VCEK/VLEK).
    ChainSigInvalid(String),

    /// SNP-CHAIN-005: ARK public key does not match any known AMD root
    /// (Milan, Genoa, Turin). Possible forged chain.
    ArkNotKnown,

    /// SNP-CHAIN-006: ARK certificate not yet valid (NotBefore in future).
    ArkNotYetValid(String),

    /// SNP-CHAIN-006b: ARK certificate expired (NotAfter in past).
    ///
    /// Reference: VCEK 1.00 §2.3 Table 7 — ARK valid 25 years.
    ArkExpired(String),

    /// SNP-CHAIN-007: ASK certificate not yet valid.
    AskNotYetValid(String),

    /// SNP-CHAIN-007b: ASK certificate expired.
    ///
    /// Reference: VCEK 1.00 §2.3 Table 8 — ASK valid 25 years.
    AskExpired(String),

    /// SNP-CHAIN-008: VCEK/VLEK certificate not yet valid.
    VekNotYetValid(String),

    /// SNP-CHAIN-008b: VCEK/VLEK certificate expired.
    ///
    /// Reference: VCEK 1.00 §3 Table 9 — VCEK valid 7 years.
    /// Direct precedent: MSRC Case 107128 / VULN-173713 (azure-cvm-tooling,
    /// Feb 2026).
    VekExpired(String),

    /// SNP-CHAIN-009: Required certificate type missing from CertTableEntry set
    /// (ARK, ASK, VCEK/VLEK identifiable by GUID).
    CertTypeMissing(String),

    /// SNP-CHAIN-010: VCEK listed in the CRL — key has been revoked.
    ///
    /// Reference: VCEK 1.00 §2.2 Table 6, §4.3 Table 15 (CRL endpoint).
    VekRevoked(String),

    /// SNP-CHAIN-011: CRL expired (nextUpdate in past) — cannot rely on it
    /// for current revocation status.
    CrlExpired(String),

    /// SNP-CHAIN-012: CRL signature did not verify against ASK/ARK.
    CrlSigInvalid(String),

    // -------------------------------------------------------------------
    // T4_POLICY: guest / platform posture
    // -------------------------------------------------------------------
    /// SNP-POL-001: Guest policy allows debugging (`POLICY.DEBUG = 1`), which
    /// authorizes the hypervisor to invoke firmware-mediated `SNP_DBG_DECRYPT` /
    /// `SNP_DBG_ENCRYPT` commands that return/write plaintext to/from guest
    /// memory. No confidentiality under this configuration.
    ///
    /// Reference: ABI 1.58 §4.3 Table 9 bit 19, §8.27-§8.28 debug commands;
    /// IETF draft-deeglaze-amd-sev-snp-corim-profile `sevsnpvm-policy-debug-allowed`.
    DebugGuestRejected,

    /// SNP-POL-002: Guest policy allows association with a migration agent
    /// (`POLICY.MIGRATE_MA = 1`). The MA can export guest state; verifiers that
    /// do not pin the MA identity should reject.
    ///
    /// Reference: ABI 1.58 §4.3 Table 9 bit 18.
    MigratableGuestRejected,

    /// SNP-POL-003: `POLICY.SMT` setting does not match required configuration.
    ///
    /// Reference: ABI 1.58 §4.3 Table 9 bit 16.
    SmtPolicyMismatch { expected: bool, actual: bool },

    /// SNP-POL-004: `POLICY.SINGLE_SOCKET` setting does not match required
    /// configuration.
    ///
    /// Reference: ABI 1.58 §4.3 Table 9 bit 20.
    SingleSocketPolicyMismatch { expected: bool, actual: bool },

    /// SNP-POL-005: `VMPL` field does not match required privilege level, or
    /// is the host-requested sentinel value `0xFFFFFFFF`.
    ///
    /// Reference: ABI 1.58 §7.3 Table 23 offset 30h ("A Host requested
    /// attestation report will have a value of 0xffffffff.").
    VmplMismatch { expected: u32, actual: u32 },

    /// SNP-POL-006: Report was host-requested via `SNP_HV_REPORT_REQ` (VMPL =
    /// 0xFFFFFFFF). Guest-facing verifiers must always reject this.
    HostRequestedReportRejected,

    /// SNP-POL-007: Measurement (`MEASUREMENT` field, 48 bytes) does not match
    /// expected value.
    ///
    /// Reference: ABI 1.58 §7.3 Table 23 offset 90h.
    MeasurementMismatch { expected: String, actual: String },

    /// SNP-POL-008: Nonce (`REPORT_DATA[32..64]`) does not match expected.
    NonceMismatch { expected: String, actual: String },

    /// SNP-POL-009: VCEK `blSPL` (OID 1.3.6.1.4.1.3704.1.3.1) does not match
    /// `report.reported_tcb.bootloader`. TCB-rollback attack indicator.
    ///
    /// Reference: VCEK 1.00 §3.1 Table 10; VirTEE 1.2 §3.2.1 step 5;
    /// AMD SB-3019 / CVE-2024-56161 (BadRAM remediation requires this check).
    TcbBootloaderMismatch { vcek: u8, report: u8 },

    /// SNP-POL-010: VCEK `teeSPL` does not match `report.reported_tcb.tee`.
    TcbTeeMismatch { vcek: u8, report: u8 },

    /// SNP-POL-011: VCEK `snpSPL` does not match `report.reported_tcb.snp`.
    TcbSnpMismatch { vcek: u8, report: u8 },

    /// SNP-POL-012: VCEK `ucodeSPL` does not match
    /// `report.reported_tcb.microcode`.
    TcbMicrocodeMismatch { vcek: u8, report: u8 },

    /// SNP-POL-013: VCEK `hwID` extension (1.3.6.1.4.1.3704.1.4) does not match
    /// `report.chip_id`. Suggests a chain/report swap attack.
    ChipIdMismatch,

    /// SNP-POL-014: VCEK `productName` (1.3.6.1.4.1.3704.1.2) does not match
    /// the product family derived from the ARK allowlist or caller pin.
    ProductMismatch { expected: String, actual: String },
}

impl fmt::Display for SnpVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // T1_PARSE
            Self::WireMarkerMismatch(msg) => write!(f, "SNP_WIRE_MARKER_MISMATCH: {msg}"),
            Self::WireTruncated(msg) => write!(f, "SNP_WIRE_TRUNCATED: {msg}"),
            Self::ReportParseFailed(msg) => write!(f, "SNP_REPORT_PARSE_FAILED: {msg}"),
            Self::ReportVersionTooOld { got, min_required } => write!(
                f,
                "SNP_REPORT_VERSION_TOO_OLD: got {got}, need >= {min_required}"
            ),
            Self::UnsupportedSignatureAlgo(algo) => write!(
                f,
                "SNP_UNSUPPORTED_SIGNATURE_ALGO: got {algo:#x}, only 0x1 (ECDSA P-384/SHA-384) supported"
            ),
            Self::HclReportInvalid(msg) => write!(f, "SNP_HCL_REPORT_INVALID: {msg}"),
            Self::VarDataInvalid(msg) => write!(f, "SNP_VARDATA_INVALID: {msg}"),

            // T2_CRYPTO
            Self::ReportSigInvalid(msg) => write!(f, "SNP_REPORT_SIG_INVALID: {msg}"),
            Self::ReportdataBindingMismatch { expected, actual } => write!(
                f,
                "SNP_REPORTDATA_BINDING_MISMATCH: expected {expected}, got {actual}"
            ),
            Self::AzureVarDataBindingMismatch { expected, actual } => write!(
                f,
                "SNP_AZURE_VARDATA_BINDING_MISMATCH: expected SHA256(VarData)={expected}, got report_data[0..32]={actual}"
            ),
            Self::MaskChipKeyEnabled => write!(
                f,
                "SNP_MASK_CHIP_KEY_ENABLED: hypervisor disabled VCEK signing via SNP_CONFIG (MaskChipKey=1); report signature is all zeros by design"
            ),

            // T3_CHAIN
            Self::CertChainMissing => write!(
                f,
                "SNP_CERT_CHAIN_MISSING: attestation document carries no certificate chain"
            ),
            Self::CertChainIncomplete { got, expected } => write!(
                f,
                "SNP_CERT_CHAIN_INCOMPLETE: got {got} certs, expected at least {expected} (ARK, ASK, VCEK/VLEK)"
            ),
            Self::CertParseFailed(msg) => write!(f, "SNP_CERT_PARSE_FAILED: {msg}"),
            Self::ChainSigInvalid(msg) => write!(f, "SNP_CHAIN_SIG_INVALID: {msg}"),
            Self::ArkNotKnown => write!(
                f,
                "SNP_ARK_NOT_KNOWN: ARK public key does not match any pinned AMD root (Milan, Genoa, Turin)"
            ),
            Self::ArkNotYetValid(msg) => write!(f, "SNP_ARK_NOT_YET_VALID: {msg}"),
            Self::ArkExpired(msg) => write!(f, "SNP_ARK_EXPIRED: {msg}"),
            Self::AskNotYetValid(msg) => write!(f, "SNP_ASK_NOT_YET_VALID: {msg}"),
            Self::AskExpired(msg) => write!(f, "SNP_ASK_EXPIRED: {msg}"),
            Self::VekNotYetValid(msg) => write!(f, "SNP_VEK_NOT_YET_VALID: {msg}"),
            Self::VekExpired(msg) => write!(f, "SNP_VEK_EXPIRED: {msg}"),
            Self::CertTypeMissing(what) => {
                write!(f, "SNP_CERT_TYPE_MISSING: {what}")
            }
            Self::VekRevoked(msg) => write!(f, "SNP_VEK_REVOKED: {msg}"),
            Self::CrlExpired(msg) => write!(f, "SNP_CRL_EXPIRED: {msg}"),
            Self::CrlSigInvalid(msg) => write!(f, "SNP_CRL_SIG_INVALID: {msg}"),

            // T4_POLICY
            Self::DebugGuestRejected => write!(
                f,
                "SNP_DEBUG_GUEST_REJECTED: POLICY.DEBUG=1 authorizes firmware SNP_DBG_DECRYPT/ENCRYPT; no confidentiality"
            ),
            Self::MigratableGuestRejected => write!(
                f,
                "SNP_MIGRATABLE_GUEST_REJECTED: POLICY.MIGRATE_MA=1 permits migration agent to export guest state"
            ),
            Self::SmtPolicyMismatch { expected, actual } => write!(
                f,
                "SNP_SMT_POLICY_MISMATCH: POLICY.SMT expected={expected}, actual={actual}"
            ),
            Self::SingleSocketPolicyMismatch { expected, actual } => write!(
                f,
                "SNP_SINGLE_SOCKET_POLICY_MISMATCH: POLICY.SINGLE_SOCKET expected={expected}, actual={actual}"
            ),
            Self::VmplMismatch { expected, actual } => write!(
                f,
                "SNP_VMPL_MISMATCH: expected VMPL={expected}, got {actual:#x}"
            ),
            Self::HostRequestedReportRejected => write!(
                f,
                "SNP_HOST_REQUESTED_REPORT_REJECTED: VMPL=0xFFFFFFFF (produced by SNP_HV_REPORT_REQ, not MSG_REPORT_REQ)"
            ),
            Self::MeasurementMismatch { expected, actual } => write!(
                f,
                "SNP_MEASUREMENT_MISMATCH: expected {expected}, got {actual}"
            ),
            Self::NonceMismatch { expected, actual } => write!(
                f,
                "SNP_NONCE_MISMATCH: expected {expected}, got {actual}"
            ),
            Self::TcbBootloaderMismatch { vcek, report } => write!(
                f,
                "SNP_TCB_BOOTLOADER_MISMATCH: VCEK blSPL={vcek}, report reported_tcb.bootloader={report}"
            ),
            Self::TcbTeeMismatch { vcek, report } => write!(
                f,
                "SNP_TCB_TEE_MISMATCH: VCEK teeSPL={vcek}, report reported_tcb.tee={report}"
            ),
            Self::TcbSnpMismatch { vcek, report } => write!(
                f,
                "SNP_TCB_SNP_MISMATCH: VCEK snpSPL={vcek}, report reported_tcb.snp={report}"
            ),
            Self::TcbMicrocodeMismatch { vcek, report } => write!(
                f,
                "SNP_TCB_MICROCODE_MISMATCH: VCEK ucodeSPL={vcek}, report reported_tcb.microcode={report}"
            ),
            Self::ChipIdMismatch => write!(
                f,
                "SNP_CHIP_ID_MISMATCH: VCEK hwID extension does not match report.chip_id"
            ),
            Self::ProductMismatch { expected, actual } => write!(
                f,
                "SNP_PRODUCT_MISMATCH: expected product {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for SnpVerifyError {}

impl From<SnpVerifyError> for AttestError {
    fn from(e: SnpVerifyError) -> Self {
        AttestError::VerificationFailed(e.to_string())
    }
}

impl SnpVerifyError {
    /// Stable string code for programmatic matching (tests, telemetry).
    pub fn code(&self) -> &'static str {
        match self {
            Self::WireMarkerMismatch(_) => "SNP_WIRE_MARKER_MISMATCH",
            Self::WireTruncated(_) => "SNP_WIRE_TRUNCATED",
            Self::ReportParseFailed(_) => "SNP_REPORT_PARSE_FAILED",
            Self::ReportVersionTooOld { .. } => "SNP_REPORT_VERSION_TOO_OLD",
            Self::UnsupportedSignatureAlgo(_) => "SNP_UNSUPPORTED_SIGNATURE_ALGO",
            Self::HclReportInvalid(_) => "SNP_HCL_REPORT_INVALID",
            Self::VarDataInvalid(_) => "SNP_VARDATA_INVALID",

            Self::ReportSigInvalid(_) => "SNP_REPORT_SIG_INVALID",
            Self::ReportdataBindingMismatch { .. } => "SNP_REPORTDATA_BINDING_MISMATCH",
            Self::AzureVarDataBindingMismatch { .. } => "SNP_AZURE_VARDATA_BINDING_MISMATCH",
            Self::MaskChipKeyEnabled => "SNP_MASK_CHIP_KEY_ENABLED",

            Self::CertChainMissing => "SNP_CERT_CHAIN_MISSING",
            Self::CertChainIncomplete { .. } => "SNP_CERT_CHAIN_INCOMPLETE",
            Self::CertParseFailed(_) => "SNP_CERT_PARSE_FAILED",
            Self::ChainSigInvalid(_) => "SNP_CHAIN_SIG_INVALID",
            Self::ArkNotKnown => "SNP_ARK_NOT_KNOWN",
            Self::ArkNotYetValid(_) => "SNP_ARK_NOT_YET_VALID",
            Self::ArkExpired(_) => "SNP_ARK_EXPIRED",
            Self::AskNotYetValid(_) => "SNP_ASK_NOT_YET_VALID",
            Self::AskExpired(_) => "SNP_ASK_EXPIRED",
            Self::VekNotYetValid(_) => "SNP_VEK_NOT_YET_VALID",
            Self::VekExpired(_) => "SNP_VEK_EXPIRED",
            Self::CertTypeMissing(_) => "SNP_CERT_TYPE_MISSING",
            Self::VekRevoked(_) => "SNP_VEK_REVOKED",
            Self::CrlExpired(_) => "SNP_CRL_EXPIRED",
            Self::CrlSigInvalid(_) => "SNP_CRL_SIG_INVALID",

            Self::DebugGuestRejected => "SNP_DEBUG_GUEST_REJECTED",
            Self::MigratableGuestRejected => "SNP_MIGRATABLE_GUEST_REJECTED",
            Self::SmtPolicyMismatch { .. } => "SNP_SMT_POLICY_MISMATCH",
            Self::SingleSocketPolicyMismatch { .. } => "SNP_SINGLE_SOCKET_POLICY_MISMATCH",
            Self::VmplMismatch { .. } => "SNP_VMPL_MISMATCH",
            Self::HostRequestedReportRejected => "SNP_HOST_REQUESTED_REPORT_REJECTED",
            Self::MeasurementMismatch { .. } => "SNP_MEASUREMENT_MISMATCH",
            Self::NonceMismatch { .. } => "SNP_NONCE_MISMATCH",
            Self::TcbBootloaderMismatch { .. } => "SNP_TCB_BOOTLOADER_MISMATCH",
            Self::TcbTeeMismatch { .. } => "SNP_TCB_TEE_MISMATCH",
            Self::TcbSnpMismatch { .. } => "SNP_TCB_SNP_MISMATCH",
            Self::TcbMicrocodeMismatch { .. } => "SNP_TCB_MICROCODE_MISMATCH",
            Self::ChipIdMismatch => "SNP_CHIP_ID_MISMATCH",
            Self::ProductMismatch { .. } => "SNP_PRODUCT_MISMATCH",
        }
    }

    /// Trust-layer classification (T1_PARSE / T2_CRYPTO / T3_CHAIN / T4_POLICY).
    pub fn layer(&self) -> &'static str {
        match self {
            Self::WireMarkerMismatch(_)
            | Self::WireTruncated(_)
            | Self::ReportParseFailed(_)
            | Self::ReportVersionTooOld { .. }
            | Self::UnsupportedSignatureAlgo(_)
            | Self::HclReportInvalid(_)
            | Self::VarDataInvalid(_) => "T1_PARSE",

            Self::ReportSigInvalid(_)
            | Self::ReportdataBindingMismatch { .. }
            | Self::AzureVarDataBindingMismatch { .. }
            | Self::MaskChipKeyEnabled => "T2_CRYPTO",

            Self::CertChainMissing
            | Self::CertChainIncomplete { .. }
            | Self::CertParseFailed(_)
            | Self::ChainSigInvalid(_)
            | Self::ArkNotKnown
            | Self::ArkNotYetValid(_)
            | Self::ArkExpired(_)
            | Self::AskNotYetValid(_)
            | Self::AskExpired(_)
            | Self::VekNotYetValid(_)
            | Self::VekExpired(_)
            | Self::CertTypeMissing(_)
            | Self::VekRevoked(_)
            | Self::CrlExpired(_)
            | Self::CrlSigInvalid(_) => "T3_CHAIN",

            Self::DebugGuestRejected
            | Self::MigratableGuestRejected
            | Self::SmtPolicyMismatch { .. }
            | Self::SingleSocketPolicyMismatch { .. }
            | Self::VmplMismatch { .. }
            | Self::HostRequestedReportRejected
            | Self::MeasurementMismatch { .. }
            | Self::NonceMismatch { .. }
            | Self::TcbBootloaderMismatch { .. }
            | Self::TcbTeeMismatch { .. }
            | Self::TcbSnpMismatch { .. }
            | Self::TcbMicrocodeMismatch { .. }
            | Self::ChipIdMismatch
            | Self::ProductMismatch { .. } => "T4_POLICY",
        }
    }

    /// Audit-facing finding reference (F-ID from the SEV-SNP audit, if any).
    ///
    /// Returns `None` for errors that did not correspond to an audit finding
    /// (e.g., pre-existing parse errors). Useful for tracing which finding's
    /// fix surfaces a given error path.
    pub fn finding_id(&self) -> Option<&'static str> {
        match self {
            Self::ReportVersionTooOld { .. } => Some("F9"),
            Self::UnsupportedSignatureAlgo(_) => Some("F10"),
            Self::MaskChipKeyEnabled => Some("F11"),
            Self::ArkExpired(_) | Self::AskExpired(_) | Self::VekExpired(_) => Some("F4"),
            Self::ArkNotYetValid(_) | Self::AskNotYetValid(_) | Self::VekNotYetValid(_) => {
                Some("F4")
            }
            Self::CertTypeMissing(_) => Some("F6"),
            Self::VekRevoked(_) | Self::CrlExpired(_) | Self::CrlSigInvalid(_) => Some("F5"),
            Self::DebugGuestRejected
            | Self::MigratableGuestRejected
            | Self::SmtPolicyMismatch { .. }
            | Self::SingleSocketPolicyMismatch { .. } => Some("F3"),
            Self::VmplMismatch { .. } | Self::HostRequestedReportRejected => Some("F2"),
            Self::TcbBootloaderMismatch { .. }
            | Self::TcbTeeMismatch { .. }
            | Self::TcbSnpMismatch { .. }
            | Self::TcbMicrocodeMismatch { .. }
            | Self::ChipIdMismatch => Some("F1"),
            Self::ProductMismatch { .. } => Some("F8"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_distinct_code() {
        let samples = [
            SnpVerifyError::WireMarkerMismatch("m".into()),
            SnpVerifyError::WireTruncated("t".into()),
            SnpVerifyError::ReportParseFailed("p".into()),
            SnpVerifyError::ReportVersionTooOld {
                got: 1,
                min_required: 2,
            },
            SnpVerifyError::UnsupportedSignatureAlgo(2),
            SnpVerifyError::HclReportInvalid("h".into()),
            SnpVerifyError::VarDataInvalid("v".into()),
            SnpVerifyError::ReportSigInvalid("s".into()),
            SnpVerifyError::ReportdataBindingMismatch {
                expected: "e".into(),
                actual: "a".into(),
            },
            SnpVerifyError::AzureVarDataBindingMismatch {
                expected: "e".into(),
                actual: "a".into(),
            },
            SnpVerifyError::MaskChipKeyEnabled,
            SnpVerifyError::CertChainMissing,
            SnpVerifyError::CertChainIncomplete {
                got: 1,
                expected: 3,
            },
            SnpVerifyError::CertParseFailed("p".into()),
            SnpVerifyError::ChainSigInvalid("s".into()),
            SnpVerifyError::ArkNotKnown,
            SnpVerifyError::ArkNotYetValid("n".into()),
            SnpVerifyError::ArkExpired("e".into()),
            SnpVerifyError::AskNotYetValid("n".into()),
            SnpVerifyError::AskExpired("e".into()),
            SnpVerifyError::VekNotYetValid("n".into()),
            SnpVerifyError::VekExpired("e".into()),
            SnpVerifyError::CertTypeMissing("VCEK".into()),
            SnpVerifyError::VekRevoked("r".into()),
            SnpVerifyError::CrlExpired("x".into()),
            SnpVerifyError::CrlSigInvalid("s".into()),
            SnpVerifyError::DebugGuestRejected,
            SnpVerifyError::MigratableGuestRejected,
            SnpVerifyError::SmtPolicyMismatch {
                expected: false,
                actual: true,
            },
            SnpVerifyError::SingleSocketPolicyMismatch {
                expected: true,
                actual: false,
            },
            SnpVerifyError::VmplMismatch {
                expected: 0,
                actual: 1,
            },
            SnpVerifyError::HostRequestedReportRejected,
            SnpVerifyError::MeasurementMismatch {
                expected: "e".into(),
                actual: "a".into(),
            },
            SnpVerifyError::NonceMismatch {
                expected: "e".into(),
                actual: "a".into(),
            },
            SnpVerifyError::TcbBootloaderMismatch { vcek: 0, report: 1 },
            SnpVerifyError::TcbTeeMismatch { vcek: 0, report: 1 },
            SnpVerifyError::TcbSnpMismatch { vcek: 0, report: 1 },
            SnpVerifyError::TcbMicrocodeMismatch { vcek: 0, report: 1 },
            SnpVerifyError::ChipIdMismatch,
            SnpVerifyError::ProductMismatch {
                expected: "Milan".into(),
                actual: "Genoa".into(),
            },
        ];

        let codes: Vec<_> = samples.iter().map(|e| e.code()).collect();
        let unique: std::collections::HashSet<_> = codes.iter().copied().collect();
        assert_eq!(
            codes.len(),
            unique.len(),
            "error codes must be unique; duplicate codes detected"
        );

        // Every code must start with "SNP_".
        for code in &codes {
            assert!(
                code.starts_with("SNP_"),
                "code {code} does not start with SNP_"
            );
        }
    }

    #[test]
    fn every_variant_has_layer() {
        let samples = [
            (SnpVerifyError::WireMarkerMismatch("".into()), "T1_PARSE"),
            (SnpVerifyError::ReportSigInvalid("".into()), "T2_CRYPTO"),
            (SnpVerifyError::ArkNotKnown, "T3_CHAIN"),
            (SnpVerifyError::DebugGuestRejected, "T4_POLICY"),
            (
                SnpVerifyError::TcbBootloaderMismatch { vcek: 0, report: 1 },
                "T4_POLICY",
            ),
        ];

        for (err, expected_layer) in &samples {
            assert_eq!(err.layer(), *expected_layer, "wrong layer for {err:?}");
        }
    }

    #[test]
    fn display_includes_code_prefix() {
        let err = SnpVerifyError::DebugGuestRejected;
        let s = format!("{err}");
        assert!(
            s.starts_with("SNP_DEBUG_GUEST_REJECTED"),
            "display should start with code: {s}"
        );
    }

    #[test]
    fn converts_to_attest_error() {
        let err = SnpVerifyError::MaskChipKeyEnabled;
        let attest: AttestError = err.into();
        match attest {
            AttestError::VerificationFailed(s) => {
                assert!(s.contains("SNP_MASK_CHIP_KEY_ENABLED"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    // -- Phase 2 helper: synthetic cert builder --
    //
    // Used by F4 validity and F7 CN-classifier tests. Builds a self-signed
    // X.509 v3 cert with the requested Subject CN and validity window. Not a
    // real AMD cert — signature won't chain-verify — but the cert IS well-formed
    // DER with valid ASN.1 times and a proper Subject, which is all we need to
    // exercise validity and CN classification.
    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    fn build_test_cert(cn: &str, not_before_days: i32, not_after_days: i32) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).expect("rsa keygen");
        let pkey = PKey::from_rsa(rsa).expect("pkey");

        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", cn).expect("CN");
        let name = name.build();

        let mut builder = X509Builder::new().expect("x509 builder");
        builder.set_version(2).expect("v3");
        let serial = BigNum::from_u32(1).expect("serial");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("asn1 int"))
            .expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer"); // self-signed

        // Signed-delta validity. days_from_now takes u32; support negatives
        // via "subtract from now" for notBefore and "add from now" for notAfter.
        let not_before = if not_before_days >= 0 {
            Asn1Time::days_from_now(not_before_days as u32).expect("nb")
        } else {
            // "days ago" — represent via from_unix(now - days*86400)
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_secs() as i64;
            let target = now_secs + (not_before_days as i64) * 86400;
            Asn1Time::from_unix(target).expect("nb_unix")
        };
        let not_after = if not_after_days >= 0 {
            Asn1Time::days_from_now(not_after_days as u32).expect("na")
        } else {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_secs() as i64;
            let target = now_secs + (not_after_days as i64) * 86400;
            Asn1Time::from_unix(target).expect("na_unix")
        };
        builder.set_not_before(&not_before).expect("nb set");
        builder.set_not_after(&not_after).expect("na set");

        builder.set_pubkey(&pkey).expect("pubkey");
        builder.sign(&pkey, MessageDigest::sha256()).expect("sign");

        builder.build().to_der().expect("to_der")
    }

    // -- F4 tests: check_cert_chain_validity --

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_accepts_all_fresh_certs() {
        // All three certs valid for the next year.
        let ark = build_test_cert("ARK-Milan", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let vek = build_test_cert("SEV-VCEK", -1, 365);

        assert!(check_cert_chain_validity(&ark, &ask, &vek).is_ok());
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_rejects_expired_ark() {
        // ARK expired 10 days ago.
        let ark = build_test_cert("ARK-Milan", -365, -10);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let vek = build_test_cert("SEV-VCEK", -1, 365);

        match check_cert_chain_validity(&ark, &ask, &vek) {
            Err(SnpVerifyError::ArkExpired(msg)) => {
                assert!(msg.contains("ARK"), "msg: {msg}");
                assert!(msg.contains("expired"), "msg: {msg}");
            }
            other => panic!("expected ArkExpired, got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_rejects_expired_ask() {
        let ark = build_test_cert("ARK-Milan", -1, 365);
        let ask = build_test_cert("SEV-Milan", -365, -10);
        let vek = build_test_cert("SEV-VCEK", -1, 365);

        assert!(matches!(
            check_cert_chain_validity(&ark, &ask, &vek),
            Err(SnpVerifyError::AskExpired(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_rejects_expired_vek() {
        let ark = build_test_cert("ARK-Milan", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let vek = build_test_cert("SEV-VCEK", -365, -10);

        assert!(matches!(
            check_cert_chain_validity(&ark, &ask, &vek),
            Err(SnpVerifyError::VekExpired(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_rejects_not_yet_valid_ark() {
        // ARK starts 10 days from now.
        let ark = build_test_cert("ARK-Milan", 10, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let vek = build_test_cert("SEV-VCEK", -1, 365);

        assert!(matches!(
            check_cert_chain_validity(&ark, &ask, &vek),
            Err(SnpVerifyError::ArkNotYetValid(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_rejects_not_yet_valid_ask() {
        let ark = build_test_cert("ARK-Milan", -1, 365);
        let ask = build_test_cert("SEV-Milan", 10, 365);
        let vek = build_test_cert("SEV-VCEK", -1, 365);

        assert!(matches!(
            check_cert_chain_validity(&ark, &ask, &vek),
            Err(SnpVerifyError::AskNotYetValid(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_rejects_not_yet_valid_vek() {
        let ark = build_test_cert("ARK-Milan", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let vek = build_test_cert("SEV-VCEK", 10, 365);

        assert!(matches!(
            check_cert_chain_validity(&ark, &ask, &vek),
            Err(SnpVerifyError::VekNotYetValid(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_rejects_malformed_der() {
        let good = build_test_cert("ARK-Milan", -1, 365);
        let malformed = vec![0xFFu8; 100];

        assert!(matches!(
            check_cert_chain_validity(&malformed, &good, &good),
            Err(SnpVerifyError::CertParseFailed(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn validity_accepts_real_amd_milan_roots() {
        // Integration: the committed Milan ARK and ASK fixtures from kdsintf.amd.com
        // were issued in 2020-2022 with 25-year validity — should pass today.
        use openssl::x509::X509;

        let ark_pem = std::fs::read("test_assets/sev-snp/Milan/ark.pem")
            .expect("fixture missing; run scripts/fetch-snp-fixtures.sh");
        let ask_pem = std::fs::read("test_assets/sev-snp/Milan/ask.pem").expect("fixture missing");
        let ark_der = X509::from_pem(&ark_pem).unwrap().to_der().unwrap();
        let ask_der = X509::from_pem(&ask_pem).unwrap().to_der().unwrap();
        // For VEK, use a synthetic cert with valid window — we're only testing
        // the validity check, not signature chaining.
        let vek_der = build_test_cert("SEV-VCEK", -1, 365);

        assert!(
            check_cert_chain_validity(&ark_der, &ask_der, &vek_der).is_ok(),
            "real Milan ARK/ASK from KDS must pass validity check"
        );
    }

    // -- F7 tests: classify_certs_by_cn --

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_canonical_order() {
        // Azure IMDS canonical order: VCEK, ASK, ARK.
        let vek = build_test_cert("SEV-VCEK", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let ark = build_test_cert("ARK-Milan", -1, 365);

        let got = classify_certs_by_cn(&[vek.clone(), ask.clone(), ark.clone()]).unwrap();
        assert_eq!(got.ark, ark);
        assert_eq!(got.ask, ask);
        assert_eq!(got.vek, vek);
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_reordered_ark_first() {
        let vek = build_test_cert("SEV-VCEK", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let ark = build_test_cert("ARK-Milan", -1, 365);

        let got = classify_certs_by_cn(&[ark.clone(), vek.clone(), ask.clone()]).unwrap();
        assert_eq!(got.ark, ark);
        assert_eq!(got.ask, ask);
        assert_eq!(got.vek, vek);
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_reordered_ask_first() {
        let vek = build_test_cert("SEV-VCEK", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let ark = build_test_cert("ARK-Milan", -1, 365);

        let got = classify_certs_by_cn(&[ask.clone(), ark.clone(), vek.clone()]).unwrap();
        assert_eq!(got.ark, ark);
        assert_eq!(got.ask, ask);
        assert_eq!(got.vek, vek);
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_handles_vlek() {
        // VLEK (CSP-derived key) should be treated as a VEK — ABI 1.58 §3.7.
        let vlek = build_test_cert("SEV-VLEK", -1, 365);
        let ask = build_test_cert("SEV-Genoa", -1, 365);
        let ark = build_test_cert("ARK-Genoa", -1, 365);

        let got = classify_certs_by_cn(&[vlek.clone(), ask.clone(), ark.clone()]).unwrap();
        assert_eq!(got.ark, ark);
        assert_eq!(got.ask, ask);
        assert_eq!(got.vek, vlek);
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_accepts_all_three_product_families() {
        for product in ["Milan", "Genoa", "Turin"] {
            let vek = build_test_cert("SEV-VCEK", -1, 365);
            let ask = build_test_cert(&format!("SEV-{product}"), -1, 365);
            let ark = build_test_cert(&format!("ARK-{product}"), -1, 365);

            let result = classify_certs_by_cn(&[vek, ask, ark]);
            assert!(result.is_ok(), "{product} chain must classify: {result:?}");
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_rejects_missing_ark() {
        let vek = build_test_cert("SEV-VCEK", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);

        match classify_certs_by_cn(&[vek, ask]) {
            Err(SnpVerifyError::CertTypeMissing(what)) => assert_eq!(what, "ARK"),
            other => panic!("expected CertTypeMissing(ARK), got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_rejects_missing_ask() {
        let vek = build_test_cert("SEV-VCEK", -1, 365);
        let ark = build_test_cert("ARK-Milan", -1, 365);

        match classify_certs_by_cn(&[vek, ark]) {
            Err(SnpVerifyError::CertTypeMissing(what)) => assert_eq!(what, "ASK"),
            other => panic!("expected CertTypeMissing(ASK), got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_rejects_missing_vek() {
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let ark = build_test_cert("ARK-Milan", -1, 365);

        match classify_certs_by_cn(&[ask, ark]) {
            Err(SnpVerifyError::CertTypeMissing(what)) => assert_eq!(what, "VCEK/VLEK"),
            other => panic!("expected CertTypeMissing(VCEK/VLEK), got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_rejects_duplicate_ark() {
        let vek = build_test_cert("SEV-VCEK", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let ark1 = build_test_cert("ARK-Milan", -1, 365);
        let ark2 = build_test_cert("ARK-Genoa", -1, 365);

        let err = classify_certs_by_cn(&[vek, ask, ark1, ark2]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate ARK"), "msg: {msg}");
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_rejects_unknown_cn() {
        let vek = build_test_cert("SEV-VCEK", -1, 365);
        let ask = build_test_cert("SEV-Milan", -1, 365);
        let rogue = build_test_cert("rogue.example.com", -1, 365);

        let err = classify_certs_by_cn(&[vek, ask, rogue]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unrecognized Subject CN") && msg.contains("rogue.example.com"),
            "msg: {msg}"
        );
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_rejects_malformed_der() {
        let malformed = vec![0xFFu8; 64];

        assert!(matches!(
            classify_certs_by_cn(&[malformed]),
            Err(SnpVerifyError::CertParseFailed(_))
        ));
    }

    // -- F5 CRL revocation tests --

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    fn load_milan_fixtures() -> (Vec<u8>, Vec<u8>) {
        use openssl::x509::X509;
        let ark_der = X509::from_pem(
            &std::fs::read("test_assets/sev-snp/Milan/ark.pem").expect("fixture missing"),
        )
        .unwrap()
        .to_der()
        .unwrap();
        let crl_der = std::fs::read("test_assets/sev-snp/Milan/crl.der").expect("fixture missing");
        (ark_der, crl_der)
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn crl_real_milan_accepts_random_vcek_not_in_revoked_list() {
        // Real Milan CRL from AMD KDS has no revoked certs today. Any
        // VCEK — even a synthetic one — should pass revocation check.
        // (The sig + time-window + issuer checks all work on the real CRL.)
        let (ark_der, crl_der) = load_milan_fixtures();
        let synthetic_vcek = build_test_cert("SEV-VCEK", -1, 365);

        assert!(
            enforce_crl_revocation(&synthetic_vcek, &crl_der, &ark_der).is_ok(),
            "real Milan CRL should accept any VCEK not in its revoked list"
        );
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn crl_rejects_wrong_issuer() {
        // Feed the Milan CRL with a synthetic non-ARK cert — issuer compare
        // must fail before sig verify.
        let (_ark_der, crl_der) = load_milan_fixtures();
        let rogue_ark = build_test_cert("ARK-Rogue", -1, 365);
        let vcek = build_test_cert("SEV-VCEK", -1, 365);

        match enforce_crl_revocation(&vcek, &crl_der, &rogue_ark) {
            Err(SnpVerifyError::CrlSigInvalid(msg)) => {
                assert!(
                    msg.contains("issuer") || msg.contains("signature"),
                    "expected issuer/sig error, got: {msg}"
                );
            }
            other => panic!("expected CrlSigInvalid, got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn crl_rejects_malformed_der() {
        let (ark_der, _crl_der) = load_milan_fixtures();
        let vcek = build_test_cert("SEV-VCEK", -1, 365);

        assert!(matches!(
            enforce_crl_revocation(&vcek, &[0xFFu8; 64], &ark_der),
            Err(SnpVerifyError::CertParseFailed(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn crl_rejects_malformed_vcek() {
        let (ark_der, crl_der) = load_milan_fixtures();
        assert!(matches!(
            enforce_crl_revocation(&[0xFFu8; 64], &crl_der, &ark_der),
            Err(SnpVerifyError::CertParseFailed(_))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn crl_issuer_check_catches_wrong_product_crl() {
        // Integration: feed Milan ARK + Genoa CRL. Even though Genoa CRL is
        // signed by AMD, the subject mismatch must reject before sig verify.
        use openssl::x509::X509;
        let ark_milan = X509::from_pem(
            &std::fs::read("test_assets/sev-snp/Milan/ark.pem").expect("fixture missing"),
        )
        .unwrap()
        .to_der()
        .unwrap();
        let crl_genoa =
            std::fs::read("test_assets/sev-snp/Genoa/crl.der").expect("fixture missing");
        let vcek = build_test_cert("SEV-VCEK", -1, 365);

        match enforce_crl_revocation(&vcek, &crl_genoa, &ark_milan) {
            Err(SnpVerifyError::CrlSigInvalid(msg)) => {
                assert!(msg.contains("issuer"), "msg: {msg}");
            }
            other => panic!("expected CrlSigInvalid for cross-product CRL, got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn classify_real_amd_milan_fixtures() {
        // Integration with the committed real AMD fixtures.
        use openssl::x509::X509;

        let ark_der = X509::from_pem(
            &std::fs::read("test_assets/sev-snp/Milan/ark.pem").expect("fixture missing"),
        )
        .unwrap()
        .to_der()
        .unwrap();
        let ask_der = X509::from_pem(
            &std::fs::read("test_assets/sev-snp/Milan/ask.pem").expect("fixture missing"),
        )
        .unwrap()
        .to_der()
        .unwrap();
        // Synthetic VCEK for the integration (we don't commit real chip-specific ones).
        let vek_der = build_test_cert("SEV-VCEK", -1, 365);

        // Deliberately reordered: [ASK, VCEK, ARK] instead of canonical.
        let got =
            classify_certs_by_cn(&[ask_der.clone(), vek_der.clone(), ark_der.clone()]).unwrap();
        assert_eq!(
            got.ark, ark_der,
            "real Milan ARK must be classified correctly"
        );
        assert_eq!(got.ask, ask_der);
        assert_eq!(got.vek, vek_der);
    }

    // -- check_report_invariants tests (F9/F10/F11) --

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    fn valid_report_template() -> sev::firmware::guest::AttestationReport {
        sev::firmware::guest::AttestationReport {
            version: MIN_REPORT_VERSION,
            sig_algo: SIG_ALGO_ECDSA_P384_SHA384,
            ..Default::default()
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_accept_well_formed_report() {
        let report = valid_report_template();
        assert!(
            check_report_invariants(&report, MIN_REPORT_VERSION).is_ok(),
            "well-formed report must pass invariants"
        );
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_reject_version_too_old() {
        // F9: report version below minimum.
        //
        // Note: in practice, the sev crate's from_bytes() refuses to parse
        // versions < 2, so this code path is reachable only by callers that
        // construct the report directly (tests + future mock providers). Our
        // check exists so that when MIN_REPORT_VERSION moves past 2, the
        // enforcement layer is in place.
        let mut report = valid_report_template();
        report.version = 0;

        match check_report_invariants(&report, MIN_REPORT_VERSION) {
            Err(SnpVerifyError::ReportVersionTooOld { got, min_required }) => {
                assert_eq!(got, 0);
                assert_eq!(min_required, MIN_REPORT_VERSION);
            }
            other => panic!("expected ReportVersionTooOld, got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_reject_version_one() {
        // Boundary: version exactly one below MIN_REPORT_VERSION.
        let mut report = valid_report_template();
        report.version = MIN_REPORT_VERSION - 1;

        assert!(matches!(
            check_report_invariants(&report, MIN_REPORT_VERSION),
            Err(SnpVerifyError::ReportVersionTooOld { .. })
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_accept_version_at_minimum() {
        let mut report = valid_report_template();
        report.version = MIN_REPORT_VERSION;

        assert!(check_report_invariants(&report, MIN_REPORT_VERSION).is_ok());
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_accept_version_above_minimum() {
        // Forward-compat: newer report versions must pass (additive fields
        // only; older verifiers should still accept, they just can't read
        // the new fields).
        let mut report = valid_report_template();
        report.version = 5; // current ABI 1.58

        assert!(check_report_invariants(&report, MIN_REPORT_VERSION).is_ok());
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_reject_unsupported_sig_algo() {
        // F10: any sig_algo other than 1h (ECDSA P-384 + SHA-384).
        let mut report = valid_report_template();
        report.sig_algo = 2; // reserved per ABI Chapter 10 Table 139

        match check_report_invariants(&report, MIN_REPORT_VERSION) {
            Err(SnpVerifyError::UnsupportedSignatureAlgo(algo)) => assert_eq!(algo, 2),
            other => panic!("expected UnsupportedSignatureAlgo, got {other:?}"),
        }
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_reject_default_report() {
        // Default::default() produces an all-zero report — version 0, sig_algo 0.
        // Confirms we never accept a naively-default-constructed report. The
        // earliest check (F9 version) fires first; either way, the report is
        // rejected.
        let report = sev::firmware::guest::AttestationReport::default();
        assert_eq!(report.version, 0);
        assert_eq!(report.sig_algo, 0);

        assert!(
            check_report_invariants(&report, MIN_REPORT_VERSION).is_err(),
            "Default::default() reports must never pass invariants"
        );
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_reject_sig_algo_zero_with_valid_version() {
        // Version valid, sig_algo zero — isolates F10 from F9.
        let mut report = valid_report_template();
        report.sig_algo = 0;

        assert!(matches!(
            check_report_invariants(&report, MIN_REPORT_VERSION),
            Err(SnpVerifyError::UnsupportedSignatureAlgo(0))
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_reject_mask_chip_key_enabled() {
        // F11: MaskChipKey=1 → signature field is all zeroes by design.
        use sev::parser::ByteParser;

        let mut report = valid_report_template();
        // Bit 1 of key_info encodes MASK_CHIP_KEY.
        let key_info_bytes: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
        report.key_info = sev::firmware::guest::KeyInfo::from_bytes(&key_info_bytes).unwrap();
        assert!(report.key_info.mask_chip_key(), "test precondition");

        assert!(matches!(
            check_report_invariants(&report, MIN_REPORT_VERSION),
            Err(SnpVerifyError::MaskChipKeyEnabled)
        ));
    }

    #[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
    #[test]
    fn invariants_check_order_matches_doc() {
        // The invariant checks run in order: version → sig_algo → mask_chip_key.
        // A report with multiple violations should surface the earliest one.
        // This matters for operator diagnostics: the first failure is the
        // most fundamental one to fix.
        let mut report = valid_report_template();
        report.version = 0; // fails F9
        report.sig_algo = 99; // fails F10 (unused because F9 fires first)

        assert!(matches!(
            check_report_invariants(&report, MIN_REPORT_VERSION),
            Err(SnpVerifyError::ReportVersionTooOld { .. })
        ));
    }

    #[test]
    fn finding_ids_map_to_audit() {
        assert_eq!(SnpVerifyError::DebugGuestRejected.finding_id(), Some("F3"));
        assert_eq!(
            SnpVerifyError::VmplMismatch {
                expected: 0,
                actual: 1
            }
            .finding_id(),
            Some("F2")
        );
        assert_eq!(
            SnpVerifyError::VekExpired("".into()).finding_id(),
            Some("F4")
        );
        assert_eq!(
            SnpVerifyError::TcbBootloaderMismatch { vcek: 0, report: 1 }.finding_id(),
            Some("F1")
        );
        assert_eq!(
            SnpVerifyError::UnsupportedSignatureAlgo(0).finding_id(),
            Some("F10")
        );
        // Non-audit-derived errors return None.
        assert_eq!(
            SnpVerifyError::WireMarkerMismatch("".into()).finding_id(),
            None
        );
    }
}
