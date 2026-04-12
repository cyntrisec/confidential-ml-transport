//! SEV-SNP verification policy configuration.
//!
//! This module defines [`SnpVerifyPolicy`] — the configuration struct that
//! controls which checks the SEV-SNP verifier enforces and with what severity.
//!
//! # Design (Phase 3)
//!
//! Phase 3 (this module) introduces the type as pure plumbing: it is stored
//! by both `SevSnpVerifier` and `AzureSevSnpVerifier`, exposed via new
//! `with_policy()` constructors, but no new enforcement fields are actively
//! consumed yet. The existing measurement check is migrated onto the policy
//! struct with zero behavior change.
//!
//! Phase 4 turns on the knobs: `reject_debug`, `require_vmpl`, TCB binding,
//! product pinning, and the other F1-F3/F8 checks all read from this struct.
//!
//! # Fail-closed defaults
//!
//! `SnpVerifyPolicy::default()` produces production-grade defaults:
//! - Reject debug-enabled guests (matches our TDX verifier's `reject_debug_td`)
//! - Reject migratable guests (MA-exported secrets leave the TEE boundary)
//! - Require VMPL 0 (innermost guest code; reject host-requested reports)
//! - Accept all AMD product families (Milan/Genoa/Turin)
//! - Enforce validity period check (F4 — landed Phase 2)
//! - Enforce TCB binding (F1 — lands Phase 5)
//! - Minimum report version = `MIN_REPORT_VERSION` (Phase 1)
//!
//! Callers opting out of any check must explicitly do so, e.g.:
//! ```ignore
//! let policy = SnpVerifyPolicy {
//!     reject_debug: false,                   // NOT recommended outside dev
//!     ..SnpVerifyPolicy::production()
//! };
//! let verifier = SevSnpVerifier::with_policy(policy);
//! ```
//!
//! # Relation to `SecurityProfile`
//!
//! The transport-wide `SecurityProfile::{Production, Development}` already
//! gates measurement expectations (see `session/mod.rs`). A future extension
//! may cross-check that `SnpVerifyPolicy` does not loosen more than the
//! active `SecurityProfile` permits — deferred until Phase 4 enforcement lands.

use super::sev_errors::{SnpProduct, SnpVerifyError, MIN_REPORT_VERSION, VMPL_HOST_REQUESTED};

/// SEV-SNP verification policy.
///
/// Fields are public so callers can construct with struct-update syntax:
/// ```ignore
/// SnpVerifyPolicy {
///     expected_measurement: Some(measurement),
///     ..SnpVerifyPolicy::default()
/// }
/// ```
///
/// # Enforcement phase map
///
/// | Field | Audit ID | Currently enforced? | Phase |
/// |---|---|---|---|
/// | `expected_measurement` | — | **yes** (since v0.1) | Phase 0 |
/// | `min_report_version` | F9 | **yes** (Phase 1, via `check_report_invariants`) | Phase 1 |
/// | `check_validity` | F4 | **yes** (Phase 2, always on today) | Phase 2 |
/// | `reject_debug` | F3 | no | Phase 4 |
/// | `reject_migratable` | F3 | no | Phase 4 |
/// | `require_vmpl` | F2 | no | Phase 4 |
/// | `require_single_socket` | F3 | no | Phase 4 |
/// | `require_smt` | F3 | no | Phase 4 |
/// | `accepted_products` | F8 | no | Phase 4 |
/// | `check_tcb_binding` | F1 | no | Phase 5 |
/// | `crl_der` | F5 | no | Phase 6 |
#[derive(Debug, Clone)]
pub struct SnpVerifyPolicy {
    // -----------------------------------------------------------------
    // Phase 0-2 fields (currently enforced)
    // -----------------------------------------------------------------
    /// Expected MEASUREMENT field (48 bytes per ABI 1.58 §7.3 Table 23
    /// offset 90h). If `Some`, the verifier fails on mismatch.
    pub expected_measurement: Option<Vec<u8>>,

    /// Minimum accepted report VERSION (ABI 1.58 §7.3 Table 23 offset 00h).
    /// Defaults to [`MIN_REPORT_VERSION`] (currently 2).
    ///
    /// Production deployments may tighten to 3 (PreTurin+) or 5 (current ABI)
    /// once the fleet is known to run firmware ≥ 1.55.
    pub min_report_version: u32,

    /// Whether to reject expired / not-yet-valid ARK/ASK/VEK certificates (F4).
    /// Default: `true`. OpenSSL's `X509::verify(pkey)` does signature-only
    /// validation; this flag controls the separate temporal check.
    pub check_validity: bool,

    // -----------------------------------------------------------------
    // Phase 4 fields (plumbing only, not yet enforced)
    // -----------------------------------------------------------------
    /// Reject guests with `POLICY.DEBUG=1` (F3).
    /// Default: `true`. DEBUG=1 authorizes firmware `SNP_DBG_DECRYPT` / `ENCRYPT`,
    /// which give the hypervisor plaintext access. No confidentiality.
    ///
    /// Reference: ABI 1.58 §4.3 Table 9 bit 19, §8.27-§8.28.
    pub reject_debug: bool,

    /// Reject guests with `POLICY.MIGRATE_MA=1` (F3).
    /// Default: `true`. Migration agents can export guest state outside the
    /// TCB boundary of the attested VM.
    ///
    /// Reference: ABI 1.58 §4.3 Table 9 bit 18.
    pub reject_migratable: bool,

    /// Required VMPL (F2). `None` disables the check (not recommended).
    /// Default: `Some(0)`.
    ///
    /// Host-requested reports (VMPL = 0xFFFFFFFF) are rejected unconditionally
    /// regardless of this setting — that check has no opt-out.
    ///
    /// Reference: ABI 1.58 §7.3 Table 23 offset 30h.
    pub require_vmpl: Option<u32>,

    /// Required `POLICY.SINGLE_SOCKET` value, if any (F3).
    /// Default: `None` (don't check).
    pub require_single_socket: Option<bool>,

    /// Required `POLICY.SMT` value, if any (F3).
    /// Default: `None` (don't check).
    pub require_smt: Option<bool>,

    /// AMD product families that this verifier will accept.
    /// Default: all of `[Milan, Genoa, Turin]`.
    ///
    /// Pin to a single product when the deployment is known to run on one
    /// SKU and cross-product misattribution is a concern (F8).
    pub accepted_products: Vec<SnpProduct>,

    // -----------------------------------------------------------------
    // Phase 5 field (plumbing only)
    // -----------------------------------------------------------------
    /// Whether to cross-check VCEK X.509 extensions against `report.reported_tcb`
    /// and `report.chip_id` (F1).
    /// Default: `true`.
    ///
    /// This is the BadRAM / AMD SB-3019 / CVE-2024-56161 remediation anchor.
    /// A valid chain with an old-TCB VCEK signing a newer-TCB-claiming report
    /// passes signature verification but fails this binding check.
    pub check_tcb_binding: bool,

    // -----------------------------------------------------------------
    // Phase 6 field (plumbing only)
    // -----------------------------------------------------------------
    /// Optional DER-encoded CRL for revocation checking (F5).
    /// `None` means "do not consult a CRL" (today's behavior).
    ///
    /// Hardcode the CRL source to `kdsintf.amd.com/vcek/v1/{product}/crl`;
    /// do NOT read the URL from the VCEK's CRLDistributionPoint extension
    /// (would allow attacker-controlled redirection).
    pub crl_der: Option<Vec<u8>>,
}

impl Default for SnpVerifyPolicy {
    /// Fail-closed production defaults.
    fn default() -> Self {
        Self {
            expected_measurement: None,
            min_report_version: MIN_REPORT_VERSION,
            check_validity: true,

            reject_debug: true,
            reject_migratable: true,
            require_vmpl: Some(0),
            require_single_socket: None,
            require_smt: None,
            accepted_products: SnpProduct::all().to_vec(),

            check_tcb_binding: true,

            crl_der: None,
        }
    }
}

impl SnpVerifyPolicy {
    /// Alias for [`SnpVerifyPolicy::default`] — fail-closed production defaults.
    pub fn production() -> Self {
        Self::default()
    }

    /// Permissive policy for local development and synthetic test suites.
    ///
    /// All opt-out-able checks are disabled; callers are expected to assert
    /// their own invariants. **Never use in production.**
    pub fn development() -> Self {
        Self {
            expected_measurement: None,
            min_report_version: MIN_REPORT_VERSION,
            check_validity: false,

            reject_debug: false,
            reject_migratable: false,
            require_vmpl: None,
            require_single_socket: None,
            require_smt: None,
            accepted_products: SnpProduct::all().to_vec(),

            check_tcb_binding: false,

            crl_der: None,
        }
    }
}

/// Enforce policy checks on a signature-verified attestation report.
///
/// Call this **after** the cert chain and signature have been validated —
/// an unverified report could lie about any field. This function assumes the
/// caller has already confirmed the report was signed by a chain-verified
/// chip key.
///
/// # Closes audit findings
///
/// - **F2** — VMPL pinning + unconditional rejection of host-requested reports
///   (`VMPL == 0xFFFFFFFF`, per ABI 1.58 §7.3 Table 23 offset 30h).
/// - **F3** — `POLICY.DEBUG`, `POLICY.MIGRATE_MA`, `POLICY.SMT`,
///   `POLICY.SINGLE_SOCKET` (per ABI 1.58 §4.3 Table 9).
/// - **F8** — cross-check `report.cpuid_fam_id`/`cpuid_mod_id` against the
///   policy's `accepted_products` list (per VCEK 1.00 §1.5 Table 4 + ABI 1.58
///   §7.3 Table 23 offsets 188h/189h).
///
/// # Order of checks
///
/// 1. **F2 host-requested** (unconditional) — catches the rawest bypass first.
/// 2. **F2 VMPL** — if policy pins a VMPL, enforce.
/// 3. **F3 DEBUG** — blocks confidentiality loss via `SNP_DBG_DECRYPT`.
/// 4. **F3 MIGRATE_MA** — blocks MA-mediated state export.
/// 5. **F3 SMT / SINGLE_SOCKET** — side-channel and topology expectations.
/// 6. **F8 product** — last: cheapest to diagnose once other posture issues
///    are ruled out.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
pub fn enforce_report_policy(
    report: &sev::firmware::guest::AttestationReport,
    policy: &SnpVerifyPolicy,
) -> Result<(), SnpVerifyError> {
    // F2.a — host-requested reports: hard reject, no policy opt-out.
    //
    // The host-only SNP_HV_REPORT_REQ command produces reports with
    // VMPL == 0xFFFFFFFF. These are not guest-attested; a guest-facing
    // verifier must never accept them. This check has no policy flag because
    // accepting a host-requested report defeats the entire point of attestation.
    if report.vmpl == VMPL_HOST_REQUESTED {
        return Err(SnpVerifyError::HostRequestedReportRejected);
    }

    // F2.b — required VMPL (configurable).
    if let Some(expected_vmpl) = policy.require_vmpl {
        if report.vmpl != expected_vmpl {
            return Err(SnpVerifyError::VmplMismatch {
                expected: expected_vmpl,
                actual: report.vmpl,
            });
        }
    }

    // F3.a — DEBUG policy bit.
    //
    // On SEV-SNP, setting POLICY.DEBUG=1 authorizes the hypervisor to invoke
    // SNP_DBG_DECRYPT / SNP_DBG_ENCRYPT firmware commands that return/write
    // plaintext to/from guest memory (ABI 1.58 §8.27–§8.28). No confidentiality.
    if policy.reject_debug && report.policy.debug_allowed() {
        return Err(SnpVerifyError::DebugGuestRejected);
    }

    // F3.b — MIGRATE_MA policy bit.
    //
    // A migration agent is an SEV-SNP VM authorized to export guest state for
    // migration. The MA is measured and appears in the report (report_id_ma),
    // but verifiers rarely pin MA identity — so the safest default is to
    // reject migratable guests entirely.
    if policy.reject_migratable && report.policy.migrate_ma_allowed() {
        return Err(SnpVerifyError::MigratableGuestRejected);
    }

    // F3.c — SMT policy (optional, skipped if None).
    if let Some(expected_smt) = policy.require_smt {
        let actual_smt = report.policy.smt_allowed();
        if actual_smt != expected_smt {
            return Err(SnpVerifyError::SmtPolicyMismatch {
                expected: expected_smt,
                actual: actual_smt,
            });
        }
    }

    // F3.d — SINGLE_SOCKET policy (optional, skipped if None).
    if let Some(expected_ss) = policy.require_single_socket {
        let actual_ss = report.policy.single_socket_required();
        if actual_ss != expected_ss {
            return Err(SnpVerifyError::SingleSocketPolicyMismatch {
                expected: expected_ss,
                actual: actual_ss,
            });
        }
    }

    // F8 — product pinning via CPUID.
    //
    // Only enforced when the policy narrows acceptance below "all products"
    // (the default). For the default case we accept any AMD product whose
    // ARK we've pinned, so the check is redundant with the ARK allowlist.
    //
    // Pinning scenarios: a deployment that's certified only on Genoa should
    // reject reports from Milan chips even if the Milan chain is valid.
    let all_known = SnpProduct::all();
    let is_pinning = policy.accepted_products.len() < all_known.len();
    if is_pinning {
        enforce_product_pinning(report, &policy.accepted_products)?;
    }

    Ok(())
}

/// Inspect `report.cpuid_fam_id` / `cpuid_mod_id` and assert the derived
/// `SnpProduct` is in the policy's accepted list. Fail-closed: if CPUID is
/// absent (older report versions) or unrecognized, reject.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
fn enforce_product_pinning(
    report: &sev::firmware::guest::AttestationReport,
    accepted: &[SnpProduct],
) -> Result<(), SnpVerifyError> {
    let expected = format_accepted_products(accepted);

    // CPUID fields are Option<u8> on the sev crate — absent on older report
    // versions. If we're pinning products and CPUID isn't available, we can't
    // safely enforce: fail closed.
    let fam = match report.cpuid_fam_id {
        Some(f) => f,
        None => {
            return Err(SnpVerifyError::ProductMismatch {
                expected,
                actual: "unknown (report version lacks CPUID_FAM_ID)".into(),
            });
        }
    };
    let model = match report.cpuid_mod_id {
        Some(m) => m,
        None => {
            return Err(SnpVerifyError::ProductMismatch {
                expected,
                actual: "unknown (report version lacks CPUID_MOD_ID)".into(),
            });
        }
    };

    let product =
        SnpProduct::from_cpuid(fam, model).ok_or_else(|| SnpVerifyError::ProductMismatch {
            expected: expected.clone(),
            actual: format!("unrecognized CPUID fam={fam:#x}, mod={model:#x}"),
        })?;

    if !accepted.contains(&product) {
        return Err(SnpVerifyError::ProductMismatch {
            expected,
            actual: product.name().to_string(),
        });
    }

    Ok(())
}

#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
fn format_accepted_products(accepted: &[SnpProduct]) -> String {
    accepted
        .iter()
        .map(|p| p.name())
        .collect::<Vec<_>>()
        .join("|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_fail_closed() {
        let p = SnpVerifyPolicy::default();
        assert!(p.reject_debug, "production must reject debug guests");
        assert!(
            p.reject_migratable,
            "production must reject migratable guests"
        );
        assert_eq!(p.require_vmpl, Some(0));
        assert!(p.check_validity);
        assert!(p.check_tcb_binding);
        assert_eq!(p.min_report_version, MIN_REPORT_VERSION);
        assert_eq!(p.accepted_products, SnpProduct::all().to_vec());
        assert!(p.expected_measurement.is_none());
        assert!(p.crl_der.is_none());
    }

    #[test]
    fn production_equals_default() {
        let a = SnpVerifyPolicy::default();
        let b = SnpVerifyPolicy::production();
        assert_eq!(a.reject_debug, b.reject_debug);
        assert_eq!(a.reject_migratable, b.reject_migratable);
        assert_eq!(a.require_vmpl, b.require_vmpl);
        assert_eq!(a.check_validity, b.check_validity);
        assert_eq!(a.check_tcb_binding, b.check_tcb_binding);
        assert_eq!(a.min_report_version, b.min_report_version);
        assert_eq!(a.accepted_products, b.accepted_products);
    }

    #[test]
    fn development_is_permissive() {
        let p = SnpVerifyPolicy::development();
        assert!(!p.reject_debug, "development loosens debug check");
        assert!(!p.reject_migratable);
        assert!(p.require_vmpl.is_none());
        assert!(!p.check_validity);
        assert!(!p.check_tcb_binding);
    }

    #[test]
    fn development_and_production_differ() {
        let prod = SnpVerifyPolicy::production();
        let dev = SnpVerifyPolicy::development();
        // At minimum the debug-rejection distinguishes them.
        assert_ne!(prod.reject_debug, dev.reject_debug);
    }

    #[test]
    fn struct_update_syntax_works() {
        // A caller customizing one field should inherit the rest from default.
        let p = SnpVerifyPolicy {
            expected_measurement: Some(vec![0xAA; 48]),
            ..SnpVerifyPolicy::default()
        };
        assert_eq!(p.expected_measurement.as_deref(), Some(&[0xAA; 48][..]));
        // Inherited fail-closed defaults:
        assert!(p.reject_debug);
        assert_eq!(p.require_vmpl, Some(0));
    }

    #[test]
    fn product_pin_narrows_acceptance() {
        let p = SnpVerifyPolicy {
            accepted_products: vec![SnpProduct::Genoa],
            ..SnpVerifyPolicy::default()
        };
        assert_eq!(p.accepted_products.len(), 1);
        assert!(p.accepted_products.contains(&SnpProduct::Genoa));
        assert!(!p.accepted_products.contains(&SnpProduct::Milan));
    }

    // Sanity-check the SnpProduct helpers that the policy depends on.

    #[test]
    fn product_all_covers_known_platforms() {
        let all = SnpProduct::all();
        assert!(all.contains(&SnpProduct::Milan));
        assert!(all.contains(&SnpProduct::Genoa));
        assert!(all.contains(&SnpProduct::Turin));
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn product_from_ark_cn() {
        assert_eq!(
            SnpProduct::from_ark_cn("ARK-Milan"),
            Some(SnpProduct::Milan)
        );
        assert_eq!(
            SnpProduct::from_ark_cn("ARK-Genoa"),
            Some(SnpProduct::Genoa)
        );
        assert_eq!(
            SnpProduct::from_ark_cn("ARK-Turin"),
            Some(SnpProduct::Turin)
        );
        assert_eq!(SnpProduct::from_ark_cn("ARK-Unknown"), None);
        assert_eq!(SnpProduct::from_ark_cn("SEV-Milan"), None);
        assert_eq!(SnpProduct::from_ark_cn("Milan"), None);
    }

    // -- Phase 4: enforce_report_policy tests --
    //
    // These tests construct synthetic AttestationReport structs with specific
    // policy / VMPL / CPUID fields and assert each SnpVerifyError variant
    // fires on the right input. They do not go through signature verification
    // — policy enforcement sits downstream of that.

    fn base_valid_report() -> sev::firmware::guest::AttestationReport {
        // Valid-invariant report with VMPL=0 and all-zero GuestPolicy (all
        // policy bits off). Default policy will accept this.
        sev::firmware::guest::AttestationReport {
            version: MIN_REPORT_VERSION,
            sig_algo: super::super::sev_errors::SIG_ALGO_ECDSA_P384_SHA384,
            vmpl: 0,
            ..Default::default()
        }
    }

    #[test]
    fn enforce_accepts_default_report_under_default_policy() {
        let report = base_valid_report();
        let policy = SnpVerifyPolicy::default();
        assert!(enforce_report_policy(&report, &policy).is_ok());
    }

    // -- F2: VMPL --

    #[test]
    fn enforce_rejects_host_requested_unconditionally() {
        // Even development() policy (require_vmpl=None) must reject VMPL=0xFFFFFFFF.
        let mut report = base_valid_report();
        report.vmpl = VMPL_HOST_REQUESTED;

        for policy in [
            SnpVerifyPolicy::production(),
            SnpVerifyPolicy::development(),
        ] {
            let err = enforce_report_policy(&report, &policy).unwrap_err();
            assert!(
                matches!(err, SnpVerifyError::HostRequestedReportRejected),
                "got {err:?} for policy {policy:?}"
            );
        }
    }

    #[test]
    fn enforce_rejects_vmpl_mismatch() {
        let mut report = base_valid_report();
        report.vmpl = 1;
        let policy = SnpVerifyPolicy::default(); // require_vmpl = Some(0)

        match enforce_report_policy(&report, &policy) {
            Err(SnpVerifyError::VmplMismatch { expected, actual }) => {
                assert_eq!(expected, 0);
                assert_eq!(actual, 1);
            }
            other => panic!("expected VmplMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_skips_vmpl_check_when_policy_is_none() {
        let mut report = base_valid_report();
        report.vmpl = 2;
        let policy = SnpVerifyPolicy {
            require_vmpl: None,
            ..SnpVerifyPolicy::default()
        };
        assert!(enforce_report_policy(&report, &policy).is_ok());
    }

    // -- F3: guest policy bits --

    #[test]
    fn enforce_rejects_debug_when_reject_debug_enabled() {
        let mut report = base_valid_report();
        report.policy.set_debug_allowed(true);
        let policy = SnpVerifyPolicy::default(); // reject_debug = true

        assert!(matches!(
            enforce_report_policy(&report, &policy),
            Err(SnpVerifyError::DebugGuestRejected)
        ));
    }

    #[test]
    fn enforce_accepts_debug_when_reject_debug_disabled() {
        // Explicit opt-out — developer scenario.
        let mut report = base_valid_report();
        report.policy.set_debug_allowed(true);
        let policy = SnpVerifyPolicy {
            reject_debug: false,
            ..SnpVerifyPolicy::default()
        };
        assert!(enforce_report_policy(&report, &policy).is_ok());
    }

    #[test]
    fn enforce_rejects_migratable_when_reject_migratable_enabled() {
        let mut report = base_valid_report();
        report.policy.set_migrate_ma_allowed(true);

        assert!(matches!(
            enforce_report_policy(&report, &SnpVerifyPolicy::default()),
            Err(SnpVerifyError::MigratableGuestRejected)
        ));
    }

    #[test]
    fn enforce_rejects_smt_mismatch() {
        let mut report = base_valid_report();
        report.policy.set_smt_allowed(true);
        let policy = SnpVerifyPolicy {
            require_smt: Some(false), // pin SMT off
            ..SnpVerifyPolicy::default()
        };

        match enforce_report_policy(&report, &policy) {
            Err(SnpVerifyError::SmtPolicyMismatch { expected, actual }) => {
                assert!(!expected);
                assert!(actual);
            }
            other => panic!("expected SmtPolicyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_accepts_smt_when_not_checked() {
        let mut report = base_valid_report();
        report.policy.set_smt_allowed(true);
        // Default policy has require_smt = None — don't check.
        assert!(enforce_report_policy(&report, &SnpVerifyPolicy::default()).is_ok());
    }

    #[test]
    fn enforce_rejects_single_socket_mismatch() {
        let mut report = base_valid_report();
        report.policy.set_single_socket_required(false); // multi-socket guest
        let policy = SnpVerifyPolicy {
            require_single_socket: Some(true), // pin to single-socket
            ..SnpVerifyPolicy::default()
        };

        assert!(matches!(
            enforce_report_policy(&report, &policy),
            Err(SnpVerifyError::SingleSocketPolicyMismatch { .. })
        ));
    }

    // -- F3: ordering —- host-requested reported before other policy checks --

    #[test]
    fn enforce_host_requested_takes_precedence_over_debug() {
        // Report with VMPL=0xFFFFFFFF AND debug_allowed — the host-requested
        // rejection must fire first (it's more fundamental).
        let mut report = base_valid_report();
        report.vmpl = VMPL_HOST_REQUESTED;
        report.policy.set_debug_allowed(true);

        assert!(matches!(
            enforce_report_policy(&report, &SnpVerifyPolicy::default()),
            Err(SnpVerifyError::HostRequestedReportRejected)
        ));
    }

    // -- F8: product pinning --

    #[test]
    fn enforce_skips_product_check_when_all_accepted() {
        // Default accepted_products contains all three; CPUID absence doesn't
        // trigger a rejection.
        let report = base_valid_report();
        assert!(report.cpuid_fam_id.is_none());
        assert!(enforce_report_policy(&report, &SnpVerifyPolicy::default()).is_ok());
    }

    #[test]
    fn enforce_rejects_missing_cpuid_when_pinning() {
        // Caller pins to Genoa; report has no CPUID (V2 report). Fail-closed.
        let report = base_valid_report();
        let policy = SnpVerifyPolicy {
            accepted_products: vec![SnpProduct::Genoa],
            ..SnpVerifyPolicy::default()
        };

        match enforce_report_policy(&report, &policy) {
            Err(SnpVerifyError::ProductMismatch { expected, actual }) => {
                assert!(expected.contains("Genoa"));
                assert!(actual.contains("unknown"), "actual: {actual}");
            }
            other => panic!("expected ProductMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_rejects_product_mismatch_when_pinning() {
        // Milan CPUID, Genoa-only policy → reject.
        let mut report = base_valid_report();
        report.cpuid_fam_id = Some(0x19);
        report.cpuid_mod_id = Some(0x01); // Milan: ExtModel 0h
        let policy = SnpVerifyPolicy {
            accepted_products: vec![SnpProduct::Genoa],
            ..SnpVerifyPolicy::default()
        };

        match enforce_report_policy(&report, &policy) {
            Err(SnpVerifyError::ProductMismatch { expected, actual }) => {
                assert_eq!(expected, "Genoa");
                assert_eq!(actual, "Milan");
            }
            other => panic!("expected ProductMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_accepts_matching_product_when_pinning() {
        let mut report = base_valid_report();
        report.cpuid_fam_id = Some(0x19);
        report.cpuid_mod_id = Some(0x11); // Genoa
        let policy = SnpVerifyPolicy {
            accepted_products: vec![SnpProduct::Genoa],
            ..SnpVerifyPolicy::default()
        };
        assert!(enforce_report_policy(&report, &policy).is_ok());
    }

    #[test]
    fn enforce_rejects_unrecognized_cpuid_when_pinning() {
        let mut report = base_valid_report();
        report.cpuid_fam_id = Some(0x15); // not a known SEV-SNP family
        report.cpuid_mod_id = Some(0x00);
        let policy = SnpVerifyPolicy {
            accepted_products: vec![SnpProduct::Milan],
            ..SnpVerifyPolicy::default()
        };

        match enforce_report_policy(&report, &policy) {
            Err(SnpVerifyError::ProductMismatch { actual, .. }) => {
                assert!(actual.contains("unrecognized"), "actual: {actual}");
            }
            other => panic!("expected ProductMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_product_check_handles_multiple_accepted() {
        // Policy pins to Milan+Genoa (not Turin). Genoa report should pass.
        let mut report = base_valid_report();
        report.cpuid_fam_id = Some(0x19);
        report.cpuid_mod_id = Some(0x11); // Genoa
        let policy = SnpVerifyPolicy {
            accepted_products: vec![SnpProduct::Milan, SnpProduct::Genoa],
            ..SnpVerifyPolicy::default()
        };
        assert!(enforce_report_policy(&report, &policy).is_ok());

        // Turin report under the same policy → reject.
        report.cpuid_fam_id = Some(0x1A);
        report.cpuid_mod_id = Some(0x00);
        match enforce_report_policy(&report, &policy) {
            Err(SnpVerifyError::ProductMismatch { expected, actual }) => {
                assert!(expected.contains("Milan") && expected.contains("Genoa"));
                assert_eq!(actual, "Turin");
            }
            other => panic!("expected ProductMismatch, got {other:?}"),
        }
    }

    // -- development() preset passes a maximally-loose report --

    #[test]
    fn development_preset_accepts_debug_migratable_nonzero_vmpl() {
        let mut report = base_valid_report();
        report.vmpl = 2;
        report.policy.set_debug_allowed(true);
        report.policy.set_migrate_ma_allowed(true);
        report.policy.set_smt_allowed(true);

        let dev = SnpVerifyPolicy::development();
        assert!(
            enforce_report_policy(&report, &dev).is_ok(),
            "development() must accept loose configs"
        );
    }

    #[test]
    fn development_preset_still_rejects_host_requested() {
        // Even development can't accept a host-requested report — that's
        // not a policy choice, it's a semantic invariant.
        let mut report = base_valid_report();
        report.vmpl = VMPL_HOST_REQUESTED;
        let dev = SnpVerifyPolicy::development();
        assert!(matches!(
            enforce_report_policy(&report, &dev),
            Err(SnpVerifyError::HostRequestedReportRejected)
        ));
    }

    #[test]
    fn product_from_cpuid() {
        // Milan: Family 19h, Extended Model 0h
        assert_eq!(SnpProduct::from_cpuid(0x19, 0x01), Some(SnpProduct::Milan));
        // Genoa: Family 19h, Extended Model 1h
        assert_eq!(SnpProduct::from_cpuid(0x19, 0x11), Some(SnpProduct::Genoa));
        // Siena: Family 19h, Extended Model Ah → uses Genoa roots
        assert_eq!(SnpProduct::from_cpuid(0x19, 0xA0), Some(SnpProduct::Genoa));
        // Turin: Family 1Ah, Extended Model 0h or 1h
        assert_eq!(SnpProduct::from_cpuid(0x1A, 0x00), Some(SnpProduct::Turin));
        assert_eq!(SnpProduct::from_cpuid(0x1A, 0x10), Some(SnpProduct::Turin));
        // Unknown
        assert_eq!(SnpProduct::from_cpuid(0x15, 0x00), None);
        assert_eq!(SnpProduct::from_cpuid(0x19, 0x50), None);
    }
}
