//! Azure SEV-SNP self-loopback smoke test.
//!
//! Must be run inside a Standard_DC4ads_v5 (or similar SEV-SNP ConfidentialVM
//! on Azure). Generates a real HCL-wrapped SNP attestation report via the
//! vTPM, then verifies it locally against Phase 4 production defaults.
//!
//! # Purpose
//!
//! Validates that real-world Azure HCL reports pass the verifier under the
//! production-default `SnpVerifyPolicy` shipped in Phase 4:
//!
//! - VMPL == 0 (Azure paravisor quirk: CVM + paravisor both run at VMPL 0)
//! - POLICY.DEBUG == 0
//! - POLICY.MIGRATE_MA == 0
//! - Valid cert chain (Milan ARK → ASK → VCEK)
//! - REPORT_DATA[0..32] == SHA256(VarData) binding
//!
//! # Build / run (on the CVM)
//!
//! ```sh
//! cargo run --example azure-sev-snp-smoke --features "mock tcp azure-sev-snp"
//! ```
//!
//! Exits 0 on success, non-zero on first failure.

use confidential_ml_transport::attestation::azure_sev::{AzureSevSnpProvider, AzureSevSnpVerifier};
use confidential_ml_transport::attestation::sev_policy::SnpVerifyPolicy;
use confidential_ml_transport::{AttestationProvider, AttestationVerifier};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Azure SEV-SNP Phase 4 smoke test ===");

    // ---- 1) Sanity: prove we're on a Confidential VM. ----
    let provider = match AzureSevSnpProvider::new() {
        Ok(p) => {
            println!("  [ok] AzureSevSnpProvider created (vTPM accessible)");
            p
        }
        Err(e) => {
            eprintln!("  [fail] not running on Azure CVM: {e}");
            std::process::exit(2);
        }
    };

    // ---- 2) Generate an attestation document binding a test pubkey + nonce. ----
    let pk = [0x42u8; 32];
    let nonce = [0x37u8; 32];
    let doc = provider.attest(None, Some(&nonce), Some(&pk)).await?;
    println!(
        "  [ok] attest() returned {} bytes (HCL report + cert chain)",
        doc.raw.len()
    );

    // ---- 3) Verify under PRODUCTION defaults (Phase 4 enforcement). ----
    let prod_verifier = AzureSevSnpVerifier::with_policy(SnpVerifyPolicy::production());
    match prod_verifier.verify(&doc).await {
        Ok(verified) => {
            println!("  [ok] production-policy verify() succeeded");
            println!(
                "       public_key matches: {}",
                verified.public_key.as_deref() == Some(&pk[..])
            );
            println!(
                "       nonce matches: {}",
                verified.nonce.as_deref() == Some(&nonce[..])
            );
            println!(
                "       measurement (48B): {}",
                hex::encode(
                    verified
                        .measurements
                        .get(&0)
                        .expect("measurement")
                        .as_slice()
                )
            );
        }
        Err(e) => {
            eprintln!("  [FAIL] production-policy verify() rejected a real Azure report: {e}");
            eprintln!();
            eprintln!(
                "  This is the Phase 4 validation that needed real hardware. \
                 Re-check which policy bit tripped and whether Azure's posture \
                 genuinely differs from our defaults."
            );
            std::process::exit(1);
        }
    }

    // ---- 4) Cross-check: development policy should also accept (sanity). ----
    let dev_verifier = AzureSevSnpVerifier::with_policy(SnpVerifyPolicy::development());
    match dev_verifier.verify(&doc).await {
        Ok(_) => println!("  [ok] development-policy verify() succeeded"),
        Err(e) => {
            eprintln!("  [FAIL] development-policy verify() failed: {e}");
            std::process::exit(1);
        }
    }

    // ---- 5) Negative: pin to the wrong product (Genoa), expect rejection. ----
    //
    // DC4ads_v5 is Milan. Azure's Genoa CVMs (DCedsv5) use a different ARK,
    // so pinning to Genoa on a Milan host should fail either at ARK-allowlist
    // or Phase 4 product-binding. Either error is acceptable evidence.
    let genoa_only = SnpVerifyPolicy {
        accepted_products: vec![
            confidential_ml_transport::attestation::sev_errors::SnpProduct::Genoa,
        ],
        ..SnpVerifyPolicy::production()
    };
    let genoa_verifier = AzureSevSnpVerifier::with_policy(genoa_only);
    match genoa_verifier.verify(&doc).await {
        Ok(_) => {
            eprintln!("  [FAIL] Genoa-only policy accepted a Milan report — F8 pinning broken");
            std::process::exit(1);
        }
        Err(e) => println!("  [ok] Genoa-only policy correctly rejected Milan report: {e}"),
    }

    // ---- 6) Phase 5 F1: explicit TCB-binding on/off comparison. ----
    //
    // The production policy default has check_tcb_binding=true. Confirm:
    //   (a) production (binding on) accepts a real Azure report — proves the
    //       real VCEK's TCB extensions match report.reported_tcb.
    //   (b) explicitly-off (binding disabled) also accepts.
    //
    // If (a) fails but (b) passes, we've got a TCB-mismatch — either our
    // parse logic has a bug, or Azure's VCEK is genuinely out of sync with
    // report.reported_tcb. Either way, actionable.
    let no_tcb = SnpVerifyPolicy {
        check_tcb_binding: false,
        ..SnpVerifyPolicy::production()
    };
    let no_tcb_verifier = AzureSevSnpVerifier::with_policy(no_tcb);
    match no_tcb_verifier.verify(&doc).await {
        Ok(_) => println!("  [ok] check_tcb_binding=false accepts real Azure report"),
        Err(e) => {
            eprintln!("  [FAIL] even with TCB binding off, verify failed: {e}");
            std::process::exit(1);
        }
    }
    // Production already verified at step 3 — re-run explicitly to make the
    // TCB-binding validation explicit in the log.
    let prod_verifier_recheck = AzureSevSnpVerifier::with_policy(SnpVerifyPolicy::production());
    match prod_verifier_recheck.verify(&doc).await {
        Ok(_) => println!(
            "  [ok] check_tcb_binding=true (production default) ALSO accepts — \
             VCEK extensions match report.reported_tcb"
        ),
        Err(e) => {
            eprintln!("  [FAIL] TCB binding rejected a real Azure report: {e}");
            eprintln!();
            eprintln!(
                "  This is the Phase 5 validation that needed real hardware. \
                 Either our VCEK parse logic has a bug OR Azure's VCEK is out \
                 of sync with its own reported_tcb. Re-check parse_vcek_extensions \
                 against the actual IMDS-returned VCEK."
            );
            std::process::exit(1);
        }
    }

    // ---- 7) Phase 6 F5: CRL-based revocation check. ----
    //
    // Fetch the live Milan CRL from AMD KDS and feed it via policy.crl_der.
    // Real Milan CRL today has no revoked entries, so verify must still pass.
    // Exercises: CRL sig verify against ARK, time-window check, serial lookup.
    let crl_url = "https://kdsintf.amd.com/vcek/v1/Milan/crl";
    let resp = match std::process::Command::new("curl")
        .args(["-sSfL", crl_url, "-o", "/tmp/milan.crl"])
        .status()
    {
        Ok(s) if s.success() => std::fs::read("/tmp/milan.crl").ok(),
        _ => None,
    };
    if let Some(crl_der) = resp {
        println!(
            "  [ok] fetched Milan CRL from KDS ({} bytes)",
            crl_der.len()
        );
        let with_crl = SnpVerifyPolicy {
            crl_der: Some(crl_der),
            ..SnpVerifyPolicy::production()
        };
        let crl_verifier = AzureSevSnpVerifier::with_policy(with_crl);
        match crl_verifier.verify(&doc).await {
            Ok(_) => println!(
                "  [ok] CRL-enabled verify succeeded — real Milan VCEK not in revoked list"
            ),
            Err(e) => {
                eprintln!("  [FAIL] CRL-enabled verify rejected real Azure report: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("  [warn] could not fetch live CRL from KDS (network?); skipping F5 smoke");
    }

    println!();
    println!("=== Phases 4 + 5 + 6 + 7 smoke PASSED ===");
    Ok(())
}
