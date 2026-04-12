//! VCEK X.509 extension parsing and TCB binding enforcement (F1).
//!
//! This module implements the **most security-critical** check in the SEV-SNP
//! verifier: cross-checking the VCEK certificate's embedded TCB component
//! extensions against the values the attestation report claims.
//!
//! Without this check, an attacker running known-vulnerable firmware
//! (e.g., pre-BadRAM microcode, pre-CVE-2024-56161 patch) can produce
//! chain-verifying reports that claim a patched `reported_tcb`. Our verifier
//! would accept those without F1. With F1 on, the mismatch between the
//! VCEK-embedded TCB (old) and report-claimed TCB (new) triggers rejection.
//!
//! # Spec references
//!
//! - **VCEK 1.00 §3.1** (Pub. 57230, Jan 2025) defines the custom X.509
//!   extension OIDs under `1.3.6.1.4.1.3704.1.*`:
//!   - Table 10 — Family 19h (Milan/Genoa): `blSPL`, `teeSPL`, `snpSPL`,
//!     `ucodeSPL`, `hwID` (64 bytes), `productName`.
//!   - Table 11 — Family 1Ah (Turin): same + `fmcSPL`; `hwID` is 8 bytes.
//! - **VirTEE 1.2 §3.2.1 step 5** (Pub. 58217, Jul 2023) marks this check
//!   as required and provides reference code (`validate_cert_metadata`).
//! - **AMD SB-3019 / CVE-2024-56161** (BadRAM / microcode signature
//!   verification) — its remediation explicitly requires consumers to verify
//!   `reported_tcb` via the VCEK, making F1 a gating check rather than a
//!   defense-in-depth nicety.
//!
//! # Related findings
//!
//! This module closes audit finding F1. It is also the parse layer used by
//! F8 (product pinning), since `productName` is one of the extensions — but
//! F8's enforcement lives in `sev_policy::enforce_report_policy` and uses
//! CPUID, not this extension. F1 and F8 share the parser; enforcement is
//! separate.

use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use super::sev_errors::SnpVerifyError;

// --- OIDs (VCEK 1.00 §3.1 Table 10/11) ----------------------------------
//
// asn1-rs `oid!` only accepts literal OIDs at const time. We declare these
// as functions returning borrowed OIDs to keep the API ergonomic.

/// `1.3.6.1.4.1.3704.1.2` — productName (IA5STRING, e.g., "Milan-B0").
pub fn oid_product_name() -> Oid<'static> {
    x509_parser::oid_registry::asn1_rs::oid!(1.3.6 .1 .4 .1 .3704 .1 .2)
}

/// `1.3.6.1.4.1.3704.1.3.1` — blSPL (bootloader SVN, INTEGER).
pub fn oid_bl_spl() -> Oid<'static> {
    x509_parser::oid_registry::asn1_rs::oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1)
}

/// `1.3.6.1.4.1.3704.1.3.2` — teeSPL (TEE/PSP SVN, INTEGER).
pub fn oid_tee_spl() -> Oid<'static> {
    x509_parser::oid_registry::asn1_rs::oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2)
}

/// `1.3.6.1.4.1.3704.1.3.3` — snpSPL (SNP firmware SVN, INTEGER).
pub fn oid_snp_spl() -> Oid<'static> {
    x509_parser::oid_registry::asn1_rs::oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3)
}

/// `1.3.6.1.4.1.3704.1.3.8` — ucodeSPL (microcode SVN, INTEGER).
pub fn oid_ucode_spl() -> Oid<'static> {
    x509_parser::oid_registry::asn1_rs::oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8)
}

/// `1.3.6.1.4.1.3704.1.4` — hwID (OCTET STRING; 64 bytes Milan/Genoa,
/// 8 bytes Turin).
pub fn oid_hw_id() -> Oid<'static> {
    x509_parser::oid_registry::asn1_rs::oid!(1.3.6 .1 .4 .1 .3704 .1 .4)
}

/// Parsed VCEK TCB-relevant extensions.
///
/// All fields here come from the VCEK certificate's custom extensions per
/// VCEK spec §3.1. None of these are standard X.509 extensions — they're
/// AMD-private and must be parsed with awareness of their encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcekTcbExtensions {
    /// Bootloader SVN (from OID `1.3.6.1.4.1.3704.1.3.1`).
    /// Must equal `report.reported_tcb.bootloader`.
    pub bl_spl: u8,

    /// TEE SVN (PSP OS SVN, from OID `1.3.6.1.4.1.3704.1.3.2`).
    /// Must equal `report.reported_tcb.tee`.
    pub tee_spl: u8,

    /// SNP firmware SVN (from OID `1.3.6.1.4.1.3704.1.3.3`).
    /// Must equal `report.reported_tcb.snp`.
    pub snp_spl: u8,

    /// Microcode SVN (from OID `1.3.6.1.4.1.3704.1.3.8`).
    /// Must equal `report.reported_tcb.microcode`.
    pub ucode_spl: u8,

    /// Chip Hardware ID / Public Serial Number (from OID
    /// `1.3.6.1.4.1.3704.1.4`). 64 bytes on Milan/Genoa/Siena, 8 bytes on
    /// Turin per VCEK 1.00 §3.1 Tables 10/11.
    ///
    /// Must equal the non-masked portion of `report.chip_id` when
    /// `MaskChipId=0` in the firmware config.
    pub hw_id: Vec<u8>,

    /// Product identifier string (from OID `1.3.6.1.4.1.3704.1.2`).
    /// Format varies per VirTEE §3.1 Note 1:
    ///   - With stepping: `"Milan-B0"`, `"Genoa-A0"`, etc.
    ///   - Without stepping (observed in the wild on some Genoa/VLEK certs):
    ///     just `"Milan"`, `"Genoa"`, `"Turin"`.
    ///
    /// Callers wanting to cross-check against the ARK-matched platform or
    /// the report's CPUID should compare the prefix before `'-'`.
    pub product_name: String,
}

impl VcekTcbExtensions {
    /// Product name prefix (before the optional `-Stepping` suffix).
    ///
    /// Handles the format variance noted in VirTEE 1.2 §3.1 + google/go-sev-guest
    /// issue #115 where some Genoa/VLEK certs ship without the stepping suffix.
    pub fn product_prefix(&self) -> &str {
        match self.product_name.split_once('-') {
            Some((prefix, _stepping)) => prefix,
            None => &self.product_name,
        }
    }
}

/// Parse VCEK TCB-relevant X.509 extensions from DER-encoded cert bytes.
///
/// Returns [`SnpVerifyError::CertParseFailed`] on any ASN.1 parse error or
/// missing extension. All five TCB-relevant extensions must be present —
/// AMD issues VCEKs with all of them per the VCEK spec, so a partial set
/// indicates a malformed cert or tampering.
pub fn parse_vcek_extensions(vcek_der: &[u8]) -> Result<VcekTcbExtensions, SnpVerifyError> {
    let (_, cert) = X509Certificate::from_der(vcek_der)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("VCEK x509_parser failure: {e}")))?;

    let mut bl_spl: Option<u8> = None;
    let mut tee_spl: Option<u8> = None;
    let mut snp_spl: Option<u8> = None;
    let mut ucode_spl: Option<u8> = None;
    let mut hw_id: Option<Vec<u8>> = None;
    let mut product_name: Option<String> = None;

    let bl = oid_bl_spl();
    let tee = oid_tee_spl();
    let snp = oid_snp_spl();
    let ucode = oid_ucode_spl();
    let hwid = oid_hw_id();
    let pname = oid_product_name();

    for ext in cert.extensions() {
        let oid = &ext.oid;
        if oid == &bl {
            bl_spl = Some(parse_spl_byte("blSPL", ext.value)?);
        } else if oid == &tee {
            tee_spl = Some(parse_spl_byte("teeSPL", ext.value)?);
        } else if oid == &snp {
            snp_spl = Some(parse_spl_byte("snpSPL", ext.value)?);
        } else if oid == &ucode {
            ucode_spl = Some(parse_spl_byte("ucodeSPL", ext.value)?);
        } else if oid == &hwid {
            // AMD's observed encoding: hwID is stored as RAW BYTES inside the
            // extension value, NOT as a DER-wrapped OCTET STRING. This matches
            // VirTEE 1.2 §3.2.1 reference code (`check_cert_ext_bytes` compares
            // ext.value directly) and google/go-sev-guest `verify.go`.
            hw_id = Some(ext.value.to_vec());
        } else if oid == &pname {
            // AMD's observed encoding: productName is a raw ASCII string
            // ("Milan-B0", "Genoa", etc.) without DER IA5String wrapping.
            // Fall back to DER-parse if raw bytes aren't valid ASCII, to stay
            // robust against future changes.
            product_name = Some(parse_product_name(ext.value)?);
        }
    }

    Ok(VcekTcbExtensions {
        bl_spl: bl_spl.ok_or_else(|| {
            SnpVerifyError::CertParseFailed("VCEK missing blSPL extension".into())
        })?,
        tee_spl: tee_spl.ok_or_else(|| {
            SnpVerifyError::CertParseFailed("VCEK missing teeSPL extension".into())
        })?,
        snp_spl: snp_spl.ok_or_else(|| {
            SnpVerifyError::CertParseFailed("VCEK missing snpSPL extension".into())
        })?,
        ucode_spl: ucode_spl.ok_or_else(|| {
            SnpVerifyError::CertParseFailed("VCEK missing ucodeSPL extension".into())
        })?,
        hw_id: hw_id
            .ok_or_else(|| SnpVerifyError::CertParseFailed("VCEK missing hwID extension".into()))?,
        product_name: product_name.ok_or_else(|| {
            SnpVerifyError::CertParseFailed("VCEK missing productName extension".into())
        })?,
    })
}

/// Parse a DER-encoded INTEGER inside the extension value bytes, returning
/// the single-byte value. AMD stores SPLs as small integers (0–255).
///
/// Per VirTEE 1.2 §3.2.1 reference `check_cert_ext_byte`, the extension
/// value starts with `0x02` (INTEGER tag), followed by length (1 or 2 bytes),
/// followed by the integer value. We use asn1-rs to parse robustly.
fn parse_spl_byte(name: &str, bytes: &[u8]) -> Result<u8, SnpVerifyError> {
    use x509_parser::oid_registry::asn1_rs::{FromDer, Integer};

    let (_, integer) = Integer::from_der(bytes)
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("{name} not a DER INTEGER: {e}")))?;

    let val: u64 = integer
        .as_u64()
        .map_err(|e| SnpVerifyError::CertParseFailed(format!("{name} INTEGER too large: {e}")))?;

    if val > u8::MAX as u64 {
        return Err(SnpVerifyError::CertParseFailed(format!(
            "{name} value {val} exceeds u8 range"
        )));
    }
    Ok(val as u8)
}

/// Parse the productName extension value into a human-readable string.
///
/// Tries raw UTF-8 first (AMD's observed encoding on Milan/Genoa VCEKs —
/// e.g., bytes == b"Milan-B0"), falls back to DER-wrapped IA5String for
/// forward compat if AMD or Microsoft-paravisor ever starts emitting
/// properly-wrapped values.
fn parse_product_name(bytes: &[u8]) -> Result<String, SnpVerifyError> {
    // Heuristic: raw ASCII if every byte is a printable non-control char.
    // AMD's observed forms are short ("Milan", "Milan-B0", "Genoa-A0", "Turin-B0")
    // so ASCII-only is a good-enough discriminator.
    if !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b'-' || b == b' ')
    {
        return std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|e| {
                SnpVerifyError::CertParseFailed(format!(
                    "productName has printable bytes but isn't valid UTF-8: {e}"
                ))
            });
    }

    // Fallback: DER-wrapped IA5String.
    use x509_parser::oid_registry::asn1_rs::{FromDer, Ia5String};
    let (_, s) = Ia5String::from_der(bytes).map_err(|e| {
        SnpVerifyError::CertParseFailed(format!(
            "productName is neither raw ASCII nor DER IA5String: {e}"
        ))
    })?;
    Ok(s.as_ref().to_string())
}

/// Cross-check VCEK TCB extensions against an attestation report (F1).
///
/// Returns a field-specific error variant on mismatch:
/// - [`SnpVerifyError::TcbBootloaderMismatch`] for blSPL
/// - [`SnpVerifyError::TcbTeeMismatch`] for teeSPL
/// - [`SnpVerifyError::TcbSnpMismatch`] for snpSPL
/// - [`SnpVerifyError::TcbMicrocodeMismatch`] for ucodeSPL
/// - [`SnpVerifyError::ChipIdMismatch`] for hwID vs report.chip_id
///
/// # hwID comparison
///
/// On Milan/Genoa, the VCEK's hwID is 64 bytes and must equal the first 64
/// bytes of `report.chip_id`. On Turin, hwID is 8 bytes and we compare only
/// those 8 bytes against the leading 8 bytes of chip_id (the rest is zero-
/// padded in the report per ABI 1.58 §7.3 Table 23 note).
///
/// If `MaskChipId` was set when the report was produced, `report.chip_id`
/// will be all zeros (ABI 1.58 §3.7 / §7.3). In that case we skip the hwID
/// comparison — MaskChipId is a legitimate hypervisor configuration, not
/// tampering. An attacker cannot set `chip_id=0` AND have a chain-verifying
/// report unless the hypervisor genuinely set MaskChipId.
#[cfg(any(feature = "sev-snp", feature = "azure-sev-snp"))]
pub fn enforce_tcb_binding(
    report: &sev::firmware::guest::AttestationReport,
    vcek: &VcekTcbExtensions,
) -> Result<(), SnpVerifyError> {
    let rtcb = &report.reported_tcb;

    if vcek.bl_spl != rtcb.bootloader {
        return Err(SnpVerifyError::TcbBootloaderMismatch {
            vcek: vcek.bl_spl,
            report: rtcb.bootloader,
        });
    }
    if vcek.tee_spl != rtcb.tee {
        return Err(SnpVerifyError::TcbTeeMismatch {
            vcek: vcek.tee_spl,
            report: rtcb.tee,
        });
    }
    if vcek.snp_spl != rtcb.snp {
        return Err(SnpVerifyError::TcbSnpMismatch {
            vcek: vcek.snp_spl,
            report: rtcb.snp,
        });
    }
    if vcek.ucode_spl != rtcb.microcode {
        return Err(SnpVerifyError::TcbMicrocodeMismatch {
            vcek: vcek.ucode_spl,
            report: rtcb.microcode,
        });
    }

    // hwID / chip_id comparison.
    //
    // Skip if chip_id is all zeros (MaskChipId = 1 — firmware zeros the field
    // per ABI §7.3 Table 23 offset 1A0h). This is a valid hypervisor config.
    let chip_id_all_zero = report.chip_id.iter().all(|&b| b == 0);
    if !chip_id_all_zero {
        let expected_len = vcek.hw_id.len();
        if expected_len > report.chip_id.len() {
            return Err(SnpVerifyError::CertParseFailed(format!(
                "VCEK hwID length ({expected_len}) exceeds report chip_id ({}) — malformed cert",
                report.chip_id.len()
            )));
        }
        if vcek.hw_id != report.chip_id[..expected_len] {
            return Err(SnpVerifyError::ChipIdMismatch);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

    /// Build a DER INTEGER from a u8 (tag 0x02).
    ///
    /// Values with the high bit set require a leading zero octet to express
    /// an unsigned integer — otherwise BER/DER interprets them as negative.
    /// AMD KDS encodes SPL values >= 128 with this two-byte form (VirTEE §3.2.1
    /// reference code accepts both 1-byte and 2-byte lengths).
    fn der_integer_u8(v: u8) -> Vec<u8> {
        if v < 0x80 {
            vec![0x02, 0x01, v]
        } else {
            vec![0x02, 0x02, 0x00, v]
        }
    }


    /// Build a synthetic VCEK-like cert with the requested TCB extensions.
    /// Self-signed so signature chain doesn't matter — we test extension parse.
    #[allow(clippy::too_many_arguments)]
    fn build_synthetic_vcek(
        cn: &str,
        product_name: &str,
        bl: u8,
        tee: u8,
        snp: u8,
        ucode: u8,
        hw_id: &[u8],
    ) -> Vec<u8> {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();

        // Add AMD-private TCB extensions using raw DER.
        let bl_ext = X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.3704.1.3.1").unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(&der_integer_u8(bl)).unwrap(),
        )
        .unwrap();
        builder.append_extension(bl_ext).unwrap();

        let tee_ext = X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.3704.1.3.2").unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(&der_integer_u8(tee)).unwrap(),
        )
        .unwrap();
        builder.append_extension(tee_ext).unwrap();

        let snp_ext = X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.3704.1.3.3").unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(&der_integer_u8(snp)).unwrap(),
        )
        .unwrap();
        builder.append_extension(snp_ext).unwrap();

        let ucode_ext = X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.3704.1.3.8").unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(&der_integer_u8(ucode)).unwrap(),
        )
        .unwrap();
        builder.append_extension(ucode_ext).unwrap();

        // NOTE: hwID and productName are stored as RAW bytes inside the
        // extension value (not DER-wrapped) per AMD's observed encoding.
        // See production parser `parse_vcek_extensions` for the matching
        // comment and references.
        let hwid_ext = X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.3704.1.4").unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(hw_id).unwrap(),
        )
        .unwrap();
        builder.append_extension(hwid_ext).unwrap();

        let pname_ext = X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.3704.1.2").unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(product_name.as_bytes()).unwrap(),
        )
        .unwrap();
        builder.append_extension(pname_ext).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    // --- parse_vcek_extensions tests ---

    #[test]
    fn parse_extracts_all_fields_from_synthetic_milan_vcek() {
        let hw_id = vec![0xAAu8; 64];
        let der = build_synthetic_vcek("SEV-VCEK", "Milan-B0", 2, 0, 6, 95, &hw_id);

        let ext = parse_vcek_extensions(&der).expect("parse");
        assert_eq!(ext.bl_spl, 2);
        assert_eq!(ext.tee_spl, 0);
        assert_eq!(ext.snp_spl, 6);
        assert_eq!(ext.ucode_spl, 95);
        assert_eq!(ext.hw_id, hw_id);
        assert_eq!(ext.product_name, "Milan-B0");
    }

    #[test]
    fn parse_handles_genoa_without_stepping() {
        // VirTEE §3.1 Note 1 describes "Milan-B0"/"Genoa-A0" but in the wild
        // some Genoa VLEK certs ship without the stepping suffix (go-sev-guest
        // issue #115). Parser must tolerate both.
        let hw_id = vec![0xBB; 64];
        let der = build_synthetic_vcek("SEV-VCEK", "Genoa", 1, 0, 3, 50, &hw_id);
        let ext = parse_vcek_extensions(&der).unwrap();
        assert_eq!(ext.product_name, "Genoa");
        assert_eq!(ext.product_prefix(), "Genoa");
    }

    #[test]
    fn product_prefix_strips_stepping() {
        let hw_id = vec![0u8; 64];
        let der = build_synthetic_vcek("SEV-VCEK", "Milan-B0", 0, 0, 0, 0, &hw_id);
        let ext = parse_vcek_extensions(&der).unwrap();
        assert_eq!(ext.product_prefix(), "Milan");
    }

    #[test]
    fn parse_handles_turin_8byte_hwid() {
        // Turin hwID is 8 bytes per VCEK 1.00 §3.1 Table 11 footnote.
        let hw_id = vec![0xCCu8; 8];
        let der = build_synthetic_vcek("SEV-VCEK", "Turin-B0", 0, 0, 0, 0, &hw_id);
        let ext = parse_vcek_extensions(&der).unwrap();
        assert_eq!(ext.hw_id.len(), 8);
        assert_eq!(ext.hw_id, hw_id);
    }

    #[test]
    fn parse_rejects_malformed_der() {
        let result = parse_vcek_extensions(&[0xFFu8; 32]);
        assert!(matches!(result, Err(SnpVerifyError::CertParseFailed(_))));
    }

    #[test]
    fn parse_rejects_cert_without_tcb_extensions() {
        // Build a plain cert with no SEV extensions.
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "SEV-VCEK").unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let der = builder.build().to_der().unwrap();

        let result = parse_vcek_extensions(&der);
        match result {
            Err(SnpVerifyError::CertParseFailed(msg)) => {
                assert!(msg.contains("missing"), "msg: {msg}");
            }
            other => panic!("expected CertParseFailed, got {other:?}"),
        }
    }

    // --- enforce_tcb_binding tests ---

    fn base_report_with_tcb(
        bl: u8,
        tee: u8,
        snp: u8,
        ucode: u8,
        chip_id: [u8; 64],
    ) -> sev::firmware::guest::AttestationReport {
        use sev::firmware::host::TcbVersion;
        sev::firmware::guest::AttestationReport {
            version: crate::attestation::sev_errors::MIN_REPORT_VERSION,
            sig_algo: crate::attestation::sev_errors::SIG_ALGO_ECDSA_P384_SHA384,
            reported_tcb: TcbVersion {
                bootloader: bl,
                tee,
                snp,
                microcode: ucode,
                ..Default::default()
            },
            chip_id,
            ..Default::default()
        }
    }

    fn build_ext(bl: u8, tee: u8, snp: u8, ucode: u8, hw_id: Vec<u8>) -> VcekTcbExtensions {
        VcekTcbExtensions {
            bl_spl: bl,
            tee_spl: tee,
            snp_spl: snp,
            ucode_spl: ucode,
            hw_id,
            product_name: "Milan-B0".into(),
        }
    }

    #[test]
    fn binding_accepts_matching_tcb_and_chip_id() {
        let hw = vec![0xA5; 64];
        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&hw);

        let report = base_report_with_tcb(2, 0, 6, 95, chip_id);
        let ext = build_ext(2, 0, 6, 95, hw);
        assert!(enforce_tcb_binding(&report, &ext).is_ok());
    }

    #[test]
    fn binding_rejects_bootloader_rollback() {
        // VCEK issued for bootloader=2, report claims bootloader=5
        // (attacker running bl=2 firmware, lying about bl=5).
        let report = base_report_with_tcb(5, 0, 6, 95, [0u8; 64]); // MaskChipId
        let ext = build_ext(2, 0, 6, 95, vec![0u8; 64]);

        match enforce_tcb_binding(&report, &ext) {
            Err(SnpVerifyError::TcbBootloaderMismatch { vcek, report }) => {
                assert_eq!(vcek, 2);
                assert_eq!(report, 5);
            }
            other => panic!("expected TcbBootloaderMismatch, got {other:?}"),
        }
    }

    #[test]
    fn binding_rejects_tee_mismatch() {
        let report = base_report_with_tcb(2, 1, 6, 95, [0u8; 64]);
        let ext = build_ext(2, 0, 6, 95, vec![0u8; 64]);
        assert!(matches!(
            enforce_tcb_binding(&report, &ext),
            Err(SnpVerifyError::TcbTeeMismatch { .. })
        ));
    }

    #[test]
    fn binding_rejects_snp_mismatch() {
        let report = base_report_with_tcb(2, 0, 7, 95, [0u8; 64]);
        let ext = build_ext(2, 0, 6, 95, vec![0u8; 64]);
        assert!(matches!(
            enforce_tcb_binding(&report, &ext),
            Err(SnpVerifyError::TcbSnpMismatch { .. })
        ));
    }

    #[test]
    fn binding_rejects_microcode_mismatch() {
        let report = base_report_with_tcb(2, 0, 6, 100, [0u8; 64]);
        let ext = build_ext(2, 0, 6, 95, vec![0u8; 64]);
        assert!(matches!(
            enforce_tcb_binding(&report, &ext),
            Err(SnpVerifyError::TcbMicrocodeMismatch { .. })
        ));
    }

    #[test]
    fn binding_rejects_chip_id_mismatch_when_not_masked() {
        let vcek_hw = vec![0xAAu8; 64];
        let mut different_chip = [0u8; 64];
        different_chip[0] = 0xBB; // non-zero so not-masked
        let report = base_report_with_tcb(2, 0, 6, 95, different_chip);
        let ext = build_ext(2, 0, 6, 95, vcek_hw);
        assert!(matches!(
            enforce_tcb_binding(&report, &ext),
            Err(SnpVerifyError::ChipIdMismatch)
        ));
    }

    #[test]
    fn binding_skips_chip_id_check_when_mask_chip_id_is_set() {
        // chip_id all zeros → MaskChipId=1 configuration. Skip comparison.
        let report = base_report_with_tcb(2, 0, 6, 95, [0u8; 64]);
        let ext = build_ext(2, 0, 6, 95, vec![0xDE; 64]); // Different, but skipped.
        assert!(enforce_tcb_binding(&report, &ext).is_ok());
    }

    #[test]
    fn binding_compares_turin_prefix_of_chip_id() {
        // Turin VCEK carries only 8 bytes of hw_id; report.chip_id still 64
        // bytes, with only the first 8 meaningful (rest zero per ABI spec).
        let turin_hw = vec![0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut chip_id = [0u8; 64];
        chip_id[..8].copy_from_slice(&turin_hw);

        let report = base_report_with_tcb(2, 0, 6, 95, chip_id);
        let ext = build_ext(2, 0, 6, 95, turin_hw.clone());
        assert!(enforce_tcb_binding(&report, &ext).is_ok());

        // Mutate first byte of chip_id — should fail.
        let mut bad_chip = chip_id;
        bad_chip[0] = 0x99;
        let bad_report = base_report_with_tcb(2, 0, 6, 95, bad_chip);
        assert!(matches!(
            enforce_tcb_binding(&bad_report, &ext),
            Err(SnpVerifyError::ChipIdMismatch)
        ));
    }

    // --- Integration-lite: parse + enforce roundtrip ---

    #[test]
    fn parse_and_enforce_roundtrip() {
        let hw_id = vec![0xCDu8; 64];
        let der = build_synthetic_vcek("SEV-VCEK", "Milan-B0", 3, 1, 8, 150, &hw_id);

        let ext = parse_vcek_extensions(&der).unwrap();

        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&hw_id);
        let report = base_report_with_tcb(3, 1, 8, 150, chip_id);

        assert!(enforce_tcb_binding(&report, &ext).is_ok());
    }

    #[test]
    fn parse_and_enforce_catches_rollback() {
        let hw_id = vec![0xCDu8; 64];
        // VCEK issued for bl=1 (vulnerable).
        let der = build_synthetic_vcek("SEV-VCEK", "Milan-B0", 1, 0, 6, 95, &hw_id);
        let ext = parse_vcek_extensions(&der).unwrap();

        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&hw_id);
        // Report claims bl=5 (patched).
        let report = base_report_with_tcb(5, 0, 6, 95, chip_id);

        match enforce_tcb_binding(&report, &ext) {
            Err(SnpVerifyError::TcbBootloaderMismatch { vcek, report }) => {
                assert_eq!(vcek, 1);
                assert_eq!(report, 5);
            }
            other => panic!("TCB rollback must be detected, got {other:?}"),
        }
    }
}
