use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::types::{AttestationDocument, VerifiedAttestation};
use super::{AttestationProvider, AttestationVerifier};
use crate::error::AttestError;

/// Global counter for unique configfs-tsm report entry names.
static TSM_ENTRY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Wire format marker for TDX attestation documents.
const TDX_MARKER: &[u8; 12] = b"TDX_V1\0\0\0\0\0\0";

/// Size of the TDX quote header (fixed at 48 bytes).
const HEADER_SIZE: usize = 48;

/// Size of the TD quote body for v4 (584 bytes).
const BODY_SIZE_V4: usize = 584;

/// Size of the TD quote body for v5 (648 bytes).
const BODY_SIZE_V5: usize = 648;

/// Expected TEE type for TDX in the quote header.
const TEE_TYPE_TDX: u32 = 0x0000_0081;

/// ECDSA-P256 attestation key type.
const ATT_KEY_TYPE_P256: u16 = 2;

/// Offset of MRTD within the TD quote body.
const MRTD_OFFSET: usize = 136;
/// Size of each measurement register (48 bytes / 384 bits).
const MEASUREMENT_SIZE: usize = 48;

/// Offset of RTMR0 within the TD quote body.
const RTMR0_OFFSET: usize = 328;

/// Offset of REPORTDATA within the TD quote body.
const REPORTDATA_OFFSET: usize = 520;
/// Size of REPORTDATA (64 bytes).
const REPORTDATA_SIZE: usize = 64;

/// Size of ECDSA P-256 signature (r || s, 32 + 32 bytes).
const ECDSA_SIG_SIZE: usize = 64;

/// Size of ECDSA P-256 public key (x || y, 32 + 32 bytes).
const ECDSA_PUBKEY_SIZE: usize = 64;

/// RAII guard that removes a configfs-tsm report entry on drop.
///
/// Ensures cleanup happens even if the attestation request fails partway
/// through (e.g., inblob write succeeds but outblob read fails).
#[cfg(target_os = "linux")]
struct TsmEntryGuard {
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for TsmEntryGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Attestation provider that requests TDX quotes via the configfs-tsm interface.
///
/// Only works inside a TDX Trust Domain where the configfs-tsm filesystem is
/// mounted at `/sys/kernel/config/tsm/report/` (Linux 6.7+).
///
/// # REPORTDATA layout
///
/// The 64-byte `REPORTDATA` field is populated as:
/// - bytes `[0..32]`: raw X25519 public key (32 bytes)
/// - bytes `[32..64]`: raw nonce (32 bytes)
///
/// This matches the SEV-SNP convention so handshake code stays unchanged.
#[cfg(target_os = "linux")]
pub struct TdxProvider {
    tsm_path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl TdxProvider {
    /// Create a provider using the default configfs-tsm path.
    pub fn new() -> Result<Self, AttestError> {
        Self::new_with_path("/sys/kernel/config/tsm/report")
    }

    /// Create a provider with a custom configfs-tsm path (for testing).
    pub fn new_with_path(path: impl Into<std::path::PathBuf>) -> Result<Self, AttestError> {
        let tsm_path = path.into();
        if !tsm_path.exists() {
            return Err(AttestError::GenerationFailed(format!(
                "configfs-tsm path does not exist: {} — not running inside a TDX TD?",
                tsm_path.display()
            )));
        }
        Ok(Self { tsm_path })
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl AttestationProvider for TdxProvider {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        use std::fs;

        // Build 64-byte REPORTDATA: pk[0..32] || nonce[32..64]
        let mut report_data = [0u8; 64];

        if let Some(pk) = public_key {
            if pk.len() != 32 {
                return Err(AttestError::GenerationFailed(format!(
                    "public key must be 32 bytes, got {}",
                    pk.len()
                )));
            }
            report_data[..32].copy_from_slice(pk);
        }

        if let Some(n) = nonce {
            if n.len() != 32 {
                return Err(AttestError::GenerationFailed(format!(
                    "nonce must be 32 bytes, got {}",
                    n.len()
                )));
            }
            report_data[32..64].copy_from_slice(n);
        }

        // Create a unique report entry under configfs-tsm.
        let entry_name = format!(
            "cmt_{}_{}",
            std::process::id(),
            TSM_ENTRY_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let entry_path = self.tsm_path.join(&entry_name);

        // Clean up any stale entry from a previous run.
        let _ = fs::remove_dir_all(&entry_path);

        fs::create_dir(&entry_path).map_err(|e| {
            AttestError::GenerationFailed(format!(
                "failed to create tsm report entry {}: {e}",
                entry_path.display()
            ))
        })?;

        // RAII guard ensures cleanup even if inblob/outblob operations fail.
        let _guard = TsmEntryGuard {
            path: entry_path.clone(),
        };

        // Write REPORTDATA to inblob.
        fs::write(entry_path.join("inblob"), report_data)
            .map_err(|e| AttestError::GenerationFailed(format!("failed to write inblob: {e}")))?;

        // Read the generated quote from outblob.
        let quote = fs::read(entry_path.join("outblob"))
            .map_err(|e| AttestError::GenerationFailed(format!("failed to read outblob: {e}")))?;

        // Guard will clean up on drop (including normal exit).

        let raw = encode_tdx_document(&quote);
        Ok(AttestationDocument::new(raw))
    }
}

/// Verifier for Intel TDX attestation quotes.
///
/// Validates the quote by:
/// 1. Parsing the wire document (marker + quote)
/// 2. Parsing the quote header (version, TEE type, key type)
/// 3. Parsing the TD quote body (MRTD, RTMRs, REPORTDATA)
/// 4. Verifying the ECDSA-P256 signature over header + body
/// 5. Optionally checking MRTD against an expected value
///
/// Full DCAP collateral verification (PCK cert chain, QE identity, TCB info)
/// is deferred to a future `tdx-dcap` feature.
pub struct TdxVerifier {
    expected_mrtd: Option<Vec<u8>>,
}

impl TdxVerifier {
    /// Create a new verifier.
    ///
    /// If `expected_mrtd` is `Some`, the verifier will check that the quote's
    /// MRTD field (48 bytes) matches the expected value.
    pub fn new(expected_mrtd: Option<Vec<u8>>) -> Self {
        Self { expected_mrtd }
    }
}

#[async_trait]
impl AttestationVerifier for TdxVerifier {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        // Step 1: Parse wire document.
        let quote = decode_tdx_document(&doc.raw)?;

        // Step 2: Parse and validate quote header.
        let header = TdxQuoteHeader::parse(&quote)?;

        // Step 3: Determine body size from version.
        let body_size = match header.version {
            4 => BODY_SIZE_V4,
            5 => BODY_SIZE_V5,
            v => {
                return Err(AttestError::VerificationFailed(format!(
                    "unsupported TDX quote version: {v} (expected 4 or 5)"
                )))
            }
        };

        if quote.len() < HEADER_SIZE + body_size + 4 {
            return Err(AttestError::VerificationFailed(format!(
                "TDX quote too short for body: need at least {} bytes, got {}",
                HEADER_SIZE + body_size + 4,
                quote.len()
            )));
        }

        // Step 4: Parse TD quote body.
        let body = TdxQuoteBody::parse(&quote[HEADER_SIZE..HEADER_SIZE + body_size])?;

        // Step 5: Verify ECDSA-P256 signature.
        //
        // WARNING: This verifies that the quote's signature is valid for the
        // public key embedded IN the quote itself. It does NOT verify that
        // the signing key belongs to a genuine Intel Quoting Enclave (QE).
        // Full DCAP collateral verification (PCK cert chain, QE identity,
        // TCB info) is required for production use — see the `tdx-dcap`
        // feature (not yet implemented).
        tracing::warn!(
            "TDX quote signature verified against embedded key only — \
             DCAP collateral verification is not implemented. \
             This verifier should NOT be used in production without \
             additional trust anchoring."
        );
        let sig_section_offset = HEADER_SIZE + body_size;
        verify_ecdsa_signature(&quote, sig_section_offset, HEADER_SIZE + body_size)?;

        // Step 6: Extract REPORTDATA fields.
        let public_key = body.reportdata[..32].to_vec();
        let nonce = body.reportdata[32..64].to_vec();

        // Step 7: Check MRTD if expected.
        let mut measurements = BTreeMap::new();
        measurements.insert(0, body.mrtd.to_vec());
        measurements.insert(1, body.rtmr0.to_vec());
        measurements.insert(2, body.rtmr1.to_vec());
        measurements.insert(3, body.rtmr2.to_vec());
        measurements.insert(4, body.rtmr3.to_vec());

        if let Some(ref expected) = self.expected_mrtd {
            if expected.as_slice() != body.mrtd.as_slice() {
                return Err(AttestError::VerificationFailed(format!(
                    "MRTD mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(body.mrtd)
                )));
            }
        }

        let document_hash: [u8; 32] = Sha256::digest(&doc.raw).into();

        let pk_opt = if public_key.iter().all(|&b| b == 0) {
            None
        } else {
            Some(public_key)
        };
        let nonce_opt = if nonce.iter().all(|&b| b == 0) {
            None
        } else {
            Some(nonce)
        };

        Ok(VerifiedAttestation {
            document_hash,
            public_key: pk_opt,
            user_data: None,
            nonce: nonce_opt,
            measurements,
        })
    }
}

// -- Wire encoding/decoding --

/// Encode a TDX attestation document for the wire.
///
/// Format:
/// ```text
/// [12 bytes] TDX_V1\0\0\0\0\0\0  (marker)
/// [4 bytes]  quote_size           (u32 LE)
/// [N bytes]  raw TDX quote        (self-contained, includes cert chain in sig section)
/// ```
#[doc(hidden)]
pub fn encode_tdx_document(quote: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(12 + 4 + quote.len());
    raw.extend_from_slice(TDX_MARKER);
    raw.extend_from_slice(&(quote.len() as u32).to_le_bytes());
    raw.extend_from_slice(quote);
    raw
}

/// Decode a TDX wire document into the raw quote bytes.
fn decode_tdx_document(raw: &[u8]) -> Result<Vec<u8>, AttestError> {
    if raw.len() < 12 {
        return Err(AttestError::VerificationFailed(
            "document too short for TDX marker".into(),
        ));
    }

    if &raw[..12] != TDX_MARKER {
        return Err(AttestError::VerificationFailed(
            "not a TDX attestation document".into(),
        ));
    }

    if raw.len() < 16 {
        return Err(AttestError::VerificationFailed(
            "truncated TDX document (quote_size)".into(),
        ));
    }

    let quote_size = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;

    if raw.len() < 16 + quote_size {
        return Err(AttestError::VerificationFailed(
            "truncated TDX document (quote)".into(),
        ));
    }

    Ok(raw[16..16 + quote_size].to_vec())
}

// -- Quote parsing --

/// Parsed TDX quote header.
#[derive(Debug)]
#[allow(dead_code)] // Fields validated during parse(), retained for debugging.
struct TdxQuoteHeader {
    version: u16,
    att_key_type: u16,
    tee_type: u32,
}

impl TdxQuoteHeader {
    fn parse(data: &[u8]) -> Result<Self, AttestError> {
        if data.len() < HEADER_SIZE {
            return Err(AttestError::VerificationFailed(format!(
                "TDX quote too short for header: need {HEADER_SIZE} bytes, got {}",
                data.len()
            )));
        }

        let version = u16::from_le_bytes([data[0], data[1]]);
        let att_key_type = u16::from_le_bytes([data[2], data[3]]);
        let tee_type = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        if version != 4 && version != 5 {
            return Err(AttestError::VerificationFailed(format!(
                "unsupported TDX quote version: {version} (expected 4 or 5)"
            )));
        }

        if tee_type != TEE_TYPE_TDX {
            return Err(AttestError::VerificationFailed(format!(
                "wrong TEE type: expected 0x{TEE_TYPE_TDX:08X}, got 0x{tee_type:08X}"
            )));
        }

        if att_key_type != ATT_KEY_TYPE_P256 {
            return Err(AttestError::VerificationFailed(format!(
                "unsupported attestation key type: {att_key_type} (only ECDSA-P256 = 2 is supported)"
            )));
        }

        Ok(Self {
            version,
            att_key_type,
            tee_type,
        })
    }
}

/// Parsed TDX TD quote body.
#[derive(Debug)]
struct TdxQuoteBody {
    mrtd: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
    reportdata: [u8; 64],
}

impl TdxQuoteBody {
    fn parse(body: &[u8]) -> Result<Self, AttestError> {
        // Minimum body size is v4 (584 bytes).
        if body.len() < BODY_SIZE_V4 {
            return Err(AttestError::VerificationFailed(format!(
                "TDX quote body too short: need at least {BODY_SIZE_V4} bytes, got {}",
                body.len()
            )));
        }

        let mut mrtd = [0u8; 48];
        mrtd.copy_from_slice(&body[MRTD_OFFSET..MRTD_OFFSET + MEASUREMENT_SIZE]);

        let mut rtmr0 = [0u8; 48];
        rtmr0.copy_from_slice(&body[RTMR0_OFFSET..RTMR0_OFFSET + MEASUREMENT_SIZE]);

        let mut rtmr1 = [0u8; 48];
        rtmr1.copy_from_slice(
            &body[RTMR0_OFFSET + MEASUREMENT_SIZE..RTMR0_OFFSET + 2 * MEASUREMENT_SIZE],
        );

        let mut rtmr2 = [0u8; 48];
        rtmr2.copy_from_slice(
            &body[RTMR0_OFFSET + 2 * MEASUREMENT_SIZE..RTMR0_OFFSET + 3 * MEASUREMENT_SIZE],
        );

        let mut rtmr3 = [0u8; 48];
        rtmr3.copy_from_slice(
            &body[RTMR0_OFFSET + 3 * MEASUREMENT_SIZE..RTMR0_OFFSET + 4 * MEASUREMENT_SIZE],
        );

        let mut reportdata = [0u8; 64];
        reportdata.copy_from_slice(&body[REPORTDATA_OFFSET..REPORTDATA_OFFSET + REPORTDATA_SIZE]);

        Ok(Self {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            reportdata,
        })
    }
}

/// Verify the ECDSA-P256 signature over the quote header + body.
///
/// The signature section starts at `sig_offset` within the quote:
/// - `[0..4]`    sig_data_len (u32 LE)
/// - `[4..68]`   ECDSA signature (r || s, 64 bytes)
/// - `[68..132]` attestation public key (x || y, 64 bytes)
///
/// The signed data is `quote[0..signed_len]` (header + body).
fn verify_ecdsa_signature(
    quote: &[u8],
    sig_offset: usize,
    signed_len: usize,
) -> Result<(), AttestError> {
    if quote.len() < sig_offset + 4 {
        return Err(AttestError::VerificationFailed(
            "TDX quote truncated before signature section".into(),
        ));
    }

    let sig_data_len = u32::from_le_bytes([
        quote[sig_offset],
        quote[sig_offset + 1],
        quote[sig_offset + 2],
        quote[sig_offset + 3],
    ]) as usize;

    if quote.len() < sig_offset + 4 + sig_data_len {
        return Err(AttestError::VerificationFailed(
            "TDX quote truncated in signature data".into(),
        ));
    }

    if sig_data_len < ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE {
        return Err(AttestError::VerificationFailed(format!(
            "signature data too short: need at least {} bytes, got {sig_data_len}",
            ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE
        )));
    }

    let sig_data = &quote[sig_offset + 4..sig_offset + 4 + sig_data_len];
    let sig_bytes = &sig_data[..ECDSA_SIG_SIZE];
    let pubkey_bytes = &sig_data[ECDSA_SIG_SIZE..ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE];

    // Build the ECDSA public key from raw x || y coordinates.
    let mut uncompressed = vec![0x04u8]; // uncompressed point prefix
    uncompressed.extend_from_slice(pubkey_bytes);

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
        .map_err(|e| {
            AttestError::VerificationFailed(format!("failed to create P-256 group: {e}"))
        })?;

    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to create BigNumContext: {e}"))
    })?;

    let point = openssl::ec::EcPoint::from_bytes(&group, &uncompressed, &mut ctx).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse attestation public key: {e}"))
    })?;

    let ec_key = openssl::ec::EcKey::from_public_key(&group, &point)
        .map_err(|e| AttestError::VerificationFailed(format!("failed to build EC key: {e}")))?;

    let pkey = openssl::pkey::PKey::from_ec_key(ec_key)
        .map_err(|e| AttestError::VerificationFailed(format!("failed to build PKey: {e}")))?;

    // Convert raw signature (r || s) to DER-encoded ECDSA signature.
    let r = openssl::bn::BigNum::from_slice(&sig_bytes[..32]).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse signature r: {e}"))
    })?;
    let s = openssl::bn::BigNum::from_slice(&sig_bytes[32..64]).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse signature s: {e}"))
    })?;

    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to build ECDSA signature: {e}"))
    })?;

    let der_sig = ecdsa_sig.to_der().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to encode signature to DER: {e}"))
    })?;

    // Verify the ECDSA signature over the raw signed data (header + body).
    // OpenSSL's verify_oneshot will hash the data internally with SHA-256.
    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .map_err(|e| AttestError::VerificationFailed(format!("failed to create verifier: {e}")))?;

    let valid = verifier
        .verify_oneshot(&der_sig, &quote[..signed_len])
        .map_err(|e| AttestError::VerificationFailed(format!("ECDSA verification error: {e}")))?;

    if !valid {
        return Err(AttestError::VerificationFailed(
            "TDX quote ECDSA-P256 signature verification failed".into(),
        ));
    }

    Ok(())
}

/// Build a synthetic TDX quote for testing (no real hardware needed).
///
/// Creates a valid TDX v4 quote with the specified fields and signs it
/// with an ephemeral ECDSA-P256 key.
#[doc(hidden)]
pub fn build_synthetic_tdx_quote(
    reportdata: [u8; 64],
    mrtd: [u8; 48],
    rtmrs: [[u8; 48]; 4],
) -> Vec<u8> {
    // -- Header (48 bytes) --
    let mut quote = Vec::with_capacity(1024);

    // version = 4 (TDX 1.0)
    quote.extend_from_slice(&4u16.to_le_bytes());
    // att_key_type = 2 (ECDSA-P256)
    quote.extend_from_slice(&ATT_KEY_TYPE_P256.to_le_bytes());
    // tee_type = 0x81 (TDX)
    quote.extend_from_slice(&TEE_TYPE_TDX.to_le_bytes());
    // qe_svn
    quote.extend_from_slice(&0u16.to_le_bytes());
    // pce_svn
    quote.extend_from_slice(&0u16.to_le_bytes());
    // qe_vendor_id (16 bytes)
    quote.extend_from_slice(&[0u8; 16]);
    // user_data (20 bytes)
    quote.extend_from_slice(&[0u8; 20]);

    assert_eq!(quote.len(), HEADER_SIZE);

    // -- TD Quote Body (584 bytes for v4) --
    let body_start = quote.len();

    // tee_tcb_svn (16 bytes)
    quote.extend_from_slice(&[0u8; 16]);
    // mrseam (48 bytes)
    quote.extend_from_slice(&[0u8; 48]);
    // mrsignerseam (48 bytes)
    quote.extend_from_slice(&[0u8; 48]);
    // seam_attributes (8 bytes)
    quote.extend_from_slice(&[0u8; 8]);
    // td_attributes (8 bytes)
    quote.extend_from_slice(&[0u8; 8]);
    // xfam (8 bytes)
    quote.extend_from_slice(&[0u8; 8]);
    // mrtd (48 bytes) at offset 136 from body start
    assert_eq!(quote.len() - body_start, MRTD_OFFSET);
    quote.extend_from_slice(&mrtd);
    // mrconfigid (48 bytes)
    quote.extend_from_slice(&[0u8; 48]);
    // mrowner (48 bytes)
    quote.extend_from_slice(&[0u8; 48]);
    // mrownerconfig (48 bytes)
    quote.extend_from_slice(&[0u8; 48]);
    // rtmr0 (48 bytes) at offset 328 from body start
    assert_eq!(quote.len() - body_start, RTMR0_OFFSET);
    quote.extend_from_slice(&rtmrs[0]);
    // rtmr1 (48 bytes)
    quote.extend_from_slice(&rtmrs[1]);
    // rtmr2 (48 bytes)
    quote.extend_from_slice(&rtmrs[2]);
    // rtmr3 (48 bytes)
    quote.extend_from_slice(&rtmrs[3]);
    // reportdata (64 bytes) at offset 520 from body start
    assert_eq!(quote.len() - body_start, REPORTDATA_OFFSET);
    quote.extend_from_slice(&reportdata);

    assert_eq!(quote.len() - body_start, BODY_SIZE_V4);

    // -- Signature Section --
    let signed_len = quote.len(); // header + body

    // Generate ephemeral ECDSA-P256 key for signing.
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
        .expect("P-256 group");
    let ec_key = openssl::ec::EcKey::generate(&group).expect("keygen");
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key.clone()).expect("pkey");

    // Sign the raw data (header + body). OpenSSL hashes it internally with SHA-256.
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("signer");
    let der_sig = signer
        .sign_oneshot_to_vec(&quote[..signed_len])
        .expect("sign");

    // Parse DER signature back to (r, s) raw components.
    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_der(&der_sig).expect("parse DER sig");
    let r = ecdsa_sig.r().to_vec_padded(32).expect("r");
    let s = ecdsa_sig.s().to_vec_padded(32).expect("s");

    // Extract raw public key (x || y).
    let mut ctx = openssl::bn::BigNumContext::new().expect("ctx");
    let pubkey_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .expect("pubkey bytes");
    // pubkey_bytes is 0x04 || x(32) || y(32) = 65 bytes
    let pubkey_xy = &pubkey_bytes[1..]; // strip 0x04 prefix

    // Build signature section.
    let sig_data_len = (ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE) as u32;
    quote.extend_from_slice(&sig_data_len.to_le_bytes());
    quote.extend_from_slice(&r);
    quote.extend_from_slice(&s);
    quote.extend_from_slice(pubkey_xy);

    quote
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_roundtrip() {
        let quote = vec![0xAA; 256];
        let encoded = encode_tdx_document(&quote);
        let decoded = decode_tdx_document(&encoded).unwrap();
        assert_eq!(decoded, quote);
    }

    #[test]
    fn reject_invalid_marker() {
        let mut raw = vec![0u8; 100];
        raw[..7].copy_from_slice(b"INVALID");
        let result = decode_tdx_document(&raw);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("not a TDX"), "error: {err}");
    }

    #[test]
    fn reject_truncated_document() {
        let quote = vec![0xAA; 256];
        let encoded = encode_tdx_document(&quote);
        // Truncate in the middle of the quote.
        let truncated = &encoded[..20];
        let result = decode_tdx_document(truncated);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("truncated"), "error: {err}");
    }

    #[test]
    fn reject_too_short_for_marker() {
        let result = decode_tdx_document(&[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn synthetic_quote_header_parsing() {
        let reportdata = [0u8; 64];
        let mrtd = [0xAA; 48];
        let rtmrs = [[0u8; 48]; 4];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);

        let header = TdxQuoteHeader::parse(&quote).unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.att_key_type, ATT_KEY_TYPE_P256);
        assert_eq!(header.tee_type, TEE_TYPE_TDX);
    }

    #[test]
    fn synthetic_quote_body_parsing() {
        let mut reportdata = [0u8; 64];
        reportdata[..32].copy_from_slice(&[0x42; 32]);
        reportdata[32..64].copy_from_slice(&[0x37; 32]);
        let mrtd = [0xBB; 48];
        let rtmrs = [[0x11; 48], [0x22; 48], [0x33; 48], [0x44; 48]];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);

        let body = TdxQuoteBody::parse(&quote[HEADER_SIZE..HEADER_SIZE + BODY_SIZE_V4]).unwrap();
        assert_eq!(body.mrtd, mrtd);
        assert_eq!(body.rtmr0, rtmrs[0]);
        assert_eq!(body.rtmr1, rtmrs[1]);
        assert_eq!(body.rtmr2, rtmrs[2]);
        assert_eq!(body.rtmr3, rtmrs[3]);
        assert_eq!(body.reportdata, reportdata);
    }

    #[test]
    fn synthetic_quote_signature_verifies() {
        let reportdata = [0u8; 64];
        let mrtd = [0xAA; 48];
        let rtmrs = [[0u8; 48]; 4];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);

        let signed_len = HEADER_SIZE + BODY_SIZE_V4;
        verify_ecdsa_signature(&quote, signed_len, signed_len).unwrap();
    }

    #[test]
    fn tampered_quote_signature_fails() {
        let reportdata = [0u8; 64];
        let mrtd = [0xAA; 48];
        let rtmrs = [[0u8; 48]; 4];
        let mut quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);

        // Tamper with a byte in the body.
        quote[HEADER_SIZE + 10] ^= 0xFF;

        let signed_len = HEADER_SIZE + BODY_SIZE_V4;
        let result = verify_ecdsa_signature(&quote, signed_len, signed_len);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verifier_extracts_fields() {
        let mut reportdata = [0u8; 64];
        reportdata[..32].copy_from_slice(&[0x42; 32]);
        reportdata[32..64].copy_from_slice(&[0x37; 32]);
        let mrtd = [0xEE; 48];
        let rtmrs = [[0x11; 48], [0x22; 48], [0x33; 48], [0x44; 48]];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let verifier = TdxVerifier::new(None);
        let verified = verifier.verify(&doc).await.unwrap();

        assert_eq!(verified.public_key.as_deref(), Some([0x42; 32].as_ref()));
        assert_eq!(verified.nonce.as_deref(), Some([0x37; 32].as_ref()));
        assert_eq!(verified.measurements[&0], mrtd.to_vec());
        assert_eq!(verified.measurements[&1], rtmrs[0].to_vec());
        assert_eq!(verified.measurements[&2], rtmrs[1].to_vec());
        assert_eq!(verified.measurements[&3], rtmrs[2].to_vec());
        assert_eq!(verified.measurements[&4], rtmrs[3].to_vec());
    }

    #[tokio::test]
    async fn verifier_rejects_measurement_mismatch() {
        let reportdata = [0u8; 64];
        let mrtd = [0xEE; 48];
        let rtmrs = [[0u8; 48]; 4];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let verifier = TdxVerifier::new(Some(vec![0xFF; 48]));
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("MRTD mismatch"), "error: {err}");
    }

    #[tokio::test]
    async fn verifier_accepts_matching_measurement() {
        let reportdata = [0u8; 64];
        let mrtd = [0xAB; 48];
        let rtmrs = [[0u8; 48]; 4];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let verifier = TdxVerifier::new(Some(vec![0xAB; 48]));
        let verified = verifier.verify(&doc).await.unwrap();
        assert_eq!(verified.measurements[&0], vec![0xAB; 48]);
    }

    #[tokio::test]
    async fn verifier_none_for_zero_pk_and_nonce() {
        let reportdata = [0u8; 64];
        let mrtd = [0u8; 48];
        let rtmrs = [[0u8; 48]; 4];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let verifier = TdxVerifier::new(None);
        let verified = verifier.verify(&doc).await.unwrap();

        assert!(verified.public_key.is_none());
        assert!(verified.nonce.is_none());
    }

    #[tokio::test]
    async fn verifier_rejects_invalid_document() {
        let verifier = TdxVerifier::new(None);
        let doc = AttestationDocument::new(b"INVALID".to_vec());
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_fails_outside_tdx() {
        // Skip if configfs-tsm path happens to exist (e.g., TDX-capable host or
        // CI runner with configfs mounted).
        if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
            return;
        }
        let result = TdxProvider::new();
        assert!(
            result.is_err(),
            "TdxProvider::new() should fail without configfs-tsm"
        );
        let err = match result {
            Err(e) => format!("{e}"),
            Ok(_) => unreachable!(),
        };
        assert!(
            err.contains("configfs-tsm") || err.contains("not running inside a TDX TD"),
            "error should mention configfs-tsm: {err}"
        );
    }
}
