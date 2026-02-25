use std::collections::BTreeMap;
use std::fmt;
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

// ---------------------------------------------------------------------------
// Structured TDX verification errors — M2 trust matrix codes
// ---------------------------------------------------------------------------

/// Structured error codes for TDX quote verification.
///
/// Each variant maps to a test case in the M2 trust verification matrix.
/// Codes follow the naming convention from `spec/internal/m2-trust-matrix.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TdxVerifyError {
    // -- T1_PARSE: Evidence shape --
    /// TDX-PARSE-001: Malformed quote bytes (corrupt, truncated, wrong marker).
    QuoteParseFailed(String),
    /// TDX-PARSE-002: Unsupported quote version, TEE type, or key type.
    QuoteUnsupportedFormat(String),

    // -- T2_CRYPTO: Signatures --
    /// TDX-CRYPTO-001: Quote ECDSA-P256 signature invalid.
    QuoteSigInvalid(String),
    /// TDX-CRYPTO-002: REPORTDATA/public key binding mismatch.
    ReportdataBindingMismatch { expected: String, actual: String },

    // -- T3_CHAIN: Trust chain (DCAP collateral) --
    /// TDX-CHAIN-001: Missing DCAP collateral bundle.
    CollateralMissing,
    /// TDX-CHAIN-002: Collateral expired or stale (nextUpdate passed).
    CollateralStale(String),
    /// TDX-CHAIN-003: PCK certificate chain invalid (wrong issuer/root).
    PckChainInvalid(String),
    /// TDX-CHAIN-004: QE identity signature invalid (tampered).
    QeIdentityInvalid(String),
    /// TDX-CHAIN-005: TCB info signature invalid (tampered).
    TcbInfoInvalid(String),
    /// TDX-CHAIN-006: FMSPC mismatch between quote and collateral.
    FmspcMismatch {
        quote_fmspc: String,
        collateral_fmspc: String,
    },
    /// TDX-CHAIN-007: PCK certificate revoked during validity window.
    PckRevoked,

    // -- T4_POLICY: Policy enforcement --
    /// TDX-POL-001/003: TCB status unacceptable under current policy.
    TcbStatusUnacceptable(String),
    /// TDX-POL-002: TCB revoked.
    TcbRevoked,
    /// TDX-POL-004: MRTD measurement mismatch.
    MrtdMismatch { expected: String, actual: String },
    /// TDX-POL-005: RTMR measurement mismatch.
    RtmrMismatch {
        register: usize,
        expected: String,
        actual: String,
    },
    /// TDX-POL-006: Nonce mismatch (REPORTDATA[32..64]).
    NonceMismatch { expected: String, actual: String },
    /// TDX-POL-007: Collateral not yet valid or clock skew detected.
    CollateralTimeInvalid(String),
}

impl fmt::Display for TdxVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuoteParseFailed(msg) => write!(f, "TDX_QUOTE_PARSE_FAILED: {msg}"),
            Self::QuoteUnsupportedFormat(msg) => {
                write!(f, "TDX_QUOTE_UNSUPPORTED_FORMAT: {msg}")
            }
            Self::QuoteSigInvalid(msg) => write!(f, "TDX_QUOTE_SIG_INVALID: {msg}"),
            Self::ReportdataBindingMismatch { expected, actual } => {
                write!(
                    f,
                    "TDX_REPORTDATA_BINDING_MISMATCH: expected {expected}, got {actual}"
                )
            }
            Self::CollateralMissing => write!(f, "TDX_COLLATERAL_MISSING"),
            Self::CollateralStale(msg) => write!(f, "TDX_COLLATERAL_STALE: {msg}"),
            Self::PckChainInvalid(msg) => write!(f, "TDX_PCK_CHAIN_INVALID: {msg}"),
            Self::QeIdentityInvalid(msg) => write!(f, "TDX_QE_IDENTITY_INVALID: {msg}"),
            Self::TcbInfoInvalid(msg) => write!(f, "TDX_TCB_INFO_INVALID: {msg}"),
            Self::FmspcMismatch {
                quote_fmspc,
                collateral_fmspc,
            } => {
                write!(
                    f,
                    "TDX_FMSPC_MISMATCH: quote={quote_fmspc}, collateral={collateral_fmspc}"
                )
            }
            Self::PckRevoked => write!(f, "TDX_PCK_REVOKED"),
            Self::TcbStatusUnacceptable(msg) => {
                write!(f, "TDX_TCB_STATUS_UNACCEPTABLE: {msg}")
            }
            Self::TcbRevoked => write!(f, "TDX_TCB_REVOKED"),
            Self::MrtdMismatch { expected, actual } => {
                write!(f, "TDX_MRTD_MISMATCH: expected {expected}, got {actual}")
            }
            Self::RtmrMismatch {
                register,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "TDX_RTMR_MISMATCH: rtmr[{register}] expected {expected}, got {actual}"
                )
            }
            Self::NonceMismatch { expected, actual } => {
                write!(f, "TDX_NONCE_MISMATCH: expected {expected}, got {actual}")
            }
            Self::CollateralTimeInvalid(msg) => {
                write!(f, "TDX_COLLATERAL_TIME_INVALID: {msg}")
            }
        }
    }
}

impl std::error::Error for TdxVerifyError {}

impl From<TdxVerifyError> for AttestError {
    fn from(e: TdxVerifyError) -> Self {
        AttestError::VerificationFailed(e.to_string())
    }
}

/// Returns the M2 matrix code string for a `TdxVerifyError`.
///
/// Useful for programmatic matching in integration tests.
impl TdxVerifyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::QuoteParseFailed(_) => "TDX_QUOTE_PARSE_FAILED",
            Self::QuoteUnsupportedFormat(_) => "TDX_QUOTE_UNSUPPORTED_FORMAT",
            Self::QuoteSigInvalid(_) => "TDX_QUOTE_SIG_INVALID",
            Self::ReportdataBindingMismatch { .. } => "TDX_REPORTDATA_BINDING_MISMATCH",
            Self::CollateralMissing => "TDX_COLLATERAL_MISSING",
            Self::CollateralStale(_) => "TDX_COLLATERAL_STALE",
            Self::PckChainInvalid(_) => "TDX_PCK_CHAIN_INVALID",
            Self::QeIdentityInvalid(_) => "TDX_QE_IDENTITY_INVALID",
            Self::TcbInfoInvalid(_) => "TDX_TCB_INFO_INVALID",
            Self::FmspcMismatch { .. } => "TDX_FMSPC_MISMATCH",
            Self::PckRevoked => "TDX_PCK_REVOKED",
            Self::TcbStatusUnacceptable(_) => "TDX_TCB_STATUS_UNACCEPTABLE",
            Self::TcbRevoked => "TDX_TCB_REVOKED",
            Self::MrtdMismatch { .. } => "TDX_MRTD_MISMATCH",
            Self::RtmrMismatch { .. } => "TDX_RTMR_MISMATCH",
            Self::NonceMismatch { .. } => "TDX_NONCE_MISMATCH",
            Self::CollateralTimeInvalid(_) => "TDX_COLLATERAL_TIME_INVALID",
        }
    }

    /// Returns the M2 trust layer for this error.
    pub fn layer(&self) -> &'static str {
        match self {
            Self::QuoteParseFailed(_) | Self::QuoteUnsupportedFormat(_) => "T1_PARSE",
            Self::QuoteSigInvalid(_) | Self::ReportdataBindingMismatch { .. } => "T2_CRYPTO",
            Self::CollateralMissing
            | Self::CollateralStale(_)
            | Self::PckChainInvalid(_)
            | Self::QeIdentityInvalid(_)
            | Self::TcbInfoInvalid(_)
            | Self::FmspcMismatch { .. }
            | Self::PckRevoked => "T3_CHAIN",
            Self::TcbStatusUnacceptable(_)
            | Self::TcbRevoked
            | Self::MrtdMismatch { .. }
            | Self::RtmrMismatch { .. }
            | Self::NonceMismatch { .. }
            | Self::CollateralTimeInvalid(_) => "T4_POLICY",
        }
    }
}

// ---------------------------------------------------------------------------
// TDX verification policy
// ---------------------------------------------------------------------------

/// Policy configuration for TDX quote verification (T4_POLICY layer).
///
/// Controls which policy checks the verifier enforces. Only fields that are
/// `Some` or non-empty are checked; unset fields are ignored.
#[derive(Debug, Clone, Default)]
pub struct TdxVerifyPolicy {
    /// Expected MRTD value (48 bytes). TDX-POL-004.
    pub expected_mrtd: Option<Vec<u8>>,
    /// Expected RTMR values, keyed by register index (0-3). TDX-POL-005.
    pub expected_rtmrs: BTreeMap<usize, Vec<u8>>,
    /// Expected nonce from REPORTDATA\[32..64\] (32 bytes). TDX-POL-006.
    pub expected_nonce: Option<Vec<u8>>,
    /// Expected public key from REPORTDATA\[0..32\] (32 bytes). TDX-CRYPTO-002.
    pub expected_public_key: Option<Vec<u8>>,
    /// DCAP collateral for T3_CHAIN verification.
    pub collateral: Option<TdxCollateral>,
    /// Whether collateral verification is required (fail-closed if missing).
    pub require_collateral: bool,
}

/// DCAP collateral bundle for TDX quote trust chain verification (T3_CHAIN).
///
/// Contains the trust anchor and certificate chain needed to verify that
/// the TDX quote was produced by a genuine Intel platform.
#[derive(Debug, Clone)]
pub struct TdxCollateral {
    /// Root CA certificate (DER-encoded X.509). Trust anchor.
    pub root_ca_der: Vec<u8>,
    /// PCK certificate chain (DER-encoded X.509, leaf first).
    /// The leaf cert's public key should correspond to the attestation key.
    pub pck_chain_der: Vec<Vec<u8>>,
    /// Optional CRL for revocation checking (DER-encoded).
    /// If provided, the verifier enables CRL checking against this list.
    pub crl_der: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// configfs-tsm RAII guard (Linux only)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// TDX attestation provider (configfs-tsm, Linux only)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// TDX attestation verifier
// ---------------------------------------------------------------------------

/// Verifier for Intel TDX attestation quotes.
///
/// Validates the quote by:
/// 1. Parsing the wire document (marker + quote) — T1_PARSE
/// 2. Parsing the quote header (version, TEE type, key type) — T1_PARSE
/// 3. Parsing the TD quote body (MRTD, RTMRs, REPORTDATA) — T1_PARSE
/// 4. Verifying the ECDSA-P256 signature over header + body — T2_CRYPTO
/// 5. Enforcing measurement and binding policies — T4_POLICY
///
/// Full DCAP collateral verification (T3_CHAIN: PCK cert chain, QE identity,
/// TCB info) is deferred to a future `tdx-dcap` feature.
pub struct TdxVerifier {
    policy: TdxVerifyPolicy,
}

impl TdxVerifier {
    /// Create a new verifier with optional MRTD pinning (backward-compatible).
    ///
    /// If `expected_mrtd` is `Some`, the verifier will check that the quote's
    /// MRTD field (48 bytes) matches the expected value.
    pub fn new(expected_mrtd: Option<Vec<u8>>) -> Self {
        Self {
            policy: TdxVerifyPolicy {
                expected_mrtd,
                ..Default::default()
            },
        }
    }

    /// Create a verifier with a full policy configuration.
    pub fn with_policy(policy: TdxVerifyPolicy) -> Self {
        Self { policy }
    }

    /// Verify a TDX attestation document with structured error codes.
    ///
    /// Returns `TdxVerifyError` with the exact M2 matrix code on failure.
    /// Use this method when you need programmatic access to the failure reason.
    pub fn verify_tdx(
        &self,
        doc: &AttestationDocument,
    ) -> Result<VerifiedAttestation, TdxVerifyError> {
        // T1_PARSE: Decode wire document.
        let quote = decode_tdx_document(&doc.raw)?;

        // T1_PARSE: Parse and validate quote header.
        let header = TdxQuoteHeader::parse(&quote)?;

        // T1_PARSE: Determine body size from version.
        let body_size = match header.version {
            4 => BODY_SIZE_V4,
            5 => BODY_SIZE_V5,
            v => {
                return Err(TdxVerifyError::QuoteUnsupportedFormat(format!(
                    "unsupported TDX quote version: {v} (expected 4 or 5)"
                )))
            }
        };

        if quote.len() < HEADER_SIZE + body_size + 4 {
            return Err(TdxVerifyError::QuoteParseFailed(format!(
                "TDX quote too short for body: need at least {} bytes, got {}",
                HEADER_SIZE + body_size + 4,
                quote.len()
            )));
        }

        // T1_PARSE: Parse TD quote body.
        let body = TdxQuoteBody::parse(&quote[HEADER_SIZE..HEADER_SIZE + body_size])?;

        // T2_CRYPTO: Verify ECDSA-P256 signature.
        //
        // WARNING: This verifies that the quote's signature is valid for the
        // public key embedded IN the quote itself. It does NOT verify that
        // the signing key belongs to a genuine Intel Quoting Enclave (QE).
        // Full DCAP collateral verification (PCK cert chain, QE identity,
        // TCB info) is required for production use — see T3_CHAIN.
        tracing::warn!(
            "TDX quote signature verified against embedded key. \
             Collateral verification here is partial (PCK chain/CRL only); \
             QE identity, TCB info, and FMSPC checks are not implemented yet. \
             Do not treat this as full DCAP verification."
        );
        let sig_section_offset = HEADER_SIZE + body_size;
        let quote_attestation_key =
            verify_ecdsa_signature(&quote, sig_section_offset, HEADER_SIZE + body_size)?;

        // T3_CHAIN: DCAP collateral verification.
        if self.policy.require_collateral {
            let collateral = self
                .policy
                .collateral
                .as_ref()
                .ok_or(TdxVerifyError::CollateralMissing)?;
            verify_pck_chain(collateral, Some(&quote_attestation_key))?;
        } else if let Some(ref collateral) = self.policy.collateral {
            // Collateral provided but not required — verify if present.
            verify_pck_chain(collateral, Some(&quote_attestation_key))?;
        }

        // Extract REPORTDATA fields.
        let public_key = body.reportdata[..32].to_vec();
        let nonce = body.reportdata[32..64].to_vec();

        // Build measurements map.
        let mut measurements = BTreeMap::new();
        measurements.insert(0, body.mrtd.to_vec());
        measurements.insert(1, body.rtmr0.to_vec());
        measurements.insert(2, body.rtmr1.to_vec());
        measurements.insert(3, body.rtmr2.to_vec());
        measurements.insert(4, body.rtmr3.to_vec());

        // T4_POLICY: MRTD pinning (TDX-POL-004).
        if let Some(ref expected) = self.policy.expected_mrtd {
            if expected.as_slice() != body.mrtd.as_slice() {
                return Err(TdxVerifyError::MrtdMismatch {
                    expected: hex::encode(expected),
                    actual: hex::encode(body.mrtd),
                });
            }
        }

        // T4_POLICY: RTMR pinning (TDX-POL-005).
        let rtmrs = [&body.rtmr0, &body.rtmr1, &body.rtmr2, &body.rtmr3];
        for (&idx, expected) in &self.policy.expected_rtmrs {
            if idx > 3 {
                return Err(TdxVerifyError::RtmrMismatch {
                    register: idx,
                    expected: hex::encode(expected),
                    actual: "N/A (invalid register index)".into(),
                });
            }
            if expected.as_slice() != rtmrs[idx].as_slice() {
                return Err(TdxVerifyError::RtmrMismatch {
                    register: idx,
                    expected: hex::encode(expected),
                    actual: hex::encode(rtmrs[idx]),
                });
            }
        }

        // T4_POLICY: Nonce binding (TDX-POL-006).
        if let Some(ref expected) = self.policy.expected_nonce {
            if expected.as_slice() != &body.reportdata[32..64] {
                return Err(TdxVerifyError::NonceMismatch {
                    expected: hex::encode(expected),
                    actual: hex::encode(&body.reportdata[32..64]),
                });
            }
        }

        // T2_CRYPTO/T4_POLICY: Public key binding (TDX-CRYPTO-002).
        if let Some(ref expected) = self.policy.expected_public_key {
            if expected.as_slice() != &body.reportdata[..32] {
                return Err(TdxVerifyError::ReportdataBindingMismatch {
                    expected: hex::encode(expected),
                    actual: hex::encode(&body.reportdata[..32]),
                });
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

#[async_trait]
impl AttestationVerifier for TdxVerifier {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        self.verify_tdx(doc).map_err(AttestError::from)
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
fn decode_tdx_document(raw: &[u8]) -> Result<Vec<u8>, TdxVerifyError> {
    if raw.len() < 12 {
        return Err(TdxVerifyError::QuoteParseFailed(
            "document too short for TDX marker".into(),
        ));
    }

    if &raw[..12] != TDX_MARKER {
        return Err(TdxVerifyError::QuoteParseFailed(
            "not a TDX attestation document (wrong marker)".into(),
        ));
    }

    if raw.len() < 16 {
        return Err(TdxVerifyError::QuoteParseFailed(
            "truncated TDX document (missing quote_size)".into(),
        ));
    }

    let quote_size = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;

    if raw.len() < 16 + quote_size {
        return Err(TdxVerifyError::QuoteParseFailed(
            "truncated TDX document (quote data incomplete)".into(),
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
    fn parse(data: &[u8]) -> Result<Self, TdxVerifyError> {
        if data.len() < HEADER_SIZE {
            return Err(TdxVerifyError::QuoteParseFailed(format!(
                "TDX quote too short for header: need {HEADER_SIZE} bytes, got {}",
                data.len()
            )));
        }

        let version = u16::from_le_bytes([data[0], data[1]]);
        let att_key_type = u16::from_le_bytes([data[2], data[3]]);
        let tee_type = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        if version != 4 && version != 5 {
            return Err(TdxVerifyError::QuoteUnsupportedFormat(format!(
                "unsupported TDX quote version: {version} (expected 4 or 5)"
            )));
        }

        if tee_type != TEE_TYPE_TDX {
            return Err(TdxVerifyError::QuoteUnsupportedFormat(format!(
                "wrong TEE type: expected 0x{TEE_TYPE_TDX:08X}, got 0x{tee_type:08X}"
            )));
        }

        if att_key_type != ATT_KEY_TYPE_P256 {
            return Err(TdxVerifyError::QuoteUnsupportedFormat(format!(
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
    fn parse(body: &[u8]) -> Result<Self, TdxVerifyError> {
        // Minimum body size is v4 (584 bytes).
        if body.len() < BODY_SIZE_V4 {
            return Err(TdxVerifyError::QuoteParseFailed(format!(
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
) -> Result<[u8; ECDSA_PUBKEY_SIZE], TdxVerifyError> {
    if quote.len() < sig_offset + 4 {
        return Err(TdxVerifyError::QuoteParseFailed(
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
        return Err(TdxVerifyError::QuoteParseFailed(
            "TDX quote truncated in signature data".into(),
        ));
    }

    if sig_data_len < ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE {
        return Err(TdxVerifyError::QuoteParseFailed(format!(
            "signature data too short: need at least {} bytes, got {sig_data_len}",
            ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE
        )));
    }

    let sig_data = &quote[sig_offset + 4..sig_offset + 4 + sig_data_len];
    let sig_bytes = &sig_data[..ECDSA_SIG_SIZE];
    let pubkey_bytes = &sig_data[ECDSA_SIG_SIZE..ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE];
    let mut quote_pubkey_xy = [0u8; ECDSA_PUBKEY_SIZE];
    quote_pubkey_xy.copy_from_slice(pubkey_bytes);

    // Build the ECDSA public key from raw x || y coordinates.
    let mut uncompressed = vec![0x04u8]; // uncompressed point prefix
    uncompressed.extend_from_slice(pubkey_bytes);

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
        .map_err(|e| {
            TdxVerifyError::QuoteSigInvalid(format!("failed to create P-256 group: {e}"))
        })?;

    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| {
        TdxVerifyError::QuoteSigInvalid(format!("failed to create BigNumContext: {e}"))
    })?;

    let point = openssl::ec::EcPoint::from_bytes(&group, &uncompressed, &mut ctx).map_err(|e| {
        TdxVerifyError::QuoteSigInvalid(format!("failed to parse attestation public key: {e}"))
    })?;

    let ec_key = openssl::ec::EcKey::from_public_key(&group, &point)
        .map_err(|e| TdxVerifyError::QuoteSigInvalid(format!("failed to build EC key: {e}")))?;

    let pkey = openssl::pkey::PKey::from_ec_key(ec_key)
        .map_err(|e| TdxVerifyError::QuoteSigInvalid(format!("failed to build PKey: {e}")))?;

    // Convert raw signature (r || s) to DER-encoded ECDSA signature.
    let r = openssl::bn::BigNum::from_slice(&sig_bytes[..32]).map_err(|e| {
        TdxVerifyError::QuoteSigInvalid(format!("failed to parse signature r: {e}"))
    })?;
    let s = openssl::bn::BigNum::from_slice(&sig_bytes[32..64]).map_err(|e| {
        TdxVerifyError::QuoteSigInvalid(format!("failed to parse signature s: {e}"))
    })?;

    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).map_err(|e| {
        TdxVerifyError::QuoteSigInvalid(format!("failed to build ECDSA signature: {e}"))
    })?;

    let der_sig = ecdsa_sig.to_der().map_err(|e| {
        TdxVerifyError::QuoteSigInvalid(format!("failed to encode signature to DER: {e}"))
    })?;

    // Verify the ECDSA signature over the raw signed data (header + body).
    // OpenSSL's verify_oneshot will hash the data internally with SHA-256.
    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .map_err(|e| TdxVerifyError::QuoteSigInvalid(format!("failed to create verifier: {e}")))?;

    let valid = verifier
        .verify_oneshot(&der_sig, &quote[..signed_len])
        .map_err(|e| TdxVerifyError::QuoteSigInvalid(format!("ECDSA verification error: {e}")))?;

    if !valid {
        return Err(TdxVerifyError::QuoteSigInvalid(
            "TDX quote ECDSA-P256 signature verification failed".into(),
        ));
    }

    Ok(quote_pubkey_xy)
}

/// Verify the PCK certificate chain against the trust anchor (T3_CHAIN).
///
/// Checks:
/// - Certificate chain verifies up to the root CA (TDX-CHAIN-003)
/// - Leaf certificate is not expired (TDX-CHAIN-002)
/// - Leaf certificate is not before its validity period (TDX-POL-007)
/// - Certificate is not revoked if CRL is provided (TDX-CHAIN-007)
fn verify_pck_chain(
    collateral: &TdxCollateral,
    expected_quote_attestation_key_xy: Option<&[u8]>,
) -> Result<(), TdxVerifyError> {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509StoreContext, X509};
    use std::cmp::Ordering;

    // Parse root CA.
    let root_ca = X509::from_der(&collateral.root_ca_der)
        .map_err(|e| TdxVerifyError::PckChainInvalid(format!("failed to parse root CA: {e}")))?;
    let root_ca_for_crl = root_ca.clone();

    // Build trust store with root CA.
    let mut store_builder = X509StoreBuilder::new().map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!("failed to create X509 store: {e}"))
    })?;
    store_builder.add_cert(root_ca).map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!("failed to add root CA to store: {e}"))
    })?;

    let store = store_builder.build();

    // Parse chain certs.
    if collateral.pck_chain_der.is_empty() {
        return Err(TdxVerifyError::PckChainInvalid(
            "empty certificate chain".into(),
        ));
    }

    let leaf_cert = X509::from_der(&collateral.pck_chain_der[0])
        .map_err(|e| TdxVerifyError::PckChainInvalid(format!("failed to parse leaf cert: {e}")))?;
    let leaf_pubkey_xy = extract_leaf_p256_pubkey_xy(&leaf_cert)?;

    let mut chain = Stack::new().map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!("failed to create cert stack: {e}"))
    })?;
    let mut issuer_cert_for_crl: Option<X509> = None;
    for (i, cert_der) in collateral.pck_chain_der.iter().skip(1).enumerate() {
        let cert = X509::from_der(cert_der).map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to parse chain cert[{i}]: {e}"))
        })?;
        if i == 0 {
            issuer_cert_for_crl = Some(cert.clone());
        }
        chain.push(cert).map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to push chain cert: {e}"))
        })?;
    }

    // Verify chain — capture the error code if verification fails.
    let mut context = X509StoreContext::new().map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!("failed to create verify context: {e}"))
    })?;

    let (valid, verify_err) = context
        .init(&store, &leaf_cert, &chain, |ctx| {
            let ok = ctx.verify_cert()?;
            let err = if !ok { Some(ctx.error()) } else { None };
            Ok((ok, err))
        })
        .map_err(|e| TdxVerifyError::PckChainInvalid(format!("chain verification error: {e}")))?;

    if !valid {
        // Map OpenSSL X509_V_ERR_* codes to structured TdxVerifyError variants.
        // Using openssl_sys named constants for clarity across OpenSSL versions.
        if let Some(err) = verify_err {
            let code = err.as_raw();
            if code == openssl_sys::X509_V_ERR_CERT_REVOKED {
                return Err(TdxVerifyError::PckRevoked);
            } else if code == openssl_sys::X509_V_ERR_CERT_HAS_EXPIRED {
                return Err(TdxVerifyError::CollateralStale(format!(
                    "PCK certificate expired: {}",
                    err.error_string()
                )));
            } else if code == openssl_sys::X509_V_ERR_CERT_NOT_YET_VALID {
                return Err(TdxVerifyError::CollateralTimeInvalid(format!(
                    "PCK certificate not yet valid: {}",
                    err.error_string()
                )));
            } else {
                return Err(TdxVerifyError::PckChainInvalid(format!(
                    "chain verification failed: {}",
                    err.error_string()
                )));
            }
        }
        return Err(TdxVerifyError::PckChainInvalid(
            "certificate chain verification failed".into(),
        ));
    }

    // Bind the trusted PCK leaf cert to the quote's attestation key (x||y).
    if let Some(expected_xy) = expected_quote_attestation_key_xy {
        if leaf_pubkey_xy.as_slice() != expected_xy {
            return Err(TdxVerifyError::PckChainInvalid(
                "PCK leaf certificate public key does not match quote attestation key".into(),
            ));
        }
    }

    // T3_CHAIN-007: Manual CRL revocation check (separate from chain verification).
    if let Some(ref crl_der) = collateral.crl_der {
        let crl = openssl::x509::X509Crl::from_der(crl_der)
            .map_err(|e| TdxVerifyError::PckChainInvalid(format!("failed to parse CRL: {e}")))?;
        let crl_issuer = crl.issuer_name();
        let expected_crl_issuer = issuer_cert_for_crl
            .as_ref()
            .map(|c| c.subject_name())
            .unwrap_or_else(|| root_ca_for_crl.subject_name());
        let issuer_cmp = crl_issuer.try_cmp(expected_crl_issuer).map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to compare CRL issuer names: {e}"))
        })?;
        if issuer_cmp != Ordering::Equal {
            return Err(TdxVerifyError::PckChainInvalid(
                "CRL issuer does not match PCK issuer".into(),
            ));
        }

        let issuer_pubkey = issuer_cert_for_crl
            .as_ref()
            .unwrap_or(&root_ca_for_crl)
            .public_key()
            .map_err(|e| {
                TdxVerifyError::PckChainInvalid(format!("failed to read CRL issuer key: {e}"))
            })?;
        let crl_sig_ok = crl.verify(&issuer_pubkey).map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to verify CRL signature: {e}"))
        })?;
        if !crl_sig_ok {
            return Err(TdxVerifyError::PckChainInvalid(
                "CRL signature verification failed".into(),
            ));
        }

        let now = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to get current time: {e}"))
        })?;
        if crl.last_update().compare(&now).map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to compare CRL lastUpdate: {e}"))
        })? == Ordering::Greater
        {
            return Err(TdxVerifyError::CollateralTimeInvalid(
                "CRL lastUpdate is in the future".into(),
            ));
        }
        let next_update = crl
            .next_update()
            .ok_or_else(|| TdxVerifyError::CollateralStale("CRL missing nextUpdate".into()))?;
        if next_update.compare(&now).map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to compare CRL nextUpdate: {e}"))
        })? == Ordering::Less
        {
            return Err(TdxVerifyError::CollateralStale(
                "CRL nextUpdate has passed".into(),
            ));
        }

        match crl.get_by_cert(&leaf_cert) {
            openssl::x509::CrlStatus::Revoked(_) => {
                return Err(TdxVerifyError::PckRevoked);
            }
            _ => { /* Not revoked, continue */ }
        }
    }

    Ok(())
}

fn extract_leaf_p256_pubkey_xy(
    leaf_cert: &openssl::x509::X509Ref,
) -> Result<[u8; ECDSA_PUBKEY_SIZE], TdxVerifyError> {
    let pkey = leaf_cert.public_key().map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!("failed to get leaf public key: {e}"))
    })?;
    let ec_key = pkey.ec_key().map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!("leaf public key is not EC P-256: {e}"))
    })?;
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
        .map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to create P-256 group: {e}"))
        })?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!("failed to create BigNumContext: {e}"))
    })?;
    let bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|e| {
            TdxVerifyError::PckChainInvalid(format!("failed to encode leaf public key: {e}"))
        })?;
    if bytes.len() != ECDSA_PUBKEY_SIZE + 1 || bytes[0] != 0x04 {
        return Err(TdxVerifyError::PckChainInvalid(format!(
            "unexpected leaf public key encoding length: {}",
            bytes.len()
        )));
    }
    let mut xy = [0u8; ECDSA_PUBKEY_SIZE];
    xy.copy_from_slice(&bytes[1..]);
    Ok(xy)
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
    build_synthetic_tdx_quote_ext(reportdata, mrtd, rtmrs, 4, TEE_TYPE_TDX, ATT_KEY_TYPE_P256)
}

/// Extended synthetic quote builder with configurable header fields.
///
/// Used to generate fixtures for TDX-PARSE-002 (wrong version/type).
#[doc(hidden)]
pub fn build_synthetic_tdx_quote_ext(
    reportdata: [u8; 64],
    mrtd: [u8; 48],
    rtmrs: [[u8; 48]; 4],
    version: u16,
    tee_type: u32,
    att_key_type: u16,
) -> Vec<u8> {
    // -- Header (48 bytes) --
    let mut quote = Vec::with_capacity(1024);

    quote.extend_from_slice(&version.to_le_bytes());
    quote.extend_from_slice(&att_key_type.to_le_bytes());
    quote.extend_from_slice(&tee_type.to_le_bytes());
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

/// Build a synthetic TDX v4 quote signed with a provided ECDSA-P256 key.
///
/// Used for T3_CHAIN tests where the quote must be signed by a key whose
/// certificate is in a specific trust chain.
#[doc(hidden)]
pub fn build_synthetic_tdx_quote_with_key(
    reportdata: [u8; 64],
    mrtd: [u8; 48],
    rtmrs: [[u8; 48]; 4],
    signing_key: &openssl::ec::EcKey<openssl::pkey::Private>,
) -> Vec<u8> {
    // -- Header (48 bytes) --
    let mut quote = Vec::with_capacity(1024);

    quote.extend_from_slice(&4u16.to_le_bytes()); // version = 4
    quote.extend_from_slice(&ATT_KEY_TYPE_P256.to_le_bytes());
    quote.extend_from_slice(&TEE_TYPE_TDX.to_le_bytes());
    quote.extend_from_slice(&0u16.to_le_bytes()); // qe_svn
    quote.extend_from_slice(&0u16.to_le_bytes()); // pce_svn
    quote.extend_from_slice(&[0u8; 16]); // qe_vendor_id
    quote.extend_from_slice(&[0u8; 20]); // user_data
    assert_eq!(quote.len(), HEADER_SIZE);

    // -- TD Quote Body (584 bytes for v4) --
    let body_start = quote.len();
    quote.extend_from_slice(&[0u8; 16]); // tee_tcb_svn
    quote.extend_from_slice(&[0u8; 48]); // mrseam
    quote.extend_from_slice(&[0u8; 48]); // mrsignerseam
    quote.extend_from_slice(&[0u8; 8]); // seam_attributes
    quote.extend_from_slice(&[0u8; 8]); // td_attributes
    quote.extend_from_slice(&[0u8; 8]); // xfam
    assert_eq!(quote.len() - body_start, MRTD_OFFSET);
    quote.extend_from_slice(&mrtd);
    quote.extend_from_slice(&[0u8; 48]); // mrconfigid
    quote.extend_from_slice(&[0u8; 48]); // mrowner
    quote.extend_from_slice(&[0u8; 48]); // mrownerconfig
    assert_eq!(quote.len() - body_start, RTMR0_OFFSET);
    quote.extend_from_slice(&rtmrs[0]);
    quote.extend_from_slice(&rtmrs[1]);
    quote.extend_from_slice(&rtmrs[2]);
    quote.extend_from_slice(&rtmrs[3]);
    assert_eq!(quote.len() - body_start, REPORTDATA_OFFSET);
    quote.extend_from_slice(&reportdata);
    assert_eq!(quote.len() - body_start, BODY_SIZE_V4);

    // -- Signature Section (signed with provided key) --
    let signed_len = quote.len();
    let pkey = openssl::pkey::PKey::from_ec_key(signing_key.clone()).expect("pkey");

    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("signer");
    let der_sig = signer
        .sign_oneshot_to_vec(&quote[..signed_len])
        .expect("sign");

    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_der(&der_sig).expect("parse DER sig");
    let r = ecdsa_sig.r().to_vec_padded(32).expect("r");
    let s = ecdsa_sig.s().to_vec_padded(32).expect("s");

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
        .expect("P-256 group");
    let mut ctx = openssl::bn::BigNumContext::new().expect("ctx");
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .expect("pubkey bytes");
    let pubkey_xy = &pubkey_bytes[1..];

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

    // -----------------------------------------------------------------------
    // Helpers for M2 matrix fixtures
    // -----------------------------------------------------------------------

    /// Build a valid synthetic quote and wrap it in the wire format.
    fn valid_fixture() -> (Vec<u8>, AttestationDocument) {
        let mut reportdata = [0u8; 64];
        reportdata[..32].copy_from_slice(&[0x42; 32]);
        reportdata[32..64].copy_from_slice(&[0x37; 32]);
        let mrtd = [0xAA; 48];
        let rtmrs = [[0x11; 48], [0x22; 48], [0x33; 48], [0x44; 48]];
        let quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        (quote, doc)
    }

    /// Build a valid quote and tamper a single byte in the signed region.
    fn tampered_sig_fixture() -> AttestationDocument {
        let reportdata = [0u8; 64];
        let mrtd = [0xAA; 48];
        let rtmrs = [[0u8; 48]; 4];
        let mut quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        // Tamper a byte in the body (within signed region).
        quote[HEADER_SIZE + 10] ^= 0xFF;
        AttestationDocument::new(encode_tdx_document(&quote))
    }

    // -----------------------------------------------------------------------
    // Existing tests (updated for TdxVerifyError return types)
    // -----------------------------------------------------------------------

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
        assert!(matches!(result, Err(TdxVerifyError::QuoteParseFailed(_))));
        assert_eq!(result.unwrap_err().code(), "TDX_QUOTE_PARSE_FAILED");
    }

    #[test]
    fn reject_truncated_document() {
        let quote = vec![0xAA; 256];
        let encoded = encode_tdx_document(&quote);
        // Truncate in the middle of the quote.
        let truncated = &encoded[..20];
        let result = decode_tdx_document(truncated);
        assert!(matches!(result, Err(TdxVerifyError::QuoteParseFailed(_))));
    }

    #[test]
    fn reject_too_short_for_marker() {
        let result = decode_tdx_document(&[0u8; 5]);
        assert!(matches!(result, Err(TdxVerifyError::QuoteParseFailed(_))));
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
        assert!(matches!(result, Err(TdxVerifyError::QuoteSigInvalid(_))));
    }

    #[tokio::test]
    async fn verifier_extracts_fields() {
        let (_, doc) = valid_fixture();

        let verifier = TdxVerifier::new(None);
        let verified = verifier.verify(&doc).await.unwrap();

        assert_eq!(verified.public_key.as_deref(), Some([0x42; 32].as_ref()));
        assert_eq!(verified.nonce.as_deref(), Some([0x37; 32].as_ref()));
        assert_eq!(verified.measurements[&0], vec![0xAA; 48]);
        assert_eq!(verified.measurements[&1], vec![0x11; 48]);
        assert_eq!(verified.measurements[&2], vec![0x22; 48]);
        assert_eq!(verified.measurements[&3], vec![0x33; 48]);
        assert_eq!(verified.measurements[&4], vec![0x44; 48]);
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
        assert!(err.contains("TDX_MRTD_MISMATCH"), "error: {err}");
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

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T1_PARSE
    // -----------------------------------------------------------------------

    /// TDX-OK-001: Valid quote + no policy constraints → PASS
    #[test]
    fn tdx_ok_001_valid_quote_baseline() {
        let (_, doc) = valid_fixture();
        let verifier = TdxVerifier::new(None);
        let result = verifier.verify_tdx(&doc);
        assert!(result.is_ok(), "TDX-OK-001 failed: {:?}", result.err());
    }

    /// TDX-OK-001 variant: Valid quote + matching policy → PASS
    #[test]
    fn tdx_ok_001_valid_quote_with_matching_policy() {
        let (_, doc) = valid_fixture();
        let policy = TdxVerifyPolicy {
            expected_mrtd: Some(vec![0xAA; 48]),
            expected_rtmrs: {
                let mut m = BTreeMap::new();
                m.insert(0, vec![0x11; 48]);
                m.insert(1, vec![0x22; 48]);
                m.insert(2, vec![0x33; 48]);
                m.insert(3, vec![0x44; 48]);
                m
            },
            expected_nonce: Some(vec![0x37; 32]),
            expected_public_key: Some(vec![0x42; 32]),
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "TDX-OK-001 (full policy) failed: {:?}",
            result.err()
        );
    }

    /// TDX-PARSE-001: Malformed quote bytes (corrupt).
    #[test]
    fn tdx_parse_001_malformed_quote_corrupt() {
        let doc = AttestationDocument::new(encode_tdx_document(&[0xFF; 10]));
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_PARSE_FAILED");
        assert_eq!(err.layer(), "T1_PARSE");
    }

    /// TDX-PARSE-001: Malformed quote bytes (truncated header).
    #[test]
    fn tdx_parse_001_malformed_quote_truncated_header() {
        // Valid quote truncated to just the header (no body).
        let quote = vec![0u8; HEADER_SIZE - 1]; // too short for header
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_PARSE_FAILED");
    }

    /// TDX-PARSE-001: Malformed wire document (wrong marker).
    #[test]
    fn tdx_parse_001_wrong_marker() {
        let mut raw = vec![0u8; 100];
        raw[..6].copy_from_slice(b"BADTDX");
        let doc = AttestationDocument::new(raw);
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_PARSE_FAILED");
    }

    /// TDX-PARSE-001: Truncated wire document (quote data incomplete).
    #[test]
    fn tdx_parse_001_truncated_wire_document() {
        let quote = vec![0xAA; 256];
        let encoded = encode_tdx_document(&quote);
        // Truncate to cut off quote data.
        let truncated = encoded[..20].to_vec();
        let doc = AttestationDocument::new(truncated);
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_PARSE_FAILED");
    }

    /// TDX-PARSE-002: Unsupported quote version (v3).
    #[test]
    fn tdx_parse_002_unsupported_version() {
        let quote = build_synthetic_tdx_quote_ext(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            3, // unsupported version
            TEE_TYPE_TDX,
            ATT_KEY_TYPE_P256,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_UNSUPPORTED_FORMAT");
        assert_eq!(err.layer(), "T1_PARSE");
    }

    /// TDX-PARSE-002: Wrong TEE type (SGX instead of TDX).
    #[test]
    fn tdx_parse_002_wrong_tee_type() {
        let quote = build_synthetic_tdx_quote_ext(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            4,
            0x0000_0000, // SGX TEE type
            ATT_KEY_TYPE_P256,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_UNSUPPORTED_FORMAT");
    }

    /// TDX-PARSE-002: Unsupported attestation key type.
    #[test]
    fn tdx_parse_002_unsupported_key_type() {
        let quote = build_synthetic_tdx_quote_ext(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            4,
            TEE_TYPE_TDX,
            3, // unsupported key type
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_UNSUPPORTED_FORMAT");
    }

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T2_CRYPTO
    // -----------------------------------------------------------------------

    /// TDX-CRYPTO-001: Quote signature tampered (body mutated after signing).
    #[test]
    fn tdx_crypto_001_tampered_body() {
        let doc = tampered_sig_fixture();
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_SIG_INVALID");
        assert_eq!(err.layer(), "T2_CRYPTO");
    }

    /// TDX-CRYPTO-001: Quote signature tampered (signature bytes mutated).
    #[test]
    fn tdx_crypto_001_tampered_signature_bytes() {
        let reportdata = [0u8; 64];
        let mrtd = [0xAA; 48];
        let rtmrs = [[0u8; 48]; 4];
        let mut quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);

        // Mutate a byte in the signature section (offset after header + body + 4-byte len).
        let sig_offset = HEADER_SIZE + BODY_SIZE_V4 + 4;
        quote[sig_offset] ^= 0xFF;

        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QUOTE_SIG_INVALID");
    }

    /// TDX-CRYPTO-002: REPORTDATA/pubkey binding mismatch.
    #[test]
    fn tdx_crypto_002_reportdata_binding_mismatch() {
        let (_, doc) = valid_fixture();
        // The fixture has pk = [0x42; 32]. Pin a different key.
        let policy = TdxVerifyPolicy {
            expected_public_key: Some(vec![0xFF; 32]),
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_REPORTDATA_BINDING_MISMATCH");
        assert_eq!(err.layer(), "T2_CRYPTO");
    }

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T4_POLICY
    // -----------------------------------------------------------------------

    /// TDX-POL-004: MRTD mismatch.
    #[test]
    fn tdx_pol_004_mrtd_mismatch() {
        let (_, doc) = valid_fixture();
        // The fixture has mrtd = [0xAA; 48]. Pin a different value.
        let verifier = TdxVerifier::new(Some(vec![0xBB; 48]));
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_MRTD_MISMATCH");
        assert_eq!(err.layer(), "T4_POLICY");
        // Verify the error contains both expected and actual values.
        let msg = err.to_string();
        assert!(msg.contains(&hex::encode([0xBB; 48])));
        assert!(msg.contains(&hex::encode([0xAA; 48])));
    }

    /// TDX-POL-004: MRTD match passes.
    #[test]
    fn tdx_pol_004_mrtd_match() {
        let (_, doc) = valid_fixture();
        let verifier = TdxVerifier::new(Some(vec![0xAA; 48]));
        assert!(verifier.verify_tdx(&doc).is_ok());
    }

    /// TDX-POL-005: RTMR mismatch (single register).
    #[test]
    fn tdx_pol_005_rtmr_mismatch_single() {
        let (_, doc) = valid_fixture();
        let policy = TdxVerifyPolicy {
            expected_rtmrs: {
                let mut m = BTreeMap::new();
                // Fixture has rtmr1 = [0x22; 48]. Pin wrong value.
                m.insert(1, vec![0xFF; 48]);
                m
            },
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_RTMR_MISMATCH");
        assert_eq!(err.layer(), "T4_POLICY");
        match err {
            TdxVerifyError::RtmrMismatch { register, .. } => assert_eq!(register, 1),
            _ => panic!("expected RtmrMismatch"),
        }
    }

    /// TDX-POL-005: All RTMRs match passes.
    #[test]
    fn tdx_pol_005_rtmr_match() {
        let (_, doc) = valid_fixture();
        let policy = TdxVerifyPolicy {
            expected_rtmrs: {
                let mut m = BTreeMap::new();
                m.insert(0, vec![0x11; 48]);
                m.insert(1, vec![0x22; 48]);
                m.insert(2, vec![0x33; 48]);
                m.insert(3, vec![0x44; 48]);
                m
            },
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        assert!(verifier.verify_tdx(&doc).is_ok());
    }

    /// TDX-POL-006: Nonce mismatch.
    #[test]
    fn tdx_pol_006_nonce_mismatch() {
        let (_, doc) = valid_fixture();
        // Fixture has nonce = [0x37; 32]. Pin a different nonce.
        let policy = TdxVerifyPolicy {
            expected_nonce: Some(vec![0xAA; 32]),
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_NONCE_MISMATCH");
        assert_eq!(err.layer(), "T4_POLICY");
    }

    /// TDX-POL-006: Nonce match passes.
    #[test]
    fn tdx_pol_006_nonce_match() {
        let (_, doc) = valid_fixture();
        let policy = TdxVerifyPolicy {
            expected_nonce: Some(vec![0x37; 32]),
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        assert!(verifier.verify_tdx(&doc).is_ok());
    }

    // -----------------------------------------------------------------------
    // Error code metadata tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_code_strings_match_m2_matrix() {
        // Verify all code() strings follow the TDX_* naming convention.
        let cases: Vec<(TdxVerifyError, &str, &str)> = vec![
            (
                TdxVerifyError::QuoteParseFailed("test".into()),
                "TDX_QUOTE_PARSE_FAILED",
                "T1_PARSE",
            ),
            (
                TdxVerifyError::QuoteUnsupportedFormat("test".into()),
                "TDX_QUOTE_UNSUPPORTED_FORMAT",
                "T1_PARSE",
            ),
            (
                TdxVerifyError::QuoteSigInvalid("test".into()),
                "TDX_QUOTE_SIG_INVALID",
                "T2_CRYPTO",
            ),
            (
                TdxVerifyError::ReportdataBindingMismatch {
                    expected: "a".into(),
                    actual: "b".into(),
                },
                "TDX_REPORTDATA_BINDING_MISMATCH",
                "T2_CRYPTO",
            ),
            (
                TdxVerifyError::CollateralMissing,
                "TDX_COLLATERAL_MISSING",
                "T3_CHAIN",
            ),
            (
                TdxVerifyError::CollateralStale("test".into()),
                "TDX_COLLATERAL_STALE",
                "T3_CHAIN",
            ),
            (
                TdxVerifyError::PckChainInvalid("test".into()),
                "TDX_PCK_CHAIN_INVALID",
                "T3_CHAIN",
            ),
            (
                TdxVerifyError::QeIdentityInvalid("test".into()),
                "TDX_QE_IDENTITY_INVALID",
                "T3_CHAIN",
            ),
            (
                TdxVerifyError::TcbInfoInvalid("test".into()),
                "TDX_TCB_INFO_INVALID",
                "T3_CHAIN",
            ),
            (
                TdxVerifyError::FmspcMismatch {
                    quote_fmspc: "a".into(),
                    collateral_fmspc: "b".into(),
                },
                "TDX_FMSPC_MISMATCH",
                "T3_CHAIN",
            ),
            (TdxVerifyError::PckRevoked, "TDX_PCK_REVOKED", "T3_CHAIN"),
            (
                TdxVerifyError::TcbStatusUnacceptable("test".into()),
                "TDX_TCB_STATUS_UNACCEPTABLE",
                "T4_POLICY",
            ),
            (TdxVerifyError::TcbRevoked, "TDX_TCB_REVOKED", "T4_POLICY"),
            (
                TdxVerifyError::MrtdMismatch {
                    expected: "a".into(),
                    actual: "b".into(),
                },
                "TDX_MRTD_MISMATCH",
                "T4_POLICY",
            ),
            (
                TdxVerifyError::RtmrMismatch {
                    register: 0,
                    expected: "a".into(),
                    actual: "b".into(),
                },
                "TDX_RTMR_MISMATCH",
                "T4_POLICY",
            ),
            (
                TdxVerifyError::NonceMismatch {
                    expected: "a".into(),
                    actual: "b".into(),
                },
                "TDX_NONCE_MISMATCH",
                "T4_POLICY",
            ),
            (
                TdxVerifyError::CollateralTimeInvalid("test".into()),
                "TDX_COLLATERAL_TIME_INVALID",
                "T4_POLICY",
            ),
        ];

        for (error, expected_code, expected_layer) in cases {
            assert_eq!(error.code(), expected_code, "code mismatch for {error:?}");
            assert_eq!(
                error.layer(),
                expected_layer,
                "layer mismatch for {error:?}"
            );
            // Display should start with the code string.
            let display = error.to_string();
            assert!(
                display.starts_with(expected_code),
                "Display for {error:?} should start with {expected_code}: got {display}"
            );
        }
    }

    #[test]
    fn tdx_verify_error_converts_to_attest_error() {
        let tdx_err = TdxVerifyError::MrtdMismatch {
            expected: "aabb".into(),
            actual: "ccdd".into(),
        };
        let attest_err: AttestError = tdx_err.into();
        let msg = format!("{attest_err}");
        assert!(msg.contains("TDX_MRTD_MISMATCH"));
        assert!(msg.contains("aabb"));
        assert!(msg.contains("ccdd"));
    }

    // -----------------------------------------------------------------------
    // T3_CHAIN: DCAP collateral test fixtures and helpers
    // -----------------------------------------------------------------------

    /// Create an ECDSA-P256 keypair for certificate generation.
    fn gen_ec_key() -> openssl::ec::EcKey<openssl::pkey::Private> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        openssl::ec::EcKey::generate(&group).unwrap()
    }

    /// Build a self-signed CA certificate (valid for 365 days).
    fn build_test_ca(
        cn: &str,
    ) -> (
        Vec<u8>,
        openssl::pkey::PKey<openssl::pkey::Private>,
        openssl::x509::X509,
    ) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        use openssl::x509::{X509NameBuilder, X509};

        let ec_key = gen_ec_key();
        let key = PKey::from_ec_key(ec_key).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
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
        builder.set_pubkey(&key).unwrap();

        let bc = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(bc).unwrap();
        let ku = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap();
        builder.append_extension(ku).unwrap();

        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let der = cert.to_der().unwrap();
        (der, key, cert)
    }

    /// Build a leaf certificate signed by the given CA (valid for 365 days).
    fn build_test_leaf(
        cn: &str,
        ca_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        ca_cert: &openssl::x509::X509,
        leaf_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        serial: u32,
        not_before_days: u32,
        not_after_days: u32,
    ) -> (Vec<u8>, openssl::x509::X509) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::x509::{X509NameBuilder, X509};

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(not_before_days).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(not_after_days).unwrap())
            .unwrap();
        builder.set_pubkey(leaf_key).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();

        let cert = builder.build();
        let der = cert.to_der().unwrap();
        (der, cert)
    }

    /// Build an expired leaf certificate (notAfter in the past).
    fn build_expired_leaf(
        cn: &str,
        ca_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        ca_cert: &openssl::x509::X509,
        leaf_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> (Vec<u8>, openssl::x509::X509) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::x509::{X509NameBuilder, X509};

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(100).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        // Set notBefore and notAfter in the past.
        let past_begin = Asn1Time::from_unix(1_000_000).unwrap(); // 1970
        let past_end = Asn1Time::from_unix(2_000_000).unwrap(); // 1970
        builder.set_not_before(&past_begin).unwrap();
        builder.set_not_after(&past_end).unwrap();
        builder.set_pubkey(leaf_key).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();

        let cert = builder.build();
        let der = cert.to_der().unwrap();
        (der, cert)
    }

    /// Build a CRL that revokes a specific certificate serial number.
    ///
    /// Uses openssl-sys FFI directly because the openssl-rs high-level API
    /// does not expose CRL builder methods in version 0.10.x.
    fn build_test_crl(
        ca_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        ca_cert: &openssl::x509::X509,
        revoked_serial: u32,
    ) -> Vec<u8> {
        use foreign_types_shared::ForeignType;
        use openssl::bn::BigNum;
        use std::ptr;

        unsafe {
            // Create new CRL.
            let crl = openssl_sys::X509_CRL_new();
            assert!(!crl.is_null());

            // Set issuer name from CA cert.
            let issuer = openssl_sys::X509_get_subject_name(ca_cert.as_ptr());
            openssl_sys::X509_CRL_set_issuer_name(crl, issuer);

            // Set last/next update.
            let last_update = openssl_sys::ASN1_TIME_new();
            openssl_sys::X509_gmtime_adj(last_update, 0);
            openssl_sys::X509_CRL_set1_lastUpdate(crl, last_update);
            openssl_sys::ASN1_TIME_free(last_update);

            let next_update = openssl_sys::ASN1_TIME_new();
            openssl_sys::X509_gmtime_adj(next_update, 30 * 24 * 60 * 60);
            openssl_sys::X509_CRL_set1_nextUpdate(crl, next_update);
            openssl_sys::ASN1_TIME_free(next_update);

            // Create revoked entry.
            let revoked = openssl_sys::X509_REVOKED_new();
            assert!(!revoked.is_null());

            let serial_bn = BigNum::from_u32(revoked_serial).unwrap();
            let serial_asn1 = serial_bn.to_asn1_integer().unwrap();
            openssl_sys::X509_REVOKED_set_serialNumber(revoked, serial_asn1.as_ptr() as *mut _);

            let rev_date = openssl_sys::ASN1_TIME_new();
            openssl_sys::X509_gmtime_adj(rev_date, 0);
            openssl_sys::X509_REVOKED_set_revocationDate(revoked, rev_date);
            openssl_sys::ASN1_TIME_free(rev_date);

            // Add revoked entry to CRL (CRL takes ownership of revoked).
            openssl_sys::X509_CRL_add0_revoked(crl, revoked);
            openssl_sys::X509_CRL_sort(crl);

            // Sign the CRL.
            let evp_md = openssl_sys::EVP_sha256();
            let ret = openssl_sys::X509_CRL_sign(crl, ca_key.as_ptr() as *mut _, evp_md);
            assert!(ret > 0, "CRL signing failed");

            // Convert to DER.
            let mut der_ptr: *mut u8 = ptr::null_mut();
            let len = openssl_sys::i2d_X509_CRL(crl, &mut der_ptr);
            assert!(len > 0, "CRL DER encoding failed");

            let der = std::slice::from_raw_parts(der_ptr, len as usize).to_vec();

            // Clean up.
            openssl_sys::CRYPTO_free(
                der_ptr as *mut std::ffi::c_void,
                concat!(file!(), '\0').as_ptr() as *const _,
                line!() as i32,
            );
            openssl_sys::X509_CRL_free(crl);

            der
        }
    }

    /// Build a complete T3 test fixture: CA + leaf cert + quote signed by leaf key.
    fn t3_valid_fixture() -> (AttestationDocument, TdxCollateral) {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _leaf_cert) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let quote =
            build_synthetic_tdx_quote_with_key([0u8; 64], [0xAA; 48], [[0u8; 48]; 4], &leaf_ec);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
        };

        (doc, collateral)
    }

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T3_CHAIN
    // -----------------------------------------------------------------------

    /// TDX-CHAIN: Positive path — valid cert chain + valid quote → PASS.
    #[test]
    fn tdx_chain_positive_valid_cert_chain() {
        let (doc, collateral) = t3_valid_fixture();
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "T3 positive path failed: {:?}",
            result.err()
        );
    }

    /// TDX-CHAIN-001: Missing collateral bundle when required → CollateralMissing.
    #[test]
    fn tdx_chain_001_collateral_missing() {
        // Build a valid quote (no collateral needed for T1/T2).
        let (_, doc) = valid_fixture();
        let policy = TdxVerifyPolicy {
            require_collateral: true,
            collateral: None,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_COLLATERAL_MISSING");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    /// TDX-CHAIN-001: Collateral not required + not present → PASS (skip T3).
    #[test]
    fn tdx_chain_001_collateral_not_required_passes() {
        let (_, doc) = valid_fixture();
        let policy = TdxVerifyPolicy {
            require_collateral: false,
            collateral: None,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        assert!(verifier.verify_tdx(&doc).is_ok());
    }

    /// TDX-CHAIN-002: Expired PCK certificate → CollateralStale.
    #[test]
    fn tdx_chain_002_collateral_stale() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (expired_leaf_der, _) = build_expired_leaf("Expired PCK", &ca_key, &ca_cert, &leaf_key);

        let quote =
            build_synthetic_tdx_quote_with_key([0u8; 64], [0xAA; 48], [[0u8; 48]; 4], &leaf_ec);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![expired_leaf_der],
            crl_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_COLLATERAL_STALE");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    /// TDX-CHAIN-003: PCK cert chain signed by wrong CA → PckChainInvalid.
    #[test]
    fn tdx_chain_003_wrong_ca() {
        // Create two CAs — trust anchor is CA1, but cert is signed by CA2.
        let (root_der_1, _ca_key_1, _ca_cert_1) = build_test_ca("Trusted Root CA");
        let (_root_der_2, ca_key_2, ca_cert_2) = build_test_ca("Untrusted Root CA");

        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        // Leaf cert signed by CA2 (untrusted).
        let (leaf_der, _) =
            build_test_leaf("Wrong PCK", &ca_key_2, &ca_cert_2, &leaf_key, 2, 0, 365);

        let quote =
            build_synthetic_tdx_quote_with_key([0u8; 64], [0xAA; 48], [[0u8; 48]; 4], &leaf_ec);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let collateral = TdxCollateral {
            root_ca_der: root_der_1,       // Trust anchor is CA1.
            pck_chain_der: vec![leaf_der], // But leaf is signed by CA2.
            crl_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_PCK_CHAIN_INVALID");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    /// TDX-CHAIN-003: Empty certificate chain → PckChainInvalid.
    #[test]
    fn tdx_chain_003_empty_chain() {
        let (root_der, _, _) = build_test_ca("Test TDX Root CA");
        let (_, doc) = valid_fixture();

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![], // No certs.
            crl_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_PCK_CHAIN_INVALID");
    }

    /// TDX-CHAIN-003: Garbage DER in root CA → PckChainInvalid.
    #[test]
    fn tdx_chain_003_bad_root_ca_der() {
        let (_, doc) = valid_fixture();
        let collateral = TdxCollateral {
            root_ca_der: vec![0xFF; 50],         // Garbage.
            pck_chain_der: vec![vec![0xAA; 50]], // Also garbage but root fails first.
            crl_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_PCK_CHAIN_INVALID");
    }

    /// TDX-CHAIN-003: Leaf cert key does not match quote attestation key → PckChainInvalid.
    #[test]
    fn tdx_chain_003_leaf_key_mismatch() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");

        // Certificate key and quote signing key are intentionally different.
        let cert_leaf_ec = gen_ec_key();
        let cert_leaf_key = openssl::pkey::PKey::from_ec_key(cert_leaf_ec).unwrap();
        let (leaf_der, _) = build_test_leaf(
            "Mismatched PCK",
            &ca_key,
            &ca_cert,
            &cert_leaf_key,
            11,
            0,
            365,
        );

        let quote_leaf_ec = gen_ec_key();
        let quote = build_synthetic_tdx_quote_with_key(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            &quote_leaf_ec,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_PCK_CHAIN_INVALID");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    /// TDX-CHAIN-007: Revoked PCK certificate → PckRevoked.
    #[test]
    fn tdx_chain_007_pck_revoked() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let leaf_serial = 42u32;
        let (leaf_der, _) = build_test_leaf(
            "Revoked PCK",
            &ca_key,
            &ca_cert,
            &leaf_key,
            leaf_serial,
            0,
            365,
        );

        // Build CRL that revokes serial 42.
        let crl_der = build_test_crl(&ca_key, &ca_cert, leaf_serial);

        let quote =
            build_synthetic_tdx_quote_with_key([0u8; 64], [0xAA; 48], [[0u8; 48]; 4], &leaf_ec);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: Some(crl_der),
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_PCK_REVOKED");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    /// TDX-CHAIN-007: Non-revoked cert with CRL present → PASS.
    #[test]
    fn tdx_chain_007_crl_present_not_revoked() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) = build_test_leaf("Good PCK", &ca_key, &ca_cert, &leaf_key, 10, 0, 365);

        // CRL revokes serial 99 (not our cert's serial 10).
        let crl_der = build_test_crl(&ca_key, &ca_cert, 99);

        let quote =
            build_synthetic_tdx_quote_with_key([0u8; 64], [0xAA; 48], [[0u8; 48]; 4], &leaf_ec);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: Some(crl_der),
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        assert!(
            verifier.verify_tdx(&doc).is_ok(),
            "Non-revoked cert should pass with CRL present"
        );
    }

    /// TDX-CHAIN-007: CRL signed by wrong key is rejected before revocation lookup.
    #[test]
    fn tdx_chain_007_invalid_crl_signature_rejected() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) = build_test_leaf("Good PCK", &ca_key, &ca_cert, &leaf_key, 12, 0, 365);

        // Build CRL with CA issuer name but sign with a different key -> invalid signature.
        let wrong_signer_ec = gen_ec_key();
        let wrong_signer_key = openssl::pkey::PKey::from_ec_key(wrong_signer_ec).unwrap();
        let crl_der = build_test_crl(&wrong_signer_key, &ca_cert, 99);

        let quote =
            build_synthetic_tdx_quote_with_key([0u8; 64], [0xAA; 48], [[0u8; 48]; 4], &leaf_ec);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: Some(crl_der),
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_PCK_CHAIN_INVALID");
        assert_eq!(err.layer(), "T3_CHAIN");
    }
}
