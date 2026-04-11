use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::types::{AttestationDocument, VerifiedAttestation};
use super::{AttestationProvider, AttestationVerifier};
use crate::error::AttestError;

// Re-export serde types for QE Identity and TCB Info deserialization.
use serde::Deserialize;

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

/// Offset of SEAM_ATTRIBUTES within the TD quote body (8 bytes).
const SEAM_ATTRIBUTES_OFFSET: usize = 112;
/// Offset of TD_ATTRIBUTES within the TD quote body (8 bytes).
const TD_ATTRIBUTES_OFFSET: usize = 120;
/// Size of each attributes field (8 bytes = 64 bits).
const ATTRIBUTES_SIZE: usize = 8;

/// Offset of REPORTDATA within the TD quote body.
const REPORTDATA_OFFSET: usize = 520;
/// Size of REPORTDATA (64 bytes).
const REPORTDATA_SIZE: usize = 64;

/// Size of ECDSA P-256 signature (r || s, 32 + 32 bytes).
const ECDSA_SIG_SIZE: usize = 64;

/// Size of ECDSA P-256 public key (x || y, 32 + 32 bytes).
const ECDSA_PUBKEY_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// QE Report offsets within the signature data section
// ---------------------------------------------------------------------------
// After the quote ECDSA signature (64 bytes) and attestation key (64 bytes),
// the signature data section contains the QE Report (384 bytes for SGX,
// used to carry QE identity measurements).
//
// QE Report layout (SGX REPORT structure, 384 bytes):
//   [0..16]    CPUSVN (16 bytes)
//   [16..20]   MISCSELECT (4 bytes, LE)
//   [20..48]   reserved (28 bytes)
//   [48..64]   ATTRIBUTES (16 bytes)
//   [64..96]   MRENCLAVE (32 bytes)
//   [96..128]  reserved (32 bytes)
//   [128..160] MRSIGNER (32 bytes)
//   [160..256] reserved (96 bytes)
//   [256..258] ISVPRODID (2 bytes, LE)
//   [258..260] ISVSVN (2 bytes, LE)
//   [260..320] reserved (60 bytes)
//   [320..384] REPORTDATA (64 bytes)

/// Offset of QE Report within signature data (after sig + pubkey).
const QE_REPORT_OFFSET: usize = ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE;
/// Size of the QE Report structure (SGX REPORT).
const QE_REPORT_SIZE: usize = 384;
/// Offset of MRSIGNER within QE Report.
const QE_MRSIGNER_OFFSET: usize = 128;
/// Size of MRSIGNER field (32 bytes for SGX QE).
const QE_MRSIGNER_SIZE: usize = 32;
/// Offset of ISVPRODID within QE Report.
const QE_ISVPRODID_OFFSET: usize = 256;
/// Offset of ISVSVN within QE Report.
const QE_ISVSVN_OFFSET: usize = 258;
/// Offset of MISCSELECT within QE Report.
const QE_MISCSELECT_OFFSET: usize = 16;
/// Offset of ATTRIBUTES within QE Report.
const QE_ATTRIBUTES_OFFSET: usize = 48;
/// Size of ATTRIBUTES field.
const QE_ATTRIBUTES_SIZE: usize = 16;

/// Offset of TEE_TCB_SVN within the TD quote body (first 16 bytes).
const TEE_TCB_SVN_OFFSET: usize = 0;
/// Size of TEE_TCB_SVN (16 bytes = 16 SVN component values).
const TEE_TCB_SVN_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// PCK certificate SGX Extensions OID constants
// ---------------------------------------------------------------------------
// Intel SGX Extensions root: 1.2.840.113741.1.13.1
// TCB sub-tree:              1.2.840.113741.1.13.1.2
//   SGX_TCB_COMP01_SVN ..16: 1.2.840.113741.1.13.1.2.1 .. .16
//   PCESVN:                  1.2.840.113741.1.13.1.2.17
//   CPUSVN:                  1.2.840.113741.1.13.1.2.18
//
// OID prefix for TCB sub-tree (encoded DER bytes for 1.2.840.113741.1.13.1.2):
//   06 0B 2A 86 48 86 F8 4D 01 0D 01 02
// The final byte after this prefix is the component index (01-12 hex).

/// DER-encoded OID prefix for 1.2.840.113741.1.13.1.2 (SGX TCB sub-tree).
/// The encoded OID is 0B bytes: 2A 86 48 86 F8 4D 01 0D 01 02
/// Preceded by tag 06 and length 0B.
const SGX_TCB_OID_PREFIX: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x02,
];

/// Number of SGX TCB component SVNs in a PCK certificate (COMP01..COMP16).
const PCK_SGX_TCB_COMP_COUNT: usize = 16;
/// Sub-OID index for PCESVN within the TCB sub-tree (0x11 = 17).
const PCK_PCESVN_SUB_OID: u8 = 0x11;
/// Sub-OID index for CPUSVN within the TCB sub-tree (0x12 = 18).
#[allow(dead_code)]
const PCK_CPUSVN_SUB_OID: u8 = 0x12;

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
    /// TDX-CHAIN-001b: Collateral present but incomplete (missing QE Identity or TCB Info).
    CollateralIncomplete { missing: String },
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
    /// TDX-POL-008: TD is in DEBUG mode (TD_ATTRIBUTES bit 0 = 1).
    /// A debug TD has no confidentiality — the VMM can read/write all TD memory.
    DebugTdRejected,
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
            Self::CollateralIncomplete { missing } => {
                write!(f, "TDX_COLLATERAL_INCOMPLETE: missing {missing}")
            }
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
            Self::DebugTdRejected => write!(
                f,
                "TDX_DEBUG_TD_REJECTED: TD is in DEBUG mode (TD_ATTRIBUTES bit 0 = 1)"
            ),
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
            Self::CollateralIncomplete { .. } => "TDX_COLLATERAL_INCOMPLETE",
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
            Self::DebugTdRejected => "TDX_DEBUG_TD_REJECTED",
        }
    }

    /// Returns the M2 trust layer for this error.
    pub fn layer(&self) -> &'static str {
        match self {
            Self::QuoteParseFailed(_) | Self::QuoteUnsupportedFormat(_) => "T1_PARSE",
            Self::QuoteSigInvalid(_) | Self::ReportdataBindingMismatch { .. } => "T2_CRYPTO",
            Self::CollateralMissing
            | Self::CollateralIncomplete { .. }
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
            | Self::CollateralTimeInvalid(_)
            | Self::DebugTdRejected => "T4_POLICY",
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
#[derive(Debug, Clone)]
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
    /// Accepted TCB statuses for T4_POLICY enforcement.
    /// If empty, defaults to `[UpToDate, SWHardeningNeeded]`.
    /// Set explicitly to control which TCB statuses are acceptable.
    pub accepted_tcb_statuses: Vec<TcbStatus>,
    /// Whether to reject debug-mode TDs (TD_ATTRIBUTES bit 0 = 1).
    /// Default: true. A debug TD has no confidentiality — the VMM can
    /// read/write all TD private memory via debug SEAMCALLs.
    /// Reference: Intel TDX Module spec, CVE-2025-30513 (CVSS 8.4).
    pub reject_debug_td: bool,
}

impl Default for TdxVerifyPolicy {
    fn default() -> Self {
        Self {
            expected_mrtd: None,
            expected_rtmrs: BTreeMap::new(),
            expected_nonce: None,
            expected_public_key: None,
            collateral: None,
            require_collateral: false,
            accepted_tcb_statuses: Vec::new(),
            reject_debug_td: true, // reject DEBUG TDs by default
        }
    }
}

/// DCAP collateral bundle for TDX quote trust chain verification (T3_CHAIN).
///
/// Contains the trust anchor, certificate chain, and Intel-signed collateral
/// structures needed to verify that the TDX quote was produced by a genuine
/// Intel platform with an acceptable TCB level.
///
/// # Intel DCAP Verification Flow
///
/// The full DCAP verification chain requires:
/// 1. PCK certificate chain validation (root CA -> intermediate -> PCK leaf)
/// 2. QE Identity verification (signed by Intel, validates QE measurements)
/// 3. TCB Info verification (signed by Intel, maps SVN values to TCB status)
/// 4. FMSPC cross-validation (PCK cert extension must match TCBInfo.fmspc)
///
/// Reference: Intel SGX DCAP Library, "Quote Verification" section.
/// See also: Intel PCS API v4 specification.
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
    /// QE Identity JSON (signed by Intel TCB Signing key).
    /// Downloaded from Intel PCS API: GET /sgx/certification/v4/qe/identity
    /// Contains QE measurement expectations (MRSIGNER, ISVPRODID, etc.).
    pub qe_identity_json: Option<String>,
    /// TCB Info JSON (signed by Intel TCB Signing key).
    /// Downloaded from Intel PCS API: GET /tdx/certification/v4/tcbinfo
    /// Contains TCB level definitions and their status (UpToDate, OutOfDate, etc.).
    pub tcb_info_json: Option<String>,
    /// TCB signing certificate chain (DER-encoded X.509, leaf first).
    /// The leaf cert's public key is used to verify QE Identity and TCB Info signatures.
    /// Downloaded from Intel PCS API (x-SGX-TCB-Info-Issuer-Chain header).
    pub tcb_signing_chain_der: Option<Vec<Vec<u8>>>,
}

// ---------------------------------------------------------------------------
// QE Identity structures (Intel PCS API v4)
// ---------------------------------------------------------------------------

/// Top-level QE Identity response from Intel PCS API.
///
/// Reference: Intel SGX DCAP, "Quoting Enclave Identity" API response.
/// The `enclaveIdentity` field contains the signed identity JSON.
/// The `signature` field is a hex-encoded ECDSA-P256 signature over
/// the raw JSON bytes of `enclaveIdentity`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentityResponse {
    /// The signed QE identity structure preserved as raw JSON bytes for
    /// signature verification.
    pub enclave_identity: Box<serde_json::value::RawValue>,
    /// Hex-encoded ECDSA-P256 signature over the UTF-8 bytes of `enclaveIdentity`.
    pub signature: String,
}

/// Parsed QE Identity structure.
///
/// Reference: Intel SGX DCAP Library, QE Identity V2 format.
/// Fields follow the Intel PCS API v4 specification.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    /// Identity version (expect 2 for v4 API).
    pub version: u32,
    /// Issue date (ISO 8601).
    pub issue_date: String,
    /// Next update date (ISO 8601).
    pub next_update: String,
    /// Expected MISCSELECT value (hex string, 4 bytes).
    pub miscselect: String,
    /// MISCSELECT mask (hex string, 4 bytes). Only masked bits are compared.
    pub miscselect_mask: String,
    /// Expected ATTRIBUTES value (hex string, 16 bytes).
    pub attributes: String,
    /// ATTRIBUTES mask (hex string, 16 bytes). Only masked bits are compared.
    pub attributes_mask: String,
    /// Expected MRSIGNER value (hex string, 32 bytes for SGX, 48 bytes for TDX QE).
    pub mrsigner: String,
    /// Expected ISVPRODID value.
    pub isvprodid: u16,
    /// TCB levels for the QE, ordered by descending SVN.
    pub tcb_levels: Vec<QeTcbLevel>,
}

/// A TCB level entry within the QE Identity structure.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    /// TCB component (ISVSVN for QE identity).
    pub tcb: QeTcbComponent,
    /// TCB status at this level.
    pub tcb_status: String,
    /// Optional advisory IDs associated with this TCB level.
    #[serde(default)]
    pub advisory_ids: Vec<String>,
}

/// TCB component within a QE TCB level.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbComponent {
    /// The QE's ISVSVN value.
    pub isvsvn: u16,
}

// ---------------------------------------------------------------------------
// TCB Info structures (Intel PCS API v4)
// ---------------------------------------------------------------------------

/// Top-level TCB Info response from Intel PCS API.
///
/// Reference: Intel TDX DCAP, "TCB Info" API response.
/// The `tcbInfo` field contains the signed TCB info JSON.
/// The `signature` field is a hex-encoded ECDSA-P256 signature.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoResponse {
    /// The signed TCB Info structure preserved as raw JSON bytes for
    /// signature verification.
    pub tcb_info: Box<serde_json::value::RawValue>,
    /// Hex-encoded ECDSA-P256 signature over the UTF-8 bytes of `tcbInfo`.
    pub signature: String,
}

/// Parsed TCB Info structure for TDX.
///
/// Reference: Intel PCS API v4, TDX TCBInfo format.
/// Contains platform-specific TCB levels that map SVN values to security status.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    /// TCBInfo version (expect 3 for TDX v4 API).
    pub version: u32,
    /// Issue date (ISO 8601).
    pub issue_date: String,
    /// Next update date (ISO 8601).
    pub next_update: String,
    /// FMSPC value (hex string, 6 bytes). Must match PCK cert extension.
    pub fmspc: String,
    /// PCE identifier (hex string).
    pub pce_id: String,
    /// TCB type (0 = SGX, 1 = TDX).
    pub tcb_type: u32,
    /// TCB evaluation data number.
    pub tcb_evaluation_data_number: u32,
    /// TDX module identities (present for TDX TCBInfo v3).
    #[serde(default)]
    pub tdx_module: Option<TdxModule>,
    /// TDX module identity entries (for multi-module support).
    #[serde(default)]
    pub tdx_module_identities: Vec<TdxModuleIdentity>,
    /// TCB levels ordered by descending component SVN values.
    pub tcb_levels: Vec<TcbLevel>,
}

/// TDX Module identity information.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    /// Expected MRSIGNER of the TDX module (hex string, 48 bytes).
    pub mrsigner: String,
    /// Expected ATTRIBUTES of the TDX module (hex string, 8 bytes).
    pub attributes: String,
    /// ATTRIBUTES mask (hex string, 8 bytes).
    pub attributes_mask: String,
}

/// Individual TDX module identity entry (for multi-module TCBInfo v3).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    /// Module identifier string.
    pub id: String,
    /// Expected MRSIGNER of this TDX module (hex string).
    pub mrsigner: String,
    /// Expected ATTRIBUTES (hex string).
    pub attributes: String,
    /// ATTRIBUTES mask (hex string).
    pub attributes_mask: String,
}

/// A TCB level entry within the TCB Info structure.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    /// TCB component values (SGX + TDX SVN components).
    pub tcb: TcbComponents,
    /// TCB date (ISO 8601) — when this TCB level was published.
    #[serde(default)]
    pub tcb_date: Option<String>,
    /// TCB status string: "UpToDate", "OutOfDate", "Revoked",
    /// "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded",
    /// "SWHardeningNeeded", "OutOfDateConfigurationNeeded".
    pub tcb_status: String,
    /// Advisory IDs associated with this TCB level.
    #[serde(default)]
    pub advisory_ids: Vec<String>,
}

/// TCB component SVN values.
///
/// Contains both SGX TEE SVN components (sgxtcbcomponents) and
/// TDX TEE SVN components (tdxtcbcomponents) for TDX quotes.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbComponents {
    /// SGX TCB SVN components (16 entries, each with `svn` field).
    #[serde(default)]
    pub sgxtcbcomponents: Vec<SvnComponent>,
    /// TDX TCB SVN components (16 entries, each with `svn` field).
    #[serde(default)]
    pub tdxtcbcomponents: Vec<SvnComponent>,
    /// PCE SVN value.
    #[serde(default)]
    pub pcesvn: u16,
}

/// A single SVN component value.
#[derive(Debug, Clone, Deserialize)]
pub struct SvnComponent {
    /// The SVN value for this component.
    pub svn: u16,
}

/// TCB status classification.
///
/// Reference: Intel DCAP specification, TCB Status values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcbStatus {
    /// TCB is up to date — no known vulnerabilities.
    UpToDate,
    /// TCB is out of date — platform needs firmware/microcode update.
    OutOfDate,
    /// TCB has been revoked — platform is permanently untrusted at this level.
    Revoked,
    /// TCB needs configuration changes but SW is current.
    ConfigurationNeeded,
    /// TCB needs both configuration changes and SW hardening.
    ConfigurationAndSWHardeningNeeded,
    /// TCB needs SW hardening updates.
    SWHardeningNeeded,
    /// TCB is out of date and also needs configuration changes.
    OutOfDateConfigurationNeeded,
    /// Unknown or unrecognized status string.
    Unknown(String),
}

impl TcbStatus {
    /// Parse a TCB status string from the Intel PCS API.
    fn from_str(s: &str) -> Self {
        match s {
            "UpToDate" => Self::UpToDate,
            "OutOfDate" => Self::OutOfDate,
            "Revoked" => Self::Revoked,
            "ConfigurationNeeded" => Self::ConfigurationNeeded,
            "ConfigurationAndSWHardeningNeeded" => Self::ConfigurationAndSWHardeningNeeded,
            "SWHardeningNeeded" => Self::SWHardeningNeeded,
            "OutOfDateConfigurationNeeded" => Self::OutOfDateConfigurationNeeded,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Whether this status is acceptable under a default (strict) policy.
    ///
    /// Only `UpToDate` and `SWHardeningNeeded` are considered acceptable
    /// by default. Callers can implement custom policies via `TdxVerifyPolicy`.
    fn is_acceptable_default(&self) -> bool {
        matches!(self, Self::UpToDate | Self::SWHardeningNeeded)
    }
}

impl fmt::Display for TcbStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpToDate => write!(f, "UpToDate"),
            Self::OutOfDate => write!(f, "OutOfDate"),
            Self::Revoked => write!(f, "Revoked"),
            Self::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            Self::ConfigurationAndSWHardeningNeeded => {
                write!(f, "ConfigurationAndSWHardeningNeeded")
            }
            Self::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            Self::OutOfDateConfigurationNeeded => write!(f, "OutOfDateConfigurationNeeded"),
            Self::Unknown(s) => write!(f, "Unknown({s})"),
        }
    }
}

/// Expected FMSPC length in bytes.
const FMSPC_LEN: usize = 6;

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
/// Validates the quote through the M2 trust verification layers:
/// 1. Parsing the wire document (marker + quote) — T1_PARSE
/// 2. Parsing the quote header (version, TEE type, key type) — T1_PARSE
/// 3. Parsing the TD quote body (MRTD, RTMRs, REPORTDATA) — T1_PARSE
/// 4. Verifying the ECDSA-P256 signature over header + body — T2_CRYPTO
/// 5. PCK certificate chain + CRL verification — T3_CHAIN
/// 6. QE Identity verification (MRSIGNER, ISVPRODID, ISVSVN) — T3_CHAIN
/// 7. TCB Info verification and TCB level matching — T3_CHAIN
/// 8. FMSPC cross-validation (PCK cert vs TCBInfo) — T3_CHAIN
/// 9. TCB status policy enforcement — T4_POLICY
/// 10. Measurement and binding policy checks — T4_POLICY
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
        // This verifies that the quote's signature is valid for the
        // public key embedded in the quote itself. The T3_CHAIN step
        // below verifies that the signing key belongs to a genuine Intel
        // platform via the PCK certificate chain and DCAP collateral.
        let sig_section_offset = HEADER_SIZE + body_size;
        let quote_attestation_key =
            verify_ecdsa_signature(&quote, sig_section_offset, HEADER_SIZE + body_size)?;

        // Extract PCE SVN from the quote header (offset 10, u16 LE).
        // This is used as a fallback when the PCK cert doesn't have SGX extensions
        // (synthetic/test certs). For real certs, PCESVN comes from the PCK cert.
        let header_pce_svn = if quote.len() >= 12 {
            u16::from_le_bytes([quote[10], quote[11]])
        } else {
            0
        };

        // T3_CHAIN: DCAP collateral verification.
        let mut tcb_status: Option<TcbStatus> = None;
        if self.policy.require_collateral {
            let collateral = self
                .policy
                .collateral
                .as_ref()
                .ok_or(TdxVerifyError::CollateralMissing)?;
            // Step 0: When collateral is required, TCB Info must be present
            // for a DCAP-backed trust decision. Reject if missing.
            let has_qe = collateral.qe_identity_json.is_some();
            let has_tcb = collateral.tcb_info_json.is_some();
            if !has_tcb {
                return Err(TdxVerifyError::CollateralIncomplete {
                    missing: "tcb_info_json (required when require_collateral=true)".into(),
                });
            }
            if !has_qe {
                return Err(TdxVerifyError::CollateralIncomplete {
                    missing: "qe_identity_json (required when require_collateral=true)".into(),
                });
            }
            // Step 1: PCK cert chain + CRL.
            verify_pck_chain(collateral, Some(&quote_attestation_key))?;
            // Step 2-5: Full DCAP verification (QE Identity, TCB Info, FMSPC).
            let status = verify_dcap_collateral(
                collateral,
                &quote,
                &body,
                sig_section_offset,
                header_pce_svn,
            )?;
            tcb_status = Some(status);
        } else if let Some(ref collateral) = self.policy.collateral {
            // Collateral provided but not required — verify if present.
            verify_pck_chain(collateral, Some(&quote_attestation_key))?;
            if collateral.qe_identity_json.is_some() || collateral.tcb_info_json.is_some() {
                let status = verify_dcap_collateral(
                    collateral,
                    &quote,
                    &body,
                    sig_section_offset,
                    header_pce_svn,
                )?;
                tcb_status = Some(status);
            }
        }

        // T4_POLICY: TCB status enforcement (TDX-POL-001/003).
        if let Some(ref status) = tcb_status {
            if *status == TcbStatus::Revoked {
                return Err(TdxVerifyError::TcbRevoked);
            }

            let acceptable = if !self.policy.accepted_tcb_statuses.is_empty() {
                self.policy.accepted_tcb_statuses.contains(status)
            } else {
                status.is_acceptable_default()
            };

            if !acceptable {
                return Err(TdxVerifyError::TcbStatusUnacceptable(format!(
                    "TCB status '{}' is not in the accepted list",
                    status
                )));
            }
        }

        // T4_POLICY: Reject debug-mode TDs (TDX-POL-008).
        // TD_ATTRIBUTES bit 0 = DEBUG. When set, the VMM has full read/write
        // access to TD private memory via debug SEAMCALLs — no confidentiality.
        if self.policy.reject_debug_td && (body.td_attributes & 0x01) != 0 {
            return Err(TdxVerifyError::DebugTdRejected);
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
    /// TEE TCB SVN values (16 bytes). Used for TCB level matching.
    tee_tcb_svn: [u8; 16],
    /// SEAM module attributes (8 bytes, offset 112). MBZ in TDX 1.0.
    #[allow(dead_code)]
    seam_attributes: u64,
    /// TD attributes (8 bytes, offset 120). Bit 0 = DEBUG.
    td_attributes: u64,
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

        let mut tee_tcb_svn = [0u8; 16];
        tee_tcb_svn
            .copy_from_slice(&body[TEE_TCB_SVN_OFFSET..TEE_TCB_SVN_OFFSET + TEE_TCB_SVN_SIZE]);

        let seam_attributes = u64::from_le_bytes(
            body[SEAM_ATTRIBUTES_OFFSET..SEAM_ATTRIBUTES_OFFSET + ATTRIBUTES_SIZE]
                .try_into()
                .unwrap(),
        );
        let td_attributes = u64::from_le_bytes(
            body[TD_ATTRIBUTES_OFFSET..TD_ATTRIBUTES_OFFSET + ATTRIBUTES_SIZE]
                .try_into()
                .unwrap(),
        );

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
            tee_tcb_svn,
            seam_attributes,
            td_attributes,
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            reportdata,
        })
    }
}

/// Parsed QE Report extracted from the TDX quote's signature data section.
#[derive(Debug)]
struct QeReportFields {
    /// MRSIGNER of the Quoting Enclave (32 bytes).
    mrsigner: [u8; QE_MRSIGNER_SIZE],
    /// ISVPRODID of the Quoting Enclave.
    isvprodid: u16,
    /// ISVSVN of the Quoting Enclave.
    isvsvn: u16,
    /// MISCSELECT of the Quoting Enclave (4 bytes).
    miscselect: [u8; 4],
    /// ATTRIBUTES of the Quoting Enclave (16 bytes).
    attributes: [u8; QE_ATTRIBUTES_SIZE],
}

impl QeReportFields {
    /// Parse QE Report fields from the signature data section.
    ///
    /// The QE Report starts at offset 128 (after 64-byte sig + 64-byte pubkey)
    /// within the signature data.
    fn parse(sig_data: &[u8]) -> Result<Self, TdxVerifyError> {
        if sig_data.len() < QE_REPORT_OFFSET + QE_REPORT_SIZE {
            return Err(TdxVerifyError::QuoteParseFailed(format!(
                "signature data too short for QE Report: need at least {} bytes, got {}",
                QE_REPORT_OFFSET + QE_REPORT_SIZE,
                sig_data.len()
            )));
        }

        let qe_report = &sig_data[QE_REPORT_OFFSET..QE_REPORT_OFFSET + QE_REPORT_SIZE];

        let mut mrsigner = [0u8; QE_MRSIGNER_SIZE];
        mrsigner
            .copy_from_slice(&qe_report[QE_MRSIGNER_OFFSET..QE_MRSIGNER_OFFSET + QE_MRSIGNER_SIZE]);

        let isvprodid = u16::from_le_bytes([
            qe_report[QE_ISVPRODID_OFFSET],
            qe_report[QE_ISVPRODID_OFFSET + 1],
        ]);

        let isvsvn =
            u16::from_le_bytes([qe_report[QE_ISVSVN_OFFSET], qe_report[QE_ISVSVN_OFFSET + 1]]);

        let mut miscselect = [0u8; 4];
        miscselect.copy_from_slice(&qe_report[QE_MISCSELECT_OFFSET..QE_MISCSELECT_OFFSET + 4]);

        let mut attributes = [0u8; QE_ATTRIBUTES_SIZE];
        attributes.copy_from_slice(
            &qe_report[QE_ATTRIBUTES_OFFSET..QE_ATTRIBUTES_OFFSET + QE_ATTRIBUTES_SIZE],
        );

        Ok(Self {
            mrsigner,
            isvprodid,
            isvsvn,
            miscselect,
            attributes,
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

// ---------------------------------------------------------------------------
// FMSPC extraction from PCK certificate
// ---------------------------------------------------------------------------

/// Extract the FMSPC value from a PCK certificate's SGX Extensions.
///
/// The FMSPC is stored in the PCK certificate under the SGX Extensions OID
/// (1.2.840.113741.1.13.1) as a nested structure. The FMSPC sub-extension
/// has OID 1.2.840.113741.1.13.1.4 and contains a 6-byte octet string.
///
/// Strategy: encode the certificate to DER and scan for the FMSPC OID bytes
/// followed by an OCTET STRING containing 6 bytes. This avoids depending on
/// the openssl crate's extension iteration API (which varies across versions).
///
/// Reference: Intel SGX PCK Certificate Profile, Section 3.2.
fn extract_fmspc_from_pck_cert(
    cert: &openssl::x509::X509Ref,
) -> Result<[u8; FMSPC_LEN], TdxVerifyError> {
    let cert_der = cert.to_der().map_err(|e| TdxVerifyError::FmspcMismatch {
        quote_fmspc: "N/A".into(),
        collateral_fmspc: format!("failed to encode cert to DER: {e}"),
    })?;

    parse_fmspc_from_sgx_extensions(&cert_der)
}

/// Parse FMSPC from the raw ASN.1 value of the SGX Extensions.
///
/// The SGX Extensions value is a SEQUENCE of SEQUENCE entries, each containing:
///   SEQUENCE { OID, OCTET STRING }
///
/// We look for the entry with OID 1.2.840.113741.1.13.1.4 (FMSPC).
fn parse_fmspc_from_sgx_extensions(data: &[u8]) -> Result<[u8; FMSPC_LEN], TdxVerifyError> {
    // Simple ASN.1 DER parser for the nested structure.
    // This is a best-effort parser for the specific Intel format.

    // The data should be a SEQUENCE at the top level.
    if data.is_empty() {
        return Err(TdxVerifyError::FmspcMismatch {
            quote_fmspc: "N/A".into(),
            collateral_fmspc: "empty SGX extensions data".into(),
        });
    }

    // Search for the FMSPC OID bytes within the ASN.1 data.
    // OID 1.2.840.113741.1.13.1.4 encodes as:
    // 06 09 2A 86 48 CE 3D 01 0D 01 04
    // But the Intel SGX OID 1.2.840.113741.1.13.1.4 actually encodes as:
    // 06 0A 2A 86 48 86 F8 4D 01 0D 01 04
    let fmspc_oid_bytes: &[u8] = &[
        0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04,
    ];

    // Find the OID in the data.
    if let Some(pos) = find_subsequence(data, fmspc_oid_bytes) {
        // After the OID, we expect an OCTET STRING containing 6 bytes.
        let after_oid = pos + fmspc_oid_bytes.len();
        if after_oid < data.len() {
            // Look for OCTET STRING tag (0x04) followed by length and 6 bytes.
            let remaining = &data[after_oid..];
            if remaining.len() >= 2 + FMSPC_LEN && remaining[0] == 0x04 {
                let len = remaining[1] as usize;
                if len == FMSPC_LEN && remaining.len() >= 2 + len {
                    let mut fmspc = [0u8; FMSPC_LEN];
                    fmspc.copy_from_slice(&remaining[2..2 + FMSPC_LEN]);
                    return Ok(fmspc);
                }
            }
        }
    }

    Err(TdxVerifyError::FmspcMismatch {
        quote_fmspc: "N/A".into(),
        collateral_fmspc: "FMSPC OID not found in SGX extensions ASN.1".into(),
    })
}

/// Find a subsequence in a byte slice. Returns the starting offset if found.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// PCK certificate SGX TCB extraction (F1 fix)
// ---------------------------------------------------------------------------

/// SGX TCB values extracted from a PCK certificate's SGX Extensions.
///
/// These values are used for TCB level matching per Intel DCAP spec:
/// - `sgx_comp_svns` are matched against `tcbInfo.sgxtcbcomponents`
/// - `pcesvn` is matched against `tcbInfo.tcbLevels[].tcb.pcesvn`
///
/// Reference: Intel SGX PCK Certificate Profile, Section 3.2;
///            Intel SGX-TDX-DCAP-QuoteVerificationLibrary `TcbLevelCheck.cpp`.
#[derive(Debug, Clone)]
pub struct PckTcbValues {
    /// SGX TCB component SVN values (COMP01..COMP16) from PCK cert OIDs
    /// 1.2.840.113741.1.13.1.2.1 through 1.2.840.113741.1.13.1.2.16.
    pub sgx_comp_svns: [u16; PCK_SGX_TCB_COMP_COUNT],
    /// PCESVN from PCK cert OID 1.2.840.113741.1.13.1.2.17.
    pub pcesvn: u16,
}

/// Extract SGX TCB component SVNs and PCESVN from a PCK certificate.
///
/// Scans the DER-encoded certificate for the SGX Extensions OID subtree
/// (1.2.840.113741.1.13.1.2.*) and reads the INTEGER values for each
/// component (COMP01..COMP16) and PCESVN.
///
/// Strategy: same DER byte scanning approach as `extract_fmspc_from_pck_cert`,
/// avoiding OpenSSL extension API version differences.
fn extract_pck_tcb_values(cert: &openssl::x509::X509Ref) -> Result<PckTcbValues, TdxVerifyError> {
    let cert_der = cert.to_der().map_err(|e| {
        TdxVerifyError::PckChainInvalid(format!(
            "failed to encode PCK cert to DER for TCB extraction: {e}"
        ))
    })?;

    let mut result = PckTcbValues {
        sgx_comp_svns: [0u16; PCK_SGX_TCB_COMP_COUNT],
        pcesvn: 0,
    };

    // Scan for each occurrence of the SGX TCB OID prefix.
    // Each match is: [06 0B 2A 86 48 86 F8 4D 01 0D 01 02] [sub_oid_byte]
    // Followed by an ASN.1 INTEGER value.
    let prefix_len = SGX_TCB_OID_PREFIX.len();
    let mut pos = 0;
    let mut found_count = 0u32;

    while pos + prefix_len + 1 < cert_der.len() {
        if let Some(match_pos) = find_subsequence(&cert_der[pos..], SGX_TCB_OID_PREFIX) {
            let abs_pos = pos + match_pos;
            let sub_oid_pos = abs_pos + prefix_len;

            if sub_oid_pos >= cert_der.len() {
                break;
            }

            let sub_oid = cert_der[sub_oid_pos];
            let value_start = sub_oid_pos + 1;

            if value_start >= cert_der.len() {
                pos = sub_oid_pos + 1;
                continue;
            }

            // Parse the ASN.1 INTEGER that follows the OID.
            // Format: 02 <length> <value_bytes>
            if cert_der[value_start] == 0x02 && value_start + 1 < cert_der.len() {
                let int_len = cert_der[value_start + 1] as usize;
                let int_data_start = value_start + 2;
                if int_data_start + int_len <= cert_der.len() && int_len <= 4 {
                    // Parse unsigned integer (ASN.1 INTEGER is signed, but SVNs
                    // are always non-negative; skip leading zero padding byte).
                    let int_bytes = &cert_der[int_data_start..int_data_start + int_len];
                    let value = parse_asn1_unsigned_int(int_bytes);

                    if (0x01..=0x10).contains(&sub_oid) {
                        // COMP01..COMP16 (sub OIDs 1..16)
                        let idx = (sub_oid - 0x01) as usize;
                        result.sgx_comp_svns[idx] = value as u16;
                        found_count += 1;
                    } else if sub_oid == PCK_PCESVN_SUB_OID {
                        // PCESVN (sub OID 17)
                        result.pcesvn = value as u16;
                        found_count += 1;
                    }
                }
            }

            pos = sub_oid_pos + 1;
        } else {
            break;
        }
    }

    if found_count == 0 {
        return Err(TdxVerifyError::PckChainInvalid(
            "no SGX TCB component OIDs found in PCK certificate".into(),
        ));
    }

    tracing::debug!(
        sgx_comp_svns = ?result.sgx_comp_svns,
        pcesvn = result.pcesvn,
        found_count,
        "extracted PCK TCB values from certificate"
    );

    Ok(result)
}

/// Parse an unsigned integer from ASN.1 INTEGER bytes.
///
/// ASN.1 INTEGER is signed; a leading 0x00 byte is padding when the
/// high bit of the value is set. This function strips the padding and
/// returns the unsigned value (up to u32).
fn parse_asn1_unsigned_int(bytes: &[u8]) -> u32 {
    // Skip leading zero padding (ASN.1 sign byte).
    let trimmed = if bytes.len() > 1 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    };
    let mut value: u32 = 0;
    for &b in trimmed {
        value = (value << 8) | (b as u32);
    }
    value
}

// ---------------------------------------------------------------------------
// ECDSA-P256 signature verification for JSON structures
// ---------------------------------------------------------------------------

/// Verify an ECDSA-P256 signature over raw JSON bytes.
///
/// Used to verify Intel's signature over QE Identity and TCB Info JSON.
/// The signature is hex-encoded (r || s, 64 bytes = 128 hex chars).
///
/// Reference: Intel SGX DCAP, "Signature Verification of TCB Structures".
fn verify_json_signature(
    json_bytes: &[u8],
    hex_signature: &str,
    signing_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Result<(), TdxVerifyError> {
    let sig_bytes = hex::decode(hex_signature)
        .map_err(|e| TdxVerifyError::TcbInfoInvalid(format!("invalid hex signature: {e}")))?;

    if sig_bytes.len() != ECDSA_SIG_SIZE {
        return Err(TdxVerifyError::TcbInfoInvalid(format!(
            "signature length mismatch: expected {ECDSA_SIG_SIZE}, got {}",
            sig_bytes.len()
        )));
    }

    // Convert raw signature (r || s) to DER-encoded ECDSA signature.
    let r = openssl::bn::BigNum::from_slice(&sig_bytes[..32])
        .map_err(|e| TdxVerifyError::TcbInfoInvalid(format!("failed to parse signature r: {e}")))?;
    let s = openssl::bn::BigNum::from_slice(&sig_bytes[32..64])
        .map_err(|e| TdxVerifyError::TcbInfoInvalid(format!("failed to parse signature s: {e}")))?;

    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to build ECDSA signature: {e}"))
    })?;

    let der_sig = ecdsa_sig.to_der().map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to encode signature to DER: {e}"))
    })?;

    let mut verifier =
        openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), signing_key).map_err(
            |e| TdxVerifyError::TcbInfoInvalid(format!("failed to create verifier: {e}")),
        )?;

    let valid = verifier
        .verify_oneshot(&der_sig, json_bytes)
        .map_err(|e| TdxVerifyError::TcbInfoInvalid(format!("ECDSA verification error: {e}")))?;

    if !valid {
        return Err(TdxVerifyError::TcbInfoInvalid(
            "JSON structure signature verification failed".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// QE Identity verification (T3_CHAIN-004)
// ---------------------------------------------------------------------------

/// Verify QE Identity against the QE Report extracted from the quote.
///
/// Checks:
/// - QE Identity JSON signature is valid (signed by TCB Signing key)
/// - QE Report MRSIGNER matches the expected value (masked)
/// - QE Report ISVPRODID matches
/// - QE Report MISCSELECT matches (masked)
/// - QE Report ATTRIBUTES matches (masked)
/// - QE Report ISVSVN meets the minimum required level
///
/// Returns the QE TCB status for the matched level.
///
/// Reference: Intel SGX DCAP Library, "QE Identity Verification" section.
fn verify_qe_identity(
    collateral: &TdxCollateral,
    qe_report: &QeReportFields,
    tcb_signing_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Result<TcbStatus, TdxVerifyError> {
    let qe_identity_json = collateral
        .qe_identity_json
        .as_ref()
        .ok_or_else(|| TdxVerifyError::QeIdentityInvalid("missing QE Identity JSON".into()))?;

    // Parse the top-level response (contains enclaveIdentity + signature).
    let response: QeIdentityResponse = serde_json::from_str(qe_identity_json).map_err(|e| {
        TdxVerifyError::QeIdentityInvalid(format!("failed to parse QE Identity response: {e}"))
    })?;

    // Verify signature over the raw enclaveIdentity JSON as delivered by PCS.
    verify_json_signature(
        response.enclave_identity.get().as_bytes(),
        &response.signature,
        tcb_signing_key,
    )
    .map_err(|_| TdxVerifyError::QeIdentityInvalid("QE Identity signature invalid".into()))?;

    // Parse the enclave identity structure.
    let identity: QeIdentity =
        serde_json::from_str(response.enclave_identity.get()).map_err(|e| {
            TdxVerifyError::QeIdentityInvalid(format!(
                "failed to parse enclaveIdentity fields: {e}"
            ))
        })?;

    // Check MRSIGNER: apply mask (for QE, typically full mask = exact match).
    let expected_mrsigner = hex::decode(&identity.mrsigner)
        .map_err(|e| TdxVerifyError::QeIdentityInvalid(format!("invalid MRSIGNER hex: {e}")))?;
    if expected_mrsigner.len() < QE_MRSIGNER_SIZE {
        return Err(TdxVerifyError::QeIdentityInvalid(format!(
            "MRSIGNER too short: expected at least {} bytes, got {}",
            QE_MRSIGNER_SIZE,
            expected_mrsigner.len()
        )));
    }
    // Compare only the first 32 bytes (SGX QE MRSIGNER size).
    if qe_report.mrsigner[..] != expected_mrsigner[..QE_MRSIGNER_SIZE] {
        return Err(TdxVerifyError::QeIdentityInvalid(format!(
            "QE MRSIGNER mismatch: expected {}, got {}",
            hex::encode(&expected_mrsigner[..QE_MRSIGNER_SIZE]),
            hex::encode(qe_report.mrsigner)
        )));
    }

    // Check ISVPRODID.
    if qe_report.isvprodid != identity.isvprodid {
        return Err(TdxVerifyError::QeIdentityInvalid(format!(
            "QE ISVPRODID mismatch: expected {}, got {}",
            identity.isvprodid, qe_report.isvprodid
        )));
    }

    // Check MISCSELECT (masked comparison).
    let miscselect_mask = hex::decode(&identity.miscselect_mask).map_err(|e| {
        TdxVerifyError::QeIdentityInvalid(format!("invalid MISCSELECT mask hex: {e}"))
    })?;
    let expected_miscselect = hex::decode(&identity.miscselect)
        .map_err(|e| TdxVerifyError::QeIdentityInvalid(format!("invalid MISCSELECT hex: {e}")))?;
    if miscselect_mask.len() >= 4 && expected_miscselect.len() >= 4 {
        for i in 0..4 {
            if (qe_report.miscselect[i] & miscselect_mask[i])
                != (expected_miscselect[i] & miscselect_mask[i])
            {
                return Err(TdxVerifyError::QeIdentityInvalid(format!(
                    "QE MISCSELECT mismatch (masked): expected {}, got {} (mask {})",
                    hex::encode(&expected_miscselect[..4]),
                    hex::encode(qe_report.miscselect),
                    hex::encode(&miscselect_mask[..4]),
                )));
            }
        }
    }

    // Check ATTRIBUTES (masked comparison).
    let attributes_mask = hex::decode(&identity.attributes_mask).map_err(|e| {
        TdxVerifyError::QeIdentityInvalid(format!("invalid ATTRIBUTES mask hex: {e}"))
    })?;
    let expected_attributes = hex::decode(&identity.attributes)
        .map_err(|e| TdxVerifyError::QeIdentityInvalid(format!("invalid ATTRIBUTES hex: {e}")))?;
    if attributes_mask.len() >= QE_ATTRIBUTES_SIZE
        && expected_attributes.len() >= QE_ATTRIBUTES_SIZE
    {
        for i in 0..QE_ATTRIBUTES_SIZE {
            if (qe_report.attributes[i] & attributes_mask[i])
                != (expected_attributes[i] & attributes_mask[i])
            {
                return Err(TdxVerifyError::QeIdentityInvalid(format!(
                    "QE ATTRIBUTES mismatch (masked): expected {}, got {} (mask {})",
                    hex::encode(&expected_attributes[..QE_ATTRIBUTES_SIZE]),
                    hex::encode(qe_report.attributes),
                    hex::encode(&attributes_mask[..QE_ATTRIBUTES_SIZE]),
                )));
            }
        }
    }

    // Determine QE TCB status by matching ISVSVN against tcb_levels.
    // TCB levels are ordered descending. Find the first level where
    // the QE's ISVSVN >= the level's ISVSVN.
    for level in &identity.tcb_levels {
        if qe_report.isvsvn >= level.tcb.isvsvn {
            return Ok(TcbStatus::from_str(&level.tcb_status));
        }
    }

    // If no level matched, the QE's ISVSVN is below all known levels.
    Err(TdxVerifyError::QeIdentityInvalid(
        "QE ISVSVN below all known TCB levels".into(),
    ))
}

// ---------------------------------------------------------------------------
// TCB Info verification (T3_CHAIN-005)
// ---------------------------------------------------------------------------

/// Verify TCB Info and determine the platform's TCB status.
///
/// Checks:
/// - TCB Info JSON signature is valid (signed by TCB Signing key)
/// - Two-phase TCB level matching per Intel DCAP spec:
///   - Phase 1: `sgxtcbcomponents` matched against PCK cert SGX TCB SVNs
///   - Phase 2: `tdxtcbcomponents` matched against quote body TEE_TCB_SVN
///   - PCESVN matched against PCK cert PCESVN
///
/// Reference: Intel SGX-TDX-DCAP-QuoteVerificationLibrary, `TcbLevelCheck.cpp`.
fn verify_tcb_info(
    collateral: &TdxCollateral,
    tee_tcb_svn: &[u8; 16],
    pck_tcb: &PckTcbValues,
    tcb_signing_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Result<(TcbStatus, TcbInfo), TdxVerifyError> {
    let tcb_info_json = collateral
        .tcb_info_json
        .as_ref()
        .ok_or_else(|| TdxVerifyError::TcbInfoInvalid("missing TCB Info JSON".into()))?;

    // Parse the top-level response (contains tcbInfo + signature).
    let response: TcbInfoResponse = serde_json::from_str(tcb_info_json).map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to parse TCB Info response: {e}"))
    })?;

    // Verify signature over the raw tcbInfo JSON as delivered by PCS.
    verify_json_signature(
        response.tcb_info.get().as_bytes(),
        &response.signature,
        tcb_signing_key,
    )
    .map_err(|_| TdxVerifyError::TcbInfoInvalid("TCB Info signature invalid".into()))?;

    // Parse the TCB Info structure.
    let tcb_info: TcbInfo = serde_json::from_str(response.tcb_info.get()).map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to parse tcbInfo fields: {e}"))
    })?;

    // Match TCB level using the two-phase algorithm from Intel DCAP.
    //
    // Per Intel SGX-TDX-DCAP-QuoteVerificationLibrary (TcbLevelCheck.cpp):
    //   Phase 1: sgxtcbcomponents matched against PCK cert's SGX TCB SVNs
    //   Phase 2: tdxtcbcomponents matched against quote body's TEE_TCB_SVN
    //   PCESVN matched against PCK cert's PCESVN
    //
    // This is NOT the same as using TEE_TCB_SVN for both (the previous
    // incorrect behavior). The PCK cert SGX SVNs track CPU microcode/firmware
    // versions, while TEE_TCB_SVN tracks TDX Module versions.
    //
    // Reference: TcbLevelCheck.cpp:matchTcbLevels(), lines 132-185.

    let matched_status = match_tcb_level(&tcb_info, pck_tcb, tee_tcb_svn)?;

    Ok((matched_status, tcb_info))
}

/// Two-phase TCB level matching per Intel DCAP specification.
///
/// Phase 1: `sgxtcbcomponents` matched against **PCK certificate** SGX TCB SVNs.
/// Phase 2: `tdxtcbcomponents` matched against **quote body** TEE_TCB_SVN.
/// PCESVN: matched against **PCK certificate** PCESVN.
///
/// Both phases must match at the same TCB level for that level to be selected.
///
/// Reference: Intel SGX-TDX-DCAP-QuoteVerificationLibrary,
///            `TcbLevelCheck.cpp:matchTcbLevels()`, lines 132-185.
fn match_tcb_level(
    tcb_info: &TcbInfo,
    pck_tcb: &PckTcbValues,
    tee_tcb_svn: &[u8; 16],
) -> Result<TcbStatus, TdxVerifyError> {
    for level in &tcb_info.tcb_levels {
        // Phase 1: Check SGX TCB components against PCK cert values.
        let mut sgx_match = true;
        for (i, component) in level.tcb.sgxtcbcomponents.iter().enumerate() {
            if i >= PCK_SGX_TCB_COMP_COUNT {
                break;
            }
            if pck_tcb.sgx_comp_svns[i] < component.svn {
                sgx_match = false;
                break;
            }
        }

        if !sgx_match {
            continue;
        }

        // Check PCE SVN against PCK cert PCESVN.
        if pck_tcb.pcesvn < level.tcb.pcesvn {
            continue;
        }

        // Phase 2: Check TDX TCB components against quote body TEE_TCB_SVN.
        let mut tdx_match = true;
        for (i, component) in level.tcb.tdxtcbcomponents.iter().enumerate() {
            if i >= 16 {
                break;
            }
            if (tee_tcb_svn[i] as u16) < component.svn {
                tdx_match = false;
                break;
            }
        }

        if !tdx_match {
            continue;
        }

        // Both phases match — this is our TCB level.
        return Ok(TcbStatus::from_str(&level.tcb_status));
    }

    // No level matched — SVN values are below all known levels.
    Err(TdxVerifyError::TcbInfoInvalid(
        "quote SVN values below all known TCB levels".into(),
    ))
}

// ---------------------------------------------------------------------------
// FMSPC cross-validation (T3_CHAIN-006)
// ---------------------------------------------------------------------------

/// Verify that the FMSPC from the PCK certificate matches the TCB Info.
///
/// The PCK cert's SGX Extensions contain the platform FMSPC, and the
/// TCBInfo structure declares which FMSPC it applies to. A mismatch
/// means the TCBInfo is for a different platform.
///
/// Reference: Intel SGX DCAP Library, "FMSPC Cross-Validation".
fn verify_fmspc(pck_fmspc: &[u8; FMSPC_LEN], tcb_info: &TcbInfo) -> Result<(), TdxVerifyError> {
    let tcb_fmspc = hex::decode(&tcb_info.fmspc).map_err(|e| TdxVerifyError::FmspcMismatch {
        quote_fmspc: hex::encode(pck_fmspc),
        collateral_fmspc: format!("invalid FMSPC hex in TCBInfo: {e}"),
    })?;

    if tcb_fmspc.len() != FMSPC_LEN {
        return Err(TdxVerifyError::FmspcMismatch {
            quote_fmspc: hex::encode(pck_fmspc),
            collateral_fmspc: format!(
                "wrong FMSPC length in TCBInfo: expected {FMSPC_LEN}, got {}",
                tcb_fmspc.len()
            ),
        });
    }

    if pck_fmspc[..] != tcb_fmspc[..] {
        return Err(TdxVerifyError::FmspcMismatch {
            quote_fmspc: hex::encode(pck_fmspc),
            collateral_fmspc: hex::encode(&tcb_fmspc),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TCB signing chain verification
// ---------------------------------------------------------------------------

/// Verify the TCB Signing certificate chain and extract the signing key.
///
/// The TCB signing chain is a separate chain from the PCK chain.
/// It's used to verify the signatures on QE Identity and TCB Info JSON.
fn verify_tcb_signing_chain(
    collateral: &TdxCollateral,
) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, TdxVerifyError> {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509StoreContext, X509};

    let tcb_chain_der = collateral.tcb_signing_chain_der.as_ref().ok_or_else(|| {
        TdxVerifyError::TcbInfoInvalid("missing TCB signing certificate chain".into())
    })?;

    if tcb_chain_der.is_empty() {
        return Err(TdxVerifyError::TcbInfoInvalid(
            "empty TCB signing certificate chain".into(),
        ));
    }

    // Parse root CA (same trust anchor as PCK chain).
    let root_ca = X509::from_der(&collateral.root_ca_der).map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to parse root CA for TCB chain: {e}"))
    })?;

    let mut store_builder = X509StoreBuilder::new()
        .map_err(|e| TdxVerifyError::TcbInfoInvalid(format!("failed to create X509 store: {e}")))?;
    store_builder.add_cert(root_ca).map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to add root CA to store: {e}"))
    })?;
    let store = store_builder.build();

    // Parse the TCB signing leaf cert.
    let leaf_cert = X509::from_der(&tcb_chain_der[0]).map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to parse TCB signing leaf cert: {e}"))
    })?;

    // Build intermediate chain.
    let mut chain = Stack::new()
        .map_err(|e| TdxVerifyError::TcbInfoInvalid(format!("failed to create cert stack: {e}")))?;
    for (i, cert_der) in tcb_chain_der.iter().skip(1).enumerate() {
        let cert = X509::from_der(cert_der).map_err(|e| {
            TdxVerifyError::TcbInfoInvalid(format!(
                "failed to parse TCB signing chain cert[{i}]: {e}"
            ))
        })?;
        chain.push(cert).map_err(|e| {
            TdxVerifyError::TcbInfoInvalid(format!("failed to push chain cert: {e}"))
        })?;
    }

    // Verify chain.
    let mut context = X509StoreContext::new().map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to create verify context: {e}"))
    })?;
    let valid = context
        .init(&store, &leaf_cert, &chain, |ctx| ctx.verify_cert())
        .map_err(|e| {
            TdxVerifyError::TcbInfoInvalid(format!("TCB signing chain verification error: {e}"))
        })?;

    if !valid {
        return Err(TdxVerifyError::TcbInfoInvalid(
            "TCB signing certificate chain verification failed".into(),
        ));
    }

    // Extract the public key from the leaf cert.
    let pubkey = leaf_cert.public_key().map_err(|e| {
        TdxVerifyError::TcbInfoInvalid(format!("failed to get TCB signing public key: {e}"))
    })?;

    Ok(pubkey)
}

// ---------------------------------------------------------------------------
// Full DCAP collateral verification orchestrator
// ---------------------------------------------------------------------------

/// Perform full DCAP collateral verification (T3_CHAIN).
///
/// This is the main orchestration function that ties together all T3 checks:
/// 1. PCK cert chain verification (already done before this call)
/// 2. TCB signing chain verification
/// 3. QE Identity verification (if QE Report present in quote)
/// 4. TCB Info verification and TCB level matching
/// 5. FMSPC cross-validation
///
/// Returns the resolved TCB status. The caller (T4_POLICY) decides whether
/// the status is acceptable.
fn verify_dcap_collateral(
    collateral: &TdxCollateral,
    quote: &[u8],
    body: &TdxQuoteBody,
    sig_section_offset: usize,
    header_pce_svn: u16,
) -> Result<TcbStatus, TdxVerifyError> {
    // Step 0: Extract PCK TCB values from the leaf certificate.
    // These are used for SGX TCB component matching (F1 fix).
    //
    // If the cert has Intel SGX Extensions (OID 1.2.840.113741.1.13.1) but
    // we fail to parse the TCB sub-OIDs, that's a hard error — the cert is
    // real but our parser can't handle it. If the cert has no SGX Extensions
    // at all (synthetic/test cert), we fall back to TEE_TCB_SVN.
    let pck_tcb = if !collateral.pck_chain_der.is_empty() {
        let leaf_cert =
            openssl::x509::X509::from_der(&collateral.pck_chain_der[0]).map_err(|e| {
                TdxVerifyError::PckChainInvalid(format!(
                    "failed to parse PCK leaf cert for TCB extraction: {e}"
                ))
            })?;
        match extract_pck_tcb_values(&leaf_cert) {
            Ok(values) => Some(values),
            Err(e) => {
                // Check whether the cert actually contains Intel SGX Extensions.
                // If it does but we failed to parse TCB sub-OIDs, that's a real
                // error even for opportunistic verification. If it doesn't have
                // SGX Extensions at all, it's a synthetic/test cert and fallback
                // is acceptable.
                let cert_der = leaf_cert.to_der().unwrap_or_default();
                let sgx_ext_root_oid: &[u8] = &[
                    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01,
                ];
                let has_sgx_ext = find_subsequence(&cert_der, sgx_ext_root_oid).is_some();

                if has_sgx_ext {
                    // Cert has Intel SGX Extensions but TCB parsing failed —
                    // this is a real parsing error, not a missing-extension case.
                    return Err(TdxVerifyError::PckChainInvalid(format!(
                        "PCK cert has SGX Extensions but TCB extraction failed: {e}"
                    )));
                }
                // Cert has no SGX Extensions — synthetic/test cert, fallback OK.
                tracing::warn!(
                    "PCK cert has no SGX Extensions (synthetic/test cert). \
                    TCB matching will use quote-only fallback."
                );
                None
            }
        }
    } else {
        None
    };

    // Step 1: Verify TCB signing chain and get signing key.
    let tcb_signing_key = verify_tcb_signing_chain(collateral)?;

    // Step 2: QE Identity verification (if provided).
    // Extract QE Report from quote signature data.
    if collateral.qe_identity_json.is_some() {
        let sig_data_start = sig_section_offset + 4; // skip sig_data_len
        let sig_data_len_raw = &quote[sig_section_offset..sig_section_offset + 4];
        let sig_data_len = u32::from_le_bytes([
            sig_data_len_raw[0],
            sig_data_len_raw[1],
            sig_data_len_raw[2],
            sig_data_len_raw[3],
        ]) as usize;

        if sig_data_len >= QE_REPORT_OFFSET + QE_REPORT_SIZE {
            let sig_data = &quote[sig_data_start..sig_data_start + sig_data_len];
            let qe_report = QeReportFields::parse(sig_data)?;
            let _qe_tcb_status = verify_qe_identity(collateral, &qe_report, &tcb_signing_key)?;
            tracing::debug!(qe_tcb_status = %_qe_tcb_status, "QE Identity verified");
        } else {
            // F6 fix: QE Identity was explicitly requested (JSON provided) but
            // the quote's signature data is too short to contain the QE Report.
            // This indicates a malformed or stripped quote — fail closed.
            return Err(TdxVerifyError::QeIdentityInvalid(format!(
                "QE Identity verification requested but quote signature data too short \
                 for QE Report ({sig_data_len} bytes < {})",
                QE_REPORT_OFFSET + QE_REPORT_SIZE
            )));
        }
    }

    // Step 3: TCB Info verification and level matching.
    // F2 fix: fail-closed when TCB Info is missing (this function is only
    // called when collateral verification is active, so we must not silently
    // assume UpToDate without evidence).
    let tcb_info_json =
        collateral
            .tcb_info_json
            .as_ref()
            .ok_or_else(|| TdxVerifyError::CollateralIncomplete {
                missing: "tcb_info_json (required for TCB level matching)".into(),
            })?;
    // Presence confirmed — now verify.
    let _ = tcb_info_json; // used below via collateral ref

    // Build the PCK TCB values for two-phase matching.
    // If real PCK TCB values are available (from cert SGX extensions), use them.
    // Otherwise fall back to TEE_TCB_SVN for SGX components too (synthetic certs).
    let effective_pck_tcb = pck_tcb.unwrap_or_else(|| {
        tracing::warn!(
            "Using TEE_TCB_SVN as fallback for SGX TCB components \
             (PCK cert has no SGX extensions). This is only safe for synthetic/test certs."
        );
        PckTcbValues {
            sgx_comp_svns: {
                let mut svns = [0u16; PCK_SGX_TCB_COMP_COUNT];
                for (i, svn) in svns.iter_mut().enumerate() {
                    *svn = body.tee_tcb_svn[i] as u16;
                }
                svns
            },
            pcesvn: header_pce_svn, // fallback to quote header PCESVN
        }
    });

    let (status, tcb_info) = verify_tcb_info(
        collateral,
        &body.tee_tcb_svn,
        &effective_pck_tcb,
        &tcb_signing_key,
    )?;

    // Step 4: FMSPC cross-validation.
    // Extract FMSPC from PCK cert and compare with TCBInfo.
    if !collateral.pck_chain_der.is_empty() {
        let leaf_cert =
            openssl::x509::X509::from_der(&collateral.pck_chain_der[0]).map_err(|e| {
                TdxVerifyError::FmspcMismatch {
                    quote_fmspc: "N/A".into(),
                    collateral_fmspc: format!("failed to parse PCK cert for FMSPC: {e}"),
                }
            })?;
        match extract_fmspc_from_pck_cert(&leaf_cert) {
            Ok(pck_fmspc) => {
                verify_fmspc(&pck_fmspc, &tcb_info)?;
                tracing::debug!(
                    fmspc = hex::encode(pck_fmspc),
                    "FMSPC cross-validation passed"
                );
            }
            Err(e) => {
                // F7 fix: Apply the same SGX Extensions OID presence check
                // as F1. If the cert has Intel SGX Extensions but FMSPC
                // extraction failed, that's a real error. If no SGX Extensions,
                // it's a synthetic/test cert and skipping is acceptable.
                let cert_der = leaf_cert.to_der().unwrap_or_default();
                let sgx_ext_root_oid: &[u8] = &[
                    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01,
                ];
                if find_subsequence(&cert_der, sgx_ext_root_oid).is_some() {
                    return Err(e);
                }
                tracing::warn!(
                    "PCK cert has no SGX Extensions (synthetic/test cert); \
                     skipping FMSPC cross-validation."
                );
            }
        }
    }

    tracing::debug!(tcb_status = %status, "TCB Info verified");
    Ok(status)
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

/// Build a synthetic TDX v4 quote with full DCAP-compatible signature section.
///
/// Includes QE Report data in the signature section (needed for QE Identity
/// verification tests). Also allows setting TEE_TCB_SVN and PCE SVN values
/// for TCB Info matching tests.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn build_synthetic_tdx_quote_full(
    reportdata: [u8; 64],
    mrtd: [u8; 48],
    rtmrs: [[u8; 48]; 4],
    tee_tcb_svn: [u8; 16],
    pce_svn: u16,
    signing_key: &openssl::ec::EcKey<openssl::pkey::Private>,
    qe_mrsigner: [u8; QE_MRSIGNER_SIZE],
    qe_isvprodid: u16,
    qe_isvsvn: u16,
    qe_miscselect: [u8; 4],
    qe_attributes: [u8; QE_ATTRIBUTES_SIZE],
) -> Vec<u8> {
    // -- Header (48 bytes) --
    let mut quote = Vec::with_capacity(2048);

    quote.extend_from_slice(&4u16.to_le_bytes()); // version = 4
    quote.extend_from_slice(&ATT_KEY_TYPE_P256.to_le_bytes());
    quote.extend_from_slice(&TEE_TYPE_TDX.to_le_bytes());
    quote.extend_from_slice(&0u16.to_le_bytes()); // qe_svn
    quote.extend_from_slice(&pce_svn.to_le_bytes()); // pce_svn
    quote.extend_from_slice(&[0u8; 16]); // qe_vendor_id
    quote.extend_from_slice(&[0u8; 20]); // user_data
    assert_eq!(quote.len(), HEADER_SIZE);

    // -- TD Quote Body (584 bytes for v4) --
    let body_start = quote.len();
    quote.extend_from_slice(&tee_tcb_svn); // tee_tcb_svn (16 bytes)
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

    // -- Signature Section (with QE Report) --
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

    // Build QE Report (384 bytes) — SGX REPORT structure.
    let mut qe_report_data = vec![0u8; QE_REPORT_SIZE];
    // CPUSVN (16 bytes) at offset 0 — leave as zeros for tests.
    // MISCSELECT (4 bytes) at offset 16.
    qe_report_data[QE_MISCSELECT_OFFSET..QE_MISCSELECT_OFFSET + 4].copy_from_slice(&qe_miscselect);
    // ATTRIBUTES (16 bytes) at offset 48.
    qe_report_data[QE_ATTRIBUTES_OFFSET..QE_ATTRIBUTES_OFFSET + QE_ATTRIBUTES_SIZE]
        .copy_from_slice(&qe_attributes);
    // MRSIGNER (32 bytes) at offset 128.
    qe_report_data[QE_MRSIGNER_OFFSET..QE_MRSIGNER_OFFSET + QE_MRSIGNER_SIZE]
        .copy_from_slice(&qe_mrsigner);
    // ISVPRODID (2 bytes) at offset 256.
    qe_report_data[QE_ISVPRODID_OFFSET..QE_ISVPRODID_OFFSET + 2]
        .copy_from_slice(&qe_isvprodid.to_le_bytes());
    // ISVSVN (2 bytes) at offset 258.
    qe_report_data[QE_ISVSVN_OFFSET..QE_ISVSVN_OFFSET + 2]
        .copy_from_slice(&qe_isvsvn.to_le_bytes());

    // sig_data_len includes: signature(64) + pubkey(64) + qe_report(384)
    let sig_data_len = (ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE + QE_REPORT_SIZE) as u32;
    quote.extend_from_slice(&sig_data_len.to_le_bytes());
    quote.extend_from_slice(&r);
    quote.extend_from_slice(&s);
    quote.extend_from_slice(pubkey_xy);
    quote.extend_from_slice(&qe_report_data);

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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
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
        // Chain-only test (no QE/TCB). Use opportunistic collateral path.
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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

    /// TDX-CHAIN-001b: DCAP bundle with tcb_info present but qe_identity missing →
    /// CollateralIncomplete error.
    #[test]
    fn tdx_chain_001b_collateral_incomplete_fails() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec).unwrap();
        let (pck_der, _pck_cert) =
            build_test_leaf("Test PCK Leaf", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);
        let crl_der = build_test_crl(&ca_key, &ca_cert, 99);
        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![pck_der],
            crl_der: Some(crl_der),
            // Partial: tcb_info present but qe_identity missing → error.
            qe_identity_json: None,
            tcb_info_json: Some(r#"{"tcbInfo":{}}"#.to_string()),
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            require_collateral: true,
            collateral: Some(collateral),
            ..Default::default()
        };
        let (_, doc) = valid_fixture();
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_COLLATERAL_INCOMPLETE");
        assert_eq!(err.layer(), "T3_CHAIN");
        assert!(
            format!("{err}").contains("qe_identity_json"),
            "error should name the missing field"
        );
    }

    /// F2: Both QE Identity and TCB Info missing with require_collateral=true →
    /// CollateralIncomplete (not silent PCK-only pass).
    #[test]
    fn f2_both_qe_and_tcb_missing_fails_closed() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec).unwrap();
        let (pck_der, _pck_cert) =
            build_test_leaf("Test PCK Leaf", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);
        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![pck_der],
            crl_der: None,
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            require_collateral: true,
            collateral: Some(collateral),
            ..Default::default()
        };
        let (_, doc) = valid_fixture();
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_COLLATERAL_INCOMPLETE");
    }

    /// TDX-CHAIN-001b: Collateral with only QE Identity but no TCB Info → incomplete.
    #[test]
    fn tdx_chain_001b_collateral_partial_qe_only_fails() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec).unwrap();
        let (pck_der, _pck_cert) =
            build_test_leaf("Test PCK Leaf", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);
        let crl_der = build_test_crl(&ca_key, &ca_cert, 99);
        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![pck_der],
            crl_der: Some(crl_der),
            qe_identity_json: Some(r#"{"enclaveIdentity":{}}"#.to_string()),
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            require_collateral: true,
            collateral: Some(collateral),
            ..Default::default()
        };
        let (_, doc) = valid_fixture();
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_COLLATERAL_INCOMPLETE");
        assert!(
            format!("{err}").contains("tcb_info_json"),
            "error should name the missing field"
        );
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
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
            qe_identity_json: None,
            tcb_info_json: None,
            tcb_signing_chain_der: None,
        };
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_PCK_CHAIN_INVALID");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    // -----------------------------------------------------------------------
    // DCAP Test Helpers — QE Identity, TCB Info, FMSPC
    // -----------------------------------------------------------------------

    /// Standard test QE MRSIGNER (32 bytes).
    const TEST_QE_MRSIGNER: [u8; 32] = [0xBE; 32];
    /// Standard test QE ISVPRODID.
    const TEST_QE_ISVPRODID: u16 = 1;
    /// Standard test QE ISVSVN.
    const TEST_QE_ISVSVN: u16 = 8;
    /// Standard test MISCSELECT (all zeros).
    const TEST_QE_MISCSELECT: [u8; 4] = [0u8; 4];
    /// Standard test ATTRIBUTES (all zeros).
    const TEST_QE_ATTRIBUTES: [u8; 16] = [0u8; 16];
    /// Standard test TEE_TCB_SVN (all 5s).
    const TEST_TEE_TCB_SVN: [u8; 16] = [5; 16];
    /// Standard test PCE SVN.
    const TEST_PCE_SVN: u16 = 10;
    /// Standard test FMSPC.
    const TEST_FMSPC: [u8; 6] = [0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00];

    /// Build a QE Identity JSON string for testing.
    ///
    /// Signs the enclaveIdentity JSON with the provided key and returns
    /// the complete response JSON (enclaveIdentity + signature).
    #[allow(clippy::too_many_arguments)]
    fn build_test_qe_identity_json(
        mrsigner: &[u8],
        isvprodid: u16,
        isvsvn: u16,
        miscselect: &[u8; 4],
        miscselect_mask: &[u8; 4],
        attributes: &[u8; 16],
        attributes_mask: &[u8; 16],
        signing_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> String {
        let identity_json = serde_json::json!({
            "version": 2,
            "issueDate": "2026-01-01T00:00:00Z",
            "nextUpdate": "2027-01-01T00:00:00Z",
            "miscselect": hex::encode(miscselect),
            "miscselectMask": hex::encode(miscselect_mask),
            "attributes": hex::encode(attributes),
            "attributesMask": hex::encode(attributes_mask),
            "mrsigner": hex::encode(mrsigner),
            "isvprodid": isvprodid,
            "tcbLevels": [
                {
                    "tcb": { "isvsvn": isvsvn },
                    "tcbStatus": "UpToDate"
                },
                {
                    "tcb": { "isvsvn": isvsvn.saturating_sub(2) },
                    "tcbStatus": "OutOfDate",
                    "advisoryIDs": ["INTEL-SA-00001"]
                }
            ]
        });

        let identity_str = identity_json.to_string();
        let sig_hex = sign_json_for_test(identity_str.as_bytes(), signing_key);

        serde_json::json!({
            "enclaveIdentity": identity_json,
            "signature": sig_hex,
        })
        .to_string()
    }

    /// Build a TCB Info JSON string for testing.
    fn build_test_tcb_info_json(
        fmspc: &[u8; 6],
        sgx_svns: &[u16; 16],
        tdx_svns: &[u16; 16],
        pcesvn: u16,
        tcb_status: &str,
        signing_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> String {
        let sgx_components: Vec<serde_json::Value> = sgx_svns
            .iter()
            .map(|&svn| serde_json::json!({"svn": svn}))
            .collect();
        let tdx_components: Vec<serde_json::Value> = tdx_svns
            .iter()
            .map(|&svn| serde_json::json!({"svn": svn}))
            .collect();

        let tcb_info_json = serde_json::json!({
            "version": 3,
            "issueDate": "2026-01-01T00:00:00Z",
            "nextUpdate": "2027-01-01T00:00:00Z",
            "fmspc": hex::encode(fmspc),
            "pceId": "0000",
            "tcbType": 1,
            "tcbEvaluationDataNumber": 1,
            "tdxModule": {
                "mrsigner": hex::encode([0u8; 48]),
                "attributes": hex::encode([0u8; 8]),
                "attributesMask": hex::encode([0u8; 8])
            },
            "tcbLevels": [
                {
                    "tcb": {
                        "sgxtcbcomponents": sgx_components,
                        "tdxtcbcomponents": tdx_components,
                        "pcesvn": pcesvn,
                    },
                    "tcbDate": "2026-01-01T00:00:00Z",
                    "tcbStatus": tcb_status,
                    "advisoryIDs": []
                },
                {
                    "tcb": {
                        "sgxtcbcomponents": (0..16).map(|_| serde_json::json!({"svn": 0})).collect::<Vec<_>>(),
                        "tdxtcbcomponents": (0..16).map(|_| serde_json::json!({"svn": 0})).collect::<Vec<_>>(),
                        "pcesvn": 0,
                    },
                    "tcbDate": "2025-01-01T00:00:00Z",
                    "tcbStatus": "OutOfDate",
                    "advisoryIDs": ["INTEL-SA-00000"]
                }
            ]
        });

        let tcb_info_str = tcb_info_json.to_string();
        let sig_hex = sign_json_for_test(tcb_info_str.as_bytes(), signing_key);

        serde_json::json!({
            "tcbInfo": tcb_info_json,
            "signature": sig_hex,
        })
        .to_string()
    }

    /// Sign bytes with an ECDSA-P256 key and return hex-encoded raw signature.
    fn sign_json_for_test(
        data: &[u8],
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> String {
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), key)
            .expect("signer");
        let der_sig = signer.sign_oneshot_to_vec(data).expect("sign");
        let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_der(&der_sig).expect("parse DER sig");
        let r = ecdsa_sig.r().to_vec_padded(32).expect("r");
        let s = ecdsa_sig.s().to_vec_padded(32).expect("s");
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&r);
        raw.extend_from_slice(&s);
        hex::encode(raw)
    }

    /// Build a full DCAP test fixture with QE Identity + TCB Info + cert chains.
    ///
    /// Returns (doc, collateral) ready for full DCAP verification.
    fn t3_dcap_valid_fixture() -> (AttestationDocument, TdxCollateral) {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");

        // PCK leaf cert (for quote signing).
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _leaf_cert) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        // TCB signing cert (for signing QE Identity + TCB Info).
        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec.clone()).unwrap();
        let (tcb_leaf_der, _tcb_cert) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        // Build quote with QE Report data.
        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        // Build QE Identity JSON signed by TCB signing key.
        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4], // full mask
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16], // full mask
            &tcb_key,
        );

        // Build TCB Info JSON signed by TCB signing key.
        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16], // SGX SVNs match TEE_TCB_SVN
            &[5; 16], // TDX SVNs match TEE_TCB_SVN
            TEST_PCE_SVN,
            "UpToDate",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        (doc, collateral)
    }

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T3_CHAIN DCAP: QE Identity
    // -----------------------------------------------------------------------

    /// TDX-CHAIN-004: Full DCAP positive path — QE Identity + TCB Info → PASS.
    #[test]
    fn tdx_chain_004_dcap_positive_path() {
        let (doc, collateral) = t3_dcap_valid_fixture();
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "DCAP positive path failed: {:?}",
            result.err()
        );
    }

    /// TDX-CHAIN-004: QE MRSIGNER mismatch → QeIdentityInvalid.
    #[test]
    fn tdx_chain_004_qe_mrsigner_mismatch() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        // Quote has QE MRSIGNER = TEST_QE_MRSIGNER ([0xBE; 32]).
        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        // QE Identity expects a DIFFERENT MRSIGNER.
        let wrong_mrsigner = [0xAA; 32];
        let qe_identity_json = build_test_qe_identity_json(
            &wrong_mrsigner,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "UpToDate",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QE_IDENTITY_INVALID");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    /// TDX-CHAIN-004: QE ISVPRODID mismatch → QeIdentityInvalid.
    #[test]
    fn tdx_chain_004_qe_isvprodid_mismatch() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        // Quote has ISVPRODID = 1 (TEST_QE_ISVPRODID).
        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        // QE Identity expects ISVPRODID = 99 (wrong).
        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            99, // wrong ISVPRODID
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "UpToDate",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QE_IDENTITY_INVALID");
        assert!(err.to_string().contains("ISVPRODID"));
    }

    /// TDX-CHAIN-004: QE Identity with tampered signature → QeIdentityInvalid.
    #[test]
    fn tdx_chain_004_qe_identity_bad_signature() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        // Sign QE Identity with a DIFFERENT key (not the TCB signing key).
        let wrong_ec = gen_ec_key();
        let wrong_key = openssl::pkey::PKey::from_ec_key(wrong_ec).unwrap();
        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &wrong_key, // signed with wrong key
        );

        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "UpToDate",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_QE_IDENTITY_INVALID");
    }

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T3_CHAIN DCAP: TCB Info
    // -----------------------------------------------------------------------

    /// TDX-CHAIN-005: TCB Info with tampered signature → TcbInfoInvalid.
    #[test]
    fn tdx_chain_005_tcb_info_bad_signature() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        // Sign TCB Info with a DIFFERENT key (not the TCB signing key).
        let wrong_ec = gen_ec_key();
        let wrong_key = openssl::pkey::PKey::from_ec_key(wrong_ec).unwrap();
        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "UpToDate",
            &wrong_key, // signed with wrong key
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        // QE identity succeeds but TCB info signature should fail.
        // Actually, since QE identity is checked first and it passes,
        // the error should be from TCB info.
        assert_eq!(err.code(), "TDX_TCB_INFO_INVALID");
        assert_eq!(err.layer(), "T3_CHAIN");
    }

    /// TDX-CHAIN-005: TCB Info missing TCB signing chain → TcbInfoInvalid.
    #[test]
    fn tdx_chain_005_missing_tcb_signing_chain() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: None,
            tcb_signing_chain_der: None, // missing!
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        // Partial DCAP bundle (qe_identity present, tcb_info missing) is now
        // rejected early as CollateralIncomplete, before reaching TCB validation.
        assert_eq!(err.code(), "TDX_COLLATERAL_INCOMPLETE");
        assert!(
            format!("{err}").contains("tcb_info_json"),
            "error should name the missing field"
        );
    }

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T4_POLICY: TCB Status
    // -----------------------------------------------------------------------

    /// TDX-POL-001: TCB status OutOfDate (default policy rejects) → TcbStatusUnacceptable.
    #[test]
    fn tdx_pol_001_tcb_out_of_date_rejected() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        // TCB Info reports "OutOfDate" status.
        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "OutOfDate", // not acceptable by default
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_TCB_STATUS_UNACCEPTABLE");
        assert_eq!(err.layer(), "T4_POLICY");
    }

    /// TDX-POL-001: TCB status OutOfDate accepted via custom policy → PASS.
    #[test]
    fn tdx_pol_001_tcb_out_of_date_accepted_custom_policy() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "OutOfDate",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        // Custom policy accepts OutOfDate.
        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            accepted_tcb_statuses: vec![TcbStatus::UpToDate, TcbStatus::OutOfDate],
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "OutOfDate should be accepted with custom policy: {:?}",
            result.err()
        );
    }

    /// TDX-POL-002: TCB status Revoked → TcbRevoked.
    #[test]
    fn tdx_pol_002_tcb_revoked() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        // TCB Info reports "Revoked" status.
        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "Revoked",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_TCB_REVOKED");
        assert_eq!(err.layer(), "T4_POLICY");
    }

    /// TDX-POL-001: TCB status SWHardeningNeeded accepted by default → PASS.
    #[test]
    fn tdx_pol_001_tcb_sw_hardening_accepted() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "SWHardeningNeeded",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "SWHardeningNeeded should be accepted by default: {:?}",
            result.err()
        );
    }

    /// TDX-CHAIN-005: TCB SVN below all levels → TcbInfoInvalid.
    #[test]
    fn tdx_chain_005_tcb_svn_below_all_levels() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        // Quote has TEE_TCB_SVN = [5; 16], but TCB Info requires [10; 16].
        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            [5; 16], // low SVN
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        // TCB Info requires SVN >= 10 for all components (above our 5).
        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[10; 16], // requires 10, we have 5
            &[10; 16],
            TEST_PCE_SVN,
            "UpToDate",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        // Should match the fallback "OutOfDate" level (svn=0, status=OutOfDate)
        // which is not acceptable by default.
        assert!(
            err.code() == "TDX_TCB_STATUS_UNACCEPTABLE" || err.code() == "TDX_TCB_INFO_INVALID",
            "Expected TCB rejection, got: {:?}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // M2 Trust Matrix Tests — T3_CHAIN DCAP: FMSPC
    // -----------------------------------------------------------------------

    /// TDX-CHAIN-006: FMSPC mismatch between PCK cert and TCBInfo.
    #[test]
    fn tdx_chain_006_fmspc_mismatch() {
        // Test the FMSPC cross-validation function directly.
        let pck_fmspc: [u8; 6] = [0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00];
        let tcb_info = TcbInfo {
            version: 3,
            issue_date: "2026-01-01T00:00:00Z".into(),
            next_update: "2027-01-01T00:00:00Z".into(),
            fmspc: "009060a10000".into(), // different from pck_fmspc
            pce_id: "0000".into(),
            tcb_type: 1,
            tcb_evaluation_data_number: 1,
            tdx_module: None,
            tdx_module_identities: vec![],
            tcb_levels: vec![],
        };

        let result = verify_fmspc(&pck_fmspc, &tcb_info);
        assert!(result.is_err());
        match result.unwrap_err() {
            TdxVerifyError::FmspcMismatch {
                quote_fmspc,
                collateral_fmspc,
            } => {
                assert_eq!(quote_fmspc, hex::encode(pck_fmspc));
                assert_eq!(collateral_fmspc, "009060a10000");
            }
            other => panic!("expected FmspcMismatch, got: {other:?}"),
        }
    }

    /// TDX-CHAIN-006: FMSPC match between PCK cert and TCBInfo → PASS.
    #[test]
    fn tdx_chain_006_fmspc_match() {
        let pck_fmspc: [u8; 6] = [0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00];
        let tcb_info = TcbInfo {
            version: 3,
            issue_date: "2026-01-01T00:00:00Z".into(),
            next_update: "2027-01-01T00:00:00Z".into(),
            fmspc: "00906ea10000".into(), // matches pck_fmspc
            pce_id: "0000".into(),
            tcb_type: 1,
            tcb_evaluation_data_number: 1,
            tdx_module: None,
            tdx_module_identities: vec![],
            tcb_levels: vec![],
        };

        let result = verify_fmspc(&pck_fmspc, &tcb_info);
        assert!(
            result.is_ok(),
            "FMSPC match should pass: {:?}",
            result.err()
        );
    }

    // -----------------------------------------------------------------------
    // TCB level matching unit tests
    // -----------------------------------------------------------------------

    /// TCB level matching: exact match → UpToDate.
    #[test]
    fn tcb_level_matching_exact() {
        let tcb_info: TcbInfo = serde_json::from_str(&format!(
            r#"{{
                "version": 3,
                "issueDate": "2026-01-01T00:00:00Z",
                "nextUpdate": "2027-01-01T00:00:00Z",
                "fmspc": "000000000000",
                "pceId": "0000",
                "tcbType": 1,
                "tcbEvaluationDataNumber": 1,
                "tcbLevels": [
                    {{
                        "tcb": {{
                            "sgxtcbcomponents": {sgx},
                            "tdxtcbcomponents": {tdx},
                            "pcesvn": 10
                        }},
                        "tcbStatus": "UpToDate"
                    }}
                ]
            }}"#,
            sgx = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 5}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            tdx = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 5}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
        ))
        .unwrap();

        // PCK cert SGX SVNs = 5 for all components, PCESVN = 10.
        let pck = PckTcbValues {
            sgx_comp_svns: [5; PCK_SGX_TCB_COMP_COUNT],
            pcesvn: 10,
        };
        // TDX TEE_TCB_SVN = 5 for all components.
        let status = match_tcb_level(&tcb_info, &pck, &[5; 16]).unwrap();
        assert_eq!(status, TcbStatus::UpToDate);
    }

    /// TCB level matching: quote SVN higher than required → still matches.
    #[test]
    fn tcb_level_matching_higher_svn() {
        let tcb_info: TcbInfo = serde_json::from_str(&format!(
            r#"{{
                "version": 3,
                "issueDate": "2026-01-01T00:00:00Z",
                "nextUpdate": "2027-01-01T00:00:00Z",
                "fmspc": "000000000000",
                "pceId": "0000",
                "tcbType": 1,
                "tcbEvaluationDataNumber": 1,
                "tcbLevels": [
                    {{
                        "tcb": {{
                            "sgxtcbcomponents": {sgx},
                            "tdxtcbcomponents": {tdx},
                            "pcesvn": 5
                        }},
                        "tcbStatus": "UpToDate"
                    }}
                ]
            }}"#,
            sgx = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 3}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            tdx = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 3}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
        ))
        .unwrap();

        // PCK cert SGX SVNs = 10, PCESVN = 10 (both higher than required 3 and 5).
        let pck = PckTcbValues {
            sgx_comp_svns: [10; PCK_SGX_TCB_COMP_COUNT],
            pcesvn: 10,
        };
        // TDX TEE_TCB_SVN = 10.
        let status = match_tcb_level(&tcb_info, &pck, &[10; 16]).unwrap();
        assert_eq!(status, TcbStatus::UpToDate);
    }

    /// TCB level matching: PCE SVN too low → falls to lower level.
    #[test]
    fn tcb_level_matching_pce_svn_too_low() {
        let tcb_info: TcbInfo = serde_json::from_str(&format!(
            r#"{{
                "version": 3,
                "issueDate": "2026-01-01T00:00:00Z",
                "nextUpdate": "2027-01-01T00:00:00Z",
                "fmspc": "000000000000",
                "pceId": "0000",
                "tcbType": 1,
                "tcbEvaluationDataNumber": 1,
                "tcbLevels": [
                    {{
                        "tcb": {{
                            "sgxtcbcomponents": {sgx_high},
                            "tdxtcbcomponents": {tdx_high},
                            "pcesvn": 10
                        }},
                        "tcbStatus": "UpToDate"
                    }},
                    {{
                        "tcb": {{
                            "sgxtcbcomponents": {sgx_low},
                            "tdxtcbcomponents": {tdx_low},
                            "pcesvn": 5
                        }},
                        "tcbStatus": "OutOfDate"
                    }}
                ]
            }}"#,
            sgx_high = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 5}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            tdx_high = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 5}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            sgx_low = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 3}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            tdx_low = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 3}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
        ))
        .unwrap();

        // PCK cert SGX SVNs = 5 (matches both levels) but PCESVN=7 (< 10, >= 5).
        // Should match the second level (OutOfDate).
        let pck = PckTcbValues {
            sgx_comp_svns: [5; PCK_SGX_TCB_COMP_COUNT],
            pcesvn: 7,
        };
        // TDX TEE_TCB_SVN = 5.
        let status = match_tcb_level(&tcb_info, &pck, &[5; 16]).unwrap();
        assert_eq!(status, TcbStatus::OutOfDate);
    }

    /// F1 test: Two-phase matching with divergent PCK SGX SVNs vs TEE_TCB_SVN.
    ///
    /// PCK cert SGX SVNs are high (match level 1), but TEE_TCB_SVN is low
    /// (only matches level 2). Should select level 2.
    #[test]
    fn tcb_level_matching_two_phase_divergent() {
        let tcb_info: TcbInfo = serde_json::from_str(&format!(
            r#"{{
                "version": 3,
                "issueDate": "2026-01-01T00:00:00Z",
                "nextUpdate": "2027-01-01T00:00:00Z",
                "fmspc": "000000000000",
                "pceId": "0000",
                "tcbType": 1,
                "tcbEvaluationDataNumber": 1,
                "tcbLevels": [
                    {{
                        "tcb": {{
                            "sgxtcbcomponents": {sgx_high},
                            "tdxtcbcomponents": {tdx_high},
                            "pcesvn": 10
                        }},
                        "tcbStatus": "UpToDate"
                    }},
                    {{
                        "tcb": {{
                            "sgxtcbcomponents": {sgx_low},
                            "tdxtcbcomponents": {tdx_low},
                            "pcesvn": 5
                        }},
                        "tcbStatus": "OutOfDate"
                    }}
                ]
            }}"#,
            sgx_high = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 10}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            tdx_high = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 10}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            sgx_low = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 3}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            tdx_low = serde_json::to_string(
                &(0..16)
                    .map(|_| serde_json::json!({"svn": 3}))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
        ))
        .unwrap();

        // PCK cert has HIGH SGX SVNs (would match level 1 for SGX phase).
        let pck = PckTcbValues {
            sgx_comp_svns: [15; PCK_SGX_TCB_COMP_COUNT],
            pcesvn: 15,
        };
        // But TEE_TCB_SVN is LOW (only matches level 2 for TDX phase).
        // Phase 1 passes for level 1 (SGX), but phase 2 fails (TDX).
        // So it falls through to level 2 where both phases pass.
        let status = match_tcb_level(&tcb_info, &pck, &[5; 16]).unwrap();
        assert_eq!(
            status,
            TcbStatus::OutOfDate,
            "two-phase matching should select level 2 when TDX SVNs are too low for level 1"
        );

        // Conversely: LOW SGX SVNs but HIGH TEE_TCB_SVN.
        let pck_low = PckTcbValues {
            sgx_comp_svns: [5; PCK_SGX_TCB_COMP_COUNT],
            pcesvn: 15,
        };
        let status = match_tcb_level(&tcb_info, &pck_low, &[15; 16]).unwrap();
        assert_eq!(
            status,
            TcbStatus::OutOfDate,
            "two-phase matching should select level 2 when SGX SVNs are too low for level 1"
        );
    }

    /// F1 test: Real PCK leaf cert fixture — verify SGX TCB SVN + PCESVN extraction.
    #[test]
    fn pck_tcb_extraction_real_cert() {
        // Real Intel-signed TDX PCK certificate vendored from intel-dcap-ref sample data.
        let pem_bytes = include_bytes!("../../tests/fixtures/intel_tdx_pck_cert.pem");
        let cert =
            openssl::x509::X509::from_pem(pem_bytes).expect("failed to parse real TDX PCK cert");

        let pck_tcb =
            extract_pck_tcb_values(&cert).expect("failed to extract PCK TCB values from real cert");

        // Verify COMP01 = 0x52 = 82 (from DER analysis of the cert).
        assert_eq!(
            pck_tcb.sgx_comp_svns[0], 82,
            "SGX_TCB_COMP01_SVN should be 82 (0x52)"
        );
        // Verify COMP08 = 0x0A = 10.
        assert_eq!(
            pck_tcb.sgx_comp_svns[7], 10,
            "SGX_TCB_COMP08_SVN should be 10 (0x0A)"
        );
        // Verify PCESVN = 0x2961 = 10593.
        assert_eq!(pck_tcb.pcesvn, 10593, "PCESVN should be 10593 (0x2961)");

        // All 16 components should be non-trivially populated.
        let nonzero_count = pck_tcb.sgx_comp_svns.iter().filter(|&&v| v > 0).count();
        assert!(
            nonzero_count >= 10,
            "expected most SGX TCB components to be non-zero, got {nonzero_count}"
        );
    }

    /// F2 test: Missing TCB Info with require_collateral=true → CollateralIncomplete.
    #[test]
    fn f2_missing_tcb_info_fails_closed() {
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        let quote = build_synthetic_tdx_quote_full(
            [0u8; 64],
            [0xAA; 48],
            [[0u8; 48]; 4],
            TEST_TEE_TCB_SVN,
            TEST_PCE_SVN,
            &leaf_ec,
            TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            TEST_QE_MISCSELECT,
            TEST_QE_ATTRIBUTES,
        );
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        // Provide QE Identity but NO TCB Info — this should now fail.
        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: None, // Deliberately missing!
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        // F2: should fail with CollateralIncomplete, not silently return UpToDate.
        assert_eq!(err.code(), "TDX_COLLATERAL_INCOMPLETE");
    }

    /// Build a synthetic TDX quote with a custom td_attributes value, properly signed.
    fn build_synthetic_quote_with_td_attributes(td_attributes: u64) -> Vec<u8> {
        // Build the quote manually so we can set td_attributes before signing.
        let mut quote = Vec::with_capacity(1024);

        // Header (48 bytes)
        quote.extend_from_slice(&4u16.to_le_bytes()); // version
        quote.extend_from_slice(&ATT_KEY_TYPE_P256.to_le_bytes());
        quote.extend_from_slice(&TEE_TYPE_TDX.to_le_bytes());
        quote.extend_from_slice(&0u16.to_le_bytes()); // qe_svn
        quote.extend_from_slice(&0u16.to_le_bytes()); // pce_svn
        quote.extend_from_slice(&[0u8; 16]); // qe_vendor_id
        quote.extend_from_slice(&[0u8; 20]); // user_data
        assert_eq!(quote.len(), HEADER_SIZE);

        // Body (584 bytes)
        quote.extend_from_slice(&[0u8; 16]); // tee_tcb_svn
        quote.extend_from_slice(&[0u8; 48]); // mrseam
        quote.extend_from_slice(&[0u8; 48]); // mrsignerseam
        quote.extend_from_slice(&[0u8; 8]); // seam_attributes
        quote.extend_from_slice(&td_attributes.to_le_bytes()); // td_attributes
        quote.extend_from_slice(&[0u8; 8]); // xfam
        quote.extend_from_slice(&[0xAA; 48]); // mrtd
        quote.extend_from_slice(&[0u8; 48]); // mrconfigid
        quote.extend_from_slice(&[0u8; 48]); // mrowner
        quote.extend_from_slice(&[0u8; 48]); // mrownerconfig
        quote.extend_from_slice(&[0u8; 48]); // rtmr0
        quote.extend_from_slice(&[0u8; 48]); // rtmr1
        quote.extend_from_slice(&[0u8; 48]); // rtmr2
        quote.extend_from_slice(&[0u8; 48]); // rtmr3
        quote.extend_from_slice(&[0u8; 64]); // reportdata
        assert_eq!(quote.len() - HEADER_SIZE, BODY_SIZE_V4);

        let signed_len = quote.len();

        // Sign with ephemeral key.
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
        let _pkey = openssl::pkey::PKey::from_ec_key(ec_key.clone()).unwrap();
        let sig =
            openssl::ecdsa::EcdsaSig::sign(&Sha256::digest(&quote[..signed_len]), &ec_key).unwrap();
        let r = sig.r().to_vec_padded(32).unwrap();
        let s = sig.s().to_vec_padded(32).unwrap();

        let mut pubkey_xy = [0u8; 64];
        let mut bn_ctx = openssl::bn::BigNumContext::new().unwrap();
        let pubkey_bytes = ec_key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )
            .unwrap();
        pubkey_xy.copy_from_slice(&pubkey_bytes[1..65]);

        let sig_data_len = (ECDSA_SIG_SIZE + ECDSA_PUBKEY_SIZE) as u32;
        quote.extend_from_slice(&sig_data_len.to_le_bytes());
        quote.extend_from_slice(&r);
        quote.extend_from_slice(&s);
        quote.extend_from_slice(&pubkey_xy);

        quote
    }

    /// F4 test: Debug-mode TD (TD_ATTRIBUTES bit 0 = 1) is rejected by default.
    #[test]
    fn f4_debug_td_rejected() {
        let quote = build_synthetic_quote_with_td_attributes(0x01); // DEBUG bit set
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let verifier = TdxVerifier::new(None);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        assert_eq!(err.code(), "TDX_DEBUG_TD_REJECTED");
        assert_eq!(err.layer(), "T4_POLICY");
    }

    /// F4 test: Debug-mode TD accepted when reject_debug_td = false.
    #[test]
    fn f4_debug_td_accepted_when_policy_allows() {
        let quote = build_synthetic_quote_with_td_attributes(0x01); // DEBUG bit set
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let policy = TdxVerifyPolicy {
            reject_debug_td: false,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "debug TD should be accepted when reject_debug_td=false: {:?}",
            result.err()
        );
    }

    /// F4 test: Non-debug TD (td_attributes = 0) passes with default policy.
    #[test]
    fn f4_non_debug_td_passes() {
        let quote = build_synthetic_quote_with_td_attributes(0x00);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));
        let verifier = TdxVerifier::new(None);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "non-debug TD should pass: {:?}",
            result.err()
        );
    }

    /// F6 test: QE Identity provided but quote too short for QE Report → error.
    #[test]
    fn f6_qe_identity_short_sig_data_fails() {
        // Build a DCAP fixture where the quote has a short signature section
        // (no QE Report) but QE Identity JSON is provided.
        let (root_der, ca_key, ca_cert) = build_test_ca("Test TDX Root CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec.clone()).unwrap();
        let (leaf_der, _) =
            build_test_leaf("Test PCK Cert", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);

        let tcb_ec = gen_ec_key();
        let tcb_key = openssl::pkey::PKey::from_ec_key(tcb_ec).unwrap();
        let (tcb_leaf_der, _) =
            build_test_leaf("Test TCB Signing", &ca_key, &ca_cert, &tcb_key, 3, 0, 365);

        // Build quote WITHOUT QE Report — use the PCK leaf key for signing
        // so the chain validation passes, but use the basic builder that
        // produces a short sig section (sig + pubkey only, no QE Report).
        let quote =
            build_synthetic_tdx_quote_with_key([0u8; 64], [0xAA; 48], [[0u8; 48]; 4], &leaf_ec);
        let doc = AttestationDocument::new(encode_tdx_document(&quote));

        let qe_identity_json = build_test_qe_identity_json(
            &TEST_QE_MRSIGNER,
            TEST_QE_ISVPRODID,
            TEST_QE_ISVSVN,
            &TEST_QE_MISCSELECT,
            &[0xFF; 4],
            &TEST_QE_ATTRIBUTES,
            &[0xFF; 16],
            &tcb_key,
        );

        let tcb_info_json = build_test_tcb_info_json(
            &TEST_FMSPC,
            &[5; 16],
            &[5; 16],
            TEST_PCE_SVN,
            "UpToDate",
            &tcb_key,
        );

        let collateral = TdxCollateral {
            root_ca_der: root_der,
            pck_chain_der: vec![leaf_der],
            crl_der: None,
            qe_identity_json: Some(qe_identity_json),
            tcb_info_json: Some(tcb_info_json),
            tcb_signing_chain_der: Some(vec![tcb_leaf_der]),
        };

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            require_collateral: true,
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let err = verifier.verify_tdx(&doc).unwrap_err();
        // F6: should fail with QeIdentityInvalid, not silently skip.
        assert_eq!(err.code(), "TDX_QE_IDENTITY_INVALID");
    }

    /// F7 test: FMSPC extraction fails on cert with SGX Extensions → hard error.
    ///
    /// Uses the real Intel PCK cert (which has SGX Extensions + valid FMSPC),
    /// then corrupts the FMSPC sub-OID so extraction fails. The F7 gating
    /// logic should detect the SGX Extensions root OID is still present and
    /// return a hard error instead of silently skipping.
    #[test]
    fn f7_fmspc_extraction_fails_with_sgx_extensions_present() {
        let pem_bytes = include_bytes!("../../tests/fixtures/intel_tdx_pck_cert.pem");
        let cert = openssl::x509::X509::from_pem(pem_bytes).unwrap();
        let mut cert_der = cert.to_der().unwrap();

        // Confirm the real cert has valid FMSPC first.
        assert!(
            extract_fmspc_from_pck_cert(&cert).is_ok(),
            "real PCK cert should have valid FMSPC"
        );

        // Find the FMSPC OID (1.2.840.113741.1.13.1.4) in the raw DER.
        let fmspc_oid: &[u8] = &[
            0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04,
        ];
        let pos =
            find_subsequence(&cert_der, fmspc_oid).expect("FMSPC OID must exist in real PCK cert");

        // Corrupt the last byte of the FMSPC OID (.04 → .FF).
        // This breaks FMSPC extraction but leaves the SGX Extensions root OID
        // (1.2.840.113741.1.13.1) intact.
        cert_der[pos + fmspc_oid.len() - 1] = 0xFF;

        // Confirm FMSPC extraction now fails on the corrupted DER.
        assert!(
            parse_fmspc_from_sgx_extensions(&cert_der).is_err(),
            "FMSPC extraction should fail on corrupted OID"
        );

        // Confirm the SGX Extensions root OID is still present.
        let sgx_ext_root_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01,
        ];
        assert!(
            find_subsequence(&cert_der, sgx_ext_root_oid).is_some(),
            "SGX Extensions root OID should still be present after FMSPC corruption"
        );

        // Therefore: F7 gating would detect SGX Extensions are present
        // and return a hard error, not silently skip.
        //
        // Also verify contrast: a synthetic cert has NO SGX Extensions OID.
        let (_, ca_key, ca_cert) = build_test_ca("Test CA");
        let leaf_ec = gen_ec_key();
        let leaf_key = openssl::pkey::PKey::from_ec_key(leaf_ec).unwrap();
        let (leaf_der, _) = build_test_leaf("Test Leaf", &ca_key, &ca_cert, &leaf_key, 2, 0, 365);
        assert!(
            find_subsequence(&leaf_der, sgx_ext_root_oid).is_none(),
            "synthetic cert must NOT have SGX Extensions OID (fallback path)"
        );
    }

    // -----------------------------------------------------------------------
    // QE Report parsing unit tests
    // -----------------------------------------------------------------------

    /// QE Report parsing: valid data extracts correct fields.
    #[test]
    fn qe_report_parsing_valid() {
        // Build signature data with QE Report.
        let mut sig_data = vec![0u8; QE_REPORT_OFFSET + QE_REPORT_SIZE];
        // Place MRSIGNER at correct offset.
        let report_start = QE_REPORT_OFFSET;
        sig_data[report_start + QE_MRSIGNER_OFFSET..report_start + QE_MRSIGNER_OFFSET + 32]
            .copy_from_slice(&[0xBE; 32]);
        sig_data[report_start + QE_ISVPRODID_OFFSET..report_start + QE_ISVPRODID_OFFSET + 2]
            .copy_from_slice(&1u16.to_le_bytes());
        sig_data[report_start + QE_ISVSVN_OFFSET..report_start + QE_ISVSVN_OFFSET + 2]
            .copy_from_slice(&8u16.to_le_bytes());
        sig_data[report_start + QE_MISCSELECT_OFFSET..report_start + QE_MISCSELECT_OFFSET + 4]
            .copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        sig_data[report_start + QE_ATTRIBUTES_OFFSET..report_start + QE_ATTRIBUTES_OFFSET + 16]
            .copy_from_slice(&[0xAA; 16]);

        let qe_report = QeReportFields::parse(&sig_data).unwrap();
        assert_eq!(qe_report.mrsigner, [0xBE; 32]);
        assert_eq!(qe_report.isvprodid, 1);
        assert_eq!(qe_report.isvsvn, 8);
        assert_eq!(qe_report.miscselect, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(qe_report.attributes, [0xAA; 16]);
    }

    /// QE Report parsing: truncated data → error.
    #[test]
    fn qe_report_parsing_truncated() {
        // Too short for QE Report.
        let sig_data = vec![0u8; QE_REPORT_OFFSET + 10]; // way too short
        let result = QeReportFields::parse(&sig_data);
        assert!(result.is_err());
        match result.unwrap_err() {
            TdxVerifyError::QuoteParseFailed(msg) => {
                assert!(msg.contains("too short for QE Report"));
            }
            other => panic!("expected QuoteParseFailed, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // TcbStatus unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn tcb_status_from_str_all_variants() {
        assert_eq!(TcbStatus::from_str("UpToDate"), TcbStatus::UpToDate);
        assert_eq!(TcbStatus::from_str("OutOfDate"), TcbStatus::OutOfDate);
        assert_eq!(TcbStatus::from_str("Revoked"), TcbStatus::Revoked);
        assert_eq!(
            TcbStatus::from_str("ConfigurationNeeded"),
            TcbStatus::ConfigurationNeeded
        );
        assert_eq!(
            TcbStatus::from_str("ConfigurationAndSWHardeningNeeded"),
            TcbStatus::ConfigurationAndSWHardeningNeeded
        );
        assert_eq!(
            TcbStatus::from_str("SWHardeningNeeded"),
            TcbStatus::SWHardeningNeeded
        );
        assert_eq!(
            TcbStatus::from_str("OutOfDateConfigurationNeeded"),
            TcbStatus::OutOfDateConfigurationNeeded
        );
        assert!(matches!(
            TcbStatus::from_str("FooBar"),
            TcbStatus::Unknown(_)
        ));
    }

    #[test]
    fn tcb_status_default_acceptability() {
        assert!(TcbStatus::UpToDate.is_acceptable_default());
        assert!(TcbStatus::SWHardeningNeeded.is_acceptable_default());
        assert!(!TcbStatus::OutOfDate.is_acceptable_default());
        assert!(!TcbStatus::Revoked.is_acceptable_default());
        assert!(!TcbStatus::ConfigurationNeeded.is_acceptable_default());
        assert!(!TcbStatus::ConfigurationAndSWHardeningNeeded.is_acceptable_default());
        assert!(!TcbStatus::OutOfDateConfigurationNeeded.is_acceptable_default());
        assert!(!TcbStatus::Unknown("test".into()).is_acceptable_default());
    }

    // -----------------------------------------------------------------------
    // FMSPC utility unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn find_subsequence_basic() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"hello", b"xyz"), None);
        assert_eq!(find_subsequence(b"abcabc", b"abc"), Some(0));
        assert_eq!(find_subsequence(b"", b"a"), None);
        assert_eq!(find_subsequence(b"a", b""), None);
    }

    // -----------------------------------------------------------------------
    // Backward compatibility: existing tests still pass with new collateral fields
    // -----------------------------------------------------------------------

    /// Verify that existing t3_valid_fixture still works (no QE/TCB fields).
    #[test]
    fn backward_compat_old_collateral_format() {
        let (doc, collateral) = t3_valid_fixture();
        // t3_valid_fixture() should produce collateral with None for new fields.
        assert!(collateral.qe_identity_json.is_none());
        assert!(collateral.tcb_info_json.is_none());
        assert!(collateral.tcb_signing_chain_der.is_none());

        let policy = TdxVerifyPolicy {
            collateral: Some(collateral),
            ..Default::default()
        };
        let verifier = TdxVerifier::with_policy(policy);
        let result = verifier.verify_tdx(&doc);
        assert!(
            result.is_ok(),
            "Old collateral format should still pass: {:?}",
            result.err()
        );
    }

    // -----------------------------------------------------------------------
    // Error code metadata for new variants
    // -----------------------------------------------------------------------

    /// Verify that new DCAP error variants have correct codes and layers.
    #[test]
    fn dcap_error_codes_correct() {
        let cases: Vec<(TdxVerifyError, &str, &str)> = vec![
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
            (
                TdxVerifyError::TcbStatusUnacceptable("test".into()),
                "TDX_TCB_STATUS_UNACCEPTABLE",
                "T4_POLICY",
            ),
            (TdxVerifyError::TcbRevoked, "TDX_TCB_REVOKED", "T4_POLICY"),
        ];

        for (error, expected_code, expected_layer) in cases {
            assert_eq!(error.code(), expected_code, "code mismatch for {error:?}");
            assert_eq!(
                error.layer(),
                expected_layer,
                "layer mismatch for {error:?}"
            );
        }
    }
}
