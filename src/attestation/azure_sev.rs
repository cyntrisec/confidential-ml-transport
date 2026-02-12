use std::collections::BTreeMap;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::types::{AttestationDocument, VerifiedAttestation};
use super::{AttestationProvider, AttestationVerifier};
use crate::error::AttestError;

/// Wire format marker for Azure SEV-SNP attestation documents.
const AZURE_SNP_MARKER: &[u8; 12] = b"AZ_SNP_V1\0\0\0";

/// Size of an SEV-SNP attestation report (fixed at 1184 bytes).
const REPORT_SIZE: usize = 1184;

/// Attestation provider for Azure Confidential VMs (SEV-SNP via vTPM).
///
/// Azure CVMs in vTOM mode do not expose `/dev/sev-guest`. Instead, the
/// HCL (Host Compatibility Layer) provides SNP attestation via the vTPM:
///
/// 1. Write custom data to TPM NV index `0x01400002`
/// 2. Wait for HCL to regenerate the report (~3 seconds)
/// 3. Read the HCL report from TPM NV index `0x01400001`
///
/// The HCL report wraps an SNP attestation report. The custom data (our
/// `pk || nonce`) appears in the VarData JSON as `"user-data":"<hex>"`.
/// The SNP report's REPORT_DATA is `SHA256(VarData)`, binding the user
/// data to the hardware report.
///
/// # REPORT_DATA layout (Azure-specific)
///
/// Unlike direct SNP, we do NOT place pk||nonce in REPORT_DATA directly.
/// Instead:
/// - `REPORT_DATA[0..32]` = SHA256(VarData JSON including user-data)
/// - `REPORT_DATA[32..64]` = zeros
/// - User data (pk||nonce) is in VarData `"user-data"` field as hex
///
/// The verifier recovers pk and nonce from the HCL report's VarData.
#[cfg(target_os = "linux")]
pub struct AzureSevSnpProvider;

#[cfg(target_os = "linux")]
impl AzureSevSnpProvider {
    /// Create a new Azure SEV-SNP provider.
    ///
    /// Returns an error if the vTPM device is not available.
    pub fn new() -> Result<Self, AttestError> {
        // Verify we can talk to the vTPM by doing a test read.
        az_cvm_vtpm::vtpm::get_report().map_err(|e| {
            AttestError::GenerationFailed(format!(
                "failed to access vTPM — not running inside an Azure CVM? {e}"
            ))
        })?;
        Ok(Self)
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl AttestationProvider for AzureSevSnpProvider {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        // Build 64-byte custom data: pk[0..32] || nonce[32..64]
        let mut custom_data = vec![0u8; 64];

        if let Some(pk) = public_key {
            if pk.len() != 32 {
                return Err(AttestError::GenerationFailed(format!(
                    "public key must be 32 bytes, got {}",
                    pk.len()
                )));
            }
            custom_data[..32].copy_from_slice(pk);
        }

        if let Some(n) = nonce {
            if n.len() != 32 {
                return Err(AttestError::GenerationFailed(format!(
                    "nonce must be 32 bytes, got {}",
                    n.len()
                )));
            }
            custom_data[32..64].copy_from_slice(n);
        }

        // Request HCL report with our custom data via vTPM.
        // This writes to NV 0x01400002, waits 3s, then reads from NV 0x01400001.
        let hcl_report_bytes = az_cvm_vtpm::vtpm::get_report_with_report_data(&custom_data)
            .map_err(|e| {
                AttestError::GenerationFailed(format!("failed to get HCL report via vTPM: {e}"))
            })?;

        // Fetch certificate chain from Azure IMDS THIM endpoint.
        let cert_chain_bytes = fetch_imds_certificates().map_err(|e| {
            AttestError::GenerationFailed(format!("failed to fetch certificates from IMDS: {e}"))
        })?;

        // Build wire document: marker + hcl_report_size + hcl_report + cert_chain_size + cert_chain
        let raw = encode_azure_snp_document(&hcl_report_bytes, &cert_chain_bytes);
        Ok(AttestationDocument::new(raw))
    }
}

/// Verifier for Azure SEV-SNP attestation reports.
///
/// Validates by:
/// 1. Parsing the wire document (marker, HCL report, certificate chain)
/// 2. Extracting the SNP report from the HCL report
/// 3. Extracting `user-data` (pk || nonce) from VarData JSON
/// 4. Verifying `REPORT_DATA[0..32] == SHA256(VarData)` (binding check)
/// 5. Validating the certificate chain (ARK → ASK → VCEK) and report signature
/// 6. Optionally checking the MEASUREMENT against an expected value
pub struct AzureSevSnpVerifier {
    expected_measurement: Option<Vec<u8>>,
}

impl AzureSevSnpVerifier {
    /// Create a new verifier.
    ///
    /// If `expected_measurement` is `Some`, the verifier will check that the
    /// report's `MEASUREMENT` field (48 bytes) matches the expected value.
    pub fn new(expected_measurement: Option<Vec<u8>>) -> Self {
        Self {
            expected_measurement,
        }
    }
}

#[async_trait]
impl AttestationVerifier for AzureSevSnpVerifier {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        // Step 1: Parse wire document.
        let (hcl_report_bytes, cert_chain_bytes) = decode_azure_snp_document(&doc.raw)?;

        // Step 2: Parse the HCL report.
        let hcl_report =
            az_cvm_vtpm::hcl::HclReport::new(hcl_report_bytes.clone()).map_err(|e| {
                AttestError::VerificationFailed(format!("failed to parse HCL report: {e}"))
            })?;

        // Verify this is an SNP report (not TDX).
        if hcl_report.report_type() != az_cvm_vtpm::hcl::ReportType::Snp {
            return Err(AttestError::VerificationFailed(format!(
                "expected SNP report type, got {:?}",
                hcl_report.report_type()
            )));
        }

        // Step 3: Extract the raw SNP report bytes.
        // The SNP report starts at offset 32 (after the AttestationHeader) and is 1184 bytes.
        let snp_offset = 32;
        if hcl_report_bytes.len() < snp_offset + REPORT_SIZE {
            return Err(AttestError::VerificationFailed(
                "HCL report too short to contain SNP report".into(),
            ));
        }
        let report_bytes = &hcl_report_bytes[snp_offset..snp_offset + REPORT_SIZE];

        // Step 4: Parse the SNP report.
        let report = parse_attestation_report(report_bytes)?;

        // Step 5: Verify REPORT_DATA binding.
        // On Azure, REPORT_DATA[0..32] = SHA256(VarData).
        let var_data = hcl_report.var_data();
        let var_data_hash: [u8; 32] = Sha256::digest(var_data).into();
        if report.report_data[..32] != var_data_hash[..] {
            return Err(AttestError::VerificationFailed(format!(
                "REPORT_DATA binding check failed: report_data[0..32] != SHA256(VarData). \
                 Expected {}, got {}",
                hex::encode(var_data_hash),
                hex::encode(&report.report_data[..32])
            )));
        }

        // Step 6: Extract pk || nonce from VarData JSON's "user-data" field.
        let (public_key, nonce) = extract_user_data_from_var_data(var_data)?;

        // Step 7: Validate certificate chain and verify report signature.
        if !cert_chain_bytes.is_empty() {
            verify_report_with_certs(&report, report_bytes, &cert_chain_bytes)?;
        } else {
            tracing::warn!("no certificate chain provided, skipping chain verification");
        }

        // Step 8: Check measurement if expected.
        let mut measurements = BTreeMap::new();
        measurements.insert(0, report.measurement.to_vec());

        if let Some(ref expected) = self.expected_measurement {
            if expected.as_slice() != report.measurement.as_slice() {
                return Err(AttestError::VerificationFailed(format!(
                    "MEASUREMENT mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(report.measurement)
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

/// Encode an Azure SEV-SNP attestation document for the wire.
///
/// Format:
/// ```text
/// [12 bytes] AZ_SNP_V1\0\0\0  (marker)
/// [4 bytes]  hcl_report_size   (u32 LE)
/// [N bytes]  hcl_report        (N = hcl_report_size, typically ~2600)
/// [4 bytes]  cert_chain_size   (u32 LE)
/// [M bytes]  cert_chain        (M = cert_chain_size, PEM-encoded)
/// ```
fn encode_azure_snp_document(hcl_report: &[u8], cert_chain: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(12 + 4 + hcl_report.len() + 4 + cert_chain.len());
    raw.extend_from_slice(AZURE_SNP_MARKER);
    raw.extend_from_slice(&(hcl_report.len() as u32).to_le_bytes());
    raw.extend_from_slice(hcl_report);
    raw.extend_from_slice(&(cert_chain.len() as u32).to_le_bytes());
    raw.extend_from_slice(cert_chain);
    raw
}

/// Decode an Azure SEV-SNP wire document into (hcl_report_bytes, cert_chain_bytes).
fn decode_azure_snp_document(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
    if raw.len() < 12 {
        return Err(AttestError::VerificationFailed(
            "document too short for Azure SNP marker".into(),
        ));
    }

    if &raw[..12] != AZURE_SNP_MARKER {
        return Err(AttestError::VerificationFailed(
            "not an Azure SEV-SNP attestation document".into(),
        ));
    }

    let mut offset = 12;

    // Read hcl_report_size.
    if offset + 4 > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated Azure SNP document (hcl_report_size)".into(),
        ));
    }
    let hcl_size = u32::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + hcl_size > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated Azure SNP document (hcl_report)".into(),
        ));
    }
    let hcl_report = raw[offset..offset + hcl_size].to_vec();
    offset += hcl_size;

    // Read cert_chain_size.
    if offset + 4 > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated Azure SNP document (cert_chain_size)".into(),
        ));
    }
    let cert_size = u32::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + cert_size > raw.len() {
        return Err(AttestError::VerificationFailed(
            "truncated Azure SNP document (cert_chain)".into(),
        ));
    }
    let cert_chain = raw[offset..offset + cert_size].to_vec();

    Ok((hcl_report, cert_chain))
}

/// Extract pk and nonce from VarData JSON's "user-data" field.
///
/// VarData is a JSON object like:
/// ```json
/// {"keys":[...],"vm-configuration":{...},"user-data":"<hex-encoded pk||nonce>"}
/// ```
fn extract_user_data_from_var_data(var_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
    let json: serde_json::Value = serde_json::from_slice(var_data).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse VarData as JSON: {e}"))
    })?;

    let user_data_hex = json
        .get("user-data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AttestError::VerificationFailed("VarData JSON missing 'user-data' field".into())
        })?;

    let user_data_bytes = hex::decode(user_data_hex).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to decode user-data hex: {e}"))
    })?;

    if user_data_bytes.len() < 64 {
        return Err(AttestError::VerificationFailed(format!(
            "user-data too short: expected 64 bytes, got {}",
            user_data_bytes.len()
        )));
    }

    let public_key = user_data_bytes[..32].to_vec();
    let nonce = user_data_bytes[32..64].to_vec();

    Ok((public_key, nonce))
}

/// Parse raw report bytes into an `AttestationReport`.
fn parse_attestation_report(
    report_bytes: &[u8],
) -> Result<sev::firmware::guest::AttestationReport, AttestError> {
    use sev::parser::ByteParser;

    if report_bytes.len() != REPORT_SIZE {
        return Err(AttestError::VerificationFailed(format!(
            "report size mismatch: expected {REPORT_SIZE}, got {}",
            report_bytes.len()
        )));
    }

    sev::firmware::guest::AttestationReport::from_bytes(report_bytes).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse SEV-SNP attestation report: {e}"))
    })
}

/// Verify the report signature using the certificate chain.
///
/// The certificate chain from Azure IMDS is PEM-encoded. We parse the PEM
/// to extract DER certificates, then verify: ARK → ASK → VCEK → report.
fn verify_report_with_certs(
    report: &sev::firmware::guest::AttestationReport,
    _report_bytes: &[u8],
    cert_chain_pem: &[u8],
) -> Result<(), AttestError> {
    // Parse PEM certificates from the IMDS response.
    // The IMDS THIM response contains:
    // - vcekCert: VCEK certificate (PEM)
    // - certificateChain: ASK + ARK certificates (PEM, concatenated)
    //
    // We receive the raw cert chain bytes which may be JSON or concatenated PEM.
    let cert_str = std::str::from_utf8(cert_chain_pem).map_err(|e| {
        AttestError::VerificationFailed(format!("cert chain is not valid UTF-8: {e}"))
    })?;

    // Parse all PEM certificates.
    let pem_certs = parse_pem_certificates(cert_str)?;
    if pem_certs.len() < 3 {
        return Err(AttestError::VerificationFailed(format!(
            "expected at least 3 certificates (VCEK, ASK, ARK), got {}",
            pem_certs.len()
        )));
    }

    // Build chain. The IMDS order is typically: VCEK, ASK, ARK.
    // sev::certs::snp::Chain expects: ARK, ASK, VCEK.
    let chain = sev::certs::snp::Chain::from_der(
        &pem_certs[2], // ARK
        &pem_certs[1], // ASK
        &pem_certs[0], // VCEK
    )
    .map_err(|e| {
        AttestError::VerificationFailed(format!("failed to build certificate chain: {e}"))
    })?;

    // Verify the certificate chain and report signature.
    use sev::certs::snp::Verifiable;
    (&chain, report).verify().map_err(|e| {
        AttestError::VerificationFailed(format!("report signature verification failed: {e}"))
    })?;

    Ok(())
}

/// Parse PEM-encoded certificates into DER byte vectors.
fn parse_pem_certificates(pem_str: &str) -> Result<Vec<Vec<u8>>, AttestError> {
    use openssl::x509::X509;

    let mut certs = Vec::new();
    let mut remaining = pem_str;

    while let Some(begin_idx) = remaining.find("-----BEGIN CERTIFICATE-----") {
        let end_marker = "-----END CERTIFICATE-----";
        let end_idx = remaining[begin_idx..].find(end_marker).ok_or_else(|| {
            AttestError::VerificationFailed("malformed PEM: missing END CERTIFICATE marker".into())
        })? + begin_idx
            + end_marker.len();

        let pem_block = &remaining[begin_idx..end_idx];
        let x509 = X509::from_pem(pem_block.as_bytes()).map_err(|e| {
            AttestError::VerificationFailed(format!("failed to parse PEM certificate: {e}"))
        })?;

        certs.push(x509.to_der().map_err(|e| {
            AttestError::VerificationFailed(format!("failed to convert cert to DER: {e}"))
        })?);

        remaining = &remaining[end_idx..];
    }

    Ok(certs)
}

/// Fetch VCEK certificate and certificate chain from Azure IMDS THIM endpoint.
///
/// Returns concatenated PEM certificates (VCEK + ASK + ARK).
#[cfg(target_os = "linux")]
fn fetch_imds_certificates() -> Result<Vec<u8>, String> {
    // Azure IMDS THIM endpoint for AMD certification
    let url = "http://169.254.169.254/metadata/THIM/amd/certification";

    let response = ureq_get_imds(url)?;

    // Parse JSON response to extract certificates.
    let json: serde_json::Value =
        serde_json::from_str(&response).map_err(|e| format!("IMDS JSON parse error: {e}"))?;

    let vcek_pem = json
        .get("vcekCert")
        .and_then(|v| v.as_str())
        .ok_or("IMDS response missing 'vcekCert'")?;

    let chain_pem = json
        .get("certificateChain")
        .and_then(|v| v.as_str())
        .ok_or("IMDS response missing 'certificateChain'")?;

    // Concatenate: VCEK + chain (ASK + ARK)
    let mut certs = String::new();
    certs.push_str(vcek_pem);
    certs.push('\n');
    certs.push_str(chain_pem);

    Ok(certs.into_bytes())
}

/// Make a GET request to Azure IMDS with the required Metadata header.
#[cfg(target_os = "linux")]
fn ureq_get_imds(url: &str) -> Result<String, String> {
    // Use a simple blocking HTTP client. We can't use reqwest (too heavy)
    // and we don't want async here. Use std::net directly.
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect("169.254.169.254:80")
        .map_err(|e| format!("failed to connect to IMDS: {e}"))?;

    let path = url.strip_prefix("http://169.254.169.254").unwrap_or(url);

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata: true\r\nConnection: close\r\n\r\n",
        path
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("failed to send IMDS request: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("failed to read IMDS response: {e}"))?;

    // Parse HTTP response — find the body after \r\n\r\n.
    let body_start = response
        .find("\r\n\r\n")
        .ok_or("malformed HTTP response from IMDS")?
        + 4;

    Ok(response[body_start..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_roundtrip() {
        let hcl_report = vec![0xAA; 2600];
        let certs = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";

        let encoded = encode_azure_snp_document(&hcl_report, certs);
        let (dec_hcl, dec_certs) = decode_azure_snp_document(&encoded).unwrap();

        assert_eq!(dec_hcl, hcl_report);
        assert_eq!(dec_certs, certs);
    }

    #[test]
    fn document_roundtrip_empty_certs() {
        let hcl_report = vec![0xCC; 1500];
        let certs = vec![];

        let encoded = encode_azure_snp_document(&hcl_report, &certs);
        let (dec_hcl, dec_certs) = decode_azure_snp_document(&encoded).unwrap();

        assert_eq!(dec_hcl, hcl_report);
        assert!(dec_certs.is_empty());
    }

    #[test]
    fn reject_invalid_marker() {
        let mut raw = vec![0u8; 100];
        raw[..7].copy_from_slice(b"INVALID");
        let result = decode_azure_snp_document(&raw);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("not an Azure"), "error: {err}");
    }

    #[test]
    fn reject_truncated_document() {
        let hcl_report = vec![0xAA; 2600];
        let certs = vec![0xBB; 256];
        let encoded = encode_azure_snp_document(&hcl_report, &certs);

        // Truncate in the middle of the report.
        let truncated = &encoded[..20];
        let result = decode_azure_snp_document(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn extract_user_data_valid() {
        let var_data = br#"{"keys":[],"user-data":"4242424242424242424242424242424242424242424242424242424242424242373737373737373737373737373737373737373737373737373737373737373737"}"#;
        let (pk, nonce) = extract_user_data_from_var_data(var_data).unwrap();
        assert_eq!(pk, vec![0x42; 32]);
        assert_eq!(nonce, vec![0x37; 32]);
    }

    #[test]
    fn extract_user_data_missing_field() {
        let var_data = br#"{"keys":[]}"#;
        let result = extract_user_data_from_var_data(var_data);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("user-data"), "error: {err}");
    }

    #[test]
    fn extract_user_data_too_short() {
        let var_data = br#"{"keys":[],"user-data":"4242"}"#;
        let result = extract_user_data_from_var_data(var_data);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("too short"), "error: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_fails_outside_azure() {
        // Skip if we're actually running on Azure.
        if std::path::Path::new("/dev/tpm0").exists() {
            return;
        }
        let result = AzureSevSnpProvider::new();
        assert!(
            result.is_err(),
            "AzureSevSnpProvider::new() should fail without vTPM"
        );
    }
}
