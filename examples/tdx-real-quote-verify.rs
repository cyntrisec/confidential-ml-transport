//! Run the TDX verifier against a real captured TDX quote.
//!
//! This example loads a real TDX v4 quote (captured from a GCP TDX VM via
//! configfs-tsm) and verifies it against caller-supplied Intel PCS collateral,
//! an independently trusted Intel root CA, a PCK CRL, and expected workload /
//! REPORTDATA values.
//!
//! Usage:
//!
//!   cargo run --release --example tdx-real-quote-verify --features tdx -- \
//!     --quote     /path/to/tdx-quote.bin \
//!     --tcb-info  /path/to/tcb-info.json \
//!     --qe-id     /path/to/qe-identity.json \
//!     --tcb-chain-header /path/to/tcb-info-issuer-chain-header.txt \
//!     --pck-chain /path/to/pck-cert-chain.pem \
//!     --root-ca   /trusted/path/to/intel-sgx-root-ca.pem \
//!     --pck-crl   /path/to/pck-crl.der \
//!     --mrtd      <96-hex-chars> \
//!     --public-key <64-hex-chars> \
//!     --nonce     <64-hex-chars>
//!
//! Exits 0 on accept, non-zero on reject. Prints an ACCEPT/REJECT verdict
//! plus verifier details for audit/debug use.
//!
//! This is an offline audit helper. A captured quote does not by itself prove
//! current liveness; use a freshly generated expected nonce in an interactive
//! protocol when freshness against replay is required.

use std::fs;
use std::io;

use confidential_ml_transport::attestation::tdx::encode_tdx_document;
use confidential_ml_transport::attestation::tdx::{TdxCollateral, TdxVerifier, TdxVerifyPolicy};
use confidential_ml_transport::attestation::types::AttestationDocument;

fn arg(name: &str) -> Option<String> {
    let mut it = std::env::args();
    while let Some(a) = it.next() {
        if a == name {
            return it.next();
        }
    }
    None
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn required_arg(name: &str) -> Result<String, io::Error> {
    arg(name).ok_or_else(|| invalid_input(format!("{name} is required")))
}

fn decode_hex_arg(name: &str, expected_len: usize) -> Result<Vec<u8>, io::Error> {
    let value = required_arg(name)?;
    let normalized = value.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(normalized).map_err(|e| invalid_input(format!("invalid {name} hex: {e}")))?;
    if bytes.len() != expected_len {
        return Err(invalid_input(format!(
            "{name} must be {expected_len} bytes, got {} bytes",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn pem_to_der_chain(pem_bytes: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    // Use openssl since it's already a dependency.
    use openssl::x509::X509;
    let stack = X509::stack_from_pem(pem_bytes)?;
    Ok(stack
        .into_iter()
        .map(|cert| cert.to_der())
        .collect::<Result<Vec<_>, _>>()?)
}

fn certificate_to_der(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use openssl::x509::X509;
    let cert = X509::from_pem(bytes).or_else(|_| X509::from_der(bytes))?;
    Ok(cert.to_der()?)
}

fn url_decode(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(invalid_input("truncated percent escape in TCB chain header").into());
            }
            let encoded = std::str::from_utf8(&bytes[i + 1..i + 3])?;
            let byte = u8::from_str_radix(encoded, 16)
                .map_err(|e| invalid_input(format!("invalid percent escape %{encoded}: {e}")))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let quote_path = required_arg("--quote")?;
    let tcb_info_path = required_arg("--tcb-info")?;
    let qe_id_path = required_arg("--qe-id")?;
    let tcb_chain_header_path = required_arg("--tcb-chain-header")?;
    let pck_chain_path = required_arg("--pck-chain")?;
    let root_ca_path = required_arg("--root-ca")?;
    let pck_crl_path = required_arg("--pck-crl")?;
    let expected_mrtd = decode_hex_arg("--mrtd", 48)?;
    let expected_public_key = decode_hex_arg("--public-key", 32)?;
    let expected_nonce = decode_hex_arg("--nonce", 32)?;

    let quote_raw = fs::read(&quote_path)?;
    let tcb_info_json = fs::read_to_string(&tcb_info_path)?;
    let qe_identity_json = fs::read_to_string(&qe_id_path)?;

    // Strip trailing zero pad (configfs-tsm outblob is 8000 bytes, real quote shorter)
    let quote = trim_trailing_zeros(&quote_raw);
    println!("quote_raw bytes: {}", quote_raw.len());
    println!("quote (post-trim): {} bytes", quote.len());

    // Parse PCK chain (PEM, leaf first), convert to DER
    let pck_pem = fs::read(&pck_chain_path)?;
    let mut pck_chain_der = pem_to_der_chain(&pck_pem)?;
    let root_ca_der = certificate_to_der(&fs::read(&root_ca_path)?)?;

    // The trust anchor comes from --root-ca, not from the quote-derived PCK
    // bundle. If the bundle repeats that root, remove it from the untrusted
    // leaf/intermediate chain before verification.
    pck_chain_der.retain(|cert| cert != &root_ca_der);
    println!(
        "pck_chain_der (without trust anchor): {} certs",
        pck_chain_der.len()
    );
    if pck_chain_der.len() < 2 {
        return Err(invalid_input(format!(
            "expected PCK leaf + intermediate certificates after removing the trusted root; got {}",
            pck_chain_der.len()
        ))
        .into());
    }
    let pck_crl_der = fs::read(&pck_crl_path)?;

    // Parse TCB signing chain from URL-encoded header file
    let header_text = fs::read_to_string(&tcb_chain_header_path)?;
    let mut tcb_chain_pem = String::new();
    for line in header_text.lines() {
        if let Some(stripped) = line.strip_prefix("TCB-Info-Issuer-Chain:") {
            let val = stripped.trim();
            tcb_chain_pem = url_decode(val)?;
            break;
        }
    }
    if tcb_chain_pem.is_empty() {
        return Err(invalid_input(format!(
            "TCB-Info-Issuer-Chain header not found in {tcb_chain_header_path}"
        ))
        .into());
    }
    let tcb_signing_chain_der = pem_to_der_chain(tcb_chain_pem.as_bytes())?;
    println!("tcb_signing_chain: {} certs", tcb_signing_chain_der.len());

    let collateral = TdxCollateral {
        root_ca_der,
        pck_chain_der,
        crl_der: Some(pck_crl_der),
        qe_identity_json: Some(qe_identity_json),
        tcb_info_json: Some(tcb_info_json),
        tcb_signing_chain_der: Some(tcb_signing_chain_der),
    };

    let policy = TdxVerifyPolicy {
        expected_mrtd: Some(expected_mrtd),
        expected_nonce: Some(expected_nonce),
        expected_public_key: Some(expected_public_key),
        require_collateral: true,
        collateral: Some(collateral),
        ..Default::default()
    };

    let verifier = TdxVerifier::with_policy(policy);
    let doc = AttestationDocument::new(encode_tdx_document(&quote));

    println!("\n--- running verifier ---");
    match verifier.verify_tdx(&doc) {
        Ok(verified) => {
            println!("VERDICT: ACCEPT");
            println!("verified TCB status: {:?}", verified);
            Ok(())
        }
        Err(e) => {
            println!("VERDICT: REJECT");
            println!("error code: {}", e.code());
            println!("error layer: {}", e.layer());
            println!("error: {}", e);
            std::process::exit(2);
        }
    }
}

fn trim_trailing_zeros(buf: &[u8]) -> Vec<u8> {
    // The outblob is fixed-size; the real quote is shorter, padded with zeros.
    // Detect end by parsing header + body + auth_data_len.
    if buf.len() < 48 + 584 + 4 {
        return buf.to_vec();
    }
    let auth_len_off = 48 + 584;
    let auth_len = u32::from_le_bytes([
        buf[auth_len_off],
        buf[auth_len_off + 1],
        buf[auth_len_off + 2],
        buf[auth_len_off + 3],
    ]) as usize;
    let total = 48 + 584 + 4 + auth_len;
    if total <= buf.len() {
        buf[..total].to_vec()
    } else {
        buf.to_vec()
    }
}
