//! Run the TDX verifier against a real captured TDX quote.
//!
//! This example loads a real TDX v4 quote (captured from a GCP TDX VM via
//! configfs-tsm) and verifies it end-to-end against current Intel PCS
//! collateral (TCB Info + QE Identity + TCB signing chain + PCK chain
//! extracted from the quote itself).
//!
//! Usage:
//!
//!   cargo run --release --example tdx-real-quote-verify --features tdx -- \
//!     --quote     /path/to/tdx-quote.bin \
//!     --tcb-info  /path/to/tcb-info.json \
//!     --qe-id     /path/to/qe-identity.json \
//!     --tcb-chain-header /path/to/tcb-info-issuer-chain-header.txt \
//!     --pck-chain /path/to/pck-cert-chain.pem
//!
//! Exits 0 on accept, non-zero on reject. Prints an ACCEPT/REJECT verdict
//! plus verifier details for audit/debug use.

use std::fs;

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

fn pem_to_der_chain(pem_bytes: &[u8]) -> Vec<Vec<u8>> {
    // Use openssl since it's already a dependency.
    use openssl::x509::X509;
    let stack = X509::stack_from_pem(pem_bytes).expect("parse PEM stack");
    stack
        .into_iter()
        .map(|c| c.to_der().expect("encode DER"))
        .collect()
}

fn url_decode(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
            let byte = u8::from_str_radix(hex, 16).unwrap();
            out.push(byte as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let quote_path = arg("--quote").expect("--quote required");
    let tcb_info_path = arg("--tcb-info").expect("--tcb-info required");
    let qe_id_path = arg("--qe-id").expect("--qe-id required");
    let tcb_chain_header_path = arg("--tcb-chain-header").expect("--tcb-chain-header required");
    let pck_chain_path = arg("--pck-chain").expect("--pck-chain required");

    let quote_raw = fs::read(&quote_path)?;
    let tcb_info_json = fs::read_to_string(&tcb_info_path)?;
    let qe_identity_json = fs::read_to_string(&qe_id_path)?;

    // Strip trailing zero pad (configfs-tsm outblob is 8000 bytes, real quote shorter)
    let quote = trim_trailing_zeros(&quote_raw);
    println!("quote_raw bytes: {}", quote_raw.len());
    println!("quote (post-trim): {} bytes", quote.len());

    // Parse PCK chain (PEM, leaf first), convert to DER
    let pck_pem = fs::read(&pck_chain_path)?;
    let pck_chain_der = pem_to_der_chain(&pck_pem);
    println!("pck_chain_der: {} certs", pck_chain_der.len());
    if pck_chain_der.len() < 3 {
        panic!(
            "expected 3 certs in PCK chain (leaf, intermediate, root); got {}",
            pck_chain_der.len()
        );
    }
    let root_ca_der = pck_chain_der.last().expect("root").clone();
    let pck_leaf_chain: Vec<Vec<u8>> = pck_chain_der[..pck_chain_der.len() - 1].to_vec();

    // Parse TCB signing chain from URL-encoded header file
    let header_text = fs::read_to_string(&tcb_chain_header_path)?;
    let mut tcb_chain_pem = String::new();
    for line in header_text.lines() {
        if line.starts_with("TCB-Info-Issuer-Chain:") {
            let val = line["TCB-Info-Issuer-Chain:".len()..].trim();
            tcb_chain_pem = url_decode(val);
            break;
        }
    }
    if tcb_chain_pem.is_empty() {
        panic!(
            "TCB-Info-Issuer-Chain header not found in {}",
            tcb_chain_header_path
        );
    }
    let tcb_signing_chain_der = pem_to_der_chain(tcb_chain_pem.as_bytes());
    println!("tcb_signing_chain: {} certs", tcb_signing_chain_der.len());

    let collateral = TdxCollateral {
        root_ca_der,
        pck_chain_der: pck_leaf_chain,
        crl_der: None,
        qe_identity_json: Some(qe_identity_json),
        tcb_info_json: Some(tcb_info_json),
        tcb_signing_chain_der: Some(tcb_signing_chain_der),
    };

    let policy = TdxVerifyPolicy {
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
