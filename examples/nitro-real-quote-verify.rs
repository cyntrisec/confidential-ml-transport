//! Run the Nitro verifier against a real captured AWS Nitro attestation document.
//!
//! Companion to `tdx-real-quote-verify.rs`. Loads a real CBOR/COSE_Sign1 Nitro
//! attestation document (captured from inside an enclave that called the NSM
//! API and forwarded the bytes via vsock to the host) and verifies its
//! certificate chain, signature, freshness, and pinned PCR measurements against
//! the bundled AWS Nitro root CA using `NitroVerifier`.
//!
//! Usage:
//!
//!   cargo run --release --example nitro-real-quote-verify --features nitro -- \
//!     --quote /path/to/attestation.bin \
//!     --pcr0 <96-hex-chars> --pcr1 <96-hex-chars> --pcr2 <96-hex-chars>
//!
//! Optional flags:
//!   --max-age-secs N    Override the default 5-minute freshness window.
//!   --allow-unpinned-for-dev
//!                       Permit missing PCR pins for offline debugging only.
//!
//! Exits 0 on accept, non-zero on reject. Prints VERDICT + verifier details.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::time::Duration;

use confidential_ml_transport::attestation::nitro::NitroVerifier;
use confidential_ml_transport::attestation::types::AttestationDocument;
use confidential_ml_transport::AttestationVerifier;

fn arg(name: &str) -> Option<String> {
    let mut it = std::env::args();
    while let Some(a) = it.next() {
        if a == name {
            return it.next();
        }
    }
    None
}

fn flag_present(name: &str) -> bool {
    std::env::args().any(|value| value == name)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let quote_path = arg("--quote").ok_or_else(|| invalid_input("--quote is required"))?;
    let max_age_secs = match arg("--max-age-secs") {
        Some(value) => value
            .parse::<u64>()
            .map_err(|e| invalid_input(format!("invalid --max-age-secs value: {e}")))?,
        None => 300,
    };

    let mut expected_pcrs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    let mut missing_pcrs = Vec::new();
    for (idx, flag) in [(0usize, "--pcr0"), (1, "--pcr1"), (2, "--pcr2")] {
        match arg(flag) {
            Some(hex_str) => {
                let normalized = hex_str.trim().trim_start_matches("0x");
                let bytes = hex::decode(normalized)
                    .map_err(|e| invalid_input(format!("invalid {flag} hex: {e}")))?;
                if bytes.len() != 48 {
                    return Err(invalid_input(format!(
                        "{flag} must be a 48-byte SHA-384 PCR value, got {} bytes",
                        bytes.len()
                    ))
                    .into());
                }
                expected_pcrs.insert(idx, bytes);
            }
            None => missing_pcrs.push(flag),
        }
    }

    if !missing_pcrs.is_empty() {
        if !flag_present("--allow-unpinned-for-dev") {
            return Err(invalid_input(format!(
                "missing required PCR pins: {}. Pass all of --pcr0/--pcr1/--pcr2, or use \
                 --allow-unpinned-for-dev for offline debugging only",
                missing_pcrs.join(", ")
            ))
            .into());
        }
        eprintln!(
            "WARNING: missing PCR pins ({}); this run does not fully authenticate workload identity",
            missing_pcrs.join(", ")
        );
    }

    let raw = fs::read(&quote_path)?;
    println!("loaded attestation document: {} bytes", raw.len());
    println!("first 16 bytes: {}", hex::encode(&raw[..16.min(raw.len())]));

    let doc = AttestationDocument::new(raw);
    let verifier =
        NitroVerifier::new(expected_pcrs.clone())?.with_max_age(Duration::from_secs(max_age_secs));

    println!(
        "expected_pcrs pinned: {} entries; max_age = {}s",
        expected_pcrs.len(),
        max_age_secs
    );

    println!("\n--- running verifier ---");
    match verifier.verify(&doc).await {
        Ok(verified) => {
            println!("VERDICT: ACCEPT");
            println!("document_hash:   {}", hex::encode(verified.document_hash));
            if let Some(ref pk) = verified.public_key {
                println!("public_key:      {}", hex::encode(pk));
            }
            if let Some(ref n) = verified.nonce {
                println!("nonce:           {}", hex::encode(n));
            }
            if let Some(ref ud) = verified.user_data {
                println!("user_data:       {}", hex::encode(ud));
            }
            println!("measurements ({} PCRs):", verified.measurements.len());
            for (idx, val) in verified.measurements.iter() {
                println!("  PCR{idx}: {}", hex::encode(val));
            }
            Ok(())
        }
        Err(e) => {
            println!("VERDICT: REJECT");
            println!("error: {}", e);
            std::process::exit(2);
        }
    }
}
