//! Run the Nitro verifier against a real captured AWS Nitro attestation document.
//!
//! Companion to `tdx-real-quote-verify.rs`. Loads a real CBOR/COSE_Sign1 Nitro
//! attestation document (captured from inside an enclave that called the NSM
//! API and forwarded the bytes via vsock to the host) and verifies it
//! end-to-end against the bundled AWS Nitro root CA using `NitroVerifier`.
//!
//! Usage:
//!
//!   cargo run --release --example nitro-real-quote-verify --features nitro -- \
//!     --quote /path/to/attestation.bin
//!
//! Optional flags:
//!   --max-age-secs N    Override the default 5-minute freshness window.
//!   --pcr0 <hex>        Pin PCR0 to a specific 96-hex-char value.
//!   --pcr1 <hex>        Pin PCR1 (likewise).
//!   --pcr2 <hex>        Pin PCR2 (likewise).
//!
//! Exits 0 on accept, non-zero on reject. Prints VERDICT + verifier details.

use std::collections::BTreeMap;
use std::fs;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let quote_path = arg("--quote").expect("--quote required");
    let max_age_secs = arg("--max-age-secs")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(86_400); // 24h default for offline replay
    let mut expected_pcrs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for (idx, flag) in [(0usize, "--pcr0"), (1, "--pcr1"), (2, "--pcr2")] {
        if let Some(hex_str) = arg(flag) {
            let bytes = hex::decode(hex_str.trim()).expect("invalid hex for PCR");
            expected_pcrs.insert(idx, bytes);
        }
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
