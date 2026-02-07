use std::collections::BTreeMap;

use async_trait::async_trait;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509StoreContext, X509};
use sha2::{Digest, Sha256};

use super::types::{AttestationDocument, VerifiedAttestation};
use super::{AttestationProvider, AttestationVerifier};
use crate::error::AttestError;

/// Attestation provider that calls the Nitro Secure Module (NSM) device.
///
/// Only works inside an AWS Nitro Enclave where `/dev/nsm` is available.
/// The NSM file descriptor is opened on construction and closed on drop.
#[derive(Debug)]
pub struct NitroProvider {
    fd: i32,
}

impl NitroProvider {
    /// Open a connection to the NSM device.
    ///
    /// Returns an error if `/dev/nsm` is not available (i.e., not running
    /// inside a Nitro Enclave).
    pub fn new() -> Result<Self, AttestError> {
        let fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
        if fd < 0 {
            return Err(AttestError::GenerationFailed(
                "failed to open /dev/nsm — not running inside a Nitro Enclave?".into(),
            ));
        }
        Ok(Self { fd })
    }
}

impl Drop for NitroProvider {
    fn drop(&mut self) {
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.fd);
    }
}

#[async_trait]
impl AttestationProvider for NitroProvider {
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument, AttestError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use serde_bytes::ByteBuf;

        let request = Request::Attestation {
            user_data: user_data.map(|d| ByteBuf::from(d.to_vec())),
            nonce: nonce.map(|d| ByteBuf::from(d.to_vec())),
            public_key: public_key.map(|d| ByteBuf::from(d.to_vec())),
        };

        let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.fd, request);

        match response {
            Response::Attestation { document } => Ok(AttestationDocument::new(document)),
            Response::Error(code) => Err(AttestError::GenerationFailed(format!(
                "NSM attestation request failed: {code:?}"
            ))),
            other => Err(AttestError::GenerationFailed(format!(
                "unexpected NSM response: {other:?}"
            ))),
        }
    }
}

/// Bundled AWS Nitro Enclaves root CA certificate (PEM).
const AWS_NITRO_ROOT_CA_PEM: &[u8] = include_bytes!("aws_nitro_root_ca.pem");

/// Parsed fields from a Nitro attestation document (CBOR payload).
struct NitroAttestationDoc {
    module_id: String,
    digest: String,
    timestamp: u64,
    pcrs: BTreeMap<usize, Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

/// Verifier for AWS Nitro Enclave attestation documents.
///
/// Validates COSE_Sign1-wrapped CBOR attestation documents by:
/// 1. Decoding the COSE_Sign1 envelope
/// 2. Parsing the inner CBOR attestation document
/// 3. Validating the X.509 certificate chain against the pinned AWS Nitro root CA
/// 4. Verifying the ECDSA P-384 signature
/// 5. Checking PCR measurements against expected values
pub struct NitroVerifier {
    root_cert: X509,
    expected_pcrs: BTreeMap<usize, Vec<u8>>,
}

impl NitroVerifier {
    /// Create a new verifier using the bundled AWS Nitro root CA.
    ///
    /// `expected_pcrs` maps PCR index (0..15) to expected measurement bytes.
    /// Only the PCRs present in this map are checked; others are ignored.
    pub fn new(expected_pcrs: BTreeMap<usize, Vec<u8>>) -> Result<Self, AttestError> {
        let root_cert = X509::from_pem(AWS_NITRO_ROOT_CA_PEM).map_err(|e| {
            AttestError::VerificationFailed(format!("failed to parse bundled root CA: {e}"))
        })?;
        Ok(Self {
            root_cert,
            expected_pcrs,
        })
    }

    /// Create a verifier with a custom root CA (for testing with synthetic certs).
    pub fn with_root_ca(
        root_ca_pem: &[u8],
        expected_pcrs: BTreeMap<usize, Vec<u8>>,
    ) -> Result<Self, AttestError> {
        let root_cert = X509::from_pem(root_ca_pem).map_err(|e| {
            AttestError::VerificationFailed(format!("failed to parse root CA PEM: {e}"))
        })?;
        Ok(Self {
            root_cert,
            expected_pcrs,
        })
    }
}

#[async_trait]
impl AttestationVerifier for NitroVerifier {
    async fn verify(&self, doc: &AttestationDocument) -> Result<VerifiedAttestation, AttestError> {
        // Step 1: Decode COSE_Sign1.
        // Try tagged first (CBOR tag 18), then untagged (raw CBOR array).
        // Real NSM returns untagged; our test helpers produce tagged.
        let cose_sign1 = CoseSign1::from_tagged_slice(&doc.raw)
            .or_else(|_| CoseSign1::from_slice(&doc.raw))
            .map_err(|e| AttestError::VerificationFailed(format!("invalid COSE_Sign1: {e}")))?;

        let payload = cose_sign1
            .payload
            .as_ref()
            .ok_or_else(|| AttestError::MissingField("COSE_Sign1 payload".into()))?;

        // Step 2: Parse inner attestation document from CBOR.
        let att_doc = parse_attestation_doc(payload)?;

        // Validate digest algorithm.
        if att_doc.digest != "SHA384" {
            return Err(AttestError::VerificationFailed(format!(
                "unsupported digest: expected SHA384, got {}",
                att_doc.digest
            )));
        }

        // Validate timestamp is non-zero.
        if att_doc.timestamp == 0 {
            return Err(AttestError::VerificationFailed(
                "timestamp must be non-zero".into(),
            ));
        }

        // Validate module_id is non-empty.
        if att_doc.module_id.is_empty() {
            return Err(AttestError::MissingField("module_id".into()));
        }

        // Step 3: Validate certificate chain.
        validate_cert_chain(&att_doc.cabundle, &att_doc.certificate, &self.root_cert)?;

        // Step 4: Verify COSE_Sign1 signature using the leaf certificate.
        verify_cose_signature(&cose_sign1, &att_doc.certificate)?;

        // Step 5: Check PCR measurements.
        for (idx, expected) in &self.expected_pcrs {
            match att_doc.pcrs.get(idx) {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(AttestError::VerificationFailed(format!(
                        "PCR{idx} mismatch: expected {}, got {}",
                        hex::encode(expected),
                        hex::encode(actual)
                    )));
                }
                None => {
                    return Err(AttestError::MissingField(format!("PCR{idx}")));
                }
            }
        }

        tracing::debug!(
            pcr_count = att_doc.pcrs.len(),
            expected_count = self.expected_pcrs.len(),
            "PCR measurement checks passed"
        );

        // Build VerifiedAttestation.
        let document_hash: [u8; 32] = Sha256::digest(&doc.raw).into();

        let measurements = att_doc.pcrs;

        Ok(VerifiedAttestation {
            document_hash,
            public_key: att_doc.public_key,
            user_data: att_doc.user_data,
            nonce: att_doc.nonce,
            measurements,
        })
    }
}

// -- CBOR Parsing Helpers --

fn parse_attestation_doc(payload: &[u8]) -> Result<NitroAttestationDoc, AttestError> {
    let value: Value = ciborium::de::from_reader(payload).map_err(|e| {
        AttestError::VerificationFailed(format!("invalid attestation doc CBOR: {e}"))
    })?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(AttestError::VerificationFailed(
                "attestation doc is not a CBOR map".into(),
            ))
        }
    };

    let module_id = get_text_field(&map, "module_id")?;
    let digest = get_text_field(&map, "digest")?;
    let timestamp = get_uint_field(&map, "timestamp")?;
    let certificate = get_bytes_field(&map, "certificate")?;
    let cabundle = get_bytes_array_field(&map, "cabundle")?;
    let pcrs = get_pcrs_field(&map)?;

    let public_key = get_optional_bytes_field(&map, "public_key");
    let user_data = get_optional_bytes_field(&map, "user_data");
    let nonce = get_optional_bytes_field(&map, "nonce");

    // Validate PCR value sizes (must be 32, 48, or 64 bytes).
    for (idx, val) in &pcrs {
        if val.len() != 32 && val.len() != 48 && val.len() != 64 {
            return Err(AttestError::VerificationFailed(format!(
                "PCR{idx} has invalid size: {} bytes (expected 32, 48, or 64)",
                val.len()
            )));
        }
    }

    Ok(NitroAttestationDoc {
        module_id,
        digest,
        timestamp,
        pcrs,
        certificate,
        cabundle,
        public_key,
        user_data,
        nonce,
    })
}

fn find_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .map(|(_, v)| v)
}

fn get_text_field(map: &[(Value, Value)], key: &str) -> Result<String, AttestError> {
    match find_field(map, key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        Some(_) => Err(AttestError::VerificationFailed(format!(
            "field '{key}' is not a text string"
        ))),
        None => Err(AttestError::MissingField(key.into())),
    }
}

fn get_uint_field(map: &[(Value, Value)], key: &str) -> Result<u64, AttestError> {
    match find_field(map, key) {
        Some(Value::Integer(i)) => {
            let val: i128 = (*i).into();
            if val < 0 {
                return Err(AttestError::VerificationFailed(format!(
                    "field '{key}' is negative"
                )));
            }
            Ok(val as u64)
        }
        Some(_) => Err(AttestError::VerificationFailed(format!(
            "field '{key}' is not an integer"
        ))),
        None => Err(AttestError::MissingField(key.into())),
    }
}

fn get_bytes_field(map: &[(Value, Value)], key: &str) -> Result<Vec<u8>, AttestError> {
    match find_field(map, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(AttestError::VerificationFailed(format!(
            "field '{key}' is not a byte string"
        ))),
        None => Err(AttestError::MissingField(key.into())),
    }
}

fn get_optional_bytes_field(map: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    match find_field(map, key) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        Some(Value::Null) => None,
        _ => None,
    }
}

fn get_bytes_array_field(map: &[(Value, Value)], key: &str) -> Result<Vec<Vec<u8>>, AttestError> {
    match find_field(map, key) {
        Some(Value::Array(arr)) => {
            let mut result = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                match item {
                    Value::Bytes(b) => result.push(b.clone()),
                    _ => {
                        return Err(AttestError::VerificationFailed(format!(
                            "{key}[{i}] is not a byte string"
                        )))
                    }
                }
            }
            Ok(result)
        }
        Some(_) => Err(AttestError::VerificationFailed(format!(
            "field '{key}' is not an array"
        ))),
        None => Err(AttestError::MissingField(key.into())),
    }
}

fn get_pcrs_field(map: &[(Value, Value)]) -> Result<BTreeMap<usize, Vec<u8>>, AttestError> {
    let pcrs_value =
        find_field(map, "pcrs").ok_or_else(|| AttestError::MissingField("pcrs".into()))?;

    let pcrs_map = match pcrs_value {
        Value::Map(m) => m,
        _ => {
            return Err(AttestError::VerificationFailed(
                "field 'pcrs' is not a map".into(),
            ))
        }
    };

    let mut result = BTreeMap::new();
    for (k, v) in pcrs_map {
        let idx = match k {
            Value::Integer(i) => {
                let val: i128 = (*i).into();
                if !(0..=15).contains(&val) {
                    return Err(AttestError::VerificationFailed(format!(
                        "PCR index {val} out of range [0, 15]"
                    )));
                }
                val as usize
            }
            _ => {
                return Err(AttestError::VerificationFailed(
                    "PCR key is not an integer".into(),
                ))
            }
        };
        let bytes = match v {
            Value::Bytes(b) => b.clone(),
            _ => {
                return Err(AttestError::VerificationFailed(format!(
                    "PCR{idx} value is not a byte string"
                )))
            }
        };
        result.insert(idx, bytes);
    }

    Ok(result)
}

// -- Certificate Chain Validation --

fn validate_cert_chain(
    cabundle: &[Vec<u8>],
    leaf_der: &[u8],
    pinned_root: &X509,
) -> Result<(), AttestError> {
    if cabundle.is_empty() {
        return Err(AttestError::VerificationFailed("cabundle is empty".into()));
    }

    // Parse the root cert from the cabundle and verify it matches the pinned root.
    let bundle_root = X509::from_der(&cabundle[0]).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse cabundle root cert: {e}"))
    })?;

    let pinned_der = pinned_root.to_der().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to encode pinned root cert: {e}"))
    })?;

    if bundle_root.to_der().unwrap_or_default() != pinned_der {
        return Err(AttestError::VerificationFailed(
            "cabundle root does not match pinned AWS Nitro root CA".into(),
        ));
    }

    // Build X509 store with the pinned root.
    let mut store_builder = X509StoreBuilder::new().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to create X509 store: {e}"))
    })?;
    store_builder.add_cert(pinned_root.clone()).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to add root cert to store: {e}"))
    })?;
    let store: X509Store = store_builder.build();

    // Build the intermediate chain (cabundle[1..]).
    let mut chain = openssl::stack::Stack::new().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to create cert stack: {e}"))
    })?;
    for (i, intermediate_der) in cabundle.iter().enumerate().skip(1) {
        let cert = X509::from_der(intermediate_der).map_err(|e| {
            AttestError::VerificationFailed(format!("failed to parse intermediate cert {i}: {e}"))
        })?;
        chain.push(cert).map_err(|e| {
            AttestError::VerificationFailed(format!("failed to push intermediate cert {i}: {e}"))
        })?;
    }

    // Parse and verify the leaf certificate.
    let leaf = X509::from_der(leaf_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse leaf certificate: {e}"))
    })?;

    let mut ctx = X509StoreContext::new().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to create store context: {e}"))
    })?;

    let valid = ctx
        .init(&store, &leaf, &chain, |ctx| ctx.verify_cert())
        .map_err(|e| {
            AttestError::VerificationFailed(format!("certificate chain verification error: {e}"))
        })?;

    if !valid {
        return Err(AttestError::VerificationFailed(
            "certificate chain verification failed".into(),
        ));
    }

    Ok(())
}

// -- COSE_Sign1 Signature Verification --

fn verify_cose_signature(cose_sign1: &CoseSign1, leaf_der: &[u8]) -> Result<(), AttestError> {
    // Parse leaf certificate and extract P-384 public key.
    let leaf = X509::from_der(leaf_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse leaf cert for sig verify: {e}"))
    })?;

    let pubkey = leaf.public_key().map_err(|e| {
        AttestError::VerificationFailed(format!("failed to extract public key: {e}"))
    })?;

    let ec_key = pubkey
        .ec_key()
        .map_err(|e| AttestError::VerificationFailed(format!("leaf cert key is not EC: {e}")))?;

    // Verify it's P-384.
    let group = ec_key.group();
    let nid = group
        .curve_name()
        .ok_or_else(|| AttestError::VerificationFailed("EC key has no named curve".into()))?;
    if nid != Nid::SECP384R1 {
        return Err(AttestError::VerificationFailed(format!(
            "expected P-384 key, got curve NID {:?}",
            nid
        )));
    }

    // Compute the to-be-signed data (Sig_structure with empty external AAD).
    let tbs = cose_sign1.tbs_data(b"");

    // Hash with SHA-384.
    let hash = openssl::hash::hash(MessageDigest::sha384(), &tbs)
        .map_err(|e| AttestError::VerificationFailed(format!("SHA-384 hash failed: {e}")))?;

    // Extract raw signature (r || s, each 48 bytes for P-384).
    let raw_sig = &cose_sign1.signature;
    if raw_sig.len() != 96 {
        return Err(AttestError::VerificationFailed(format!(
            "ECDSA signature has invalid length: {} (expected 96)",
            raw_sig.len()
        )));
    }

    let r = BigNum::from_slice(&raw_sig[..48]).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse signature r: {e}"))
    })?;
    let s = BigNum::from_slice(&raw_sig[48..]).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse signature s: {e}"))
    })?;

    let ecdsa_sig = EcdsaSig::from_private_components(r, s)
        .map_err(|e| AttestError::VerificationFailed(format!("failed to build ECDSA sig: {e}")))?;

    let valid = ecdsa_sig
        .verify(&hash, &ec_key)
        .map_err(|e| AttestError::VerificationFailed(format!("ECDSA verification error: {e}")))?;

    if !valid {
        return Err(AttestError::VerificationFailed(
            "COSE_Sign1 signature verification failed".into(),
        ));
    }

    Ok(())
}

/// Encode a `NitroAttestationDoc` to CBOR bytes (for test helpers).
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn encode_attestation_doc(
    module_id: &str,
    digest: &str,
    timestamp: u64,
    pcrs: &BTreeMap<usize, Vec<u8>>,
    certificate: &[u8],
    cabundle: &[Vec<u8>],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Vec<u8> {
    let mut map_entries: Vec<(Value, Value)> = Vec::new();

    map_entries.push((
        Value::Text("module_id".into()),
        Value::Text(module_id.into()),
    ));
    map_entries.push((Value::Text("digest".into()), Value::Text(digest.into())));
    map_entries.push((
        Value::Text("timestamp".into()),
        Value::Integer(timestamp.into()),
    ));

    // PCRs
    let pcr_entries: Vec<(Value, Value)> = pcrs
        .iter()
        .map(|(k, v)| (Value::Integer((*k as u64).into()), Value::Bytes(v.clone())))
        .collect();
    map_entries.push((Value::Text("pcrs".into()), Value::Map(pcr_entries)));

    map_entries.push((
        Value::Text("certificate".into()),
        Value::Bytes(certificate.to_vec()),
    ));

    let bundle: Vec<Value> = cabundle.iter().map(|c| Value::Bytes(c.clone())).collect();
    map_entries.push((Value::Text("cabundle".into()), Value::Array(bundle)));

    match public_key {
        Some(pk) => map_entries.push((Value::Text("public_key".into()), Value::Bytes(pk.to_vec()))),
        None => map_entries.push((Value::Text("public_key".into()), Value::Null)),
    }

    match user_data {
        Some(ud) => map_entries.push((Value::Text("user_data".into()), Value::Bytes(ud.to_vec()))),
        None => map_entries.push((Value::Text("user_data".into()), Value::Null)),
    }

    match nonce {
        Some(n) => map_entries.push((Value::Text("nonce".into()), Value::Bytes(n.to_vec()))),
        None => map_entries.push((Value::Text("nonce".into()), Value::Null)),
    }

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map_entries), &mut buf)
        .expect("CBOR serialization should not fail");
    buf
}

/// Sign a CBOR payload as COSE_Sign1 using an EC P-384 private key.
/// Returns tagged CBOR bytes (COSE tag 18).
#[doc(hidden)]
pub fn sign_cose_with_key(
    ec_key: &openssl::ec::EcKey<openssl::pkey::Private>,
    payload: &[u8],
) -> Vec<u8> {
    use coset::{CoseSign1Builder, HeaderBuilder};

    // Build protected header with ES384 algorithm.
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::ES384)
        .build();

    // Build the COSE_Sign1 without signature first to compute tbs_data.
    let builder = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec());

    // We need to compute tbs_data, then sign it.
    // CoseSign1Builder::create_signature needs a closure.
    let cose = builder
        .create_signature(b"", |tbs| {
            let hash =
                openssl::hash::hash(MessageDigest::sha384(), tbs).expect("SHA-384 hash failed");
            let sig = EcdsaSig::sign(&hash, ec_key).expect("ECDSA sign failed");
            let r = sig.r().to_vec_padded(48).expect("r padding failed");
            let s = sig.s().to_vec_padded(48).expect("s padding failed");
            let mut raw_sig = Vec::with_capacity(96);
            raw_sig.extend_from_slice(&r);
            raw_sig.extend_from_slice(&s);
            raw_sig
        })
        .build();

    cose.to_tagged_vec()
        .expect("COSE_Sign1 serialization failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509Builder, X509NameBuilder};

    /// Generate a self-signed P-384 CA certificate.
    fn generate_test_ca() -> (EcKey<openssl::pkey::Private>, X509) {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Test Nitro CA").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let bc = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(bc).unwrap();

        let ku = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap();
        builder.append_extension(ku).unwrap();

        builder.sign(&pkey, MessageDigest::sha384()).unwrap();
        let cert = builder.build();

        (ec_key, cert)
    }

    /// Generate a leaf certificate signed by the given CA.
    fn generate_test_leaf(
        ca_key: &EcKey<openssl::pkey::Private>,
        ca_cert: &X509,
    ) -> (EcKey<openssl::pkey::Private>, X509) {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Test Nitro Leaf").unwrap();
        let name = name.build();

        let ca_pkey = PKey::from_ec_key(ca_key.clone()).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(3650).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let ku = KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap();
        builder.append_extension(ku).unwrap();

        builder.sign(&ca_pkey, MessageDigest::sha384()).unwrap();
        let cert = builder.build();

        (ec_key, cert)
    }

    /// Build a complete synthetic attestation document (COSE_Sign1 tagged bytes).
    #[allow(clippy::too_many_arguments)]
    fn build_synthetic_attestation(
        ca_key: &EcKey<openssl::pkey::Private>,
        ca_cert: &X509,
        leaf_key: &EcKey<openssl::pkey::Private>,
        leaf_cert: &X509,
        pcrs: &BTreeMap<usize, Vec<u8>>,
        public_key: Option<&[u8]>,
        nonce: Option<&[u8]>,
        user_data: Option<&[u8]>,
    ) -> Vec<u8> {
        let _ = ca_key; // CA key only used for signing leaf (already done).
        let leaf_der = leaf_cert.to_der().unwrap();
        let ca_der = ca_cert.to_der().unwrap();

        let payload = encode_attestation_doc(
            "i-test-module-1234",
            "SHA384",
            1700000000000, // timestamp in ms
            pcrs,
            &leaf_der,
            &[ca_der],
            public_key,
            user_data,
            nonce,
        );

        sign_cose_with_key(leaf_key, &payload)
    }

    fn default_pcrs() -> BTreeMap<usize, Vec<u8>> {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![0xAA; 48]);
        pcrs.insert(1, vec![0xBB; 48]);
        pcrs.insert(2, vec![0xCC; 48]);
        pcrs
    }

    #[tokio::test]
    async fn verify_synthetic_attestation() {
        let (ca_key, ca_cert) = generate_test_ca();
        let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);

        let pcrs = default_pcrs();
        let expected_pcrs = pcrs.clone();

        let raw = build_synthetic_attestation(
            &ca_key,
            &ca_cert,
            &leaf_key,
            &leaf_cert,
            &pcrs,
            Some(&[1u8; 32]),
            Some(b"test-nonce"),
            Some(b"user-data"),
        );

        let ca_pem = ca_cert.to_pem().unwrap();
        let verifier = NitroVerifier::with_root_ca(&ca_pem, expected_pcrs).unwrap();

        let doc = AttestationDocument::new(raw);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "verification failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn verify_extracts_all_fields() {
        let (ca_key, ca_cert) = generate_test_ca();
        let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);

        let pcrs = default_pcrs();
        let pk = [42u8; 32];
        let nonce = b"my-nonce";
        let user_data = b"my-user-data";

        let raw = build_synthetic_attestation(
            &ca_key,
            &ca_cert,
            &leaf_key,
            &leaf_cert,
            &pcrs,
            Some(&pk),
            Some(nonce),
            Some(user_data),
        );

        let ca_pem = ca_cert.to_pem().unwrap();
        let verifier = NitroVerifier::with_root_ca(&ca_pem, BTreeMap::new()).unwrap();

        let doc = AttestationDocument::new(raw);
        let verified = verifier.verify(&doc).await.unwrap();

        assert_eq!(verified.public_key.as_deref(), Some(pk.as_ref()));
        assert_eq!(verified.nonce.as_deref(), Some(nonce.as_ref()));
        assert_eq!(verified.user_data.as_deref(), Some(user_data.as_ref()));
        assert_eq!(verified.measurements.len(), 3);
        assert_eq!(verified.measurements[&0], vec![0xAA; 48]);
        assert_eq!(verified.measurements[&1], vec![0xBB; 48]);
        assert_eq!(verified.measurements[&2], vec![0xCC; 48]);
    }

    #[tokio::test]
    async fn reject_tampered_signature() {
        let (ca_key, ca_cert) = generate_test_ca();
        let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);

        let pcrs = default_pcrs();

        let mut raw = build_synthetic_attestation(
            &ca_key,
            &ca_cert,
            &leaf_key,
            &leaf_cert,
            &pcrs,
            Some(&[1u8; 32]),
            None,
            None,
        );

        // Flip a bit in the last byte (inside the COSE_Sign1 signature).
        let len = raw.len();
        raw[len - 2] ^= 0x01;

        let ca_pem = ca_cert.to_pem().unwrap();
        let verifier = NitroVerifier::with_root_ca(&ca_pem, pcrs).unwrap();

        let doc = AttestationDocument::new(raw);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reject_wrong_root_ca() {
        let (ca_key, ca_cert) = generate_test_ca();
        let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);
        let pcrs = default_pcrs();

        let raw = build_synthetic_attestation(
            &ca_key,
            &ca_cert,
            &leaf_key,
            &leaf_cert,
            &pcrs,
            Some(&[1u8; 32]),
            None,
            None,
        );

        // Generate a different CA.
        let (_other_ca_key, other_ca_cert) = generate_test_ca();
        let other_ca_pem = other_ca_cert.to_pem().unwrap();
        let verifier = NitroVerifier::with_root_ca(&other_ca_pem, pcrs).unwrap();

        let doc = AttestationDocument::new(raw);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("root") || err_msg.contains("chain"),
            "error should mention root/chain: {err_msg}"
        );
    }

    #[tokio::test]
    async fn reject_pcr_mismatch() {
        let (ca_key, ca_cert) = generate_test_ca();
        let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);
        let pcrs = default_pcrs();

        let raw = build_synthetic_attestation(
            &ca_key,
            &ca_cert,
            &leaf_key,
            &leaf_cert,
            &pcrs,
            Some(&[1u8; 32]),
            None,
            None,
        );

        // Expect different PCR0 value.
        let mut expected_pcrs = BTreeMap::new();
        expected_pcrs.insert(0, vec![0xFF; 48]);

        let ca_pem = ca_cert.to_pem().unwrap();
        let verifier = NitroVerifier::with_root_ca(&ca_pem, expected_pcrs).unwrap();

        let doc = AttestationDocument::new(raw);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("PCR0"),
            "error should mention PCR0: {err_msg}"
        );
    }

    #[tokio::test]
    async fn reject_missing_mandatory_field() {
        let (ca_key, ca_cert) = generate_test_ca();
        let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);

        // Build a CBOR doc missing `module_id`.
        let leaf_der = leaf_cert.to_der().unwrap();
        let ca_der = ca_cert.to_der().unwrap();

        let mut map_entries: Vec<(Value, Value)> = Vec::new();
        // Deliberately omit module_id
        map_entries.push((Value::Text("digest".into()), Value::Text("SHA384".into())));
        map_entries.push((
            Value::Text("timestamp".into()),
            Value::Integer(1700000000000u64.into()),
        ));
        let pcr_entries: Vec<(Value, Value)> =
            vec![(Value::Integer(0u64.into()), Value::Bytes(vec![0xAA; 48]))];
        map_entries.push((Value::Text("pcrs".into()), Value::Map(pcr_entries)));
        map_entries.push((Value::Text("certificate".into()), Value::Bytes(leaf_der)));
        map_entries.push((
            Value::Text("cabundle".into()),
            Value::Array(vec![Value::Bytes(ca_der)]),
        ));
        map_entries.push((Value::Text("public_key".into()), Value::Null));
        map_entries.push((Value::Text("user_data".into()), Value::Null));
        map_entries.push((Value::Text("nonce".into()), Value::Null));

        let mut payload = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map_entries), &mut payload).unwrap();

        let raw = sign_cose_with_key(&leaf_key, &payload);

        let ca_pem = ca_cert.to_pem().unwrap();
        let verifier = NitroVerifier::with_root_ca(&ca_pem, BTreeMap::new()).unwrap();

        let doc = AttestationDocument::new(raw);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("module_id"),
            "error should mention module_id: {err_msg}"
        );
    }

    #[test]
    fn nitro_provider_fails_outside_enclave() {
        let result = NitroProvider::new();
        assert!(
            result.is_err(),
            "NitroProvider::new() should fail without /dev/nsm"
        );
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("/dev/nsm"),
            "error should mention /dev/nsm: {msg}"
        );
    }

    #[tokio::test]
    async fn reject_tampered_payload() {
        let (ca_key, ca_cert) = generate_test_ca();
        let (leaf_key, leaf_cert) = generate_test_leaf(&ca_key, &ca_cert);
        let pcrs = default_pcrs();

        let leaf_der = leaf_cert.to_der().unwrap();
        let ca_der = ca_cert.to_der().unwrap();

        let payload = encode_attestation_doc(
            "i-test-module-1234",
            "SHA384",
            1700000000000,
            &pcrs,
            &leaf_der,
            std::slice::from_ref(&ca_der),
            Some(&[1u8; 32]),
            None,
            None,
        );

        // Sign the original payload.
        let signed = sign_cose_with_key(&leaf_key, &payload);

        // Now tamper: decode, modify payload, re-encode without re-signing.
        let mut cose = CoseSign1::from_tagged_slice(&signed).unwrap();

        // Modify the payload (change module_id).
        let tampered_payload = encode_attestation_doc(
            "i-TAMPERED-module",
            "SHA384",
            1700000000000,
            &pcrs,
            &leaf_der,
            std::slice::from_ref(&ca_der),
            Some(&[1u8; 32]),
            None,
            None,
        );
        cose.payload = Some(tampered_payload);

        let tampered_raw = cose.to_tagged_vec().unwrap();

        let ca_pem = ca_cert.to_pem().unwrap();
        let verifier = NitroVerifier::with_root_ca(&ca_pem, pcrs).unwrap();

        let doc = AttestationDocument::new(tampered_raw);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
    }
}
