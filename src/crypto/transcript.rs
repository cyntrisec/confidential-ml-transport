use sha2::{Digest, Sha256};

use super::PublicKey;
use crate::frame::PROTOCOL_VERSION;

fn update_labeled_component(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    debug_assert!(label.len() <= u8::MAX as usize);
    debug_assert!(value.len() <= u16::MAX as usize);

    hasher.update([label.len() as u8]);
    hasher.update(label);
    hasher.update((value.len() as u16).to_be_bytes());
    hasher.update(value);
}

/// Compute the transcript hash binding the session to attestation and key material.
///
/// `transcript = SHA256(TLV(init_att_hash) || TLV(resp_att_hash) || TLV(pk_low) || TLV(pk_high) || TLV(nonce) || TLV(version))`
///
/// Both attestation hashes are included so the transcript binds both sides'
/// identities (mutual attestation). The sorted public keys ensure both sides
/// compute the same transcript regardless of who initiated.
pub fn compute_transcript(
    init_attestation_hash: &[u8; 32],
    resp_attestation_hash: &[u8; 32],
    pk_a: &PublicKey,
    pk_b: &PublicKey,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    update_labeled_component(&mut hasher, b"init-attestation-hash", init_attestation_hash);
    update_labeled_component(&mut hasher, b"resp-attestation-hash", resp_attestation_hash);

    // Sort public keys for deterministic ordering.
    if pk_a <= pk_b {
        update_labeled_component(&mut hasher, b"pk-low", pk_a);
        update_labeled_component(&mut hasher, b"pk-high", pk_b);
    } else {
        update_labeled_component(&mut hasher, b"pk-low", pk_b);
        update_labeled_component(&mut hasher, b"pk-high", pk_a);
    }

    update_labeled_component(&mut hasher, b"combined-nonce", nonce);
    update_labeled_component(&mut hasher, b"protocol-version", &[PROTOCOL_VERSION]);

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_deterministic() {
        let init_hash = [0xAA; 32];
        let resp_hash = [0xBB; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce = [0xCC; 32];

        let t1 = compute_transcript(&init_hash, &resp_hash, &pk_a, &pk_b, &nonce);
        let t2 = compute_transcript(&init_hash, &resp_hash, &pk_a, &pk_b, &nonce);
        assert_eq!(t1, t2);
    }

    #[test]
    fn transcript_commutative_on_keys() {
        let init_hash = [0xAA; 32];
        let resp_hash = [0xBB; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce = [0xCC; 32];

        let t1 = compute_transcript(&init_hash, &resp_hash, &pk_a, &pk_b, &nonce);
        let t2 = compute_transcript(&init_hash, &resp_hash, &pk_b, &pk_a, &nonce);
        assert_eq!(t1, t2);
    }

    #[test]
    fn transcript_different_inputs_differ() {
        let init_hash = [0xAA; 32];
        let resp_hash = [0xBB; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce1 = [0xCC; 32];
        let nonce2 = [0xDD; 32];

        let t1 = compute_transcript(&init_hash, &resp_hash, &pk_a, &pk_b, &nonce1);
        let t2 = compute_transcript(&init_hash, &resp_hash, &pk_a, &pk_b, &nonce2);
        assert_ne!(t1, t2);
    }

    #[test]
    fn transcript_different_attestation_hashes_differ() {
        let init_hash1 = [0xAA; 32];
        let init_hash2 = [0xFF; 32];
        let resp_hash = [0xBB; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce = [0xCC; 32];

        let t1 = compute_transcript(&init_hash1, &resp_hash, &pk_a, &pk_b, &nonce);
        let t2 = compute_transcript(&init_hash2, &resp_hash, &pk_a, &pk_b, &nonce);
        assert_ne!(t1, t2);
    }

    #[test]
    fn transcript_binds_protocol_version() {
        let init_hash = [0xAA; 32];
        let resp_hash = [0xBB; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce = [0xCC; 32];

        let transcript = compute_transcript(&init_hash, &resp_hash, &pk_a, &pk_b, &nonce);

        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(init_hash);
        legacy_hasher.update(resp_hash);
        legacy_hasher.update(pk_a);
        legacy_hasher.update(pk_b);
        legacy_hasher.update(nonce);
        legacy_hasher.update([3u8]);
        let legacy: [u8; 32] = legacy_hasher.finalize().into();

        assert_ne!(transcript, legacy);
    }
}
