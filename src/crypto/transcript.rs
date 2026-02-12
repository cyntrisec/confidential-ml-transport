use sha2::{Digest, Sha256};

use super::PublicKey;
use crate::frame::PROTOCOL_VERSION;

/// Compute the transcript hash binding the session to attestation and key material.
///
/// `transcript = SHA256(init_att_hash || resp_att_hash || sorted(pk_a, pk_b) || nonce || version)`
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

    hasher.update(init_attestation_hash);
    hasher.update(resp_attestation_hash);

    // Sort public keys for deterministic ordering.
    if pk_a <= pk_b {
        hasher.update(pk_a);
        hasher.update(pk_b);
    } else {
        hasher.update(pk_b);
        hasher.update(pk_a);
    }

    hasher.update(nonce);
    hasher.update([PROTOCOL_VERSION]);

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
}
