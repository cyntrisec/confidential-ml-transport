use sha2::{Digest, Sha256};

use super::PublicKey;
use crate::frame::PROTOCOL_VERSION;

/// Compute the transcript hash binding the session to attestation and key material.
///
/// `transcript = SHA256(attestation_hash || sorted(pk_a, pk_b) || nonce || protocol_version)`
///
/// The sorted public keys ensure both sides compute the same transcript regardless of
/// who initiated.
pub fn compute_transcript(
    attestation_hash: &[u8; 32],
    pk_a: &PublicKey,
    pk_b: &PublicKey,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(attestation_hash);

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
        let att_hash = [0xAA; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce = [0xBB; 32];

        let t1 = compute_transcript(&att_hash, &pk_a, &pk_b, &nonce);
        let t2 = compute_transcript(&att_hash, &pk_a, &pk_b, &nonce);
        assert_eq!(t1, t2);
    }

    #[test]
    fn transcript_commutative_on_keys() {
        let att_hash = [0xAA; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce = [0xBB; 32];

        let t1 = compute_transcript(&att_hash, &pk_a, &pk_b, &nonce);
        let t2 = compute_transcript(&att_hash, &pk_b, &pk_a, &nonce);
        assert_eq!(t1, t2);
    }

    #[test]
    fn transcript_different_inputs_differ() {
        let att_hash = [0xAA; 32];
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let nonce1 = [0xBB; 32];
        let nonce2 = [0xCC; 32];

        let t1 = compute_transcript(&att_hash, &pk_a, &pk_b, &nonce1);
        let t2 = compute_transcript(&att_hash, &pk_a, &pk_b, &nonce2);
        assert_ne!(t1, t2);
    }
}
