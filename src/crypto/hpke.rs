use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use super::SymmetricKey;
use crate::error::CryptoError;

/// An X25519 key pair.
pub struct KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Perform X25519 Diffie-Hellman and derive send/recv keys via HKDF.
///
/// Returns `(send_key, recv_key)`. The key assignment is deterministic based on
/// the `is_initiator` flag: the initiator's send key is the responder's recv key.
///
/// Checks that the shared secret is contributory (not the identity point).
pub fn derive_session_keys(
    our_secret: &StaticSecret,
    their_public: &PublicKey,
    transcript_hash: &[u8; 32],
    is_initiator: bool,
) -> Result<(SymmetricKey, SymmetricKey), CryptoError> {
    let shared_secret = our_secret.diffie_hellman(their_public);

    // Fix #6: Reject non-contributory DH results (small-subgroup / identity point).
    if !shared_secret.was_contributory() {
        return Err(CryptoError::NonContributoryKey);
    }

    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret.as_bytes());

    let mut key_a = [0u8; 32];
    let mut key_b = [0u8; 32];

    hkdf.expand(b"cmt-initiator-to-responder", &mut key_a)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;
    hkdf.expand(b"cmt-responder-to-initiator", &mut key_b)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;

    let (send, recv) = if is_initiator {
        (SymmetricKey::from(key_a), SymmetricKey::from(key_b))
    } else {
        (SymmetricKey::from(key_b), SymmetricKey::from(key_a))
    };

    // Zeroize the raw arrays now that we've moved them into SymmetricKey.
    use zeroize::Zeroize;
    key_a.zeroize();
    key_b.zeroize();

    Ok((send, recv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_symmetry() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let transcript = [0xCC; 32];

        let (alice_send, alice_recv) =
            derive_session_keys(&alice.secret, &bob.public, &transcript, true).unwrap();
        let (bob_send, bob_recv) =
            derive_session_keys(&bob.secret, &alice.public, &transcript, false).unwrap();

        // Alice's send key == Bob's recv key.
        assert_eq!(alice_send.0, bob_recv.0);
        // Bob's send key == Alice's recv key.
        assert_eq!(bob_send.0, alice_recv.0);
        // Send and recv keys are different.
        assert_ne!(alice_send.0, alice_recv.0);
    }
}
