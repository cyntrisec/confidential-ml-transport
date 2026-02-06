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
pub fn derive_session_keys(
    our_secret: &StaticSecret,
    their_public: &PublicKey,
    transcript_hash: &[u8; 32],
    is_initiator: bool,
) -> Result<(SymmetricKey, SymmetricKey), CryptoError> {
    let shared_secret = our_secret.diffie_hellman(their_public);

    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret.as_bytes());

    let mut key_a = [0u8; 32];
    let mut key_b = [0u8; 32];

    hkdf.expand(b"cmt-initiator-to-responder", &mut key_a)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;
    hkdf.expand(b"cmt-responder-to-initiator", &mut key_b)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;

    if is_initiator {
        Ok((key_a, key_b))
    } else {
        Ok((key_b, key_a))
    }
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
        assert_eq!(alice_send, bob_recv);
        // Bob's send key == Alice's recv key.
        assert_eq!(bob_send, alice_recv);
        // Send and recv keys are different.
        assert_ne!(alice_send, alice_recv);
    }
}
