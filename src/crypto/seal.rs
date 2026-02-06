use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use super::SymmetricKey;
use crate::error::CryptoError;

/// Builds per-message AAD: `version || session_id || sequence`.
fn build_aad(version: u8, session_id: &[u8; 32], sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 32 + 8);
    aad.push(version);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

/// Build a 12-byte nonce from a u64 counter (big-endian, left-padded with zeros).
fn build_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&nonce_bytes)
}

/// Context for encrypting outgoing messages.
pub struct SealingContext {
    cipher: ChaCha20Poly1305,
    session_id: [u8; 32],
    sequence: u64,
}

impl SealingContext {
    pub fn new(key: &SymmetricKey, session_id: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key length is 32");
        Self {
            cipher,
            session_id,
            sequence: 0,
        }
    }

    /// Encrypt a plaintext payload. Returns ciphertext (includes AEAD tag).
    /// Also returns the sequence number used.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, u64), CryptoError> {
        let seq = self.sequence;
        self.sequence = seq.checked_add(1).ok_or(CryptoError::NonceOverflow)?;

        let nonce = build_nonce(seq);
        let aad = build_aad(crate::frame::PROTOCOL_VERSION, &self.session_id, seq);

        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::SealFailed)?;

        Ok((ciphertext, seq))
    }

    /// Current sequence number (next to be used).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Context for decrypting incoming messages.
pub struct OpeningContext {
    cipher: ChaCha20Poly1305,
    session_id: [u8; 32],
    /// The last accepted sequence number. Next accepted must be > this.
    last_sequence: Option<u64>,
}

impl OpeningContext {
    pub fn new(key: &SymmetricKey, session_id: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key length is 32");
        Self {
            cipher,
            session_id,
            last_sequence: None,
        }
    }

    /// Decrypt a ciphertext payload. Enforces monotonic sequence numbers.
    pub fn open(&mut self, ciphertext: &[u8], sequence: u64) -> Result<Vec<u8>, CryptoError> {
        // Monotonic sequence enforcement.
        if let Some(last) = self.last_sequence {
            if sequence <= last {
                return Err(CryptoError::SequenceReplay {
                    received: sequence,
                    expected: last,
                });
            }
        }

        let nonce = build_nonce(sequence);
        let aad = build_aad(
            crate::frame::PROTOCOL_VERSION,
            &self.session_id,
            sequence,
        );

        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::OpenFailed)?;

        self.last_sequence = Some(sequence);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_id() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn seal_then_open() {
        let key: SymmetricKey = [0x42; 32];
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let plaintext = b"hello confidential world";
        let (ciphertext, seq) = sealer.seal(plaintext).unwrap();

        let recovered = opener.open(&ciphertext, seq).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key: SymmetricKey = [0x42; 32];
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let (mut ciphertext, seq) = sealer.seal(b"secret").unwrap();
        ciphertext[0] ^= 0xFF;

        let result = opener.open(&ciphertext, seq);
        assert!(matches!(result, Err(CryptoError::OpenFailed)));
    }

    #[test]
    fn wrong_sequence_fails() {
        let key: SymmetricKey = [0x42; 32];
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let (ciphertext, _seq) = sealer.seal(b"secret").unwrap();

        // Use wrong sequence number.
        let result = opener.open(&ciphertext, 999);
        assert!(matches!(result, Err(CryptoError::OpenFailed)));
    }

    #[test]
    fn replay_rejected() {
        let key: SymmetricKey = [0x42; 32];
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let (ct0, seq0) = sealer.seal(b"first").unwrap();
        let (ct1, seq1) = sealer.seal(b"second").unwrap();

        opener.open(&ct0, seq0).unwrap();
        opener.open(&ct1, seq1).unwrap();

        // Replay seq0.
        let result = opener.open(&ct0, seq0);
        assert!(matches!(result, Err(CryptoError::SequenceReplay { .. })));
    }

    #[test]
    fn sequence_increments() {
        let key: SymmetricKey = [0x42; 32];
        let sid = test_session_id();
        let mut sealer = SealingContext::new(&key, sid);

        assert_eq!(sealer.sequence(), 0);
        let (_, seq) = sealer.seal(b"a").unwrap();
        assert_eq!(seq, 0);
        assert_eq!(sealer.sequence(), 1);
        let (_, seq) = sealer.seal(b"b").unwrap();
        assert_eq!(seq, 1);
        assert_eq!(sealer.sequence(), 2);
    }
}
