use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroize;

use super::SymmetricKey;
use crate::error::CryptoError;

/// Builds per-message AAD: `version || msg_type || flags || session_id || sequence`.
///
/// Including `msg_type` and `flags` prevents an active attacker from flipping the
/// frame type in the unencrypted header without breaking AEAD verification.
fn build_aad(
    version: u8,
    msg_type: u8,
    flags: u8,
    session_id: &[u8; 32],
    sequence: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 1 + 1 + 32 + 8);
    aad.push(version);
    aad.push(msg_type);
    aad.push(flags);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

/// Build a 12-byte nonce from a u64 counter (big-endian, left-padded with zeros).
///
/// The upper 4 bytes are always zero. This is intentional: ChaCha20 requires a
/// 12-byte nonce (RFC 8439 §2.3), and a u64 counter provides 2^64 messages per
/// session which far exceeds practical use. The zero-padded prefix follows the
/// standard counter-nonce construction.
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

impl Drop for SealingContext {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.sequence = 0;
        // ChaCha20Poly1305 does not impl Zeroize. Use volatile writes to
        // clear the cipher struct (which contains the key) on drop.
        unsafe {
            let ptr = &mut self.cipher as *mut ChaCha20Poly1305 as *mut u8;
            let size = core::mem::size_of::<ChaCha20Poly1305>();
            core::ptr::write_bytes(ptr, 0, size);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl SealingContext {
    /// Create a new encryption context from a symmetric key and session ID.
    pub fn new(key: &SymmetricKey, session_id: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key length is 32");
        Self {
            cipher,
            session_id,
            sequence: 0,
        }
    }

    /// Encrypt a plaintext payload. Returns ciphertext (includes AEAD tag)
    /// and the sequence number used (for the frame header).
    ///
    /// `msg_type` and `flags` are bound into the AEAD associated data so that
    /// an attacker cannot flip the frame type without breaking authentication.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        msg_type: u8,
        flags: u8,
    ) -> Result<(Vec<u8>, u64), CryptoError> {
        let seq = self.sequence;
        self.sequence = seq.checked_add(1).ok_or(CryptoError::NonceOverflow)?;

        let nonce = build_nonce(seq);
        let aad = build_aad(
            crate::frame::PROTOCOL_VERSION,
            msg_type,
            flags,
            &self.session_id,
            seq,
        );

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

impl Drop for OpeningContext {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.last_sequence = None;
        // ChaCha20Poly1305 does not impl Zeroize. Use volatile writes to
        // clear the cipher struct (which contains the key) on drop.
        unsafe {
            let ptr = &mut self.cipher as *mut ChaCha20Poly1305 as *mut u8;
            let size = core::mem::size_of::<ChaCha20Poly1305>();
            core::ptr::write_bytes(ptr, 0, size);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl OpeningContext {
    /// Create a new decryption context from a symmetric key and session ID.
    pub fn new(key: &SymmetricKey, session_id: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key length is 32");
        Self {
            cipher,
            session_id,
            last_sequence: None,
        }
    }

    /// Decrypt a ciphertext payload. Enforces monotonic sequence numbers.
    ///
    /// `msg_type` and `flags` must match the values used during encryption;
    /// any mismatch (e.g., attacker flipping the frame type) will cause AEAD
    /// decryption to fail.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        sequence: u64,
        msg_type: u8,
        flags: u8,
    ) -> Result<Vec<u8>, CryptoError> {
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
            msg_type,
            flags,
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

    fn test_key() -> SymmetricKey {
        SymmetricKey::from([0x42; 32])
    }

    fn test_session_id() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn seal_then_open() {
        let key = test_key();
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let plaintext = b"hello confidential world";
        let msg_type = 0x02; // Data
        let flags = 0x01; // Encrypted
        let (ciphertext, seq) = sealer.seal(plaintext, msg_type, flags).unwrap();

        let recovered = opener.open(&ciphertext, seq, msg_type, flags).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let msg_type = 0x02;
        let flags = 0x01;
        let (mut ciphertext, seq) = sealer.seal(b"secret", msg_type, flags).unwrap();
        ciphertext[0] ^= 0xFF;

        let result = opener.open(&ciphertext, seq, msg_type, flags);
        assert!(matches!(result, Err(CryptoError::OpenFailed)));
    }

    #[test]
    fn wrong_sequence_fails() {
        let key = test_key();
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let msg_type = 0x02;
        let flags = 0x01;
        let (ciphertext, _seq) = sealer.seal(b"secret", msg_type, flags).unwrap();

        let result = opener.open(&ciphertext, 999, msg_type, flags);
        assert!(matches!(result, Err(CryptoError::OpenFailed)));
    }

    #[test]
    fn replay_rejected() {
        let key = test_key();
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let msg_type = 0x02;
        let flags = 0x01;
        let (ct0, seq0) = sealer.seal(b"first", msg_type, flags).unwrap();
        let (ct1, seq1) = sealer.seal(b"second", msg_type, flags).unwrap();

        opener.open(&ct0, seq0, msg_type, flags).unwrap();
        opener.open(&ct1, seq1, msg_type, flags).unwrap();

        let result = opener.open(&ct0, seq0, msg_type, flags);
        assert!(matches!(result, Err(CryptoError::SequenceReplay { .. })));
    }

    #[test]
    fn sequence_increments() {
        let key = test_key();
        let sid = test_session_id();
        let mut sealer = SealingContext::new(&key, sid);

        assert_eq!(sealer.sequence(), 0);
        let (_, seq) = sealer.seal(b"a", 0x02, 0x01).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(sealer.sequence(), 1);
        let (_, seq) = sealer.seal(b"b", 0x02, 0x01).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(sealer.sequence(), 2);
    }

    #[test]
    fn wrong_msg_type_fails() {
        let key = test_key();
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let (ciphertext, seq) = sealer.seal(b"secret", 0x02, 0x01).unwrap();

        // Attempt to open with a different msg_type (type-confusion attack).
        let result = opener.open(&ciphertext, seq, 0x06, 0x01);
        assert!(matches!(result, Err(CryptoError::OpenFailed)));
    }

    #[test]
    fn wrong_flags_fails() {
        let key = test_key();
        let sid = test_session_id();

        let mut sealer = SealingContext::new(&key, sid);
        let mut opener = OpeningContext::new(&key, sid);

        let (ciphertext, seq) = sealer.seal(b"secret", 0x02, 0x01).unwrap();

        // Attempt to open with different flags (flag-flip attack).
        let result = opener.open(&ciphertext, seq, 0x02, 0x03);
        assert!(matches!(result, Err(CryptoError::OpenFailed)));
    }
}
