pub mod hpke;
pub mod seal;
pub mod transcript;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// X25519 key exchange + HKDF-SHA256 + ChaCha20Poly1305.
    X25519ChaChaPoly,
}

impl CipherSuite {
    /// AEAD key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::X25519ChaChaPoly => 32,
        }
    }

    /// AEAD nonce length in bytes.
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::X25519ChaChaPoly => 12,
        }
    }

    /// AEAD tag length in bytes.
    pub const fn tag_len(self) -> usize {
        match self {
            Self::X25519ChaChaPoly => 16,
        }
    }
}

/// 32-byte symmetric key, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SymmetricKey {
    /// Construct a [`SymmetricKey`] from a raw 32-byte array.
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// 32-byte X25519 public key.
pub type PublicKey = [u8; 32];
