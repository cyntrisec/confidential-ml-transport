pub mod hpke;
pub mod seal;
pub mod transcript;

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

/// 32-byte symmetric key.
pub type SymmetricKey = [u8; 32];

/// 32-byte X25519 public key.
pub type PublicKey = [u8; 32];
