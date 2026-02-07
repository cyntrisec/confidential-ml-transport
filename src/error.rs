use std::io;

/// Errors from frame parsing and encoding.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("invalid magic bytes: expected 0xCF4D, got 0x{0:04X}")]
    InvalidMagic(u16),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("unknown message type: 0x{0:02X}")]
    UnknownMessageType(u8),

    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: u32, max: u32 },

    #[error("unknown dtype: {0}")]
    UnknownDType(u8),

    #[error("tensor shape overflow: dimensions produce more elements than representable")]
    ShapeOverflow,

    #[error("tensor data size mismatch: expected {expected} bytes, got {actual}")]
    TensorDataSizeMismatch { expected: usize, actual: usize },

    #[error("invalid tensor name: {0}")]
    InvalidTensorName(#[from] std::string::FromUtf8Error),

    #[error("incomplete tensor header")]
    IncompleteTensorHeader,

    #[error("tensor padding contains non-zero bytes")]
    InvalidPadding,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("HKDF expand failed: invalid length")]
    HkdfExpandFailed,

    #[error("AEAD encryption failed")]
    SealFailed,

    #[error("AEAD decryption failed: ciphertext is invalid or tampered")]
    OpenFailed,

    #[error("nonce overflow: maximum sequence number reached")]
    NonceOverflow,

    #[error("sequence number replay: received {received}, expected > {expected}")]
    SequenceReplay { received: u64, expected: u64 },

    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("non-contributory key exchange: peer sent small-subgroup or identity point")]
    NonContributoryKey,
}

/// Errors from attestation operations.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("attestation generation failed: {0}")]
    GenerationFailed(String),

    #[error("attestation verification failed: {0}")]
    VerificationFailed(String),

    #[error("attestation document expired")]
    Expired,

    #[error("attestation public key mismatch")]
    PublicKeyMismatch,

    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Errors from session establishment and communication.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("unexpected handshake message type: expected {expected}, got {actual}")]
    UnexpectedMessage {
        expected: &'static str,
        actual: String,
    },

    #[error("session not established")]
    NotEstablished,

    #[error("session closed")]
    Closed,

    #[error("handshake timeout")]
    Timeout,

    #[error("received unencrypted frame in established session")]
    UnencryptedFrame,

    #[error("read buffer overflow: {size} bytes exceeds maximum")]
    ReadBufferOverflow { size: usize },
}

/// Top-level error type for the crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Frame(#[from] FrameError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Attestation(#[from] AttestError),

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
