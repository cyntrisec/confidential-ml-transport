pub mod attestation;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod session;
pub mod transport;

// Re-export key types at crate root for convenience.
pub use error::{Error, Result};
pub use frame::tensor::{DType, OwnedTensor, TensorRef};
pub use frame::{Flags, Frame, FrameType};
pub use session::channel::{Message, SecureChannel};
pub use session::SessionConfig;

pub use attestation::{AttestationProvider, AttestationVerifier};

#[cfg(feature = "mock")]
pub use attestation::mock::{MockProvider, MockVerifier};
