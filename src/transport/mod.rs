/// TCP transport helpers (connect, listen, accept).
#[cfg(feature = "tcp")]
pub mod tcp;

/// VSock transport for AWS Nitro Enclaves (connect, listen, accept).
#[cfg(feature = "vsock")]
pub mod vsock;
