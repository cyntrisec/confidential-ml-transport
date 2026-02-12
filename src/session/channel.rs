use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use std::future::Future;

use crate::attestation::types::VerifiedAttestation;
use crate::attestation::{AttestationProvider, AttestationVerifier};
use crate::crypto::seal::{OpeningContext, SealingContext};
use crate::error::{Error, SessionError};
use crate::frame::codec::FrameCodec;
use crate::frame::tensor::{OwnedTensor, TensorRef};
use crate::frame::{Flags, Frame, FrameHeader, FrameType, HEADER_SIZE, PROTOCOL_VERSION};

use super::handshake;
use super::retry;
use super::SessionConfig;

/// Margin added to max_payload_size for the read buffer bound.
const READ_BUF_MARGIN: usize = HEADER_SIZE + 4096;

/// A high-level message received from a secure channel.
#[derive(Debug)]
pub enum Message {
    /// Decrypted application data.
    Data(Bytes),
    /// Decrypted tensor data.
    Tensor(OwnedTensor),
    /// Heartbeat (no payload).
    Heartbeat,
    /// Peer-initiated shutdown.
    Shutdown,
    /// Error message from peer.
    Error(String),
}

/// Bidirectional encrypted channel over any `AsyncRead + AsyncWrite` transport.
///
/// **Security notes:**
/// - All post-handshake frames are encrypted and authenticated via AEAD.
/// - The handshake currently supports one-way attestation only: the initiator
///   verifies the responder's attestation, but the responder does not verify the
///   initiator. For mutual attestation, perform a second application-level
///   challenge-response after the session is established.
/// - This channel authenticates the data stream but does not bind to a specific
///   transport address (IP, VSock CID). A transport-level identity check should
///   be performed separately if required.
pub struct SecureChannel<T> {
    transport: T,
    sealer: SealingContext,
    opener: OpeningContext,
    read_buf: BytesMut,
    codec: FrameCodec,
    #[allow(dead_code)]
    config: SessionConfig,
    peer_attestation: Option<VerifiedAttestation>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SecureChannel<T> {
    /// Establish a secure channel as the initiator (client).
    ///
    /// Performs the 3-message handshake, verifying the responder's attestation.
    /// Subject to the configured `handshake_timeout`.
    pub async fn connect_with_attestation(
        mut transport: T,
        verifier: &dyn AttestationVerifier,
        config: SessionConfig,
    ) -> Result<Self, Error> {
        let result = tokio::time::timeout(
            config.handshake_timeout,
            handshake::initiate(
                &mut transport,
                verifier,
                config.expected_measurements.as_ref(),
            ),
        )
        .await
        .map_err(|_| Error::Session(SessionError::Timeout))??;

        let sealer = SealingContext::new(&result.send_key, result.session_id);
        let opener = OpeningContext::new(&result.recv_key, result.session_id);
        let peer_attestation = result.peer_attestation;

        Ok(Self {
            transport,
            sealer,
            opener,
            read_buf: result.residual,
            codec: FrameCodec::with_max_payload_size(config.max_payload_size),
            config,
            peer_attestation,
        })
    }

    /// Establish a secure channel as the initiator with automatic retry.
    ///
    /// Uses the `transport_factory` closure to create a fresh transport for each
    /// attempt. If `config.retry_policy` is `None`, behaves identically to
    /// [`connect_with_attestation`](Self::connect_with_attestation).
    pub async fn connect_with_retry<F, Fut>(
        transport_factory: F,
        verifier: &dyn AttestationVerifier,
        config: SessionConfig,
    ) -> Result<Self, Error>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, std::io::Error>>,
    {
        match config.retry_policy.clone() {
            Some(policy) => {
                retry::with_retry(&policy, || async {
                    let transport = transport_factory().await.map_err(Error::Io)?;
                    Self::connect_with_attestation(transport, verifier, config.clone()).await
                })
                .await
            }
            None => {
                let transport = transport_factory().await.map_err(Error::Io)?;
                Self::connect_with_attestation(transport, verifier, config).await
            }
        }
    }

    /// Establish a secure channel as the responder (server).
    ///
    /// Performs the 3-message handshake, providing our attestation.
    /// Subject to the configured `handshake_timeout`.
    pub async fn accept_with_attestation(
        mut transport: T,
        provider: &dyn AttestationProvider,
        config: SessionConfig,
    ) -> Result<Self, Error> {
        let result = tokio::time::timeout(
            config.handshake_timeout,
            handshake::respond(&mut transport, provider),
        )
        .await
        .map_err(|_| Error::Session(SessionError::Timeout))??;

        let sealer = SealingContext::new(&result.send_key, result.session_id);
        let opener = OpeningContext::new(&result.recv_key, result.session_id);
        let peer_attestation = result.peer_attestation;

        Ok(Self {
            transport,
            sealer,
            opener,
            read_buf: result.residual,
            codec: FrameCodec::with_max_payload_size(config.max_payload_size),
            config,
            peer_attestation,
        })
    }

    /// Return the peer's verified attestation, if available.
    ///
    /// For the initiator (client), this contains the responder's attestation
    /// including `user_data`, `public_key`, and `measurements`.
    /// For the responder (server), this is `None` (one-way attestation).
    pub fn peer_attestation(&self) -> Option<&VerifiedAttestation> {
        self.peer_attestation.as_ref()
    }

    /// Encrypt plaintext and construct a frame. The sealer's internal sequence
    /// counter is used as the frame header sequence, keeping them unified.
    ///
    /// Note: post-handshake sequence numbers start at 0 independently of the
    /// handshake's Hello frame sequences. This is safe because Hello and Data
    /// frames use different `FrameType` values, and `msg_type` is bound into
    /// the AEAD associated data, so seq=0 for Hello and seq=0 for Data produce
    /// distinct nonces.
    fn seal_frame(
        &mut self,
        msg_type: FrameType,
        plaintext: &[u8],
        extra_flags: u8,
    ) -> Result<Frame, Error> {
        let flags_byte = Flags::ENCRYPTED | extra_flags;
        let (ciphertext, seq) = self.sealer.seal(plaintext, msg_type as u8, flags_byte)?;
        if seq > u32::MAX as u64 {
            return Err(crate::error::CryptoError::NonceOverflow.into());
        }
        Ok(Frame {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type,
                flags: Flags(flags_byte),
                sequence: seq as u32,
                payload_len: ciphertext.len() as u32,
            },
            payload: Bytes::from(ciphertext),
        })
    }

    /// Send an encrypted data payload.
    pub async fn send(&mut self, payload: Bytes) -> Result<(), Error> {
        let frame = self.seal_frame(FrameType::Data, &payload, 0)?;
        self.send_frame(frame).await
    }

    /// Send an encrypted tensor.
    pub async fn send_tensor(&mut self, tensor: TensorRef<'_>) -> Result<(), Error> {
        let mut tensor_buf = BytesMut::new();
        tensor.encode(&mut tensor_buf)?;
        let frame = self.seal_frame(FrameType::Tensor, &tensor_buf, Flags::TENSOR_PAYLOAD)?;
        self.send_frame(frame).await
    }

    /// Receive a message from the channel.
    ///
    /// All post-handshake frames must be encrypted. Unencrypted frames are rejected.
    pub async fn recv(&mut self) -> Result<Message, Error> {
        let frame = self.recv_frame().await?;

        match frame.header.msg_type {
            FrameType::Hello => Err(SessionError::UnexpectedMessage {
                expected: "Data/Tensor/Heartbeat/Shutdown/Error",
                actual: "Hello".to_string(),
            }
            .into()),
            _ => {
                // All post-handshake frames must be encrypted.
                if !frame.header.flags.is_encrypted() {
                    return Err(SessionError::UnencryptedFrame.into());
                }
                let plaintext = self.opener.open(
                    &frame.payload,
                    frame.header.sequence as u64,
                    frame.header.msg_type as u8,
                    frame.header.flags.raw(),
                )?;

                match frame.header.msg_type {
                    FrameType::Data => Ok(Message::Data(Bytes::from(plaintext))),
                    FrameType::Tensor => {
                        let tensor = OwnedTensor::decode(Bytes::from(plaintext))?;
                        Ok(Message::Tensor(tensor))
                    }
                    FrameType::Heartbeat => Ok(Message::Heartbeat),
                    FrameType::Shutdown => Ok(Message::Shutdown),
                    FrameType::Error => {
                        let msg = String::from_utf8_lossy(&plaintext).to_string();
                        Ok(Message::Error(msg))
                    }
                    FrameType::Hello => unreachable!(),
                }
            }
        }
    }

    /// Send an encrypted shutdown frame to the peer.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        let frame = self.seal_frame(FrameType::Shutdown, &[], 0)?;
        self.send_frame(frame).await
    }

    /// Send an encrypted heartbeat frame.
    pub async fn heartbeat(&mut self) -> Result<(), Error> {
        let frame = self.seal_frame(FrameType::Heartbeat, &[], 0)?;
        self.send_frame(frame).await
    }

    async fn send_frame(&mut self, frame: Frame) -> Result<(), Error> {
        let mut buf = BytesMut::new();
        self.codec.encode(frame, &mut buf).map_err(Error::Frame)?;
        self.transport.write_all(&buf).await.map_err(Error::Io)?;
        self.transport.flush().await.map_err(Error::Io)?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<Frame, Error> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.read_buf)
                .map_err(Error::Frame)?
            {
                return Ok(frame);
            }
            // Enforce read buffer bounds before reading more data.
            let max_read_buf = self.config.max_payload_size as usize + READ_BUF_MARGIN;
            if self.read_buf.len() > max_read_buf {
                return Err(SessionError::ReadBufferOverflow {
                    size: self.read_buf.len(),
                }
                .into());
            }
            let n = self
                .transport
                .read_buf(&mut self.read_buf)
                .await
                .map_err(Error::Io)?;
            if n == 0 {
                return Err(SessionError::Closed.into());
            }
        }
    }
}
