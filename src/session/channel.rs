use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::attestation::{AttestationProvider, AttestationVerifier};
use crate::crypto::seal::{OpeningContext, SealingContext};
use crate::error::{Error, SessionError};
use crate::frame::codec::FrameCodec;
use crate::frame::tensor::{OwnedTensor, TensorRef};
use crate::frame::{Frame, FrameType};

use super::handshake;
use super::SessionConfig;

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
pub struct SecureChannel<T> {
    transport: T,
    sealer: SealingContext,
    opener: OpeningContext,
    send_seq: u32,
    read_buf: BytesMut,
    codec: FrameCodec,
    #[allow(dead_code)]
    config: SessionConfig,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SecureChannel<T> {
    /// Establish a secure channel as the initiator (client).
    ///
    /// Performs the 3-message handshake, verifying the responder's attestation.
    pub async fn connect_with_attestation(
        mut transport: T,
        verifier: &dyn AttestationVerifier,
        config: SessionConfig,
    ) -> Result<Self, Error> {
        let result = handshake::initiate(&mut transport, verifier).await?;

        let sealer = SealingContext::new(&result.send_key, result.session_id);
        let opener = OpeningContext::new(&result.recv_key, result.session_id);

        Ok(Self {
            transport,
            sealer,
            opener,
            send_seq: 0,
            read_buf: result.residual,
            codec: FrameCodec::new(),
            config,
        })
    }

    /// Establish a secure channel as the responder (server).
    ///
    /// Performs the 3-message handshake, providing our attestation.
    pub async fn accept_with_attestation(
        mut transport: T,
        provider: &dyn AttestationProvider,
        config: SessionConfig,
    ) -> Result<Self, Error> {
        let result = handshake::respond(&mut transport, provider).await?;

        let sealer = SealingContext::new(&result.send_key, result.session_id);
        let opener = OpeningContext::new(&result.recv_key, result.session_id);

        Ok(Self {
            transport,
            sealer,
            opener,
            send_seq: 0,
            read_buf: result.residual,
            codec: FrameCodec::new(),
            config,
        })
    }

    /// Send an encrypted data payload.
    pub async fn send(&mut self, payload: Bytes) -> Result<(), Error> {
        let (ciphertext, _seq) = self.sealer.seal(&payload)?;
        let seq = self.next_seq();
        let frame = Frame::data(seq, Bytes::from(ciphertext), true);
        self.send_frame(frame).await
    }

    /// Send an encrypted tensor.
    pub async fn send_tensor(&mut self, tensor: TensorRef<'_>) -> Result<(), Error> {
        let mut tensor_buf = BytesMut::new();
        tensor.encode(&mut tensor_buf)?;

        let (ciphertext, _seq) = self.sealer.seal(&tensor_buf)?;
        let seq = self.next_seq();
        let frame = Frame::tensor(seq, Bytes::from(ciphertext), true);
        self.send_frame(frame).await
    }

    /// Receive a message from the channel.
    pub async fn recv(&mut self) -> Result<Message, Error> {
        let frame = self.recv_frame().await?;

        match frame.header.msg_type {
            FrameType::Heartbeat => Ok(Message::Heartbeat),
            FrameType::Shutdown => Ok(Message::Shutdown),
            FrameType::Error => {
                let msg = String::from_utf8_lossy(&frame.payload).to_string();
                Ok(Message::Error(msg))
            }
            FrameType::Data => {
                if frame.header.flags.is_encrypted() {
                    let plaintext =
                        self.opener.open(&frame.payload, frame.header.sequence as u64)?;
                    Ok(Message::Data(Bytes::from(plaintext)))
                } else {
                    Ok(Message::Data(frame.payload))
                }
            }
            FrameType::Tensor => {
                if frame.header.flags.is_encrypted() {
                    let plaintext =
                        self.opener.open(&frame.payload, frame.header.sequence as u64)?;
                    let tensor = OwnedTensor::decode(Bytes::from(plaintext))?;
                    Ok(Message::Tensor(tensor))
                } else {
                    let tensor = OwnedTensor::decode(frame.payload)?;
                    Ok(Message::Tensor(tensor))
                }
            }
            FrameType::Hello => Err(SessionError::UnexpectedMessage {
                expected: "Data/Tensor/Heartbeat/Shutdown/Error",
                actual: "Hello".to_string(),
            }
            .into()),
        }
    }

    /// Send a shutdown frame to the peer.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        let seq = self.next_seq();
        let frame = Frame::shutdown(seq);
        self.send_frame(frame).await
    }

    /// Send a heartbeat frame.
    pub async fn heartbeat(&mut self) -> Result<(), Error> {
        let seq = self.next_seq();
        let frame = Frame::heartbeat(seq);
        self.send_frame(frame).await
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
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
            if let Some(frame) = self.codec.decode(&mut self.read_buf).map_err(Error::Frame)? {
                return Ok(frame);
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
