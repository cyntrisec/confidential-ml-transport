use bytes::{Buf, BufMut, Bytes, BytesMut};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::attestation::types::{AttestationDocument, ExpectedMeasurements, VerifiedAttestation};
use crate::attestation::{AttestationProvider, AttestationVerifier};
use crate::crypto::hpke::{self, KeyPair};
use crate::crypto::transcript;
use crate::crypto::SymmetricKey;
use crate::error::{AttestError, SessionError};
use crate::frame::codec::FrameCodec;
use crate::frame::{Frame, FrameType};

/// Result of a completed handshake.
pub struct HandshakeResult {
    /// Key for encrypting outgoing messages.
    pub send_key: SymmetricKey,
    /// Key for decrypting incoming messages.
    pub recv_key: SymmetricKey,
    /// Session ID derived from the transcript (domain-separated from key material).
    pub session_id: [u8; 32],
    /// The verified attestation from the peer (initiator gets server's attestation).
    pub peer_attestation: Option<VerifiedAttestation>,
    /// Residual bytes read from the transport but not consumed by the handshake.
    /// Must be prepended to the channel's read buffer.
    pub residual: BytesMut,
}

// -- Wire helpers --

fn encode_initiator_hello(public_key: &[u8; 32], nonce: &[u8; 32]) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + 32 + 32);
    buf.put_u8(1); // message number
    buf.put_slice(public_key);
    buf.put_slice(nonce);
    buf.freeze()
}

fn encode_responder_hello(
    public_key: &[u8; 32],
    nonce: &[u8; 32],
    attestation_doc: &[u8],
) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + 32 + 32 + 4 + attestation_doc.len());
    buf.put_u8(2); // message number
    buf.put_slice(public_key);
    buf.put_slice(nonce);
    buf.put_u32(attestation_doc.len() as u32);
    buf.put_slice(attestation_doc);
    buf.freeze()
}

fn encode_confirmation(confirmation_hash: &[u8; 32]) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + 32);
    buf.put_u8(3); // message number
    buf.put_slice(confirmation_hash);
    buf.freeze()
}

fn parse_initiator_hello(payload: &[u8]) -> Result<([u8; 32], [u8; 32]), SessionError> {
    const EXPECTED_LEN: usize = 1 + 32 + 32;
    if payload.len() != EXPECTED_LEN {
        return Err(SessionError::HandshakeFailed(format!(
            "initiator hello: expected {EXPECTED_LEN} bytes, got {}",
            payload.len()
        )));
    }
    if payload[0] != 1 {
        return Err(SessionError::UnexpectedMessage {
            expected: "initiator_hello (1)",
            actual: format!("message type {}", payload[0]),
        });
    }
    let mut pk = [0u8; 32];
    let mut nonce = [0u8; 32];
    pk.copy_from_slice(&payload[1..33]);
    nonce.copy_from_slice(&payload[33..65]);
    Ok((pk, nonce))
}

/// Maximum attestation document size accepted during handshake (64 KiB).
///
/// Real Nitro attestation documents are typically <16 KiB. This cap prevents an
/// adversary from sending a multi-megabyte document to exhaust memory.
const MAX_ATTESTATION_DOC_SIZE: usize = 64 * 1024;

fn parse_responder_hello(
    payload: &[u8],
) -> Result<([u8; 32], [u8; 32], AttestationDocument), SessionError> {
    const MIN_LEN: usize = 1 + 32 + 32 + 4;
    if payload.len() < MIN_LEN {
        return Err(SessionError::HandshakeFailed(
            "responder hello too short".into(),
        ));
    }
    if payload[0] != 2 {
        return Err(SessionError::UnexpectedMessage {
            expected: "responder_hello (2)",
            actual: format!("message type {}", payload[0]),
        });
    }
    let mut pk = [0u8; 32];
    let mut nonce = [0u8; 32];
    pk.copy_from_slice(&payload[1..33]);
    nonce.copy_from_slice(&payload[33..65]);
    let mut cursor = &payload[65..];
    let doc_len = cursor.get_u32() as usize;
    if doc_len > MAX_ATTESTATION_DOC_SIZE {
        return Err(SessionError::HandshakeFailed(format!(
            "attestation document too large: {doc_len} bytes (max {MAX_ATTESTATION_DOC_SIZE})"
        )));
    }
    let expected_total = MIN_LEN.checked_add(doc_len).ok_or_else(|| {
        SessionError::HandshakeFailed("responder hello length overflow".into())
    })?;
    if payload.len() != expected_total {
        return Err(SessionError::HandshakeFailed(format!(
            "responder hello: expected {expected_total} bytes, got {}",
            payload.len()
        )));
    }
    let doc = AttestationDocument::new(cursor[..doc_len].to_vec());
    Ok((pk, nonce, doc))
}

fn parse_confirmation(payload: &[u8]) -> Result<[u8; 32], SessionError> {
    const EXPECTED_LEN: usize = 1 + 32;
    if payload.len() != EXPECTED_LEN {
        return Err(SessionError::HandshakeFailed(format!(
            "confirmation: expected {EXPECTED_LEN} bytes, got {}",
            payload.len()
        )));
    }
    if payload[0] != 3 {
        return Err(SessionError::UnexpectedMessage {
            expected: "confirmation (3)",
            actual: format!("message type {}", payload[0]),
        });
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[1..33]);
    Ok(hash)
}

/// Compute confirmation hash binding both session keys (fix #9: includes both keys).
fn compute_confirmation(
    session_id: &[u8; 32],
    send_key: &SymmetricKey,
    recv_key: &SymmetricKey,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cmt-confirmation");
    hasher.update(session_id);
    hasher.update(send_key.as_bytes());
    hasher.update(recv_key.as_bytes());
    hasher.finalize().into()
}

/// Derive a session ID from the transcript hash via HKDF (domain-separated from key material).
fn derive_session_id(transcript_hash: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, transcript_hash);
    let mut session_id = [0u8; 32];
    hkdf.expand(b"cmt-session-id", &mut session_id)
        .expect("32 bytes is valid for SHA256 HKDF");
    session_id
}

// -- Transport helpers --

async fn send_frame<T: AsyncWrite + Unpin>(
    transport: &mut T,
    frame: Frame,
) -> Result<(), crate::error::Error> {
    let mut buf = BytesMut::new();
    FrameCodec::new()
        .encode(frame, &mut buf)
        .map_err(crate::error::Error::Frame)?;
    transport
        .write_all(&buf)
        .await
        .map_err(crate::error::Error::Io)?;
    transport.flush().await.map_err(crate::error::Error::Io)?;
    Ok(())
}

/// Maximum read buffer size during handshake.
///
/// Handshake messages are small (initiator hello ~65B, responder hello ~65B + attestation doc,
/// confirmation ~33B). The attestation doc is the largest variable component (typically <16 KB
/// for Nitro/SEV-SNP). We cap at `MAX_PAYLOAD_SIZE + HEADER_SIZE + margin` to match the channel's
/// strategy, but in practice handshake reads should never approach this limit.
const HANDSHAKE_MAX_READ_BUF: usize =
    crate::frame::MAX_PAYLOAD_SIZE as usize + crate::frame::HEADER_SIZE + 4096;

async fn recv_frame<T: AsyncRead + Unpin>(
    transport: &mut T,
    read_buf: &mut BytesMut,
) -> Result<Frame, crate::error::Error> {
    let mut codec = FrameCodec::new();
    loop {
        if let Some(frame) = codec.decode(read_buf).map_err(crate::error::Error::Frame)? {
            return Ok(frame);
        }
        if read_buf.len() > HANDSHAKE_MAX_READ_BUF {
            return Err(SessionError::ReadBufferOverflow {
                size: read_buf.len(),
            }
            .into());
        }
        let n = transport
            .read_buf(read_buf)
            .await
            .map_err(crate::error::Error::Io)?;
        if n == 0 {
            return Err(SessionError::Closed.into());
        }
    }
}

/// Validate that a handshake frame has the expected type and sequence number.
fn validate_handshake_frame(
    frame: &Frame,
    expected_type: FrameType,
    expected_seq: u32,
) -> Result<(), crate::error::Error> {
    if frame.header.msg_type != expected_type {
        return Err(SessionError::UnexpectedMessage {
            expected: match expected_type {
                FrameType::Hello => "Hello",
                _ => "unknown",
            },
            actual: format!("{:?}", frame.header.msg_type),
        }
        .into());
    }
    if frame.header.sequence != expected_seq {
        return Err(SessionError::HandshakeFailed(format!(
            "unexpected handshake sequence: expected {expected_seq}, got {}",
            frame.header.sequence
        ))
        .into());
    }
    Ok(())
}

/// Run the initiator (client) side of the handshake.
pub async fn initiate<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
    verifier: &dyn AttestationVerifier,
    expected_measurements: Option<&ExpectedMeasurements>,
) -> Result<HandshakeResult, crate::error::Error> {
    let keypair = KeyPair::generate();
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill(&mut nonce);
    let pk_bytes = keypair.public.to_bytes();

    // Step 1: Send initiator hello (seq=0).
    let hello = Frame::hello(0, encode_initiator_hello(&pk_bytes, &nonce));
    send_frame(transport, hello).await?;

    // Step 2: Receive responder hello (expect seq=0).
    let mut read_buf = BytesMut::with_capacity(4096);
    let resp_frame = recv_frame(transport, &mut read_buf).await?;
    validate_handshake_frame(&resp_frame, FrameType::Hello, 0)?;

    let (resp_pk_bytes, resp_nonce, att_doc) = parse_responder_hello(&resp_frame.payload)?;

    // Step 3: Verify attestation.
    let verified = verifier.verify(&att_doc).await.map_err(|e| {
        tracing::warn!("attestation verification failed: {e}");
        SessionError::HandshakeFailed("attestation verification failed".into())
    })?;

    tracing::info!(
        document_hash = hex::encode(verified.document_hash),
        measurement_count = verified.measurements.len(),
        "attestation verification succeeded"
    );
    tracing::debug!(
        measurements = ?verified.measurements.iter().map(|(k, v)| (k, hex::encode(v))).collect::<Vec<_>>(),
        "peer attestation measurements"
    );

    // Verify the attestation binds the responder's public key (mandatory).
    match verified.public_key {
        Some(ref att_pk) => {
            if att_pk.as_slice() != resp_pk_bytes.as_slice() {
                return Err(AttestError::PublicKeyMismatch.into());
            }
        }
        None => {
            return Err(AttestError::MissingField("public_key".into()).into());
        }
    }

    // Verify measurements if expected values are provided.
    if let Some(expected) = expected_measurements {
        expected.verify(&verified.measurements)?;
        tracing::info!(
            expected_count = expected.values.len(),
            "measurement verification passed"
        );
    }

    // Combine nonces.
    let mut combined_nonce = [0u8; 32];
    for i in 0..32 {
        combined_nonce[i] = nonce[i] ^ resp_nonce[i];
    }

    // Compute transcript and derive keys.
    let resp_pk = x25519_dalek::PublicKey::from(resp_pk_bytes);
    let transcript_hash = transcript::compute_transcript(
        &verified.document_hash,
        &pk_bytes,
        &resp_pk_bytes,
        &combined_nonce,
    );

    let (send_key, recv_key) =
        hpke::derive_session_keys(&keypair.secret, &resp_pk, &transcript_hash, true)?;

    // Derive session_id via HKDF (domain-separated from transcript_hash).
    let session_id = derive_session_id(&transcript_hash);

    // Step 4: Send confirmation (seq=1), binding both keys.
    let confirmation_hash = compute_confirmation(&session_id, &send_key, &recv_key);
    let confirm_frame = Frame::hello(1, encode_confirmation(&confirmation_hash));
    send_frame(transport, confirm_frame).await?;

    Ok(HandshakeResult {
        send_key,
        recv_key,
        session_id,
        peer_attestation: Some(verified),
        residual: read_buf,
    })
}

/// Run the responder (server) side of the handshake.
pub async fn respond<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
    provider: &dyn AttestationProvider,
) -> Result<HandshakeResult, crate::error::Error> {
    // Step 1: Receive initiator hello (expect seq=0).
    let mut read_buf = BytesMut::with_capacity(4096);
    let init_frame = recv_frame(transport, &mut read_buf).await?;
    validate_handshake_frame(&init_frame, FrameType::Hello, 0)?;

    let (init_pk_bytes, init_nonce) = parse_initiator_hello(&init_frame.payload)?;

    // Generate our keypair and nonce.
    let keypair = KeyPair::generate();
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill(&mut nonce);
    let pk_bytes = keypair.public.to_bytes();

    // Step 2: Generate attestation binding our public key.
    let att_doc = provider
        .attest(None, Some(&nonce), Some(&pk_bytes))
        .await
        .map_err(|e| {
            tracing::warn!("attestation generation failed: {e}");
            SessionError::HandshakeFailed("attestation generation failed".into())
        })?;

    tracing::debug!(
        doc_len = att_doc.raw.len(),
        "attestation document generated"
    );

    // Send responder hello (seq=0).
    let hello = Frame::hello(0, encode_responder_hello(&pk_bytes, &nonce, &att_doc.raw));
    send_frame(transport, hello).await?;

    // Derive keys.
    let att_hash: [u8; 32] = Sha256::digest(&att_doc.raw).into();

    let mut combined_nonce = [0u8; 32];
    for i in 0..32 {
        combined_nonce[i] = init_nonce[i] ^ nonce[i];
    }

    let init_pk = x25519_dalek::PublicKey::from(init_pk_bytes);
    let transcript_hash =
        transcript::compute_transcript(&att_hash, &init_pk_bytes, &pk_bytes, &combined_nonce);

    let (send_key, recv_key) =
        hpke::derive_session_keys(&keypair.secret, &init_pk, &transcript_hash, false)?;

    // Derive session_id via HKDF (domain-separated from transcript_hash).
    let session_id = derive_session_id(&transcript_hash);

    // Step 3: Receive and verify confirmation (expect seq=1).
    let confirm_frame = recv_frame(transport, &mut read_buf).await?;
    validate_handshake_frame(&confirm_frame, FrameType::Hello, 1)?;

    let received_hash = parse_confirmation(&confirm_frame.payload)?;
    // The initiator's (send_key, recv_key) == our (recv_key, send_key).
    let expected_hash = compute_confirmation(&session_id, &recv_key, &send_key);

    if received_hash != expected_hash {
        return Err(SessionError::HandshakeFailed(
            "confirmation hash mismatch: peer derived different keys".into(),
        )
        .into());
    }

    Ok(HandshakeResult {
        send_key,
        recv_key,
        session_id,
        peer_attestation: None,
        residual: read_buf,
    })
}
