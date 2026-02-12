use bytes::{Buf, BufMut, Bytes, BytesMut};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
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
    /// The verified attestation from the peer.
    /// Both initiator and responder receive this (mutual attestation).
    pub peer_attestation: Option<VerifiedAttestation>,
    /// Residual bytes read from the transport but not consumed by the handshake.
    /// Must be prepended to the channel's read buffer.
    pub residual: BytesMut,
}

// -- Wire helpers --

/// Encode an initiator hello message (v3: includes attestation document).
///
/// Wire format: `[1:u8 | pk:32B | nonce:32B | doc_len:4B | attestation_doc:var]`
fn encode_initiator_hello(
    public_key: &[u8; 32],
    nonce: &[u8; 32],
    attestation_doc: &[u8],
) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + 32 + 32 + 4 + attestation_doc.len());
    buf.put_u8(1); // message number
    buf.put_slice(public_key);
    buf.put_slice(nonce);
    buf.put_u32(attestation_doc.len() as u32);
    buf.put_slice(attestation_doc);
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

/// Maximum attestation document size accepted during handshake (64 KiB).
///
/// Real Nitro attestation documents are typically <16 KiB. This cap prevents an
/// adversary from sending a multi-megabyte document to exhaust memory.
const MAX_ATTESTATION_DOC_SIZE: usize = 64 * 1024;

/// Parse a hello message containing a public key, nonce, and attestation document.
///
/// Used for both initiator (msg_num=1) and responder (msg_num=2) hellos in v3.
fn parse_hello_with_attestation(
    payload: &[u8],
    expected_msg_num: u8,
    role_name: &str,
) -> Result<([u8; 32], [u8; 32], AttestationDocument), SessionError> {
    const MIN_LEN: usize = 1 + 32 + 32 + 4;
    if payload.len() < MIN_LEN {
        return Err(SessionError::HandshakeFailed(format!(
            "{role_name} hello too short"
        )));
    }
    if payload[0] != expected_msg_num {
        return Err(SessionError::UnexpectedMessage {
            expected: if expected_msg_num == 1 {
                "initiator_hello (1)"
            } else {
                "responder_hello (2)"
            },
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
    let expected_total = MIN_LEN
        .checked_add(doc_len)
        .ok_or_else(|| SessionError::HandshakeFailed(format!("{role_name} hello length overflow")))?;
    if payload.len() != expected_total {
        return Err(SessionError::HandshakeFailed(format!(
            "{role_name} hello: expected {expected_total} bytes, got {}",
            payload.len()
        )));
    }
    let doc = AttestationDocument::new(cursor[..doc_len].to_vec());
    Ok((pk, nonce, doc))
}

fn parse_initiator_hello(
    payload: &[u8],
) -> Result<([u8; 32], [u8; 32], AttestationDocument), SessionError> {
    parse_hello_with_attestation(payload, 1, "initiator")
}

fn parse_responder_hello(
    payload: &[u8],
) -> Result<([u8; 32], [u8; 32], AttestationDocument), SessionError> {
    parse_hello_with_attestation(payload, 2, "responder")
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
fn derive_session_id(transcript_hash: &[u8; 32]) -> Result<[u8; 32], crate::error::Error> {
    let hkdf = Hkdf::<Sha256>::new(None, transcript_hash);
    let mut session_id = [0u8; 32];
    hkdf.expand(b"cmt-session-id", &mut session_id)
        .map_err(|_| crate::error::Error::Crypto(crate::error::CryptoError::HkdfExpandFailed))?;
    Ok(session_id)
}

/// Verify an attestation document: check signature, public key binding, and measurements.
fn verify_attestation(
    verified: &VerifiedAttestation,
    peer_pk_bytes: &[u8; 32],
    expected_measurements: Option<&ExpectedMeasurements>,
    role: &str,
) -> Result<(), crate::error::Error> {
    // Verify the attestation binds the peer's public key (mandatory).
    match verified.public_key {
        Some(ref att_pk) => {
            if att_pk.as_slice() != peer_pk_bytes.as_slice() {
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
            role,
            expected_count = expected.values.len(),
            "measurement verification passed"
        );
    }

    Ok(())
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
/// Handshake messages are small (initiator/responder hello ~69B + attestation doc,
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
///
/// In v3 (mutual attestation), the initiator sends its own attestation document
/// in Msg1 and verifies the responder's attestation in Msg2. Both sides receive
/// `peer_attestation: Some(verified)`.
///
/// Individual frame reads are not independently timed; the caller is expected
/// to wrap this function in a `tokio::time::timeout` (which `SecureChannel`
/// does via `SessionConfig::handshake_timeout`).
pub async fn initiate<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
    provider: &dyn AttestationProvider,
    verifier: &dyn AttestationVerifier,
    expected_measurements: Option<&ExpectedMeasurements>,
) -> Result<HandshakeResult, crate::error::Error> {
    let keypair = KeyPair::generate();
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill(&mut nonce);
    let pk_bytes = keypair.public.to_bytes();

    // Generate our attestation binding our public key.
    let our_att_doc = provider
        .attest(None, Some(&nonce), Some(&pk_bytes))
        .await
        .map_err(|e| {
            tracing::warn!("initiator attestation generation failed: {e}");
            SessionError::HandshakeFailed("initiator attestation generation failed".into())
        })?;

    // Step 1: Send initiator hello with attestation (seq=0).
    let hello = Frame::hello(
        0,
        encode_initiator_hello(&pk_bytes, &nonce, &our_att_doc.raw),
    );
    send_frame(transport, hello).await?;

    let init_att_hash: [u8; 32] = Sha256::digest(&our_att_doc.raw).into();

    // Step 2: Receive responder hello (expect seq=0).
    let mut read_buf = BytesMut::with_capacity(4096);
    let resp_frame = recv_frame(transport, &mut read_buf).await?;
    validate_handshake_frame(&resp_frame, FrameType::Hello, 0)?;

    let (resp_pk_bytes, resp_nonce, resp_att_doc) = parse_responder_hello(&resp_frame.payload)?;

    // Step 3: Verify responder's attestation.
    let verified = verifier.verify(&resp_att_doc).await.map_err(|e| {
        tracing::warn!("responder attestation verification failed: {e}");
        SessionError::HandshakeFailed("attestation verification failed".into())
    })?;

    tracing::info!(
        document_hash = hex::encode(verified.document_hash),
        measurement_count = verified.measurements.len(),
        "responder attestation verification succeeded"
    );
    tracing::debug!(
        measurements = ?verified.measurements.iter().map(|(k, v)| (k, hex::encode(v))).collect::<Vec<_>>(),
        "peer attestation measurements"
    );

    verify_attestation(&verified, &resp_pk_bytes, expected_measurements, "initiator")?;

    // Combine nonces.
    let mut combined_nonce = [0u8; 32];
    for i in 0..32 {
        combined_nonce[i] = nonce[i] ^ resp_nonce[i];
    }

    // Compute transcript binding both attestation hashes and derive keys.
    let resp_pk = x25519_dalek::PublicKey::from(resp_pk_bytes);
    let transcript_hash = transcript::compute_transcript(
        &init_att_hash,
        &verified.document_hash,
        &pk_bytes,
        &resp_pk_bytes,
        &combined_nonce,
    );

    let (send_key, recv_key) =
        hpke::derive_session_keys(&keypair.secret, &resp_pk, &transcript_hash, true)?;

    // Derive session_id via HKDF (domain-separated from transcript_hash).
    let session_id = derive_session_id(&transcript_hash)?;

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
///
/// In v3 (mutual attestation), the responder verifies the initiator's attestation
/// from Msg1 and sends its own attestation in Msg2. Both sides receive
/// `peer_attestation: Some(verified)`.
///
/// Individual frame reads are not independently timed; the caller is expected
/// to wrap this function in a `tokio::time::timeout` (which `SecureChannel`
/// does via `SessionConfig::handshake_timeout`).
pub async fn respond<T: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut T,
    provider: &dyn AttestationProvider,
    verifier: &dyn AttestationVerifier,
    expected_measurements: Option<&ExpectedMeasurements>,
) -> Result<HandshakeResult, crate::error::Error> {
    // Step 1: Receive initiator hello with attestation (expect seq=0).
    let mut read_buf = BytesMut::with_capacity(4096);
    let init_frame = recv_frame(transport, &mut read_buf).await?;
    validate_handshake_frame(&init_frame, FrameType::Hello, 0)?;

    let (init_pk_bytes, init_nonce, init_att_doc) = parse_initiator_hello(&init_frame.payload)?;

    // Verify initiator's attestation.
    let init_verified = verifier.verify(&init_att_doc).await.map_err(|e| {
        tracing::warn!("initiator attestation verification failed: {e}");
        SessionError::HandshakeFailed("initiator attestation verification failed".into())
    })?;

    tracing::info!(
        document_hash = hex::encode(init_verified.document_hash),
        measurement_count = init_verified.measurements.len(),
        "initiator attestation verification succeeded"
    );

    verify_attestation(
        &init_verified,
        &init_pk_bytes,
        expected_measurements,
        "responder",
    )?;

    let init_att_hash: [u8; 32] = Sha256::digest(&init_att_doc.raw).into();

    // Generate our keypair and nonce.
    let keypair = KeyPair::generate();
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill(&mut nonce);
    let pk_bytes = keypair.public.to_bytes();

    // Step 2: Generate our attestation binding our public key.
    let att_doc = provider
        .attest(None, Some(&nonce), Some(&pk_bytes))
        .await
        .map_err(|e| {
            tracing::warn!("responder attestation generation failed: {e}");
            SessionError::HandshakeFailed("attestation generation failed".into())
        })?;

    tracing::debug!(
        doc_len = att_doc.raw.len(),
        "responder attestation document generated"
    );

    // Send responder hello (seq=0).
    let hello = Frame::hello(0, encode_responder_hello(&pk_bytes, &nonce, &att_doc.raw));
    send_frame(transport, hello).await?;

    // Derive keys.
    let resp_att_hash: [u8; 32] = Sha256::digest(&att_doc.raw).into();

    let mut combined_nonce = [0u8; 32];
    for i in 0..32 {
        combined_nonce[i] = init_nonce[i] ^ nonce[i];
    }

    let init_pk = x25519_dalek::PublicKey::from(init_pk_bytes);
    let transcript_hash = transcript::compute_transcript(
        &init_att_hash,
        &resp_att_hash,
        &init_pk_bytes,
        &pk_bytes,
        &combined_nonce,
    );

    let (send_key, recv_key) =
        hpke::derive_session_keys(&keypair.secret, &init_pk, &transcript_hash, false)?;

    // Derive session_id via HKDF (domain-separated from transcript_hash).
    let session_id = derive_session_id(&transcript_hash)?;

    // Step 3: Receive and verify confirmation (expect seq=1).
    let confirm_frame = recv_frame(transport, &mut read_buf).await?;
    validate_handshake_frame(&confirm_frame, FrameType::Hello, 1)?;

    let received_hash = parse_confirmation(&confirm_frame.payload)?;
    // The initiator's (send_key, recv_key) == our (recv_key, send_key).
    let expected_hash = compute_confirmation(&session_id, &recv_key, &send_key);

    // Constant-time comparison to prevent timing side-channel attacks on the
    // confirmation hash. A variable-time `!=` would let an attacker learn
    // correct bytes incrementally by measuring response latency.
    if received_hash.ct_eq(&expected_hash).unwrap_u8() == 0 {
        return Err(SessionError::HandshakeFailed(
            "confirmation hash mismatch: peer derived different keys".into(),
        )
        .into());
    }

    Ok(HandshakeResult {
        send_key,
        recv_key,
        session_id,
        peer_attestation: Some(init_verified),
        residual: read_buf,
    })
}
