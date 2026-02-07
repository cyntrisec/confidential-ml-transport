use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use super::{Frame, FrameHeader, HEADER_SIZE};
use crate::error::FrameError;

/// Tokio codec for encoding/decoding frames on the wire.
#[derive(Debug)]
pub struct FrameCodec {
    /// Cached header from a partial decode.
    current_header: Option<FrameHeader>,
    /// Configured maximum payload size (enforced on decode).
    max_payload_size: u32,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameCodec {
    pub fn new() -> Self {
        Self {
            current_header: None,
            max_payload_size: super::MAX_PAYLOAD_SIZE,
        }
    }

    /// Create a codec with a custom maximum payload size.
    pub fn with_max_payload_size(max_payload_size: u32) -> Self {
        Self {
            current_header: None,
            max_payload_size,
        }
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Parse header if we don't have one cached.
        let header = match self.current_header.take() {
            Some(h) => h,
            None => match FrameHeader::decode(src)? {
                Some(h) => h,
                None => return Ok(None),
            },
        };

        // Enforce configured payload size limit (may be stricter than the
        // hard cap already checked in FrameHeader::decode).
        if header.payload_len > self.max_payload_size {
            return Err(FrameError::PayloadTooLarge {
                size: header.payload_len,
                max: self.max_payload_size,
            });
        }

        // Wait for full payload.
        let payload_len = header.payload_len as usize;
        if src.len() < payload_len {
            // Reserve space so the next read has room.
            src.reserve(payload_len - src.len());
            self.current_header = Some(header);
            return Ok(None);
        }

        let payload = src.split_to(payload_len).freeze();

        Ok(Some(Frame { header, payload }))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(HEADER_SIZE + frame.payload.len());
        frame.header.encode(dst);
        dst.extend_from_slice(&frame.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn roundtrip_data_frame() {
        let mut codec = FrameCodec::new();
        let frame = Frame::data(42, Bytes::from_static(b"hello world"), false);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let mut codec = FrameCodec::new();
        let frame = Frame::shutdown(1);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn partial_header() {
        let mut codec = FrameCodec::new();
        let frame = Frame::data(1, Bytes::from_static(b"test"), false);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        // Only give 5 bytes of the header.
        let mut partial = buf.split_to(5);
        assert!(codec.decode(&mut partial).unwrap().is_none());

        // Give the rest.
        partial.extend_from_slice(&buf);
        let decoded = codec.decode(&mut partial).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn partial_payload() {
        let mut codec = FrameCodec::new();
        let payload = Bytes::from(vec![0xABu8; 100]);
        let frame = Frame::data(7, payload, true);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        // Give header + partial payload.
        let mut partial = buf.split_to(HEADER_SIZE + 50);
        assert!(codec.decode(&mut partial).unwrap().is_none());

        // Give the rest.
        partial.extend_from_slice(&buf);
        let decoded = codec.decode(&mut partial).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn invalid_magic() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::from(&[0x00, 0x00, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::InvalidMagic(0x0000)));
    }

    #[test]
    fn payload_too_large() {
        let mut codec = FrameCodec::new();
        // Header with payload_len = 0xFFFFFFFF
        let mut buf =
            BytesMut::from(&[0xCF, 0x4D, 1, 0x02, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::PayloadTooLarge { .. }));
    }
}
