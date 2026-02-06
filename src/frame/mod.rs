pub mod codec;
pub mod tensor;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::FrameError;

/// Magic bytes: 0xCF 0x4D ("Confidential ML").
pub const MAGIC: u16 = 0xCF4D;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 13;

/// Maximum payload size: 32 MiB.
pub const MAX_PAYLOAD_SIZE: u32 = 32 * 1024 * 1024;

/// Frame message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    Data = 0x02,
    Error = 0x03,
    Heartbeat = 0x04,
    Shutdown = 0x05,
    Tensor = 0x06,
}

impl FrameType {
    pub fn from_u8(v: u8) -> std::result::Result<Self, FrameError> {
        match v {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Error),
            0x04 => Ok(Self::Heartbeat),
            0x05 => Ok(Self::Shutdown),
            0x06 => Ok(Self::Tensor),
            other => Err(FrameError::UnknownMessageType(other)),
        }
    }
}

/// Frame flags (bit field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(pub(crate) u8);

impl Flags {
    pub const ENCRYPTED: u8 = 0x01;
    pub const TENSOR_PAYLOAD: u8 = 0x02;
    pub const BATCH: u8 = 0x04;
    pub const COMPRESSED: u8 = 0x08;

    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create flags from raw bits.
    pub const fn from_raw(bits: u8) -> Self {
        Self(bits)
    }

    /// Get the raw flag bits.
    pub const fn raw(self) -> u8 {
        self.0
    }

    pub const fn is_encrypted(self) -> bool {
        self.0 & Self::ENCRYPTED != 0
    }

    pub const fn is_tensor_payload(self) -> bool {
        self.0 & Self::TENSOR_PAYLOAD != 0
    }

    pub const fn is_batch(self) -> bool {
        self.0 & Self::BATCH != 0
    }

    pub const fn is_compressed(self) -> bool {
        self.0 & Self::COMPRESSED != 0
    }
}

/// A parsed frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub msg_type: FrameType,
    pub flags: Flags,
    pub sequence: u32,
    pub payload_len: u32,
}

impl FrameHeader {
    /// Encode the header into bytes.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(MAGIC);
        buf.put_u8(self.version);
        buf.put_u8(self.msg_type as u8);
        buf.put_u8(self.flags.0);
        buf.put_u32(self.sequence);
        buf.put_u32(self.payload_len);
    }

    /// Decode a header from a buffer. Returns `None` if not enough bytes.
    pub fn decode(buf: &mut BytesMut) -> std::result::Result<Option<Self>, FrameError> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }

        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != MAGIC {
            return Err(FrameError::InvalidMagic(magic));
        }

        let version = buf[2];
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }

        let msg_type = FrameType::from_u8(buf[3])?;
        let flags = Flags(buf[4]);
        let sequence = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let payload_len = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge {
                size: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        buf.advance(HEADER_SIZE);

        Ok(Some(Self {
            version,
            msg_type,
            flags,
            sequence,
            payload_len,
        }))
    }
}

/// A complete frame: header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Bytes,
}

impl Frame {
    /// Create a new data frame.
    pub fn data(sequence: u32, payload: Bytes, encrypted: bool) -> Self {
        let mut flags = Flags::empty();
        if encrypted {
            flags = Flags(flags.0 | Flags::ENCRYPTED);
        }
        Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type: FrameType::Data,
                flags,
                sequence,
                payload_len: payload.len() as u32,
            },
            payload,
        }
    }

    /// Create a hello frame (used during handshake).
    pub fn hello(sequence: u32, payload: Bytes) -> Self {
        Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type: FrameType::Hello,
                flags: Flags::empty(),
                sequence,
                payload_len: payload.len() as u32,
            },
            payload,
        }
    }

    /// Create a shutdown frame.
    pub fn shutdown(sequence: u32) -> Self {
        Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type: FrameType::Shutdown,
                flags: Flags::empty(),
                sequence,
                payload_len: 0,
            },
            payload: Bytes::new(),
        }
    }

    /// Create a heartbeat frame.
    pub fn heartbeat(sequence: u32) -> Self {
        Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type: FrameType::Heartbeat,
                flags: Flags::empty(),
                sequence,
                payload_len: 0,
            },
            payload: Bytes::new(),
        }
    }

    /// Create an error frame.
    pub fn error(sequence: u32, message: &str) -> Self {
        let payload = Bytes::copy_from_slice(message.as_bytes());
        Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type: FrameType::Error,
                flags: Flags::empty(),
                sequence,
                payload_len: payload.len() as u32,
            },
            payload,
        }
    }

    /// Create a tensor frame.
    pub fn tensor(sequence: u32, payload: Bytes, encrypted: bool) -> Self {
        let mut flags = Flags(Flags::TENSOR_PAYLOAD);
        if encrypted {
            flags = Flags(flags.0 | Flags::ENCRYPTED);
        }
        Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type: FrameType::Tensor,
                flags,
                sequence,
                payload_len: payload.len() as u32,
            },
            payload,
        }
    }
}
