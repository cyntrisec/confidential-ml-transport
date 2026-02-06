use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::FrameError;

/// Tensor data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DType {
    F32 = 0,
    F64 = 1,
    F16 = 2,
    BF16 = 3,
    I32 = 4,
    I64 = 5,
    U8 = 6,
    U32 = 7,
}

impl DType {
    pub fn from_u8(v: u8) -> Result<Self, FrameError> {
        match v {
            0 => Ok(Self::F32),
            1 => Ok(Self::F64),
            2 => Ok(Self::F16),
            3 => Ok(Self::BF16),
            4 => Ok(Self::I32),
            5 => Ok(Self::I64),
            6 => Ok(Self::U8),
            7 => Ok(Self::U32),
            other => Err(FrameError::UnknownDType(other)),
        }
    }

    /// Size in bytes of one element of this dtype.
    pub const fn element_size(self) -> usize {
        match self {
            DType::U8 => 1,
            DType::F16 | DType::BF16 => 2,
            DType::F32 | DType::I32 | DType::U32 => 4,
            DType::F64 | DType::I64 => 8,
        }
    }
}

/// A borrowed tensor reference (zero-copy for encoding).
#[derive(Debug, Clone)]
pub struct TensorRef<'a> {
    pub name: &'a str,
    pub dtype: DType,
    pub shape: &'a [u32],
    pub data: &'a [u8],
}

impl<'a> TensorRef<'a> {
    /// Validate that the data length matches the shape and dtype.
    pub fn validate(&self) -> Result<(), FrameError> {
        let expected = self.expected_data_len()?;
        if self.data.len() != expected {
            return Err(FrameError::TensorDataSizeMismatch {
                expected,
                actual: self.data.len(),
            });
        }
        Ok(())
    }

    fn expected_data_len(&self) -> Result<usize, FrameError> {
        let elem_count = self
            .shape
            .iter()
            .try_fold(1usize, |acc, &dim| acc.checked_mul(dim as usize))
            .ok_or(FrameError::ShapeOverflow)?;
        elem_count
            .checked_mul(self.dtype.element_size())
            .ok_or(FrameError::ShapeOverflow)
    }

    /// Encode this tensor into a payload buffer (sub-header + data).
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), FrameError> {
        self.validate()?;

        let ndims = self.shape.len() as u16;
        let name_bytes = self.name.as_bytes();
        let name_len = name_bytes.len() as u16;

        // Sub-header: ndims(2 LE) + dtype(1) + shape(ndims*4 LE) + name_len(2 LE) + name + padding + data
        let sub_header_len = 2 + 1 + (ndims as usize) * 4 + 2 + name_bytes.len();
        let padding = (8 - (sub_header_len % 8)) % 8;
        let total = sub_header_len + padding + self.data.len();

        buf.reserve(total);
        buf.put_u16_le(ndims);
        buf.put_u8(self.dtype as u8);
        for &dim in self.shape {
            buf.put_u32_le(dim);
        }
        buf.put_u16_le(name_len);
        buf.extend_from_slice(name_bytes);
        // Padding to 8-byte alignment.
        for _ in 0..padding {
            buf.put_u8(0);
        }
        buf.extend_from_slice(self.data);

        Ok(())
    }
}

/// An owned tensor (decoded from wire).
#[derive(Debug, Clone, PartialEq)]
pub struct OwnedTensor {
    pub name: String,
    pub dtype: DType,
    pub shape: Vec<u32>,
    pub data: Bytes,
}

/// Maximum number of tensor dimensions (no practical tensor exceeds 32 dims).
const MAX_NDIMS: u16 = 32;

impl OwnedTensor {
    /// Decode a tensor from a payload buffer.
    pub fn decode(mut buf: Bytes) -> Result<Self, FrameError> {
        // ndims (2 LE)
        if buf.len() < 3 {
            return Err(FrameError::IncompleteTensorHeader);
        }
        let ndims = (&buf[..2]).get_u16_le();
        if ndims > MAX_NDIMS {
            return Err(FrameError::ShapeOverflow);
        }
        buf.advance(2);

        // dtype (1)
        let dtype = DType::from_u8(buf[0])?;
        buf.advance(1);

        // shape (ndims * 4 LE)
        let shape_bytes = (ndims as usize) * 4;
        if buf.len() < shape_bytes {
            return Err(FrameError::IncompleteTensorHeader);
        }
        let mut shape = Vec::with_capacity(ndims as usize);
        for _ in 0..ndims {
            shape.push((&buf[..4]).get_u32_le());
            buf.advance(4);
        }

        // name_len (2 LE) + name
        if buf.len() < 2 {
            return Err(FrameError::IncompleteTensorHeader);
        }
        let name_len = (&buf[..2]).get_u16_le() as usize;
        buf.advance(2);
        if buf.len() < name_len {
            return Err(FrameError::IncompleteTensorHeader);
        }
        let name = String::from_utf8(buf.split_to(name_len).to_vec())?;

        // Compute sub-header length for padding calculation.
        let sub_header_len = 2 + 1 + shape_bytes + 2 + name_len;
        let padding = (8 - (sub_header_len % 8)) % 8;
        if buf.len() < padding {
            return Err(FrameError::IncompleteTensorHeader);
        }
        buf.advance(padding);

        // Remaining bytes are tensor data.
        let data = buf;

        // Validate data size.
        let elem_count = shape
            .iter()
            .try_fold(1usize, |acc, &dim| acc.checked_mul(dim as usize))
            .ok_or(FrameError::ShapeOverflow)?;
        let expected = elem_count
            .checked_mul(dtype.element_size())
            .ok_or(FrameError::ShapeOverflow)?;
        if data.len() != expected {
            return Err(FrameError::TensorDataSizeMismatch {
                expected,
                actual: data.len(),
            });
        }

        Ok(Self {
            name,
            dtype,
            shape,
            data,
        })
    }

    /// Get a borrowed reference to this tensor.
    pub fn as_ref(&self) -> TensorRef<'_> {
        TensorRef {
            name: &self.name,
            dtype: self.dtype,
            shape: &self.shape,
            data: &self.data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_f32_tensor() {
        let data: Vec<u8> = (0..24).map(|i| i as u8).collect(); // 6 f32s = 24 bytes
        let tensor = TensorRef {
            name: "hidden_state",
            dtype: DType::F32,
            shape: &[2, 3],
            data: &data,
        };

        let mut buf = BytesMut::new();
        tensor.encode(&mut buf).unwrap();

        let decoded = OwnedTensor::decode(buf.freeze()).unwrap();
        assert_eq!(decoded.name, "hidden_state");
        assert_eq!(decoded.dtype, DType::F32);
        assert_eq!(decoded.shape, vec![2, 3]);
        assert_eq!(&decoded.data[..], &data);
    }

    #[test]
    fn roundtrip_scalar() {
        let data = [0u8; 4]; // single f32
        let tensor = TensorRef {
            name: "loss",
            dtype: DType::F32,
            shape: &[1],
            data: &data,
        };

        let mut buf = BytesMut::new();
        tensor.encode(&mut buf).unwrap();

        let decoded = OwnedTensor::decode(buf.freeze()).unwrap();
        assert_eq!(decoded.name, "loss");
        assert_eq!(decoded.shape, vec![1]);
    }

    #[test]
    fn data_size_mismatch() {
        let tensor = TensorRef {
            name: "bad",
            dtype: DType::F32,
            shape: &[2, 3],
            data: &[0u8; 10], // should be 24
        };

        let mut buf = BytesMut::new();
        let err = tensor.encode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::TensorDataSizeMismatch { .. }));
    }

    #[test]
    fn empty_name() {
        let data = [0u8; 8]; // 2 f32s
        let tensor = TensorRef {
            name: "",
            dtype: DType::F32,
            shape: &[2],
            data: &data,
        };

        let mut buf = BytesMut::new();
        tensor.encode(&mut buf).unwrap();

        let decoded = OwnedTensor::decode(buf.freeze()).unwrap();
        assert_eq!(decoded.name, "");
    }

    #[test]
    fn dtype_element_sizes() {
        assert_eq!(DType::U8.element_size(), 1);
        assert_eq!(DType::F16.element_size(), 2);
        assert_eq!(DType::BF16.element_size(), 2);
        assert_eq!(DType::F32.element_size(), 4);
        assert_eq!(DType::I32.element_size(), 4);
        assert_eq!(DType::U32.element_size(), 4);
        assert_eq!(DType::F64.element_size(), 8);
        assert_eq!(DType::I64.element_size(), 8);
    }
}
