use bytes::{Bytes, BytesMut};
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::frame::tensor::{DType, OwnedTensor, TensorRef};
use confidential_ml_transport::frame::{Frame, FrameType, Flags, PROTOCOL_VERSION};

// Strategy for generating arbitrary frame types.
fn arb_frame_type() -> impl Strategy<Value = FrameType> {
    prop_oneof![
        Just(FrameType::Hello),
        Just(FrameType::Data),
        Just(FrameType::Error),
        Just(FrameType::Heartbeat),
        Just(FrameType::Shutdown),
        Just(FrameType::Tensor),
    ]
}

// Strategy for generating arbitrary flags.
fn arb_flags() -> impl Strategy<Value = Flags> {
    (0u8..=0x0F).prop_map(Flags)
}

// Strategy for generating arbitrary payloads (limited size for speed).
fn arb_payload() -> impl Strategy<Value = Bytes> {
    prop::collection::vec(any::<u8>(), 0..1024).prop_map(Bytes::from)
}

// Strategy for generating arbitrary frames.
fn arb_frame() -> impl Strategy<Value = Frame> {
    (arb_frame_type(), arb_flags(), any::<u32>(), arb_payload()).prop_map(
        |(msg_type, flags, sequence, payload)| Frame {
            header: confidential_ml_transport::frame::FrameHeader {
                version: PROTOCOL_VERSION,
                msg_type,
                flags,
                sequence,
                payload_len: payload.len() as u32,
            },
            payload,
        },
    )
}

proptest! {
    #[test]
    fn frame_roundtrip(frame in arb_frame()) {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();

        codec.encode(frame.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        prop_assert_eq!(decoded.header.version, frame.header.version);
        prop_assert_eq!(decoded.header.msg_type, frame.header.msg_type);
        prop_assert_eq!(decoded.header.flags, frame.header.flags);
        prop_assert_eq!(decoded.header.sequence, frame.header.sequence);
        prop_assert_eq!(decoded.header.payload_len, frame.header.payload_len);
        prop_assert_eq!(&decoded.payload[..], &frame.payload[..]);
    }

    #[test]
    fn frame_roundtrip_chunked(frame in arb_frame(), split_point in 0usize..2048) {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let total_len = buf.len();
        let split = split_point.min(total_len);

        // Feed in two chunks.
        let rest = buf.split_off(split);
        let mut partial = buf;

        // First decode attempt may return None (not enough data).
        let result = codec.decode(&mut partial).unwrap();
        if result.is_some() {
            // Got it in one chunk — fine.
            return Ok(());
        }

        // Feed the rest.
        partial.extend_from_slice(&rest);
        let decoded = codec.decode(&mut partial).unwrap().unwrap();
        prop_assert_eq!(decoded, frame);
    }
}

// Strategy for DType.
fn arb_dtype() -> impl Strategy<Value = DType> {
    prop_oneof![
        Just(DType::F32),
        Just(DType::F64),
        Just(DType::F16),
        Just(DType::BF16),
        Just(DType::I32),
        Just(DType::I64),
        Just(DType::U8),
        Just(DType::U32),
    ]
}

proptest! {
    #[test]
    fn tensor_roundtrip(
        dtype in arb_dtype(),
        shape in prop::collection::vec(1u32..=16, 1..=4),
        name in "[a-z_]{0,32}",
    ) {
        let elem_count: usize = shape.iter().map(|&d| d as usize).product();
        let data_len = elem_count * dtype.element_size();

        // Generate random data of the correct size.
        let data: Vec<u8> = (0..data_len).map(|i| (i % 256) as u8).collect();

        let tensor = TensorRef {
            name: &name,
            dtype,
            shape: &shape,
            data: &data,
        };

        let mut buf = BytesMut::new();
        tensor.encode(&mut buf).unwrap();

        let decoded = OwnedTensor::decode(buf.freeze()).unwrap();
        prop_assert_eq!(&decoded.name, &name);
        prop_assert_eq!(decoded.dtype, dtype);
        prop_assert_eq!(&decoded.shape, &shape);
        prop_assert_eq!(&decoded.data[..], &data[..]);
    }
}
