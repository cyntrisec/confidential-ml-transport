use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::frame::tensor::{DType, OwnedTensor, TensorRef};
use confidential_ml_transport::frame::Frame;

/// Test encoding/decoding multiple frames over an in-memory duplex stream.
#[tokio::test]
async fn multiple_frames_over_duplex() {
    let (mut client, mut server) = tokio::io::duplex(8192);

    let frames = vec![
        Frame::data(0, Bytes::from_static(b"hello"), false),
        Frame::data(1, Bytes::from_static(b"world"), true),
        Frame::heartbeat(2),
        Frame::error(3, "something went wrong"),
        Frame::shutdown(4),
    ];

    // Encode and write all frames.
    let frames_clone = frames.clone();
    let write_handle = tokio::spawn(async move {
        let mut codec = FrameCodec::new();
        for frame in &frames_clone {
            let mut buf = BytesMut::new();
            codec.encode(frame.clone(), &mut buf).unwrap();
            client.write_all(&buf).await.unwrap();
        }
        client.shutdown().await.unwrap();
    });

    // Read and decode all frames.
    let mut codec = FrameCodec::new();
    let mut read_buf = BytesMut::with_capacity(4096);
    let mut decoded = Vec::new();

    loop {
        let n = server.read_buf(&mut read_buf).await.unwrap();
        while let Some(frame) = codec.decode(&mut read_buf).unwrap() {
            decoded.push(frame);
        }
        if n == 0 {
            break;
        }
    }

    write_handle.await.unwrap();

    assert_eq!(decoded.len(), frames.len());
    for (d, f) in decoded.iter().zip(frames.iter()) {
        assert_eq!(d, f);
    }
}

/// Test tensor encoding over an in-memory stream.
#[tokio::test]
async fn tensor_frame_over_duplex() {
    let (mut client, mut server) = tokio::io::duplex(8192);

    let write_handle = tokio::spawn(async move {
        let data = vec![0u8; 4 * 3 * 4]; // [4, 3] f32 = 48 bytes
        let tensor = TensorRef {
            name: "activations",
            dtype: DType::F32,
            shape: &[4, 3],
            data: &data,
        };
        let mut tensor_buf = BytesMut::new();
        tensor.encode(&mut tensor_buf).unwrap();

        let frame = Frame::tensor(0, tensor_buf.freeze(), false);
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        client.write_all(&buf).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let mut codec = FrameCodec::new();
    let mut read_buf = BytesMut::with_capacity(4096);

    loop {
        let n = server.read_buf(&mut read_buf).await.unwrap();
        if let Some(frame) = codec.decode(&mut read_buf).unwrap() {
            assert!(frame.header.flags.is_tensor_payload());
            let decoded_tensor = OwnedTensor::decode(frame.payload).unwrap();
            assert_eq!(decoded_tensor.name, "activations");
            assert_eq!(decoded_tensor.dtype, DType::F32);
            assert_eq!(decoded_tensor.shape, vec![4, 3]);
            assert_eq!(decoded_tensor.data.len(), 48);
            break;
        }
        if n == 0 {
            panic!("stream ended before frame received");
        }
    }

    write_handle.await.unwrap();
}

/// Test that a single frame split across many tiny reads still decodes correctly.
#[tokio::test]
async fn byte_at_a_time_decode() {
    let frame = Frame::data(42, Bytes::from(vec![0xABu8; 100]), true);
    let mut codec = FrameCodec::new();
    let mut full_buf = BytesMut::new();
    codec.encode(frame.clone(), &mut full_buf).unwrap();

    let full_bytes = full_buf.freeze();
    let mut decode_buf = BytesMut::new();
    let mut codec2 = FrameCodec::new();

    for i in 0..full_bytes.len() {
        decode_buf.extend_from_slice(&full_bytes[i..i + 1]);
        if let Some(decoded) = codec2.decode(&mut decode_buf).unwrap() {
            assert_eq!(decoded, frame);
            return;
        }
    }
    panic!("frame was never decoded");
}
