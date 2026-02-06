#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::frame::tensor::OwnedTensor;

fuzz_target!(|data: &[u8]| {
    // Fuzz the frame decoder: feed arbitrary bytes and ensure no panics.
    let mut codec = FrameCodec::new();
    let mut buf = BytesMut::from(data);

    // Try to decode frames until we run out of data.
    loop {
        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                // If we got a frame with the tensor flag, try to parse the tensor.
                if frame.header.flags.is_tensor_payload() {
                    let _ = OwnedTensor::decode(frame.payload);
                }
            }
            Ok(None) => break, // Need more data.
            Err(_) => break,   // Parse error is fine — no panics.
        }
    }
});
