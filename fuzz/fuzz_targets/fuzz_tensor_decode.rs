#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

use confidential_ml_transport::frame::tensor::OwnedTensor;

fuzz_target!(|data: &[u8]| {
    // Fuzz the tensor decoder: feed arbitrary bytes and ensure no panics.
    // OwnedTensor::decode validates ndims, dtype, shape overflow, name UTF-8,
    // padding bytes, and data size — none of these should ever panic.
    let _ = OwnedTensor::decode(Bytes::copy_from_slice(data));
});
