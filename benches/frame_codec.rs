use bytes::{Bytes, BytesMut};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use tokio_util::codec::{Decoder, Encoder};

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::frame::tensor::{DType, TensorRef, OwnedTensor};
use confidential_ml_transport::frame::Frame;

fn bench_frame_encode_decode(c: &mut Criterion) {
    let payload = Bytes::from(vec![0xABu8; 4096]);

    let mut group = c.benchmark_group("frame_codec");
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("encode_4k", |b| {
        b.iter(|| {
            let frame = Frame::data(0, payload.clone(), true);
            let mut codec = FrameCodec::new();
            let mut buf = BytesMut::with_capacity(4096 + 13);
            codec.encode(frame, &mut buf).unwrap();
            black_box(buf);
        })
    });

    group.bench_function("decode_4k", |b| {
        let frame = Frame::data(0, payload.clone(), true);
        let mut codec_enc = FrameCodec::new();
        let mut encoded = BytesMut::new();
        codec_enc.encode(frame, &mut encoded).unwrap();
        let encoded = encoded.freeze();

        b.iter(|| {
            let mut codec = FrameCodec::new();
            let mut buf = BytesMut::from(&encoded[..]);
            let frame = codec.decode(&mut buf).unwrap().unwrap();
            black_box(frame);
        })
    });

    group.bench_function("roundtrip_4k", |b| {
        b.iter(|| {
            let frame = Frame::data(0, payload.clone(), true);
            let mut codec = FrameCodec::new();
            let mut buf = BytesMut::new();
            codec.encode(frame, &mut buf).unwrap();
            let decoded = codec.decode(&mut buf).unwrap().unwrap();
            black_box(decoded);
        })
    });

    group.finish();
}

fn bench_tensor_encode_decode(c: &mut Criterion) {
    // [128, 768] f32 tensor (~384 KB, typical embedding)
    let shape = [128u32, 768];
    let data = vec![0u8; 128 * 768 * 4];
    let total_bytes = data.len();

    let mut group = c.benchmark_group("tensor_codec");
    group.throughput(Throughput::Bytes(total_bytes as u64));

    group.bench_function("encode_128x768_f32", |b| {
        b.iter(|| {
            let tensor = TensorRef {
                name: "hidden",
                dtype: DType::F32,
                shape: &shape,
                data: &data,
            };
            let mut buf = BytesMut::with_capacity(total_bytes + 64);
            tensor.encode(&mut buf).unwrap();
            black_box(buf);
        })
    });

    group.bench_function("decode_128x768_f32", |b| {
        let tensor = TensorRef {
            name: "hidden",
            dtype: DType::F32,
            shape: &shape,
            data: &data,
        };
        let mut buf = BytesMut::new();
        tensor.encode(&mut buf).unwrap();
        let encoded = buf.freeze();

        b.iter(|| {
            let decoded = OwnedTensor::decode(encoded.clone()).unwrap();
            black_box(decoded);
        })
    });

    group.finish();
}

fn bench_seal_open(c: &mut Criterion) {
    use confidential_ml_transport::crypto::seal::{SealingContext, OpeningContext};

    let key = [0x42u8; 32];
    let session_id = [0xAA; 32];
    let plaintext = vec![0xBBu8; 4096];

    let mut group = c.benchmark_group("crypto");
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("seal_4k", |b| {
        let mut sealer = SealingContext::new(&key, session_id);
        b.iter(|| {
            let (ct, _) = sealer.seal(&plaintext).unwrap();
            black_box(ct);
        })
    });

    group.bench_function("open_4k", |b| {
        // Pre-seal messages to decrypt.
        let mut sealer = SealingContext::new(&key, session_id);
        let messages: Vec<(Vec<u8>, u64)> = (0..10000)
            .map(|_| sealer.seal(&plaintext).unwrap())
            .collect();
        let mut opener = OpeningContext::new(&key, session_id);
        let mut idx = 0;

        b.iter(|| {
            if idx >= messages.len() {
                return;
            }
            let (ct, seq) = &messages[idx];
            let pt = opener.open(ct, *seq).unwrap();
            black_box(pt);
            idx += 1;
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_frame_encode_decode,
    bench_tensor_encode_decode,
    bench_seal_open,
);
criterion_main!(benches);
