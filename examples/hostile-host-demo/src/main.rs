//! Hostile Host Relay Capture Demo
//!
//! A/B demo proving SecureChannel protects tensor data from a hostile host relay:
//! - Mode A (baseline): raw tensor frames through relay — host reads prompt, activations, values
//! - Mode B (secure): SecureChannel through same relay — host sees only ciphertext
//!
//! Usage:
//!   cargo run --release -p hostile-host-demo
//!   cargo run --release -p hostile-host-demo -- --dump artifacts/

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use clap::Parser;
use serde::Serialize;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder};

use confidential_ml_transport::frame::codec::FrameCodec;
use confidential_ml_transport::{
    DType, Flags, Frame, FrameType, Message, MockProvider, MockVerifier, OwnedTensor,
    SecureChannel, SessionConfig,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "hostile-host-demo")]
#[command(about = "A/B demo: plaintext vs SecureChannel through a hostile relay")]
struct Cli {
    /// Write raw captures and summary JSON to this directory.
    #[arg(long, value_name = "DIR")]
    dump: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Sample tensors (GPT-2 inter-stage data)
// ---------------------------------------------------------------------------

/// GPT-2 token IDs for "The capital of France is"
const TOKEN_IDS: [u32; 5] = [464, 3139, 286, 4881, 318];

fn token_lookup() -> HashMap<u32, &'static str> {
    HashMap::from([
        (464, "The"),
        (3139, " capital"),
        (286, " of"),
        (4881, " France"),
        (318, " is"),
    ])
}

/// Build the input_ids tensor: U32 [1, 5]
fn make_input_ids() -> OwnedTensor {
    let data: Vec<u8> = TOKEN_IDS.iter().flat_map(|t| t.to_le_bytes()).collect();
    OwnedTensor {
        name: "input_ids".into(),
        dtype: DType::U32,
        shape: vec![1, 5],
        data: Bytes::from(data),
    }
}

/// Build hidden_states tensor: F32 [1, 5, 768]
/// Pattern: token_id * 0.001 + dim_idx * 0.0001
fn make_hidden_states() -> OwnedTensor {
    let mut data = Vec::with_capacity(5 * 768 * 4);
    for token_idx in 0..5 {
        let base = TOKEN_IDS[token_idx] as f32 * 0.001;
        for dim in 0..768u32 {
            let val = base + dim as f32 * 0.0001;
            data.extend_from_slice(&val.to_le_bytes());
        }
    }
    OwnedTensor {
        name: "hidden_states".into(),
        dtype: DType::F32,
        shape: vec![1, 5, 768],
        data: Bytes::from(data),
    }
}

// ---------------------------------------------------------------------------
// Tapping relay
// ---------------------------------------------------------------------------

/// Result of relaying bytes through the tapping proxy.
struct RelayCapture {
    /// Bytes captured in the forward direction (left → right, i.e. sender → receiver).
    fwd: Vec<u8>,
    /// Bytes captured in the backward direction (right → left).
    bwd: Vec<u8>,
    /// I/O error from the forward relay leg, if any.
    fwd_error: Option<String>,
    /// I/O error from the backward relay leg, if any.
    bwd_error: Option<String>,
}

impl RelayCapture {
    /// Panics with a descriptive message if either relay leg hit an I/O error,
    /// which would mean the capture is partial and conclusions unreliable.
    fn assert_clean(&self, label: &str) {
        if let Some(e) = &self.fwd_error {
            panic!("{label}: forward relay I/O error (capture may be partial): {e}");
        }
        if let Some(e) = &self.bwd_error {
            panic!("{label}: backward relay I/O error (capture may be partial): {e}");
        }
    }
}

async fn tapping_relay(left: DuplexStream, right: DuplexStream) -> RelayCapture {
    let (left_read, left_write) = io::split(left);
    let (right_read, right_write) = io::split(right);

    let fwd_capture = Arc::new(Mutex::new(Vec::new()));
    let bwd_capture = Arc::new(Mutex::new(Vec::new()));

    let fwd_cap = fwd_capture.clone();
    let fwd =
        tokio::spawn(async move { relay_one_direction(left_read, right_write, fwd_cap).await });

    let bwd_cap = bwd_capture.clone();
    let bwd =
        tokio::spawn(async move { relay_one_direction(right_read, left_write, bwd_cap).await });

    let (fwd_result, bwd_result) = tokio::join!(fwd, bwd);

    let fwd_error = fwd_result.ok().and_then(|r| r.err()).map(|e| e.to_string());
    let bwd_error = bwd_result.ok().and_then(|r| r.err()).map(|e| e.to_string());

    let fwd_data = Arc::try_unwrap(fwd_capture).unwrap().into_inner();
    let bwd_data = Arc::try_unwrap(bwd_capture).unwrap().into_inner();
    RelayCapture {
        fwd: fwd_data,
        bwd: bwd_data,
        fwd_error,
        bwd_error,
    }
}

async fn relay_one_direction(
    mut reader: io::ReadHalf<DuplexStream>,
    mut writer: io::WriteHalf<DuplexStream>,
    capture: Arc<Mutex<Vec<u8>>>,
) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Err(e) => return Err(e),
            Ok(n) => {
                capture.lock().await.extend_from_slice(&buf[..n]);
                writer.write_all(&buf[..n]).await?;
            }
        }
    }
    let _ = writer.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Mode A: Plaintext transfer
// ---------------------------------------------------------------------------

async fn mode_a_sender(mut transport: DuplexStream) {
    let input_ids = make_input_ids();
    let hidden = make_hidden_states();
    let mut codec = FrameCodec::new();
    let mut out = BytesMut::new();

    let mut payload = BytesMut::new();
    input_ids.as_ref().encode(&mut payload).unwrap();
    let frame = Frame::tensor(0, payload.freeze(), false);
    codec.encode(frame, &mut out).unwrap();

    let mut payload = BytesMut::new();
    hidden.as_ref().encode(&mut payload).unwrap();
    let frame = Frame::tensor(1, payload.freeze(), false);
    codec.encode(frame, &mut out).unwrap();

    let frame = Frame::shutdown(2);
    codec.encode(frame, &mut out).unwrap();

    transport.write_all(&out).await.unwrap();
    transport.shutdown().await.unwrap();
}

async fn mode_a_receiver(mut transport: DuplexStream) {
    let mut codec = FrameCodec::new();
    let mut buf = BytesMut::new();
    let mut raw = [0u8; 8192];
    loop {
        match transport.read(&mut raw).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&raw[..n]),
            Err(_) => break,
        }
        while let Ok(Some(frame)) = codec.decode(&mut buf) {
            if frame.header.msg_type == FrameType::Shutdown {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mode B: SecureChannel transfer
// ---------------------------------------------------------------------------

async fn mode_b_sender(transport: DuplexStream) {
    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let config = SessionConfig::default();
    let mut ch = SecureChannel::accept_with_attestation(transport, &provider, &verifier, config)
        .await
        .unwrap();

    let input_ids = make_input_ids();
    let hidden = make_hidden_states();

    ch.send_tensor(input_ids.as_ref()).await.unwrap();
    ch.send_tensor(hidden.as_ref()).await.unwrap();
    ch.shutdown().await.unwrap();
}

async fn mode_b_receiver(transport: DuplexStream) {
    let provider = MockProvider::new();
    let verifier = MockVerifier::new();
    let config = SessionConfig::default();
    let mut ch = SecureChannel::connect_with_attestation(transport, &provider, &verifier, config)
        .await
        .unwrap();

    loop {
        match ch.recv().await.unwrap() {
            Message::Tensor(_) => {}
            Message::Shutdown => break,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Core capture runners (shared by main + tests)
// ---------------------------------------------------------------------------

/// Captures from Mode A. Returns the forward-direction bytes (sender → receiver).
///
/// Topology: sender writes to `sender_to_relay`, relay left→right = forward direction.
/// Mode A is unidirectional (sender→receiver only), so `bwd` should be empty.
async fn run_mode_a() -> Vec<u8> {
    let (sender_to_relay, relay_left) = tokio::io::duplex(256 * 1024);
    let (relay_right, receiver_from_relay) = tokio::io::duplex(256 * 1024);

    let relay = tokio::spawn(tapping_relay(relay_left, relay_right));
    let send = tokio::spawn(mode_a_sender(sender_to_relay));
    let recv = tokio::spawn(mode_a_receiver(receiver_from_relay));

    send.await.unwrap();
    recv.await.unwrap();
    let capture = relay.await.unwrap();
    capture.assert_clean("Mode A");
    assert!(
        capture.bwd.is_empty(),
        "Mode A is unidirectional: backward capture should be empty, got {} bytes",
        capture.bwd.len()
    );
    capture.fwd
}

/// Captures from Mode B. Returns the relay capture (both directions).
async fn run_mode_b() -> RelayCapture {
    let (sender_to_relay, relay_left) = tokio::io::duplex(256 * 1024);
    let (relay_right, receiver_from_relay) = tokio::io::duplex(256 * 1024);

    let relay = tokio::spawn(tapping_relay(relay_left, relay_right));
    let send = tokio::spawn(mode_b_sender(sender_to_relay));
    let recv = tokio::spawn(mode_b_receiver(receiver_from_relay));

    recv.await.unwrap();
    send.await.unwrap();
    let capture = relay.await.unwrap();
    capture.assert_clean("Mode B");
    capture
}

// ---------------------------------------------------------------------------
// Capture analysis
// ---------------------------------------------------------------------------

struct FrameInfo {
    msg_type: FrameType,
    flags: Flags,
    sequence: u32,
    payload_len: u32,
}

fn scan_frames(captured: &[u8]) -> Vec<FrameInfo> {
    let mut buf = BytesMut::from(captured);
    let mut codec = FrameCodec::new();
    let mut frames = Vec::new();

    while let Ok(Some(frame)) = codec.decode(&mut buf) {
        frames.push(FrameInfo {
            msg_type: frame.header.msg_type,
            flags: frame.header.flags,
            sequence: frame.header.sequence,
            payload_len: frame.header.payload_len,
        });
    }
    frames
}

fn scan_frames_with_payloads(captured: &[u8]) -> Vec<(FrameInfo, Bytes)> {
    let mut buf = BytesMut::from(captured);
    let mut codec = FrameCodec::new();
    let mut frames = Vec::new();

    while let Ok(Some(frame)) = codec.decode(&mut buf) {
        frames.push((
            FrameInfo {
                msg_type: frame.header.msg_type,
                flags: frame.header.flags,
                sequence: frame.header.sequence,
                payload_len: frame.header.payload_len,
            },
            frame.payload,
        ));
    }
    frames
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn collect_payload_bytes(captured: &[u8]) -> Vec<u8> {
    let frames = scan_frames_with_payloads(captured);
    let mut payload_bytes = Vec::new();
    for (_, payload) in &frames {
        payload_bytes.extend_from_slice(payload);
    }
    payload_bytes
}

fn frame_type_name(ft: FrameType) -> &'static str {
    match ft {
        FrameType::Hello => "Hello",
        FrameType::Data => "Data",
        FrameType::Error => "Error",
        FrameType::Heartbeat => "Heartbeat",
        FrameType::Shutdown => "Shutdown",
        FrameType::Tensor => "Tensor",
    }
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

fn print_header() {
    println!("========================================================");
    println!("  HOSTILE HOST RELAY CAPTURE DEMO");
    println!("  confidential-ml-transport v0.2.0");
    println!("========================================================");
    println!();
    println!("Topology: Sender --> [Hostile Relay] --> Receiver");
    println!();
    println!("Tensors transmitted:");
    println!("  input_ids       U32  [1, 5]        20 bytes");
    println!("  hidden_states   F32  [1, 5, 768]   15,360 bytes");
}

fn print_mode_a(captured: &[u8]) {
    println!();
    println!("--- MODE A: No encryption (baseline) ---");
    println!();
    println!("Relay captured {} bytes", captured.len());
    println!();

    let frames = scan_frames_with_payloads(captured);

    println!("Frames intercepted:");
    for (i, (info, _)) in frames.iter().enumerate() {
        let enc_str = if info.msg_type == FrameType::Tensor {
            if info.flags.is_encrypted() {
                "  ENCRYPTED"
            } else {
                "  UNENCRYPTED"
            }
        } else {
            ""
        };
        println!(
            "  #{:<2} {:<8} seq={}  payload={} bytes{}",
            i,
            frame_type_name(info.msg_type),
            info.sequence,
            info.payload_len,
            enc_str
        );
    }

    println!();
    println!("Tensor recovery from relay capture:");

    let lookup = token_lookup();
    for (info, payload) in &frames {
        if info.msg_type != FrameType::Tensor {
            continue;
        }
        match OwnedTensor::decode(payload.clone()) {
            Ok(tensor) => {
                let shape_str: Vec<String> = tensor.shape.iter().map(|s| s.to_string()).collect();
                println!(
                    "  {} {:?} [{}]:",
                    tensor.name,
                    tensor.dtype,
                    shape_str.join(", ")
                );

                if tensor.name == "input_ids" && tensor.dtype == DType::U32 {
                    let values: Vec<u32> = tensor
                        .data
                        .chunks_exact(4)
                        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                        .collect();
                    println!("    Values: {:?}", values);
                    let prompt: String = values
                        .iter()
                        .filter_map(|id| lookup.get(id).copied())
                        .collect();
                    println!("    Prompt: {:?}", prompt);
                    println!("    >> PROMPT EXPOSED <<");
                } else if tensor.name == "hidden_states" {
                    let values: Vec<f32> = tensor
                        .data
                        .chunks_exact(4)
                        .take(8)
                        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                        .collect();
                    let total_elements = tensor.data.len() / 4;
                    let formatted: Vec<String> =
                        values.iter().map(|v| format!("{:.4}", v)).collect();
                    println!("    First 8 values: [{}]", formatted.join(", "));
                    println!("    >> {} ACTIVATION VALUES EXPOSED <<", total_elements);
                }
                println!();
            }
            Err(e) => {
                println!("  Frame: {:?} -- cannot decode", e);
                println!();
            }
        }
    }

    let payload_bytes = collect_payload_bytes(captured);
    let entropy = shannon_entropy(&payload_bytes);
    println!("Payload entropy: {:.2} bits/byte", entropy);
}

fn print_mode_b(fwd: &[u8], bwd: &[u8]) {
    let total = fwd.len() + bwd.len();
    println!();
    println!("--- MODE B: SecureChannel + attestation ---");
    println!();
    println!("Relay captured {} bytes", total);
    println!();

    let fwd_frames = scan_frames_with_payloads(fwd);
    let bwd_frames = scan_frames_with_payloads(bwd);

    let mut handshake_frames = Vec::new();
    let mut data_frames = Vec::new();
    for (info, payload) in fwd_frames.iter().chain(bwd_frames.iter()) {
        if info.msg_type == FrameType::Hello {
            handshake_frames.push((info, payload));
        } else {
            data_frames.push((info, payload));
        }
    }

    handshake_frames.sort_by_key(|(info, _)| info.sequence);

    let all_frames: Vec<_> = handshake_frames.iter().chain(data_frames.iter()).collect();

    println!("Frames intercepted:");
    for (i, (info, _)) in all_frames.iter().enumerate() {
        let label = match info.msg_type {
            FrameType::Hello => "  (handshake)".to_string(),
            FrameType::Tensor => {
                if info.flags.is_encrypted() {
                    "  ENCRYPTED".to_string()
                } else {
                    "  UNENCRYPTED".to_string()
                }
            }
            FrameType::Shutdown => {
                if info.flags.is_encrypted() {
                    "  ENCRYPTED".to_string()
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        };
        println!(
            "  #{:<2} {:<8} seq={}  payload={} bytes{}",
            i,
            frame_type_name(info.msg_type),
            info.sequence,
            info.payload_len,
            label
        );
    }

    println!();
    println!("Tensor recovery attempt:");

    let mut any_encrypted = false;
    for (i, (info, payload)) in all_frames.iter().enumerate() {
        if info.flags.is_encrypted() {
            match OwnedTensor::decode((*payload).clone()) {
                Ok(tensor) => {
                    println!("  Frame #{}: decoded {} -- UNEXPECTED!", i, tensor.name);
                }
                Err(e) => {
                    println!("  Frame #{}: {:?} -- cannot decode", i, e);
                }
            }
            any_encrypted = true;
        }
    }

    if any_encrypted {
        println!("  >> ALL TENSORS PROTECTED <<");
    }

    println!();
    let mut all_payload_bytes = collect_payload_bytes(fwd);
    all_payload_bytes.extend_from_slice(&collect_payload_bytes(bwd));
    let entropy = shannon_entropy(&all_payload_bytes);
    println!("Payload entropy: {:.3} bits/byte", entropy);
}

/// Attempt to reconstruct the prompt from captured bytes by decoding tensor
/// frames and looking up token IDs. Returns `Some(prompt)` only if a tensor
/// named "input_ids" with dtype U32 is successfully decoded and every element
/// maps to a known token.
fn try_reconstruct_prompt(captured: &[u8]) -> Option<String> {
    let frames = scan_frames_with_payloads(captured);
    let lookup = token_lookup();
    for (info, payload) in &frames {
        if info.msg_type != FrameType::Tensor {
            continue;
        }
        if let Ok(tensor) = OwnedTensor::decode(payload.clone()) {
            if tensor.name == "input_ids" && tensor.dtype == DType::U32 {
                let values: Vec<u32> = tensor
                    .data
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
                let tokens: Vec<&str> = values
                    .iter()
                    .filter_map(|id| lookup.get(id).copied())
                    .collect();
                if tokens.len() == values.len() && !tokens.is_empty() {
                    return Some(tokens.concat());
                }
            }
        }
    }
    None
}

fn print_comparison(captured_a: &[u8], captured_b_fwd: &[u8], captured_b_bwd: &[u8]) {
    let payload_a = collect_payload_bytes(captured_a);
    let mut payload_b = collect_payload_bytes(captured_b_fwd);
    payload_b.extend_from_slice(&collect_payload_bytes(captured_b_bwd));
    let entropy_a = shannon_entropy(&payload_a);
    let entropy_b = shannon_entropy(&payload_b);

    let captured_b_len = captured_b_fwd.len() + captured_b_bwd.len();

    let frames_a = scan_frames(captured_a);
    let mut frames_b = scan_frames(captured_b_fwd);
    frames_b.extend(scan_frames(captured_b_bwd));

    let tensors_visible_a = frames_a
        .iter()
        .any(|f| f.msg_type == FrameType::Tensor && !f.flags.is_encrypted());
    let tensors_visible_b = frames_b
        .iter()
        .any(|f| f.msg_type == FrameType::Tensor && !f.flags.is_encrypted());

    // Actually attempt prompt reconstruction from each capture.
    let prompt_a = try_reconstruct_prompt(captured_a).is_some();
    let prompt_b = try_reconstruct_prompt(captured_b_fwd).is_some()
        || try_reconstruct_prompt(captured_b_bwd).is_some();

    let overhead = if !captured_a.is_empty() {
        let diff = captured_b_len as i64 - captured_a.len() as i64;
        let pct = (diff as f64 / captured_a.len() as f64) * 100.0;
        format!("+{} bytes ({:.1}%)", diff, pct)
    } else {
        "--".into()
    };

    let yn = |b: bool| if b { "YES" } else { "NO" };

    println!();
    println!("--- COMPARISON ---");
    println!();
    println!("                        {:<16}{}", "Mode A", "Mode B");
    println!(
        "Bytes captured:         {:<16}{}",
        captured_a.len(),
        captured_b_len
    );
    println!(
        "Tensor names visible:   {:<16}{}",
        yn(tensors_visible_a),
        yn(tensors_visible_b)
    );
    println!(
        "Tensor shapes visible:  {:<16}{}",
        yn(tensors_visible_a),
        yn(tensors_visible_b)
    );
    println!(
        "Tensor values visible:  {:<16}{}",
        yn(tensors_visible_a),
        yn(tensors_visible_b)
    );
    println!(
        "Prompt recoverable:     {:<16}{}",
        yn(prompt_a),
        yn(prompt_b)
    );
    println!(
        "Payload entropy:        {:<16}{:.3} b/byte",
        format!("{:.2} b/byte", entropy_a),
        entropy_b
    );
    println!("AEAD overhead:          {:<16}{}", "--", overhead);
}

// ---------------------------------------------------------------------------
// Dump export
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct DumpFrameInfo {
    index: usize,
    msg_type: String,
    sequence: u32,
    payload_len: u32,
    encrypted: bool,
}

#[derive(Serialize)]
struct DumpSummary {
    mode_a: DumpMode,
    mode_b: DumpMode,
    comparison: DumpComparison,
}

#[derive(Serialize)]
struct DumpMode {
    total_bytes: usize,
    frames: Vec<DumpFrameInfo>,
    payload_entropy_bits_per_byte: f64,
    tensors_recoverable: bool,
}

#[derive(Serialize)]
struct DumpComparison {
    mode_a_bytes: usize,
    mode_b_bytes: usize,
    aead_overhead_bytes: i64,
    aead_overhead_pct: f64,
    mode_a_entropy: f64,
    mode_b_entropy: f64,
}

fn build_dump_frame_list(captured: &[u8]) -> Vec<DumpFrameInfo> {
    scan_frames(captured)
        .into_iter()
        .enumerate()
        .map(|(i, f)| DumpFrameInfo {
            index: i,
            msg_type: frame_type_name(f.msg_type).to_string(),
            sequence: f.sequence,
            payload_len: f.payload_len,
            encrypted: f.flags.is_encrypted(),
        })
        .collect()
}

fn write_dump(dir: &std::path::Path, captured_a: &[u8], fwd_b: &[u8], bwd_b: &[u8]) {
    std::fs::create_dir_all(dir).expect("failed to create dump directory");

    std::fs::write(dir.join("mode_a_capture.bin"), captured_a).unwrap();
    std::fs::write(dir.join("mode_b_fwd_capture.bin"), fwd_b).unwrap();
    std::fs::write(dir.join("mode_b_bwd_capture.bin"), bwd_b).unwrap();

    let entropy_a = shannon_entropy(&collect_payload_bytes(captured_a));
    let mut payload_b = collect_payload_bytes(fwd_b);
    payload_b.extend_from_slice(&collect_payload_bytes(bwd_b));
    let entropy_b = shannon_entropy(&payload_b);

    let frames_a = scan_frames(captured_a);
    let mut frames_b_all = scan_frames(fwd_b);
    frames_b_all.extend(scan_frames(bwd_b));

    let tensors_visible_a = frames_a
        .iter()
        .any(|f| f.msg_type == FrameType::Tensor && !f.flags.is_encrypted());
    let tensors_visible_b = frames_b_all
        .iter()
        .any(|f| f.msg_type == FrameType::Tensor && !f.flags.is_encrypted());

    let b_total = fwd_b.len() + bwd_b.len();
    let overhead = b_total as i64 - captured_a.len() as i64;
    let overhead_pct = if !captured_a.is_empty() {
        (overhead as f64 / captured_a.len() as f64) * 100.0
    } else {
        0.0
    };

    let mut b_frame_list = build_dump_frame_list(fwd_b);
    let bwd_list = build_dump_frame_list(bwd_b);
    let offset = b_frame_list.len();
    for mut f in bwd_list {
        f.index += offset;
        b_frame_list.push(f);
    }

    let summary = DumpSummary {
        mode_a: DumpMode {
            total_bytes: captured_a.len(),
            frames: build_dump_frame_list(captured_a),
            payload_entropy_bits_per_byte: entropy_a,
            tensors_recoverable: tensors_visible_a,
        },
        mode_b: DumpMode {
            total_bytes: b_total,
            frames: b_frame_list,
            payload_entropy_bits_per_byte: entropy_b,
            tensors_recoverable: tensors_visible_b,
        },
        comparison: DumpComparison {
            mode_a_bytes: captured_a.len(),
            mode_b_bytes: b_total,
            aead_overhead_bytes: overhead,
            aead_overhead_pct: overhead_pct,
            mode_a_entropy: entropy_a,
            mode_b_entropy: entropy_b,
        },
    };

    let json = serde_json::to_string_pretty(&summary).unwrap();
    std::fs::write(dir.join("summary.json"), &json).unwrap();

    println!();
    println!("Artifacts written to {}/", dir.display());
    println!("  mode_a_capture.bin      ({} bytes)", captured_a.len());
    println!("  mode_b_fwd_capture.bin  ({} bytes)", fwd_b.len());
    println!("  mode_b_bwd_capture.bin  ({} bytes)", bwd_b.len());
    println!("  summary.json");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_header();

    let captured_a = run_mode_a().await;
    print_mode_a(&captured_a);

    let cap_b = run_mode_b().await;
    print_mode_b(&cap_b.fwd, &cap_b.bwd);
    print_comparison(&captured_a, &cap_b.fwd, &cap_b.bwd);

    if let Some(dir) = cli.dump {
        write_dump(&dir, &captured_a, &cap_b.fwd, &cap_b.bwd);
    }

    println!();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Mode A: deterministic, exact structural snapshot ----

    #[tokio::test]
    async fn mode_a_exact_byte_count() {
        let captured = run_mode_a().await;
        // Mode A is fully deterministic (no crypto randomness).
        // 3 frames: tensor(44) + tensor(15392) + shutdown(0) + 3*13-byte headers = 15475
        assert_eq!(captured.len(), 15475);
    }

    #[tokio::test]
    async fn mode_a_frame_structure() {
        let captured = run_mode_a().await;
        let frames = scan_frames(&captured);

        assert_eq!(frames.len(), 3, "expected exactly 3 frames");

        // Frame 0: Tensor, unencrypted, seq 0
        assert_eq!(frames[0].msg_type, FrameType::Tensor);
        assert!(!frames[0].flags.is_encrypted());
        assert_eq!(frames[0].sequence, 0);
        assert_eq!(frames[0].payload_len, 44); // input_ids tensor

        // Frame 1: Tensor, unencrypted, seq 1
        assert_eq!(frames[1].msg_type, FrameType::Tensor);
        assert!(!frames[1].flags.is_encrypted());
        assert_eq!(frames[1].sequence, 1);
        assert_eq!(frames[1].payload_len, 15392); // hidden_states tensor

        // Frame 2: Shutdown, seq 2
        assert_eq!(frames[2].msg_type, FrameType::Shutdown);
        assert_eq!(frames[2].sequence, 2);
        assert_eq!(frames[2].payload_len, 0);
    }

    #[tokio::test]
    async fn mode_a_prompt_fully_recoverable() {
        let captured = run_mode_a().await;
        let frames = scan_frames_with_payloads(&captured);

        let (_, payload) = &frames[0];
        let tensor = OwnedTensor::decode(payload.clone()).expect("should decode input_ids");

        assert_eq!(tensor.name, "input_ids");
        assert_eq!(tensor.dtype, DType::U32);
        assert_eq!(tensor.shape, vec![1, 5]);

        let values: Vec<u32> = tensor
            .data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert_eq!(values, vec![464, 3139, 286, 4881, 318]);

        let lookup = token_lookup();
        let prompt: String = values
            .iter()
            .filter_map(|id| lookup.get(id).copied())
            .collect();
        assert_eq!(prompt, "The capital of France is");
    }

    #[tokio::test]
    async fn mode_a_activations_recoverable() {
        let captured = run_mode_a().await;
        let frames = scan_frames_with_payloads(&captured);

        let (_, payload) = &frames[1];
        let tensor = OwnedTensor::decode(payload.clone()).expect("should decode hidden_states");

        assert_eq!(tensor.name, "hidden_states");
        assert_eq!(tensor.dtype, DType::F32);
        assert_eq!(tensor.shape, vec![1, 5, 768]);
        assert_eq!(tensor.data.len(), 5 * 768 * 4);

        // Check first 4 values: base = 464 * 0.001 = 0.464, dim 0..3
        let first_four: Vec<f32> = tensor
            .data
            .chunks_exact(4)
            .take(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert!((first_four[0] - 0.4640).abs() < 1e-4);
        assert!((first_four[1] - 0.4641).abs() < 1e-4);
        assert!((first_four[2] - 0.4642).abs() < 1e-4);
        assert!((first_four[3] - 0.4643).abs() < 1e-4);
    }

    // ---- Mode B: structural invariants (byte counts vary due to random keys) ----

    #[tokio::test]
    async fn mode_b_no_unencrypted_tensors() {
        let cap = run_mode_b().await;
        let mut frames = scan_frames(&cap.fwd);
        frames.extend(scan_frames(&cap.bwd));

        for f in &frames {
            if f.msg_type == FrameType::Tensor {
                assert!(
                    f.flags.is_encrypted(),
                    "Tensor frame seq={} must be encrypted",
                    f.sequence
                );
            }
        }
    }

    #[tokio::test]
    async fn mode_b_tensor_decode_always_fails() {
        let cap = run_mode_b().await;
        let mut frames = scan_frames_with_payloads(&cap.fwd);
        frames.extend(scan_frames_with_payloads(&cap.bwd));

        for (info, payload) in &frames {
            if info.flags.is_encrypted() {
                assert!(
                    OwnedTensor::decode(payload.clone()).is_err(),
                    "encrypted frame seq={} must not decode as tensor",
                    info.sequence
                );
            }
        }
    }

    #[tokio::test]
    async fn mode_b_has_handshake_frames() {
        let cap = run_mode_b().await;
        let mut frames = scan_frames(&cap.fwd);
        frames.extend(scan_frames(&cap.bwd));

        let hello_count = frames
            .iter()
            .filter(|f| f.msg_type == FrameType::Hello)
            .count();
        // 3-message handshake: Hello(seq=0) from each side + Hello(seq=1)
        assert_eq!(hello_count, 3, "expected 3 handshake frames");
    }

    #[tokio::test]
    async fn mode_b_shutdown_encrypted() {
        let cap = run_mode_b().await;
        let mut frames = scan_frames(&cap.fwd);
        frames.extend(scan_frames(&cap.bwd));

        let shutdown = frames
            .iter()
            .find(|f| f.msg_type == FrameType::Shutdown)
            .expect("expected a shutdown frame");
        assert!(shutdown.flags.is_encrypted(), "shutdown must be encrypted");
    }

    #[tokio::test]
    async fn mode_b_entropy_near_maximum() {
        let cap = run_mode_b().await;
        let mut payload_bytes = collect_payload_bytes(&cap.fwd);
        payload_bytes.extend_from_slice(&collect_payload_bytes(&cap.bwd));

        let entropy = shannon_entropy(&payload_bytes);
        assert!(
            entropy > 7.9,
            "ciphertext entropy should be >7.9, got {:.3}",
            entropy
        );
    }

    #[tokio::test]
    async fn aead_overhead_bounded() {
        let captured_a = run_mode_a().await;
        let cap_b = run_mode_b().await;
        let b_total = cap_b.fwd.len() + cap_b.bwd.len();

        let overhead_pct =
            (b_total as f64 - captured_a.len() as f64) / captured_a.len() as f64 * 100.0;
        assert!(
            overhead_pct < 5.0,
            "AEAD overhead should be <5%, got {:.1}%",
            overhead_pct
        );
        assert!(
            overhead_pct > 0.0,
            "AEAD overhead should be positive (encryption adds bytes)"
        );
    }

    #[tokio::test]
    async fn mode_a_entropy_lower_than_mode_b() {
        let captured_a = run_mode_a().await;
        let cap_b = run_mode_b().await;

        let entropy_a = shannon_entropy(&collect_payload_bytes(&captured_a));
        let mut payload_b = collect_payload_bytes(&cap_b.fwd);
        payload_b.extend_from_slice(&collect_payload_bytes(&cap_b.bwd));
        let entropy_b = shannon_entropy(&payload_b);

        assert!(
            entropy_b > entropy_a,
            "encrypted entropy ({:.3}) should exceed plaintext ({:.3})",
            entropy_b,
            entropy_a
        );
    }
}
