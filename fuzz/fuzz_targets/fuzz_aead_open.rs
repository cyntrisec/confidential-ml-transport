#![no_main]

use libfuzzer_sys::fuzz_target;

use confidential_ml_transport::crypto::seal::OpeningContext;
use confidential_ml_transport::crypto::SymmetricKey;

/// Structured input for the AEAD opening fuzzer.
/// The fuzzer generates arbitrary ciphertext, sequence, msg_type, and flags,
/// attempting to find inputs that cause panics (as opposed to clean error returns).
struct AeadInput<'a> {
    ciphertext: &'a [u8],
    sequence: u64,
    msg_type: u8,
    flags: u8,
}

fn parse_input(data: &[u8]) -> Option<AeadInput<'_>> {
    // Need at least 10 bytes: 8 (sequence) + 1 (msg_type) + 1 (flags) + ciphertext
    if data.len() < 10 {
        return None;
    }
    let sequence = u64::from_be_bytes(data[0..8].try_into().ok()?);
    let msg_type = data[8];
    let flags = data[9];
    let ciphertext = &data[10..];
    Some(AeadInput {
        ciphertext,
        sequence,
        msg_type,
        flags,
    })
}

fuzz_target!(|data: &[u8]| {
    let Some(input) = parse_input(data) else {
        return;
    };

    // Fixed key and session_id — we're testing that OpeningContext never panics
    // on any combination of ciphertext, sequence, msg_type, and flags.
    let key = SymmetricKey::from([0x42; 32]);
    let session_id = [0xAA; 32];
    let mut opener = OpeningContext::new(&key, session_id);

    // First open: any sequence is valid (no prior sequence)
    let _ = opener.open(input.ciphertext, input.sequence, input.msg_type, input.flags);

    // Second open with sequence+1: tests monotonic enforcement path
    if let Some(next_seq) = input.sequence.checked_add(1) {
        let _ = opener.open(input.ciphertext, next_seq, input.msg_type, input.flags);
    }

    // Third open with same sequence: tests replay rejection path
    let _ = opener.open(input.ciphertext, input.sequence, input.msg_type, input.flags);
});
