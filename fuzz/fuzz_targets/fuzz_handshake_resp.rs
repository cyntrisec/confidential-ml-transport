#![no_main]

use libfuzzer_sys::fuzz_target;

use confidential_ml_transport::attestation::mock::MockProvider;
use confidential_ml_transport::session::handshake;

fuzz_target!(|data: &[u8]| {
    // Fuzz the responder side of the handshake: feed arbitrary bytes as the
    // "initiator" transport and verify the responder never panics.
    //
    // The responder will:
    //   1. Try to read a frame from the fuzzed bytes (frame codec parsing)
    //   2. Validate it's a Hello frame with sequence 0
    //   3. Parse initiator hello (65 bytes: msg_num + pk + nonce)
    //   4. Generate attestation document
    //   5. Send responder hello
    //   6. Try to read confirmation frame
    //   7. Validate and parse confirmation
    //
    // Most fuzz inputs will fail at step 1-3, which exercises the frame parser,
    // handshake validation, and message parsing under adversarial conditions.

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    // Copy fuzz data so it can be moved into the spawned task.
    let owned_data = data.to_vec();

    rt.block_on(async {
        let provider = MockProvider::new();

        // Create a duplex where one side is pre-loaded with fuzz data.
        // The responder reads from reader and writes to writer.
        let (mut server, mut client) = tokio::io::duplex(64 * 1024);

        // Write the fuzz data into the client side, then drop it
        // so the server sees EOF after consuming all bytes.
        let write_handle = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = client.write_all(&owned_data).await;
            let _ = client.shutdown().await;
        });

        // Run the responder — it should return Err, never panic.
        let _ = handshake::respond(&mut server, &provider).await;

        let _ = write_handle.await;
    });
});
