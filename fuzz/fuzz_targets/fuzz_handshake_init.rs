#![no_main]

use libfuzzer_sys::fuzz_target;

use confidential_ml_transport::attestation::mock::{MockProvider, MockVerifier};
use confidential_ml_transport::session::handshake;

fuzz_target!(|data: &[u8]| {
    // Fuzz the initiator side of the handshake: feed arbitrary bytes as the
    // "responder" transport and verify the initiator never panics.
    //
    // The initiator will:
    //   1. Generate keypair + nonce
    //   2. Send initiator hello frame (writes to transport)
    //   3. Try to read responder hello from fuzzed bytes
    //   4. Parse responder hello (pk + nonce + attestation doc)
    //   5. Verify attestation document
    //   6. Derive keys
    //   7. Send confirmation
    //
    // Most fuzz inputs will fail at step 3-5, exercising the responder hello
    // parser and attestation verifier under adversarial conditions.

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    let owned_data = data.to_vec();

    rt.block_on(async {
        let provider = MockProvider::new();
        let verifier = MockVerifier::new();

        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        // Write the fuzz data into the server side, then drop it
        // so the client sees EOF after consuming all bytes.
        let write_handle = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            // Read and discard the initiator hello that the client sends.
            let mut discard = vec![0u8; 4096];
            use tokio::io::AsyncReadExt;
            let _ = server.read(&mut discard).await;
            // Then send fuzz data as the "responder hello".
            let _ = server.write_all(&owned_data).await;
            let _ = server.shutdown().await;
        });

        // Run the initiator — it should return Err, never panic.
        let _ = handshake::initiate(&mut client, &provider, &verifier, None).await;

        let _ = write_handle.await;
    });
});
