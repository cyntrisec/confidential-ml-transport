//! Tests for retry policy, measurement verification, and connect_with_retry.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use confidential_ml_transport::attestation::types::ExpectedMeasurements;
use confidential_ml_transport::session::channel::{Message, SecureChannel};
use confidential_ml_transport::session::retry::RetryPolicy;
use confidential_ml_transport::{
    MockProvider, MockVerifier, MockVerifierWithMeasurements, SessionConfig,
};

// ---------------------------------------------------------------------------
// RetryPolicy unit tests
// ---------------------------------------------------------------------------

#[test]
fn retry_policy_default_values() {
    let p = RetryPolicy::default();
    assert_eq!(p.max_retries, 3);
    assert_eq!(p.initial_delay, Duration::from_secs(1));
    assert_eq!(p.max_delay, Duration::from_secs(30));
    assert!((p.backoff_multiplier - 2.0).abs() < f64::EPSILON);
}

#[test]
fn retry_policy_none_has_zero_retries() {
    let p = RetryPolicy::none();
    assert_eq!(p.max_retries, 0);
}

#[test]
fn delay_for_attempt_increases() {
    let p = RetryPolicy {
        max_retries: 5,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        backoff_multiplier: 2.0,
    };

    // With jitter in [0.5, 1.0], attempt 0 delay should be in [50ms, 100ms].
    let d0 = p.delay_for_attempt(0);
    assert!(d0 >= Duration::from_millis(50));
    assert!(d0 <= Duration::from_millis(100));

    // attempt 2 base = 100ms * 4 = 400ms, jittered [200ms, 400ms].
    let d2 = p.delay_for_attempt(2);
    assert!(d2 >= Duration::from_millis(200));
    assert!(d2 <= Duration::from_millis(400));
}

#[test]
fn delay_capped_at_max() {
    let p = RetryPolicy {
        max_retries: 10,
        initial_delay: Duration::from_secs(1),
        max_delay: Duration::from_millis(500),
        backoff_multiplier: 10.0,
    };

    // attempt 5: base = 1s * 10^5 = 100000s, should be capped to 500ms,
    // then jittered to [250ms, 500ms].
    let d = p.delay_for_attempt(5);
    assert!(d <= Duration::from_millis(500));
    assert!(d >= Duration::from_millis(250));
}

// ---------------------------------------------------------------------------
// with_retry tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retry_succeeds_after_failures() {
    use confidential_ml_transport::session::retry::with_retry;

    let counter = Arc::new(AtomicU32::new(0));
    let policy = RetryPolicy {
        max_retries: 3,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(10),
        backoff_multiplier: 1.0,
    };

    let counter_clone = Arc::clone(&counter);
    let result: Result<&str, String> = with_retry(&policy, || {
        let c = Arc::clone(&counter_clone);
        async move {
            let attempt = c.fetch_add(1, Ordering::SeqCst);
            if attempt < 2 {
                Err(format!("attempt {attempt} failed"))
            } else {
                Ok("success")
            }
        }
    })
    .await;

    assert_eq!(result.unwrap(), "success");
    assert_eq!(counter.load(Ordering::SeqCst), 3); // 2 failures + 1 success
}

#[tokio::test]
async fn retry_exhausted_returns_last_error() {
    use confidential_ml_transport::session::retry::with_retry;

    let counter = Arc::new(AtomicU32::new(0));
    let policy = RetryPolicy {
        max_retries: 2,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(10),
        backoff_multiplier: 1.0,
    };

    let counter_clone = Arc::clone(&counter);
    let result: Result<(), String> = with_retry(&policy, || {
        let c = Arc::clone(&counter_clone);
        async move {
            let attempt = c.fetch_add(1, Ordering::SeqCst);
            Err(format!("attempt {attempt} failed"))
        }
    })
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("attempt 2")); // last error
    assert_eq!(counter.load(Ordering::SeqCst), 3); // initial + 2 retries
}

// ---------------------------------------------------------------------------
// connect_with_retry integration test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_with_retry_succeeds() {
    let attempt = Arc::new(AtomicU32::new(0));

    let provider = MockProvider::new();
    let verifier = MockVerifier::new();

    // Start a server that accepts on the first attempt.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut channel =
            SecureChannel::accept_with_attestation(stream, &provider, SessionConfig::default())
                .await
                .unwrap();
        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Shutdown));
    });

    let config = SessionConfig::builder()
        .retry_policy(RetryPolicy {
            max_retries: 2,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 1.0,
        })
        .build()
        .unwrap();

    let attempt_clone = Arc::clone(&attempt);
    let mut channel = SecureChannel::connect_with_retry(
        || {
            let a = Arc::clone(&attempt_clone);
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                tokio::net::TcpStream::connect(addr).await
            }
        },
        &verifier,
        config,
    )
    .await
    .unwrap();

    channel.shutdown().await.unwrap();
    server_handle.await.unwrap();

    assert_eq!(attempt.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// Measurement verification tests
// ---------------------------------------------------------------------------

#[test]
fn measurement_verification_passes_on_match() {
    let mut expected = BTreeMap::new();
    expected.insert(0, vec![0xAA; 32]);
    expected.insert(1, vec![0xBB; 32]);

    let measurements = ExpectedMeasurements::new(expected);
    let actual = vec![vec![0xAA; 32], vec![0xBB; 32], vec![0xCC; 32]];

    assert!(measurements.verify(&actual).is_ok());
}

#[test]
fn measurement_verification_fails_on_mismatch() {
    let mut expected = BTreeMap::new();
    expected.insert(0, vec![0xAA; 32]);

    let measurements = ExpectedMeasurements::new(expected);
    let actual = vec![vec![0xFF; 32]]; // different

    let result = measurements.verify(&actual);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("mismatch"), "error should contain 'mismatch': {err}");
}

#[test]
fn measurement_verification_fails_on_missing_index() {
    let mut expected = BTreeMap::new();
    expected.insert(5, vec![0xAA; 32]); // index 5 doesn't exist

    let measurements = ExpectedMeasurements::new(expected);
    let actual = vec![vec![0xAA; 32]]; // only index 0

    let result = measurements.verify(&actual);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("measurement[5]"),
        "error should mention index: {err}"
    );
}

#[test]
fn no_verification_when_empty() {
    let measurements = ExpectedMeasurements::new(BTreeMap::new());
    let actual = vec![vec![0xAA; 32]];
    assert!(measurements.verify(&actual).is_ok());
}

// ---------------------------------------------------------------------------
// End-to-end measurement verification via MockVerifierWithMeasurements
// ---------------------------------------------------------------------------

#[tokio::test]
async fn measurement_verification_in_handshake() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();

    // Server returns measurements [0xAA*32, 0xBB*32].
    let verifier = MockVerifierWithMeasurements::new(vec![vec![0xAA; 32], vec![0xBB; 32]]);

    // Client expects measurement[0] == 0xAA*32.
    let mut expected = BTreeMap::new();
    expected.insert(0, vec![0xAA; 32]);

    let config = SessionConfig::builder()
        .expected_measurements(ExpectedMeasurements::new(expected))
        .build()
        .unwrap();

    let server_handle = tokio::spawn(async move {
        let mut channel = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await
        .unwrap();
        let msg = channel.recv().await.unwrap();
        assert!(matches!(msg, Message::Data(_)));
    });

    let client_handle = tokio::spawn(async move {
        let mut channel =
            SecureChannel::connect_with_attestation(client_transport, &verifier, config)
                .await
                .unwrap();
        channel
            .send(Bytes::from_static(b"measurement-test"))
            .await
            .unwrap();
    });

    server_handle.await.unwrap();
    client_handle.await.unwrap();
}

#[tokio::test]
async fn measurement_mismatch_rejects_handshake() {
    let (client_transport, server_transport) = tokio::io::duplex(16384);

    let provider = MockProvider::new();

    // Server returns measurements [0xAA*32].
    let verifier = MockVerifierWithMeasurements::new(vec![vec![0xAA; 32]]);

    // Client expects measurement[0] == 0xFF*32 (mismatch).
    let mut expected = BTreeMap::new();
    expected.insert(0, vec![0xFF; 32]);

    let config = SessionConfig::builder()
        .expected_measurements(ExpectedMeasurements::new(expected))
        .build()
        .unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = SecureChannel::accept_with_attestation(
            server_transport,
            &provider,
            SessionConfig::default(),
        )
        .await;
    });

    let client_handle = tokio::spawn(async move {
        let result =
            SecureChannel::connect_with_attestation(client_transport, &verifier, config).await;
        assert!(result.is_err());
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("mismatch"),
            "error should contain 'mismatch': {err}"
        );
    });

    let _ = server_handle.await;
    client_handle.await.unwrap();
}
