//! ROADMAP SC3 decline path: when the Prompter returns `Err(Error::Declined)`,
//! `run_receive` surfaces `Error::Declined` which the CLI maps to exit code 7.
//! No decrypted material is ever written to the sink (Pitfall #6).
//!
//! Approach: drive the library directly with the `DeclinePrompter` (from
//! `flow::test_helpers`, gated on `--features mock`). This is the authoritative
//! assertion of the decline branch: Error::Declined → exit_code == 7 → sink empty.
//!
//! Driving the decline path through the binary via assert_cmd is NOT possible
//! because cross-process MockTransport state is not shared (each process has its
//! own in-memory HashMap). The library-level test covers the full run_receive
//! decline semantics including the "no material written" invariant.

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::test_helpers::DeclinePrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn receive_declined_returns_error_declined_exit_7() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());

    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "decline test",
        MaterialSource::Bytes(b"secret".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("run_send self-mode");
    let uri = ShareUri::parse(&uri_str).unwrap();

    let mut sink = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &DeclinePrompter,
        false,
    )
    .expect_err("DeclinePrompter must cause run_receive to Err");

    // The error must be Error::Declined (not some other sig/decrypt failure).
    assert!(
        matches!(err, cipherpost::Error::Declined),
        "expected Error::Declined, got {err:?}"
    );
    // Exit-code taxonomy: Declined → 7 (CLI-02 / ROADMAP SC3).
    assert_eq!(cipherpost::error::exit_code(&err), 7);

    // Pitfall #6: declined BEFORE material is written to the sink.
    match sink {
        OutputSink::InMemory(buf) => assert!(
            buf.is_empty(),
            "no material should have been written on decline, got {} bytes",
            buf.len()
        ),
        _ => panic!("expected InMemory sink"),
    }
}
