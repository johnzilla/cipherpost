//! D-STATE-02: state dir mode 0700, accepted/ mode 0700, accepted.jsonl mode
//! 0600, accepted/<share_ref> sentinel mode 0600.

use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[test]
#[serial]
fn state_permissions_are_0700_and_0600_after_receive() {
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
        "perm test",
        MaterialSource::Bytes(b"x".to_vec()),
        DEFAULT_TTL_SECONDS,
    )
    .unwrap();
    let uri = ShareUri::parse(&uri_str).unwrap();

    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(&id, &transport, &uri, &mut sink, &AutoConfirmPrompter).unwrap();

    let state = dir.path().join("state");
    let accepted = state.join("accepted");
    let ledger = state.join("accepted.jsonl");
    let sentinel = accepted.join(&uri.share_ref_hex);

    let mode_of = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode_of(&state), 0o700, "state/ must be 0700");
    assert_eq!(mode_of(&accepted), 0o700, "state/accepted/ must be 0700");
    assert_eq!(mode_of(&ledger), 0o600, "state/accepted.jsonl must be 0600");
    assert_eq!(mode_of(&sentinel), 0o600, "sentinel must be 0600");
}
