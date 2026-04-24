//! SC1 self-mode: cipherpost send --self + cipherpost receive (same identity)
//! round-trips the plaintext byte-for-byte via MockTransport.

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
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
fn self_round_trip_recovers_plaintext() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();

    // `flow::run_send` accepts a &pkarr::Keypair alongside the Identity
    // because publishing needs the keypair for signing. Construct one from the
    // signing seed.
    let seed_zeroizing = id.signing_seed();
    let seed: [u8; 32] = *seed_zeroizing;
    let kp = pkarr::Keypair::from_secret_key(&seed);

    // Wire-budget math: JCS envelope + age overhead (~231 bytes) + base64 1.33x
    // expansion + OuterRecord JSON wrapping + DNS SignedPacket encoding must
    // all fit in pkarr's 1000-byte BEP44 budget. A short plaintext + short
    // purpose leaves headroom; larger payloads belong in the wire-budget test.
    let plaintext = b"topsecret1".to_vec();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
    )
    .expect("run_send self-mode");

    let uri = ShareUri::parse(&uri_str).expect("run_send must return a valid URI");

    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect("run_receive self-mode");

    match sink {
        OutputSink::InMemory(buf) => {
            assert_eq!(buf, plaintext, "recovered plaintext must match sent")
        }
        _ => panic!("expected InMemory sink"),
    }
}
