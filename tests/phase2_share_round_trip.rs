//! SC1 share-mode: A→B decrypts on B; third identity C cannot.
//!
//! Identities use deterministic seeds (NOT `identity::generate`, whose internal
//! RNG varies the z32 length of the encoded key and causes flaky results near
//! the 1000-byte wire-budget boundary). The flow is still exercised end-to-end;
//! the substitution is purely about repeatable DNS-packet sizing.

use cipherpost::cli::MaterialVariant;
use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::identity::Identity;
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tempfile::TempDir;
use zeroize::Zeroizing;

/// Write a real CIPHPOSK identity file at `home/secret_key` from a specific
/// 32-byte seed, then load it. Gives us deterministic z32 values so the wire
/// budget is predictable.
fn deterministic_identity_at(home: &std::path::Path, seed: [u8; 32]) -> (Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", home);
    fs::create_dir_all(home).unwrap();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    let pw = SecretBox::new(Box::new("pw".to_string()));
    let seed_z = Zeroizing::new(seed);
    let blob = crypto::encrypt_key_envelope(&seed_z, &pw).unwrap();
    let path = home.join("secret_key");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(&blob).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let id = cipherpost::identity::load(&pw).unwrap();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

#[test]
#[serial]
fn share_round_trip_recipient_decrypts_third_party_fails() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let dir_c = TempDir::new().unwrap();
    let (id_c, kp_c) = deterministic_identity_at(dir_c.path(), [0xCC; 32]);

    let transport = MockTransport::new();
    // Minimal plaintext + purpose keeps the share-mode encoded packet under
    // the 1000-byte budget.
    let plaintext = b"tok".to_vec();

    // A sends → B
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: id_b.z32_pubkey(),
        },
        "t",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("run_send share-mode");
    let uri = ShareUri::parse(&uri_str).unwrap();

    // B decrypts
    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink_b = OutputSink::InMemory(Vec::new());
    run_receive(
        &id_b,
        &transport,
        &kp_b,
        &uri,
        &mut sink_b,
        &AutoConfirmPrompter,
        false,
    )
    .expect("B decrypts");
    match sink_b {
        OutputSink::InMemory(buf) => assert_eq!(buf, plaintext),
        _ => panic!("InMemory expected"),
    }

    // C cannot decrypt
    std::env::set_var("CIPHERPOST_HOME", dir_c.path());
    let mut sink_c = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id_c,
        &transport,
        &kp_c,
        &uri,
        &mut sink_c,
        &AutoConfirmPrompter,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, cipherpost::Error::DecryptFailed),
        "third party must fail with DecryptFailed, got {:?}",
        err
    );
}
