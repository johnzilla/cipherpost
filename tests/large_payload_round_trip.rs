//! v2 large-payload send→receive round-trip under MockTransport + MockBlobStore.
//! No live homeserver, no DHT — pure in-memory, CI-safe.

use cipherpost::blobstore::MockBlobStore;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{run_receive_large, run_send_large, SendMode};
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use std::fs;
use tempfile::TempDir;

/// Generate an in-memory identity under a temp CIPHERPOST_HOME, returning it plus
/// the derived signing keypair (mirrors tests/phase2_self_round_trip.rs).
fn make_identity() -> (cipherpost::identity::Identity, pkarr::Keypair) {
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

#[test]
#[serial]
fn send_large_receive_large_self_round_trip() {
    let home = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", home.path());
    let work = TempDir::new().unwrap();

    // a small "workspace" directory to hand off
    let src = work.path().join("workspace");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"hello large payload").unwrap();
    fs::write(src.join("sub/b.bin"), vec![0xABu8; 5000]).unwrap();

    let (identity, keypair) = make_identity();
    let transport = MockTransport::new();
    let blobstore = MockBlobStore::new();

    let uri = run_send_large(
        &identity,
        &transport,
        &blobstore,
        &keypair,
        SendMode::SelfMode,
        "vllm workspace backup",
        &src,
        86400,
    )
    .expect("send-large should succeed");

    assert_eq!(blobstore.len(), 1, "exactly one blob stored");

    let dest = work.path().join("restored");
    let parsed = ShareUri::parse(&uri).unwrap();
    run_receive_large(
        &identity,
        &transport,
        &blobstore,
        &parsed,
        &dest,
        &AutoConfirmPrompter,
    )
    .expect("receive-large should succeed");

    // archive unpacks under <dest>/workspace/...
    assert_eq!(
        fs::read(dest.join("workspace/a.txt")).unwrap(),
        b"hello large payload"
    );
    assert_eq!(
        fs::read(dest.join("workspace/sub/b.bin")).unwrap(),
        vec![0xABu8; 5000]
    );
}

#[test]
#[serial]
fn tampered_blob_fails_hash_check() {
    let home = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", home.path());
    let work = TempDir::new().unwrap();

    let src = work.path().join("file.txt");
    fs::write(&src, b"sensitive ciphertext material").unwrap();

    let (identity, keypair) = make_identity();
    let transport = MockTransport::new();
    let blobstore = MockBlobStore::new();

    let uri = run_send_large(
        &identity,
        &transport,
        &blobstore,
        &keypair,
        SendMode::SelfMode,
        "p",
        &src,
        86400,
    )
    .unwrap();

    // Homeserver serves bytes that no longer match the signed manifest hash.
    blobstore.corrupt_all_for_test(b"garbage-not-matching-hash");

    let dest = work.path().join("out");
    let parsed = ShareUri::parse(&uri).unwrap();
    let err = run_receive_large(
        &identity,
        &transport,
        &blobstore,
        &parsed,
        &dest,
        &AutoConfirmPrompter,
    )
    .unwrap_err();
    // hash mismatch funnels to the unified signature-failure Display (exit 3)
    assert_eq!(format!("{err}"), "signature verification failed");
}
