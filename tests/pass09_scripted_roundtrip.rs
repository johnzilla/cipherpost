#![cfg(feature = "mock")]

//! PASS-09: end-to-end scripted send→receive round trip with no TTY.
//!
//! SC1 canonical invocations proved here:
//!   cipherpost send - --passphrase-fd 3 < payload.bin 3< passphrase.txt
//!   cipherpost receive <uri> --passphrase-file ~/.cipherpost/pp.txt
//!
//! Runs under MockTransport — no real DHT in CI. See D-P5-09.

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

/// Cloned verbatim from tests/phase3_end_to_end_a_sends_b_receipt.rs:27-47.
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

fn run_roundtrip(id_a: &Identity, kp_a: &pkarr::Keypair, id_b: &Identity, kp_b: &pkarr::Keypair) {
    let b_z32 = kp_b.public_key().to_z32();
    let transport = MockTransport::new();

    let uri_str = run_send(
        id_a,
        &transport,
        kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "pass09",
        MaterialSource::Bytes(b"secret".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("A run_send");
    let uri = ShareUri::parse(&uri_str).unwrap();

    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        id_b,
        &transport,
        kp_b,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect("B run_receive");
    match sink {
        OutputSink::InMemory(buf) => {
            assert_eq!(buf, b"secret", "round-trip bytes must match")
        }
        _ => panic!("InMemory sink expected"),
    }
}

#[test]
#[serial]
fn scripted_roundtrip_via_passphrase_file() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);

    // Write a passphrase file at mode 0600.
    let pw_dir = TempDir::new().unwrap();
    let pw_path = pw_dir.path().join("pp.txt");
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&pw_path)
            .unwrap();
        f.write_all(b"pw\n").unwrap();
    }

    // Env must be clear, otherwise it would mask the file branch.
    std::env::remove_var("CIPHERPOST_PASSPHRASE");

    // Prove --passphrase-file resolves to "pw" (file branch, strip rule from 05-01).
    let pw = cipherpost::identity::resolve_passphrase(
        None,
        Some("CIPHERPOST_PASSPHRASE"),
        Some(&pw_path),
        None,
        false,
    )
    .expect("resolve via --passphrase-file");
    assert_eq!(
        pw.expose(),
        "pw",
        "file-branch must strip the trailing newline"
    );

    run_roundtrip(&id_a, &kp_a, &id_b, &kp_b);
}

#[test]
#[serial]
fn scripted_roundtrip_via_passphrase_fd() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);

    // Create a pipe and write the passphrase to it.
    let mut fds: [libc::c_int; 2] = [0; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe() must succeed");
    let (read_fd, write_fd) = (fds[0], fds[1]);
    let payload = b"pw\n";
    let n = unsafe { libc::write(write_fd, payload.as_ptr() as *const _, payload.len()) };
    assert_eq!(n, payload.len() as isize);
    unsafe { libc::close(write_fd) };

    // Env must be clear, otherwise it would mask the fd branch.
    std::env::remove_var("CIPHERPOST_PASSPHRASE");

    // Prove --passphrase-fd resolves to "pw" (fd branch, BorrowedFd from 05-01).
    let pw = cipherpost::identity::resolve_passphrase(
        None,
        Some("CIPHERPOST_PASSPHRASE"),
        None,
        Some(read_fd),
        false,
    )
    .expect("resolve via --passphrase-fd");
    assert_eq!(
        pw.expose(),
        "pw",
        "fd-branch must strip the trailing newline"
    );

    run_roundtrip(&id_a, &kp_a, &id_b, &kp_b);

    unsafe { libc::close(read_fd) };
}
