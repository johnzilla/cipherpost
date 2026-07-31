//! Phase 3 Plan 03-04 — D-IT-01 test 2 / ROADMAP SC3: after publish_receipt,
//! the recipient's own outgoing _cipherpost share is NOT clobbered. Proves
//! TRANS-03's coexistence invariant end-to-end via the full run_send +
//! run_receive pipeline (not just direct MockTransport calls like Plan 03-02's
//! coexistence test — this test exercises the production path).

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::identity::Identity;
use cipherpost::transport::MockTransport;
use cipherpost::{ShareUri, DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX};
use secrecy::SecretBox;
use serial_test::serial;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tempfile::TempDir;
use zeroize::Zeroizing;

// Reuse the same helper as the end-to-end test. Duplicated here rather than
// factored into a shared module because Rust integration tests don't share
// test-only modules cleanly (each tests/*.rs is its own binary).
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
fn bs_self_share_blocks_receipt_accrual_over_budget() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);

    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();

    let transport = MockTransport::new();

    // 1. B does a self-mode run_send first — establishes B's own _cipherpost entry.
    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let _b_self_uri_str = run_send(
        &id_b,
        &transport,
        &kp_b,
        SendMode::SelfMode,
        "b self",
        MaterialSource::Bytes(b"b self note".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("B self-send");

    // Pre-condition: B has exactly 1 entry under its key, a _cipherpost.
    let pre = transport.resolve_all_txt(&b_z32);
    assert_eq!(pre.len(), 1, "pre-condition: B should have exactly 1 entry");
    assert_eq!(pre[0].0, DHT_LABEL_OUTER);

    // 2. A sends a share to B.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "a to b",
        MaterialSource::Bytes(b"a-to-b share".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("A run_send share mode");
    let uri = ShareUri::parse(&uri_str).expect("parse share URI");

    // 3. B receives + accepts. B ALREADY holds a self-share (~647B) under its key,
    //    so publishing the ~568B receipt would push the merged per-key packet to
    //    ~1215B > 1000B. publish_receipt is best-effort (D-SEQ-02 warn+degrade):
    //    the PacketBudgetExceeded is logged to stderr, the plaintext is still
    //    delivered, and run_receive returns Ok — but NO receipt is accrued.
    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id_b,
        &transport,
        &kp_b,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect("B run_receive still succeeds (receipt failure is warn+degrade)");
    match sink {
        OutputSink::InMemory(buf) => assert_eq!(
            buf, b"a-to-b share",
            "plaintext must still be delivered despite receipt degradation"
        ),
        _ => panic!("InMemory sink expected"),
    }

    // 4. Packet-budget ceiling: a key holds at most ONE real record — B's outgoing
    //    self-share (~647B) plus even a single receipt (~568B) exceed the 1000B
    //    per-key budget together. So B still holds ONLY its self-share; the receipt
    //    could not be accrued. This is NOT a clobber (the merge preserves the
    //    share) — the NEW receipt is what overflows and is dropped.
    let post = transport.resolve_all_txt(&b_z32);
    assert_eq!(
        post.len(),
        1,
        "B holds only its self-share; the receipt can't coexist (packet budget), got {:?}",
        post.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>()
    );
    assert_eq!(
        post[0].0, DHT_LABEL_OUTER,
        "the surviving entry is B's outgoing share"
    );
    let expected_receipt_label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, uri.share_ref_hex);
    assert!(
        !post.iter().any(|(l, _)| l == &expected_receipt_label),
        "receipt must NOT be present — it was budget-degraded (D-SEQ-02)"
    );
}

/// Canonical regression for the packet-budget collision: B first accrues a
/// receipt (as a recipient), THEN tries to publish its own share (as a sender).
/// Because any two real records (share ~647B + receipt ~568B) exceed the 1000B
/// per-key packet, the merge PRESERVES the receipt but the new share cannot fit,
/// so the send fails with `PacketBudgetExceeded` — an identity that has received
/// a share is blocked from sending until the receipt clears. This is the exact
/// consequence fix #1 (merge-don't-clobber) exposed; the accurate error names
/// accumulated records, not the user's (fine) payload.
#[test]
#[serial]
fn accrued_receipt_blocks_self_share_with_packet_budget_error() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xCC; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xDD; 32]);
    let b_z32 = kp_b.public_key().to_z32();
    let transport = MockTransport::new();

    // 1. A sends to B; B receives → B publishes a receipt. B has NO _cipherpost yet.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "a to b",
        MaterialSource::Bytes(b"a-to-b".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,
        false,
    )
    .expect("A send");
    let uri = ShareUri::parse(&uri_str).unwrap();
    let receipt_label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, uri.share_ref_hex);

    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id_b,
        &transport,
        &kp_b,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect("B receive");
    let after_receipt = transport.resolve_all_txt(&b_z32);
    assert!(
        after_receipt.iter().any(|(l, _)| l == &receipt_label),
        "precondition: B should hold a receipt"
    );
    assert!(
        !after_receipt.iter().any(|(l, _)| l == DHT_LABEL_OUTER),
        "precondition: B has not published a share yet"
    );

    // 2. B tries to publish its OWN self-share. The merge preserves the receipt,
    //    but receipt (~568B) + share (~647B) blow past the 1000B per-key budget,
    //    so the publish fails with PacketBudgetExceeded — NOT WireBudgetExceeded
    //    (the payload is fine; accumulated records are the cause). run_send
    //    surfaces the error (unlike receive's warn+degrade).
    let err = run_send(
        &id_b,
        &transport,
        &kp_b,
        SendMode::SelfMode,
        "b self",
        MaterialSource::Bytes(b"b self 1".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,
        false,
    )
    .expect_err("B self-send must fail — receipt + share exceed the per-key packet budget");
    assert!(
        matches!(err, cipherpost::Error::PacketBudgetExceeded { .. }),
        "expected PacketBudgetExceeded (accumulated records), got {err:?}"
    );
    // Accurate, non-misleading message: blames accumulated records, never the
    // user's payload (no "plaintext" phrasing like the old WireBudgetExceeded).
    let msg = format!("{err}");
    assert!(
        msg.contains("accumulated records") && !msg.contains("plaintext"),
        "message must blame accumulated records, not payload size: {msg}"
    );
    assert_eq!(
        cipherpost::error::exit_code(&err),
        1,
        "PacketBudgetExceeded maps to exit 1"
    );

    // The receipt is untouched (merge preserved it) and B's share was NOT published.
    let after = transport.resolve_all_txt(&b_z32);
    assert!(
        after.iter().any(|(l, _)| l == &receipt_label),
        "B's receipt must survive the failed share publish (got {:?})",
        after.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>()
    );
    assert!(
        !after.iter().any(|(l, _)| l == DHT_LABEL_OUTER),
        "B's share must NOT have been published (it overflowed the budget)"
    );
}
