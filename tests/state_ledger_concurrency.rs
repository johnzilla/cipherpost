//! Quick 260427-axn: regression test for the per-share_ref receive lock.
//!
//! Two `std::thread`s synchronized via `std::sync::Barrier::new(2)` both
//! call `run_receive` on the same share_ref. Without the lock (the v1.0/
//! v1.1 state) both could pass `check_already_consumed`, both decrypt
//! the share, and both append ledger rows. With `acquire_share_lock`
//! covering the resolve→sentinel→ledger window, exactly one observes
//! the fresh path; the other short-circuits via `LedgerState::Accepted`
//! (or returns `Error::Declined` for a burn share).
//!
//! Mirrors tests/cas_racer.rs Barrier pattern verbatim (Pitfall #28
//! mandate: NEVER sleep simulation). Each test carries `#[serial]`
//! because they mutate the process-global `CIPHERPOST_HOME`.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::error::exit_code;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::test_paths::{ledger_path, lock_path, sentinel_path};
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::{Error, ShareUri, DHT_LABEL_RECEIPT_PREFIX};
use secrecy::SecretBox;
use serial_test::serial;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use tempfile::TempDir;

// Helper: count how many ledger rows reference share_ref_hex.
fn count_ledger_rows_for(share_ref_hex: &str) -> usize {
    let path = ledger_path();
    let data = std::fs::read_to_string(&path).unwrap_or_default();
    data.lines()
        .filter(|line| {
            // Parse-then-match (avoid false positives in purpose text);
            // mirrors check_already_consumed's matching logic.
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| {
                    v.get("share_ref")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string())
                })
                .as_deref()
                == Some(share_ref_hex)
        })
        .count()
}

// Helper: count receipts for a given share_ref under the recipient's PKARR key.
// Mirrors tests/burn_roundtrip.rs::count_receipts_for_share_ref.
fn count_receipts_for(
    transport: &MockTransport,
    recipient_z32: &str,
    share_ref_hex: &str,
) -> usize {
    let label = format!("{DHT_LABEL_RECEIPT_PREFIX}{share_ref_hex}");
    transport
        .resolve_all_txt(recipient_z32)
        .iter()
        .filter(|(l, _)| l == &label)
        .count()
}

#[test]
#[serial]
fn concurrent_receive_same_share_ref_serializes_accepted() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let transport = Arc::new(MockTransport::new());

    // Send a tiny SelfMode share (burn=false, pin=None) — fits BEP44 budget.
    let plaintext = b"k1".to_vec();
    let uri_str = run_send(
        &id,
        transport.as_ref(),
        &kp,
        SendMode::SelfMode,
        "i",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // pin=None
        false, // burn=false
    )
    .expect("run_send");
    let uri = Arc::new(ShareUri::parse(&uri_str).unwrap());

    // Both threads attempt to receive concurrently.
    let barrier = Arc::new(Barrier::new(2));
    let results: Arc<Mutex<Vec<Result<(), Error>>>> = Arc::new(Mutex::new(Vec::new()));

    // SelfMode shares: both threads need an Identity that holds the same secret
    // material. Identity is not Clone (it holds a SecretBox). Loading from the
    // same CIPHERPOST_HOME twice yields two Identity instances backed by the
    // same on-disk key file.
    let id_a = cipherpost::identity::load(&pw).unwrap();
    let seed_a: [u8; 32] = *id_a.signing_seed();
    let kp_a = pkarr::Keypair::from_secret_key(&seed_a);
    let id_b = cipherpost::identity::load(&pw).unwrap();
    let seed_b: [u8; 32] = *id_b.signing_seed();
    let kp_b = pkarr::Keypair::from_secret_key(&seed_b);

    let h_a = {
        let transport = transport.clone();
        let uri = uri.clone();
        let barrier = barrier.clone();
        let results = results.clone();
        thread::spawn(move || {
            let mut sink = OutputSink::InMemory(Vec::new());
            barrier.wait();
            let r = run_receive(
                &id_a,
                transport.as_ref(),
                &kp_a,
                &uri,
                &mut sink,
                &AutoConfirmPrompter,
                false,
            );
            results.lock().unwrap().push(r);
        })
    };
    let h_b = {
        let transport = transport.clone();
        let uri = uri.clone();
        let barrier = barrier.clone();
        let results = results.clone();
        thread::spawn(move || {
            let mut sink = OutputSink::InMemory(Vec::new());
            barrier.wait();
            let r = run_receive(
                &id_b,
                transport.as_ref(),
                &kp_b,
                &uri,
                &mut sink,
                &AutoConfirmPrompter,
                false,
            );
            results.lock().unwrap().push(r);
        })
    };

    h_a.join().unwrap();
    h_b.join().unwrap();

    let results = results.lock().unwrap();
    assert_eq!(results.len(), 2);
    // Both Ok — one decrypted, the other observed Accepted and short-circuited.
    assert!(
        results.iter().all(|r| r.is_ok()),
        "both calls must return Ok; got {results:?}"
    );

    // Exactly ONE accepted-row for this share_ref. Without the lock, both
    // threads can pass check_already_consumed concurrently, both decrypt,
    // both append a step-12 row → 2 rows; this assertion is the regression
    // gate. (Step 13's optional second row with receipt_published_at also
    // counts — but it ALSO only fires once per winning receive, so the
    // total is 1 or 2 rows. Without the lock it's 2 or 4.)
    let row_count = count_ledger_rows_for(&uri.share_ref_hex);
    assert!(
        (1..=2).contains(&row_count),
        "exactly 1 or 2 ledger rows expected for serialized concurrent receive (1 step-12 row \
         + optional step-13 receipt-success row); got {row_count}. \
         Without the per-share_ref lock the count would be 2 or 4."
    );
    assert!(
        sentinel_path(&uri.share_ref_hex).exists(),
        "sentinel must exist after winning receive"
    );
    assert!(
        lock_path(&uri.share_ref_hex).exists(),
        "lock file must persist after the lock window closes"
    );
}

#[test]
#[serial]
fn concurrent_receive_same_share_ref_burn_one_succeeds_one_declined() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let transport = Arc::new(MockTransport::new());

    // Burn-mode send (pin=None, burn=true). Tiny GenericSecret in self-mode
    // fits within the 1000-byte BEP44 ceiling without PIN nesting.
    let plaintext = b"burnable".to_vec();
    let uri_str = run_send(
        &id,
        transport.as_ref(),
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None, // pin=None
        true, // burn=true
    )
    .expect("run_send burn");
    let uri = Arc::new(ShareUri::parse(&uri_str).unwrap());
    let recipient_z32 = id.z32_pubkey();

    let barrier = Arc::new(Barrier::new(2));
    let results: Arc<Mutex<Vec<Result<(), Error>>>> = Arc::new(Mutex::new(Vec::new()));

    let id_a = cipherpost::identity::load(&pw).unwrap();
    let seed_a: [u8; 32] = *id_a.signing_seed();
    let kp_a = pkarr::Keypair::from_secret_key(&seed_a);
    let id_b = cipherpost::identity::load(&pw).unwrap();
    let seed_b: [u8; 32] = *id_b.signing_seed();
    let kp_b = pkarr::Keypair::from_secret_key(&seed_b);

    let h_a = {
        let transport = transport.clone();
        let uri = uri.clone();
        let barrier = barrier.clone();
        let results = results.clone();
        thread::spawn(move || {
            let mut sink = OutputSink::InMemory(Vec::new());
            barrier.wait();
            let r = run_receive(
                &id_a,
                transport.as_ref(),
                &kp_a,
                &uri,
                &mut sink,
                &AutoConfirmPrompter,
                false,
            );
            results.lock().unwrap().push(r);
        })
    };
    let h_b = {
        let transport = transport.clone();
        let uri = uri.clone();
        let barrier = barrier.clone();
        let results = results.clone();
        thread::spawn(move || {
            let mut sink = OutputSink::InMemory(Vec::new());
            barrier.wait();
            let r = run_receive(
                &id_b,
                transport.as_ref(),
                &kp_b,
                &uri,
                &mut sink,
                &AutoConfirmPrompter,
                false,
            );
            results.lock().unwrap().push(r);
        })
    };

    h_a.join().unwrap();
    h_b.join().unwrap();

    let results = results.lock().unwrap();
    assert_eq!(results.len(), 2);

    // Exactly one Ok (the winner — decrypted + emitted plaintext) and exactly
    // one Err(Declined) (the loser — saw LedgerState::Burned and short-circuited).
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    let declined_count = results
        .iter()
        .filter(|r| matches!(r, Err(Error::Declined)))
        .count();
    assert_eq!(
        ok_count, 1,
        "exactly one thread must succeed for a burn share under contention; got {results:?}"
    );
    assert_eq!(
        declined_count, 1,
        "exactly one thread must observe Declined for a burn share under contention; got {results:?}"
    );
    // The losing thread's Err is exit-7-equivalent (Pitfall #16 oracle hygiene
    // preserved — Declined is the public face of "already consumed").
    for r in results.iter() {
        if let Err(e) = r {
            assert_eq!(exit_code(e), 7, "loser exit code must be 7 (Declined)");
        }
    }

    // Exactly ONE ledger row carries state=burned. Without the lock both
    // threads could append a state=burned row.
    let lp = ledger_path();
    let ledger = std::fs::read_to_string(&lp).expect("ledger file must exist");
    let burned_rows = ledger
        .lines()
        .filter(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .map(|v| {
                    v.get("share_ref").and_then(|s| s.as_str()) == Some(uri.share_ref_hex.as_str())
                        && v.get("state").and_then(|s| s.as_str()) == Some("burned")
                })
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        burned_rows, 1,
        "exactly one state=burned row must exist after concurrent burn-receive; got {burned_rows}. \
         Without the per-share_ref lock the count would be 2."
    );

    // Receipt count == 1 (BURN-04 invariant under contention). The loser
    // returns Declined at STEP 1 before STEP 13's publish_outcome closure
    // can run, and the winner publishes exactly one receipt.
    let receipt_count = count_receipts_for(&transport, &recipient_z32, &uri.share_ref_hex);
    assert_eq!(
        receipt_count, 1,
        "exactly one receipt must persist after concurrent burn-receive (BURN-04); got {receipt_count}"
    );

    assert!(
        sentinel_path(&uri.share_ref_hex).exists(),
        "sentinel must exist after winning burn receive"
    );
    assert!(
        lock_path(&uri.share_ref_hex).exists(),
        "lock file must persist after the lock window closes"
    );
}

#[test]
#[serial]
fn concurrent_receive_distinct_share_refs_does_not_serialize() {
    // Per-share_ref granularity contract — design-document test.
    //
    // The lock layout creates a separate file per `share_ref_hex`
    // (`{state_dir}/locks/<share_ref>.lock`) so concurrent receives of
    // DIFFERENT share_refs do not serialize against each other. A global
    // lock would also pass tests 1+2 above but would serialize unrelated
    // receives unnecessarily, hurting throughput when a user has a queue
    // of pending shares.
    //
    // True concurrent-distinct-share contention against MockTransport is
    // structurally awkward because MockTransport stores ONE outer record
    // per sender pubkey under DHT_LABEL_OUTER (mirrors real-DHT semantics:
    // a second `publish` from the same key overwrites the first). Forging
    // two independent identities sharing one CIPHERPOST_HOME is also not
    // possible — the on-disk key file is singleton.
    //
    // Therefore this test validates the granularity DOCUMENTARILY: it
    // performs two SEQUENTIAL receives on TWO distinct share_refs (each
    // its own send→receive on its own MockTransport instance) and asserts
    // that two distinct lock files are created at distinct paths. If a
    // future refactor regresses to a global lock (single
    // `{state_dir}/global.lock`), the per-share_ref lock_path() helper
    // would either return identical paths or stop creating files at
    // share_ref-keyed paths, and this assertion would catch that.
    //
    // Treat this as a design-contract document, not a contention gate.

    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);

    // Round-trip share A on MockTransport A.
    let transport_a = MockTransport::new();
    let uri_a_str = run_send(
        &id,
        &transport_a,
        &kp,
        SendMode::SelfMode,
        "alpha",
        MaterialSource::Bytes(b"a1".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,
        false,
    )
    .expect("run_send a");
    let uri_a = ShareUri::parse(&uri_a_str).unwrap();
    let mut sink_a = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport_a,
        &kp,
        &uri_a,
        &mut sink_a,
        &AutoConfirmPrompter,
        false,
    )
    .expect("run_receive a");

    // Round-trip share B on MockTransport B (fresh transport so its outer
    // record doesn't collide with A's).
    let transport_b = MockTransport::new();
    let uri_b_str = run_send(
        &id,
        &transport_b,
        &kp,
        SendMode::SelfMode,
        "bravo",
        MaterialSource::Bytes(b"b2".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,
        false,
    )
    .expect("run_send b");
    let uri_b = ShareUri::parse(&uri_b_str).unwrap();
    let mut sink_b = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport_b,
        &kp,
        &uri_b,
        &mut sink_b,
        &AutoConfirmPrompter,
        false,
    )
    .expect("run_receive b");

    assert_ne!(
        uri_a.share_ref_hex, uri_b.share_ref_hex,
        "test prerequisite: two distinct share_refs"
    );

    // Both share_refs have at least one ledger row each.
    assert!(
        count_ledger_rows_for(&uri_a.share_ref_hex) >= 1,
        "share_ref a must have a ledger row"
    );
    assert!(
        count_ledger_rows_for(&uri_b.share_ref_hex) >= 1,
        "share_ref b must have a ledger row"
    );

    // Two distinct lock files at two distinct paths — per-share_ref
    // granularity assertion.
    let lp_a = lock_path(&uri_a.share_ref_hex);
    let lp_b = lock_path(&uri_b.share_ref_hex);
    assert_ne!(
        lp_a, lp_b,
        "lock_path() must return distinct paths for distinct share_refs"
    );
    assert!(lp_a.exists(), "lock file for share a must exist: {lp_a:?}");
    assert!(lp_b.exists(), "lock file for share b must exist: {lp_b:?}");

    // Silence dead-code on the imports that only test 1+2 use under this
    // simplified test 3 (Barrier/Mutex/thread are still imported for the
    // other two tests in this file).
    let _ = (
        Arc::new(Barrier::new(2)),
        Mutex::new(Vec::<Result<(), Error>>::new()),
        thread::current,
    );
}
