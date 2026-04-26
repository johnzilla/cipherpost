//! Phase 9 Plan 02 (DHT-03 + DHT-04 + DHT-05): real-Mainline-DHT cross-
//! identity round trip — the v1.1 release-acceptance gate.
//!
//! ## Triple-gate discipline
//!
//! `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` —
//! D-P9-D2 belt-and-suspenders. Any single gate would already block CI;
//! using all three eliminates accidental execution under any plausible
//! invocation. PR CI + nightly CI stay mock-only per Pitfall #29.
//!
//! ## Scope
//!
//! Single cross-identity round trip: Alice publishes a share to Bob, Bob
//! resolves it with a 7-step exponential-backoff loop bounded at 120s,
//! Bob decrypts, Bob publishes a receipt to his own PKARR key, Alice
//! fetches the receipt. CAS racer stays MockTransport-only (D-P9-D1
//! pinned by Plan 09-01).
//!
//! ## UDP pre-flight (DHT-05)
//!
//! Probes `router.bittorrent.com:6881` (Mainline's first default
//! bootstrap node, mainline 6.1.1 verified) with a 5s timeout via
//! `std::net::UdpSocket`. If unreachable, prints the canonical skip
//! message and returns Ok — NOT a release-blocking failure.
//!
//! ## In-test deadline + nextest outer guard
//!
//! D-P9-D3 belt-and-suspenders: in-test `Instant::now() >= deadline`
//! check (primary) + `.config/nextest.toml` `slow-timeout = { period =
//! "60s", terminate-after = 2 }` (secondary; total budget = 120s).
//! Stable cargo has no `--test-timeout` flag (RESEARCH.md OQ-5).
//!
//! ## No async runtime
//!
//! `pkarr::ClientBlocking` is used via `DhtTransport::new` — CLAUDE.md
//! load-bearing rule (no async runtime at the cipherpost layer).
//! `std::thread::sleep` is the backoff primitive — NOT any async-runtime
//! sleep helper.

#![cfg(feature = "real-dht-e2e")]

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, Prompter, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::{DhtTransport, Transport};
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// UDP pre-flight (DHT-05) — probe Mainline's first default bootstrap
/// node. Returns `false` on DNS failure, route failure, or socket-bind
/// failure; `true` if `connect()` succeeds within `timeout`.
fn udp_bootstrap_reachable(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut addrs = match "router.bittorrent.com:6881".to_socket_addrs() {
        Ok(it) => it,
        Err(_) => return false,
    };
    let target = match addrs.next() {
        Some(a) => a,
        None => return false,
    };
    if Instant::now() >= deadline {
        return false;
    }
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = socket.set_read_timeout(Some(timeout));
    socket.connect(target).is_ok()
}

/// Per-identity setup: fresh CIPHERPOST_HOME under `dir`, generate a
/// fresh Identity, reconstruct the matching pkarr::Keypair from the
/// signing seed (mirrors main.rs Send dispatch + tests/burn_send_smoke.rs).
fn setup(dir: &TempDir) -> (cipherpost::identity::Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

#[test]
#[ignore]
#[serial]
fn real_dht_cross_identity_round_trip_with_receipt() {
    // 1. UDP pre-flight (DHT-05) — skip with canonical message if Mainline's
    //    first default bootstrap is unreachable.
    if !udp_bootstrap_reachable(Duration::from_secs(5)) {
        eprintln!("real-dht-e2e: UDP unreachable; test skipped (not counted as pass)");
        return;
    }

    // 2. Two independent in-process clients (D-P9-D1 + 09-RESEARCH.md OQ-4).
    //    DhtTransport::new is reused — never inline pkarr::Client::builder().
    let alice_dir = TempDir::new().unwrap();
    let (alice_id, alice_kp) = setup(&alice_dir);
    let alice_transport =
        DhtTransport::new(Duration::from_secs(120)).expect("DhtTransport::new alice");

    // Bob needs a SEPARATE CIPHERPOST_HOME because identity::generate()
    // overwrites the on-disk identity. #[serial] keeps env mutation
    // race-free across tests.
    let bob_dir = TempDir::new().unwrap();
    let (bob_id, bob_kp) = setup(&bob_dir);
    let bob_transport = DhtTransport::new(Duration::from_secs(120)).expect("DhtTransport::new bob");

    let bob_z32 = bob_id.z32_pubkey();
    let alice_z32 = alice_id.z32_pubkey();

    // 3. Alice sends a share to Bob (cross-identity = SendMode::Share).
    //    Re-set CIPHERPOST_HOME to alice's dir so sealed-identity reads
    //    find her keystore.
    std::env::set_var("CIPHERPOST_HOME", alice_dir.path());
    let plaintext = b"phase 9 real-dht handoff payload".to_vec();
    let share_uri_str = run_send(
        &alice_id,
        &alice_transport,
        &alice_kp,
        SendMode::Share {
            recipient_z32: bob_z32.clone(),
        },
        "real-dht round trip",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // no PIN
        false, // no burn
    )
    .expect("alice run_send");

    // 4. Bob resolves Alice's published share with 7-step exp-backoff
    //    (D-P9-D3 + 09-RESEARCH.md OQ-2 — curve 1s,2s,4s,8s,16s,32s,64s
    //    clipped to remaining-budget; total sum 127s, deadline-clipped
    //    at 120s). Re-set CIPHERPOST_HOME to bob's dir for run_receive.
    std::env::set_var("CIPHERPOST_HOME", bob_dir.path());

    let deadline = Instant::now() + Duration::from_secs(120);
    let backoff_curve = [1u64, 2, 4, 8, 16, 32, 64];
    let mut resolved = None;
    for delay_secs in backoff_curve {
        if Instant::now() >= deadline {
            panic!("real-dht-e2e: 120s deadline reached without successful resolve");
        }
        match alice_transport.resolve(&alice_z32) {
            Ok(record) => {
                resolved = Some(record);
                break;
            }
            Err(_) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let sleep_for = Duration::from_secs(delay_secs).min(remaining);
                if sleep_for.is_zero() {
                    panic!("real-dht-e2e: deadline exhausted between attempts");
                }
                std::thread::sleep(sleep_for);
            }
        }
    }
    let _resolved = resolved.expect("real-dht-e2e: resolve never succeeded within 120s budget");

    // NOTE: the typed-z32 acceptance gate is intentionally bypassed by this
    //       network-round-trip test. AutoConfirmPrompter is a bare unit
    //       struct at src/flow.rs:1349 (no constructor function); its
    //       `render_and_confirm` ignores `_sender_z32` and always returns
    //       Ok(()). The acceptance gate's correctness is exercised by every
    //       OTHER receive test in the suite (tests/burn_roundtrip.rs,
    //       tests/pin_burn_compose.rs, etc.) — this test's focus is purely
    //       *real-DHT network round-trip viability*, not acceptance-gate
    //       semantics. A human running RELEASE-CHECKLIST manually exercises
    //       the gate via interactive `cipherpost receive` separately.
    //
    //       run_receive takes `prompter: &dyn Prompter` (not
    //       `Box<dyn Prompter>`); we still construct via `Box::new(...)` per
    //       the executor contract and pass `&*prompter` to coerce to the
    //       trait reference the function expects. The unit-struct invariant
    //       (no constructor function) is preserved — we use the type name
    //       directly as a value.
    //
    // 5. Bob runs the full receive flow against alice's share URI.
    //    Receipt publishes to bob's own PKARR key (BURN-04 / TRANS-03 —
    //    receipt always published on success).
    let share_uri = ShareUri::parse(&share_uri_str).expect("parse share URI");
    let prompter: Box<dyn Prompter> = Box::new(AutoConfirmPrompter); // unit struct — see NOTE above
    let recovered = {
        let mut sink = OutputSink::InMemory(Vec::new());
        run_receive(
            &bob_id,
            &bob_transport,
            &bob_kp,
            &share_uri,
            &mut sink,
            &*prompter,
            false, // armor
        )
        .expect("bob run_receive");
        match sink {
            OutputSink::InMemory(buf) => buf,
            _ => panic!("expected InMemory sink"),
        }
    };
    assert_eq!(
        recovered, plaintext,
        "decrypted payload must round-trip byte-for-byte"
    );

    // 6. Alice fetches receipts under bob's z32 and asserts count == 1
    //    (BURN-04 invariant). Same backoff for receipt propagation.
    std::env::set_var("CIPHERPOST_HOME", alice_dir.path());
    let mut receipts: Option<Vec<String>> = None;
    for delay_secs in backoff_curve {
        if Instant::now() >= deadline {
            break;
        }
        match alice_transport.resolve_all_cprcpt(&bob_z32) {
            Ok(rs) if !rs.is_empty() => {
                receipts = Some(rs);
                break;
            }
            _ => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let sleep_for = Duration::from_secs(delay_secs).min(remaining);
                if sleep_for.is_zero() {
                    break;
                }
                std::thread::sleep(sleep_for);
            }
        }
    }
    let receipts =
        receipts.expect("real-dht-e2e: alice never observed a receipt under bob's z32 within 120s");
    assert_eq!(
        receipts.len(),
        1,
        "exactly one receipt expected (BURN-04 receipt-count == 1 invariant); got {}",
        receipts.len()
    );

    // 7. Cleanup; tempdirs auto-drop.
    std::env::remove_var("CIPHERPOST_HOME");
}
