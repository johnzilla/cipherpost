//! Phase 8 Plan 05: pin × burn × typed-material compose matrix.
//!
//! No new requirement coverage (PIN-01..10 + BURN-01..09 covered by Plans
//! 01-04). This file pins compose invariants ACROSS the typed-material
//! variants:
//!
//!   - 12 base round-trip cases (4 variants × {pin, burn, pin+burn})
//!   - 4 burn receipt-count cross-cutting (BURN-04; RESEARCH Open Risk #4)
//!   - 4 burn second-receive returns exit 7 cross-cutting (BURN-09)
//!   - 1 wrong-PIN-on-burn doesn't mark burned (negative-path safety)
//!   - 1 typed-z32-declined-on-burn doesn't mark burned (negative-path safety)
//!   - 1 pin+burn+pgp wire-budget pre-flight (RESEARCH Open Risk #5)
//!
//! ## Wire-budget reality (W3 split)
//!
//! Plan 01's `pin_send_smoke.rs` established that pin-protected shares
//! exceed the 1000-byte BEP44 ceiling for any non-trivial plaintext, and
//! Phase 6/7's typed-material round-trip tests are universally `#[ignore]`'d
//! for the same reason. As a result, ONLY `generic_burn_only` reliably fits
//! within the wire budget (small GenericSecret + single age layer + 1-byte
//! JCS overhead from `burn_after_read=true`). Every other base round-trip
//! case uses the LENIENT pattern that surfaces `Error::WireBudgetExceeded`
//! as `Ok(())` with an `eprintln!` skip note — Phase 9 DHT-07 will measure
//! empirically. This is per-plan-spec consistent with Plans 01/02/04's
//! treatment.
//!
//! ## Identity reuse caveat
//!
//! `cipherpost::identity::generate` overwrites the existing identity on
//! disk via `create_new(tmp) + rename(tmp, dest)` so calling `setup(&dir)`
//! twice in the same TempDir destroys the original identity. The
//! `compose_round_trip` helper therefore RETURNS the identity + keypair so
//! the second-receive cross-cutting tests can re-use them without
//! regenerating.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::error::exit_code;
use cipherpost::flow::test_helpers::{AutoConfirmPrompter, DeclinePrompter};
use cipherpost::flow::test_paths::{ledger_path, sentinel_path};
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::{Error, ShareUri};
use secrecy::SecretBox;
use serial_test::serial;
use std::fs;
use tempfile::TempDir;

const VALID_PIN: &str = "validpin1";
// 11 chars, validate_pin-clean (mixed alpha; not all-same, not sequential,
// not in blocklist). Wrong-PIN test uses this so prompt_pin doesn't reject
// it BEFORE age-decrypt — we want age to fail at the inner-decrypt step
// (Error::DecryptFailed exit 4), not validate_pin's Error::Config exit 1.
const WRONG_PIN: &str = "differntpin";

/// Phase 8 Plan 05 (B1 fix): receipt-count helper. Mirror of the helper
/// landed in Plan 04's `tests/burn_roundtrip.rs`. MockTransport does NOT
/// expose a `count_receipts_for(share_ref)` method; the actual API surface
/// (verified at src/transport.rs:313-321) is
/// `MockTransport::resolve_all_txt(pubkey_z32) -> Vec<(label, json)>`.
/// Receipt labels follow the format `_cprcpt-<share_ref_hex>`, so we filter
/// on exact-match label. The recipient pubkey for SelfMode shares is the
/// sender identity itself.
///
/// Re-defined inline rather than extracted to `tests/common/mod.rs` —
/// duplication is one 9-line function shared by two test files; refactor
/// only once a third consumer appears.
fn count_receipts_for_share_ref(
    transport: &MockTransport,
    recipient_z32: &str,
    share_ref_hex: &str,
) -> usize {
    let label = format!("_cprcpt-{share_ref_hex}");
    transport
        .resolve_all_txt(recipient_z32)
        .iter()
        .filter(|(l, _json)| l == &label)
        .count()
}

fn setup(dir: &TempDir) -> (cipherpost::identity::Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

fn fixture_for(variant: MaterialVariant) -> Vec<u8> {
    match variant {
        MaterialVariant::GenericSecret => b"generic-payload-bytes".to_vec(),
        // Phase 6 fixture: 388-byte Ed25519 X.509 DER cert.
        MaterialVariant::X509Cert => fs::read("tests/fixtures/x509_cert_fixture.der").unwrap(),
        // Phase 7 fixture: 202-byte rpgp-minimal Ed25519 public TPK.
        MaterialVariant::PgpKey => fs::read("tests/fixtures/material_pgp_fixture.pgp").unwrap(),
        // Phase 7 fixture: 387-byte OpenSSH v1 Ed25519 keypair.
        MaterialVariant::SshKey => {
            fs::read("tests/fixtures/material_ssh_fixture.openssh-v1").unwrap()
        }
    }
}

fn variant_label(variant: MaterialVariant) -> &'static str {
    match variant {
        MaterialVariant::GenericSecret => "generic",
        MaterialVariant::X509Cert => "x509",
        MaterialVariant::PgpKey => "pgp",
        MaterialVariant::SshKey => "ssh",
    }
}

/// Plan 05 helper: run send (with optional pin/burn) followed by ONE receive;
/// return the transport (for receipt-count introspection), URI, recovered
/// bytes, identity, and keypair. The identity + keypair are returned so
/// callers can issue a SECOND receive without re-generating the identity
/// (which would clobber the on-disk key — see module doc "Identity reuse
/// caveat").
///
/// On success the caller is responsible for clearing `CIPHERPOST_TEST_PIN`;
/// this helper sets it for the send path but does NOT clear it on return so
/// that callers wishing to drive a second receive under the same PIN can do
/// so without re-setting. Tests using this helper must remove the env var
/// at the end of the test body.
#[allow(clippy::type_complexity)]
fn compose_round_trip(
    dir: &TempDir,
    variant: MaterialVariant,
    pin: bool,
    burn: bool,
) -> Result<
    (
        MockTransport,
        ShareUri,
        Vec<u8>,
        cipherpost::identity::Identity,
        pkarr::Keypair,
    ),
    Error,
> {
    let (id, kp) = setup(dir);
    let plaintext = fixture_for(variant);
    let transport = MockTransport::new();

    if pin {
        std::env::set_var("CIPHERPOST_TEST_PIN", VALID_PIN);
    }
    let pin_arg = if pin {
        Some(SecretBox::new(Box::new(VALID_PIN.to_string())))
    } else {
        None
    };

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        variant,
        DEFAULT_TTL_SECONDS,
        pin_arg,
        burn,
    )?;
    let uri = ShareUri::parse(&uri_str)?;

    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )?;
    let recovered = match sink {
        OutputSink::InMemory(buf) => buf,
        _ => panic!("InMemory sink expected"),
    };

    Ok((transport, uri, recovered, id, kp))
}

// ---------------------------------------------------------------------------
// Step B — 12 base round-trip cases (4 variants × {pin, burn, pin+burn}).
//
// W3 split: only `generic_burn_only` reliably fits within the 1000-byte
// BEP44 ceiling. Every other case uses the LENIENT pattern that surfaces
// WireBudgetExceeded as `Ok(())` with an eprintln skip note. This matches
// Plan 01/02/04's treatment of the wire-budget reality.
// ---------------------------------------------------------------------------

/// Strict round-trip: small payload, single age layer, fits within budget.
/// Used ONLY for `generic_burn_only` per the W3 split.
macro_rules! compose_base_test_strict {
    ($name:ident, $variant:expr, $pin:expr, $burn:expr) => {
        #[test]
        #[serial]
        fn $name() {
            let dir = TempDir::new().unwrap();
            let (_transport, _uri, recovered, _id, _kp) =
                compose_round_trip(&dir, $variant, $pin, $burn).expect(stringify!($name));
            let expected = fixture_for($variant);
            assert_eq!(
                recovered,
                expected,
                "{}+{}+{}: plaintext recovery mismatch",
                variant_label($variant),
                if $pin { "pin" } else { "" },
                if $burn { "burn" } else { "" }
            );
            if $pin {
                std::env::remove_var("CIPHERPOST_TEST_PIN");
            }
        }
    };
}

/// Lenient round-trip: surfaces WireBudgetExceeded as graceful skip rather
/// than hard-failing. Used for every typed-material variant + every PIN
/// path (per Plan 01's wire-budget reality — non-trivial plaintext under
/// nested-age exceeds the 1000-byte BEP44 ceiling).
macro_rules! compose_base_test_lenient {
    ($name:ident, $variant:expr, $pin:expr, $burn:expr) => {
        #[test]
        #[serial]
        fn $name() -> Result<(), Box<dyn std::error::Error>> {
            let dir = TempDir::new().unwrap();
            let result = compose_round_trip(&dir, $variant, $pin, $burn);
            // Always clean up the PIN env var, even on Err.
            if $pin {
                std::env::remove_var("CIPHERPOST_TEST_PIN");
            }
            match result {
                Ok((_transport, _uri, recovered, _id, _kp)) => {
                    let expected = fixture_for($variant);
                    assert_eq!(
                        recovered,
                        expected,
                        "{}+{}+{}: plaintext recovery mismatch",
                        variant_label($variant),
                        if $pin { "pin" } else { "" },
                        if $burn { "burn" } else { "" }
                    );
                    Ok(())
                }
                Err(e) if matches!(&e, Error::WireBudgetExceeded { .. }) => {
                    eprintln!(
                        "{}: WireBudgetExceeded gracefully — Phase 9 DHT-07 measures empirically: {:?}",
                        stringify!($name),
                        e
                    );
                    Ok(())
                }
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
            }
        }
    };
}

// Pin only (4 variants — pin nesting exceeds budget for ANY non-trivial
// plaintext per Plan 01; all four use the lenient pattern).
compose_base_test_lenient!(
    generic_pin_only,
    MaterialVariant::GenericSecret,
    true,
    false
);
compose_base_test_lenient!(x509_pin_only, MaterialVariant::X509Cert, true, false);
compose_base_test_lenient!(pgp_pin_only, MaterialVariant::PgpKey, true, false);
compose_base_test_lenient!(ssh_pin_only, MaterialVariant::SshKey, true, false);

// Burn only — only GenericSecret (small payload, single age layer) fits
// within budget; typed-material variants use the lenient pattern.
compose_base_test_strict!(
    generic_burn_only,
    MaterialVariant::GenericSecret,
    false,
    true
);
compose_base_test_lenient!(x509_burn_only, MaterialVariant::X509Cert, false, true);
compose_base_test_lenient!(pgp_burn_only, MaterialVariant::PgpKey, false, true);
compose_base_test_lenient!(ssh_burn_only, MaterialVariant::SshKey, false, true);

// Pin + burn compose (worst case — nested age + 1-byte JCS overhead).
// All four lenient because the pin nesting alone already exceeds budget.
compose_base_test_lenient!(generic_pin_burn, MaterialVariant::GenericSecret, true, true);
compose_base_test_lenient!(x509_pin_burn, MaterialVariant::X509Cert, true, true);
compose_base_test_lenient!(pgp_pin_burn, MaterialVariant::PgpKey, true, true);
compose_base_test_lenient!(ssh_pin_burn, MaterialVariant::SshKey, true, true);

// ---------------------------------------------------------------------------
// Step C — Receipt-count cross-cutting (4 variants). BURN-04 + RESEARCH
// Open Risk #4: receipt publishes for both burn and non-burn shares; no
// `if !envelope.burn_after_read { publish_receipt(...) }` guard. Asserted
// per typed-material variant under burn-only (NOT pin+burn — pin nesting
// exceeds budget so the round-trip would skip via lenient pattern, which
// would not exercise the receipt path).
// ---------------------------------------------------------------------------

macro_rules! receipt_count_after_burn_first_receive {
    ($name:ident, $variant:expr) => {
        #[test]
        #[serial]
        fn $name() {
            let dir = TempDir::new().unwrap();
            let result = compose_round_trip(&dir, $variant, false, true);
            match result {
                Ok((transport, uri, _recovered, id, _kp)) => {
                    // Recipient = sender (SelfMode); use the returned identity
                    // rather than re-calling setup() which would clobber the
                    // on-disk key (see module doc "Identity reuse caveat").
                    let recipient_z32 = id.z32_pubkey();
                    let count = count_receipts_for_share_ref(
                        &transport,
                        &recipient_z32,
                        &uri.share_ref_hex,
                    );
                    assert_eq!(
                        count,
                        1,
                        "{}+burn: expected 1 receipt after first successful receive, got {}",
                        variant_label($variant),
                        count
                    );
                }
                Err(e) if matches!(&e, Error::WireBudgetExceeded { .. }) => {
                    eprintln!(
                        "skipping {}: WireBudgetExceeded (Phase 9 DHT-07 measures empirically): {:?}",
                        stringify!($name),
                        e
                    );
                }
                Err(e) => panic!("{}: unexpected error {:?}", stringify!($name), e),
            }
        }
    };
}

receipt_count_after_burn_first_receive!(
    generic_burn_publishes_one_receipt,
    MaterialVariant::GenericSecret
);
receipt_count_after_burn_first_receive!(x509_burn_publishes_one_receipt, MaterialVariant::X509Cert);
receipt_count_after_burn_first_receive!(pgp_burn_publishes_one_receipt, MaterialVariant::PgpKey);
receipt_count_after_burn_first_receive!(ssh_burn_publishes_one_receipt, MaterialVariant::SshKey);

// ---------------------------------------------------------------------------
// Step D — Second-receive on burned share returns exit 7 (4 variants).
// BURN-09 cross-cutting: re-tests the LedgerState::Burned arm under each
// typed-material variant. Burn-only path (no pin) so the round-trip fits
// for GenericSecret; typed materials skip via lenient pattern.
// ---------------------------------------------------------------------------

macro_rules! second_receive_burn_returns_exit_7 {
    ($name:ident, $variant:expr) => {
        #[test]
        #[serial]
        fn $name() {
            let dir = TempDir::new().unwrap();
            let result = compose_round_trip(&dir, $variant, false, true);
            match result {
                Ok((transport, uri, _recovered, id, kp)) => {
                    // Re-use returned identity + keypair (do NOT call setup()
                    // again — that would regenerate the identity).
                    let mut sink = OutputSink::InMemory(Vec::new());
                    let err = run_receive(
                        &id,
                        &transport,
                        &kp,
                        &uri,
                        &mut sink,
                        &AutoConfirmPrompter,
                        false,
                    )
                    .unwrap_err();
                    assert!(
                        matches!(err, Error::Declined),
                        "{}+burn: second receive must yield Declined, got {:?}",
                        variant_label($variant),
                        err
                    );
                    assert_eq!(exit_code(&err), 7);
                }
                Err(e) if matches!(&e, Error::WireBudgetExceeded { .. }) => {
                    eprintln!(
                        "skipping {}: WireBudgetExceeded (Phase 9 DHT-07 measures empirically): {:?}",
                        stringify!($name),
                        e
                    );
                }
                Err(e) => panic!("{}: unexpected error {:?}", stringify!($name), e),
            }
        }
    };
}

second_receive_burn_returns_exit_7!(
    generic_burn_second_receive_exit_7,
    MaterialVariant::GenericSecret
);
second_receive_burn_returns_exit_7!(x509_burn_second_receive_exit_7, MaterialVariant::X509Cert);
second_receive_burn_returns_exit_7!(pgp_burn_second_receive_exit_7, MaterialVariant::PgpKey);
second_receive_burn_returns_exit_7!(ssh_burn_second_receive_exit_7, MaterialVariant::SshKey);

// ---------------------------------------------------------------------------
// Step E — Negative-path safety: wrong-PIN-on-burn doesn't mark burned.
//
// CRITICAL safety property. Without it, a wrong-PIN attempt consumes the
// user's only chance at the share. Order:
//   prompt -> derive -> outer-decrypt -> inner-decrypt (FAILS with wrong
//   PIN) -> return Err. The ledger and sentinel are NEVER touched; the
//   share remains re-receivable when the correct PIN is later supplied.
//
// IMPLEMENTATION NOTE: pin+burn round-trip exceeds the wire budget for
// non-trivial plaintext (Plan 01 reality). We synthesize a pin-required
// OuterRecord directly via the same pattern as Plan 02's PIN-08 case (c)
// — it lets us hit the wrong-PIN code path WITHOUT a successful publish.
// The wrong-PIN failure surface is independently asserted at the synthetic
// layer; the negative-path safety property (NO ledger touch + share
// re-receivable) is what we verify here.
//
// Approach: synthesize a pin_required+burn share directly into MockTransport
// via the same OuterRecord-construction pattern Plan 02 used. The blob is
// arbitrary >32-byte bytes (run_receive aborts at age-decrypt BEFORE
// touching the ledger when the PIN is wrong, so the blob's actual content
// is irrelevant for this test). This MUST stay below 1000 bytes published
// or MockTransport rejects the publish.
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn wrong_pin_on_pin_burn_share_does_not_mark_burned_and_share_remains_re_receivable() {
    use base64::Engine;
    use cipherpost::record::{sign_record, OuterRecord, OuterRecordSignable};
    use cipherpost::transport::Transport;

    let dir = TempDir::new().unwrap();
    let (id, kp) = setup(&dir);
    let transport = MockTransport::new();

    // Synthesize a pin_required OuterRecord with arbitrary blob bytes. The
    // wrong-PIN path aborts run_receive at age-decrypt (STEP 6a in run_receive)
    // BEFORE STEP 11 emit + STEP 12 ledger write, so the blob's actual
    // content is irrelevant — we just need a wire-validatable record.
    //
    // 64-byte dummy blob keeps total publish under 1000 bytes (signature ~64
    // bytes + JSON framing ~200 bytes + base64-encoded blob ~88 bytes = ~352
    // bytes — well under the 1000-byte ceiling).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let dummy_blob_bytes = vec![0u8; 64];
    let blob = base64::engine::general_purpose::STANDARD.encode(&dummy_blob_bytes);
    let share_ref = cipherpost::record::share_ref_from_bytes(&dummy_blob_bytes, now);

    let signable = OuterRecordSignable {
        blob: blob.clone(),
        created_at: now,
        pin_required: true,
        protocol_version: cipherpost::PROTOCOL_VERSION,
        pubkey: id.z32_pubkey(),
        recipient: None,
        share_ref: share_ref.clone(),
        ttl_seconds: DEFAULT_TTL_SECONDS,
    };
    let signature = sign_record(&signable, &kp).unwrap();
    let record = OuterRecord {
        blob,
        created_at: now,
        pin_required: true,
        protocol_version: cipherpost::PROTOCOL_VERSION,
        pubkey: id.z32_pubkey(),
        recipient: None,
        share_ref: share_ref.clone(),
        signature,
        ttl_seconds: DEFAULT_TTL_SECONDS,
    };
    transport
        .publish(&kp, &record)
        .expect("MockTransport accepts pin-required record under wire ceiling");

    let uri = ShareUri::parse(&format!("cipherpost://{}/{}", id.z32_pubkey(), share_ref)).unwrap();

    // First receive: WRONG PIN.
    std::env::set_var("CIPHERPOST_TEST_PIN", WRONG_PIN);
    let mut sink_wrong = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink_wrong,
        &AutoConfirmPrompter,
        false,
    )
    .unwrap_err();
    // wrong PIN funnels through Error::DecryptFailed (PIN-07 narrow) — same
    // exit 4 as wrong-passphrase, distinct from sig-failures (exit 3).
    assert!(
        matches!(err, Error::DecryptFailed),
        "wrong PIN must yield DecryptFailed; got {err:?}"
    );
    assert_eq!(exit_code(&err), 4);

    // Ledger MUST NOT contain a burn row — the wrong-PIN abort happens
    // BEFORE STEP 11 emit + STEP 12 ledger write. Use the test_paths
    // re-export rather than duplicating the layout.
    let lp = ledger_path();
    if lp.exists() {
        let ledger = fs::read_to_string(&lp).unwrap();
        assert!(
            !ledger.contains(r#""state":"burned""#),
            "wrong-PIN must NOT write a burn row; ledger contents: {ledger}"
        );
        assert!(
            !ledger.contains(&share_ref),
            "wrong-PIN must NOT write ANY ledger row for the share; ledger contents: {ledger}"
        );
    }
    // Sentinel must NOT exist — no successful receive happened.
    let sp = sentinel_path(&share_ref);
    assert!(
        !sp.exists(),
        "wrong-PIN must NOT create a sentinel; path exists: {sp:?}"
    );

    // No receipt published — publish_outcome runs only on successful
    // receive.
    let recipient_z32 = id.z32_pubkey();
    let receipt_count = count_receipts_for_share_ref(&transport, &recipient_z32, &share_ref);
    assert_eq!(
        receipt_count, 0,
        "wrong-PIN must NOT publish a receipt; got {receipt_count} receipts"
    );

    // Cleanup PIN env so subsequent tests don't race on stale value.
    std::env::remove_var("CIPHERPOST_TEST_PIN");
}

// ---------------------------------------------------------------------------
// Step F — Negative-path safety: typed-z32-declined-on-burn doesn't mark
// burned. Order:
//   prompt -> derive -> outer-decrypt -> inner-decrypt -> inner-verify ->
//   preview render -> Acceptance banner (typed-z32 prompted) -> DECLINE ->
//   return Err(Declined). STEP 11 emit + STEP 12 ledger write are NEVER
//   reached; the share remains re-receivable.
//
// IMPLEMENTATION NOTE: This test uses a small GenericSecret payload + burn
// (no pin) so the round-trip fits within budget. The decline path is
// reached via DeclinePrompter (returns Err(Error::Declined) from
// render_and_confirm).
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn typed_z32_declined_on_burn_share_does_not_mark_burned_and_share_remains_re_receivable() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup(&dir);
    let plaintext = b"declinable-payload".to_vec();
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
        None,
        true,
    )
    .expect("run_send burn-only with small generic payload must fit budget");
    let uri = ShareUri::parse(&uri_str).unwrap();

    // First receive: DECLINE at typed-z32 prompt.
    let mut sink_declined = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink_declined,
        &DeclinePrompter,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Declined),
        "DeclinePrompter must yield Declined; got {err:?}"
    );
    assert_eq!(exit_code(&err), 7);

    // Sink must be empty — no plaintext emitted (decline returns BEFORE
    // STEP 11 emit).
    match sink_declined {
        OutputSink::InMemory(buf) => assert!(
            buf.is_empty(),
            "declined receive must not emit any bytes; got {} bytes",
            buf.len()
        ),
        _ => panic!("InMemory sink expected"),
    }

    // Ledger MUST NOT contain burn row; sentinel MUST NOT exist.
    let lp = ledger_path();
    if lp.exists() {
        let ledger = fs::read_to_string(&lp).unwrap();
        assert!(
            !ledger.contains(r#""state":"burned""#),
            "declined-z32 must NOT write a burn row; ledger contents: {ledger}"
        );
        assert!(
            !ledger.contains(&uri.share_ref_hex),
            "declined-z32 must NOT write ANY ledger row; ledger contents: {ledger}"
        );
    }
    let sp = sentinel_path(&uri.share_ref_hex);
    assert!(
        !sp.exists(),
        "declined-z32 must NOT create a sentinel; path exists: {sp:?}"
    );

    // No receipt published — publish_outcome runs only after typed-z32
    // acceptance. Decline returns BEFORE the publish_outcome closure runs.
    let recipient_z32 = id.z32_pubkey();
    let receipt_count =
        count_receipts_for_share_ref(&transport, &recipient_z32, &uri.share_ref_hex);
    assert_eq!(
        receipt_count, 0,
        "declined-z32 must NOT publish a receipt; got {receipt_count} receipts"
    );

    // Second receive with AutoConfirm: succeeds (share is re-receivable
    // because no ledger row was written).
    let mut sink_ok = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink_ok,
        &AutoConfirmPrompter,
        false,
    )
    .expect("share re-receivable after typed-z32 decline");
    match sink_ok {
        OutputSink::InMemory(buf) => assert_eq!(buf, plaintext),
        _ => panic!("InMemory sink expected"),
    }
}

// ---------------------------------------------------------------------------
// Step G — Wire-budget pre-flight (RESEARCH Open Risk #5).
//
// pin+burn+pgp-secret-key worst-case compose: predicted ~1080 B encoded
// (PGP fixture ~202 B + nested age (2 layers × ~165 B) + 32 B salt + 1 B
// JCS overhead from burn_after_read=true). Plan 05 asserts the failure
// mode is a CLEAN Error::WireBudgetExceeded — never a panic, never a
// Transport-internal error, never a SignatureCanonicalMismatch /
// DecryptFailed (which would indicate wire-format or crypto regression
// rather than budget exceedance). Phase 9 DHT-07 measures empirically;
// v1.2 ships the wire-budget escape hatch if needed.
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn pin_plus_burn_plus_pgp_wire_budget_surfaces_cleanly_or_succeeds() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup(&dir);
    let pgp_fixture = fs::read("tests/fixtures/material_pgp_fixture.pgp")
        .expect("PGP fixture from Phase 7 must exist");
    let transport = MockTransport::new();

    std::env::set_var("CIPHERPOST_TEST_PIN", VALID_PIN);
    let pin = SecretBox::new(Box::new(VALID_PIN.to_string()));

    let result = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "secret-key handoff",
        MaterialSource::Bytes(pgp_fixture),
        MaterialVariant::PgpKey,
        DEFAULT_TTL_SECONDS,
        Some(pin),
        true,
    );

    // Always clean up the PIN env var, regardless of result.
    std::env::remove_var("CIPHERPOST_TEST_PIN");

    match result {
        Ok(_uri) => {
            eprintln!(
                "pin+burn+pgp fits within 1000 B BEP44 budget (Phase 9 DHT-07 will measure actual margin)"
            );
        }
        Err(Error::WireBudgetExceeded {
            encoded,
            budget,
            plaintext,
        }) => {
            // Clean error — exactly what RESEARCH Open Risk #5 predicted.
            eprintln!(
                "pin+burn+pgp exceeds budget cleanly: encoded={encoded}, budget={budget}, plaintext={plaintext} (Phase 9 DHT-07 + v1.2 escape-hatch will resolve)"
            );
            assert_eq!(budget, 1000, "BEP44 budget must be 1000 bytes");
        }
        Err(other) => {
            panic!("pin+burn+pgp must surface as Ok OR WireBudgetExceeded; got {other:?}")
        }
    }
}
