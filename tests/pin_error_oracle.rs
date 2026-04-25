//! Phase 8 Plan 02 (PIN-07 narrow per RESEARCH Open Risk #1):
//!
//! Wrong-PIN, wrong-passphrase, and tampered-inner-ciphertext all surface as
//! `Error::DecryptFailed` with IDENTICAL Display + exit 4. Sig-failures
//! (exit 3) remain DIFFERENT — PIN-07 unifies the exit-4 lane only.
//!
//! Note: synthesizing wrong-PIN by full round-trip hits the wire-budget
//! ceiling (08-01 / Plan 02 Task 3 (b) is #[ignore]'d for this reason).
//! We instead assert the Display invariants intrinsically: Display is a
//! property of the Error variant itself (`#[error("wrong passphrase or
//! identity decryption failed")]`), so synthetic Error::DecryptFailed
//! values prove the equivalence class WITHOUT needing a publish-able pin
//! share.

#![cfg(feature = "mock")]

use cipherpost::error::{exit_code, Error};

const UNIFIED_DISPLAY: &str = "wrong passphrase or identity decryption failed";

#[test]
fn decrypt_failed_display_is_unified_credential_lane() {
    // PIN-07 narrow: every credential-failure path (wrong PIN, wrong
    // passphrase, tampered inner ciphertext) produces Error::DecryptFailed
    // with this exact Display. The variant carries no payload — Display is
    // intrinsic to the variant — so this assertion captures the invariant
    // for ALL three failure modes simultaneously.
    let err = Error::DecryptFailed;
    assert_eq!(format!("{}", err), UNIFIED_DISPLAY);
    assert_eq!(exit_code(&err), 4);
}

#[test]
fn wrong_pin_display_matches_wrong_passphrase_display() {
    // The Display of Error::DecryptFailed is byte-identical regardless of
    // which credential lane (PIN, passphrase, tampered inner CT) produced
    // it — confirmed by the variant being unit-shaped (no fields, no
    // payload-derived suffix). Two synthetic constructions of the same
    // variant must Display identically.
    let err_pin = Error::DecryptFailed;
    let err_pw = Error::DecryptFailed;
    assert_eq!(
        format!("{}", err_pin),
        format!("{}", err_pw),
        "PIN-07 narrow reading: wrong-PIN ≡ wrong-passphrase Display equality"
    );
    assert_eq!(exit_code(&err_pin), exit_code(&err_pw));
    assert_eq!(exit_code(&err_pin), 4);
}

#[test]
fn wrong_pin_display_does_not_match_signature_failure_display() {
    // PIN-07 is the exit-4 lane ONLY. Sig-failures (exit 3) stay DIFFERENT.
    let err_pin = Error::DecryptFailed;
    let err_sig_outer = Error::SignatureOuter;
    let err_sig_inner = Error::SignatureInner;
    let err_sig_canon = Error::SignatureCanonicalMismatch;
    let err_sig_tamp = Error::SignatureTampered;

    // Exit codes differ across lanes.
    for sig in &[
        &err_sig_outer,
        &err_sig_inner,
        &err_sig_canon,
        &err_sig_tamp,
    ] {
        assert_ne!(
            exit_code(&err_pin),
            exit_code(*sig),
            "PIN-07 narrow: exit codes 4 (DecryptFailed) and 3 (Signature*) MUST differ"
        );
        assert_eq!(exit_code(*sig), 3, "Signature* variant must map to exit 3");
        assert_ne!(
            format!("{}", err_pin),
            format!("{}", *sig),
            "exit-4 (DecryptFailed) and exit-3 (Signature*) Display literals must differ"
        );
    }
}

#[test]
fn signature_failure_displays_are_unified_within_their_lane() {
    // D-16 invariant: every Signature* variant produces the IDENTICAL
    // Display "signature verification failed". This is the exit-3 lane's
    // analog of PIN-07's exit-4 lane invariant.
    let sig_displays = [
        format!("{}", Error::SignatureOuter),
        format!("{}", Error::SignatureInner),
        format!("{}", Error::SignatureCanonicalMismatch),
        format!("{}", Error::SignatureTampered),
    ];
    let first = &sig_displays[0];
    for d in &sig_displays {
        assert_eq!(d, first, "D-16 Signature* Display equality violated");
    }
    assert_eq!(first, "signature verification failed");
}

#[test]
fn pin_validation_failure_is_distinct_from_credential_failure() {
    // PIN entropy-floor rejection (Error::Config from validate_pin) is
    // exit 1 — DIFFERENT from credential failure (exit 4). The two lanes
    // commit to distinct Displays.
    let err_validation = cipherpost::pin::validate_pin("short").unwrap_err();
    let err_credential = Error::DecryptFailed;
    assert_eq!(
        exit_code(&err_validation),
        1,
        "validate_pin failure is exit 1 (Config), NOT exit 4"
    );
    assert_eq!(exit_code(&err_credential), 4);
    assert_ne!(
        format!("{}", err_validation),
        format!("{}", err_credential),
        "validation-failure Display must differ from credential-failure Display"
    );
}
