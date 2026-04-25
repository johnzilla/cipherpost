//! Phase 8 Plan 02 (PIN-02): validate_pin matrix.
//!
//! Asserts the entropy floor + anti-pattern + blocklist rejection rules and
//! the oracle-hygiene invariant that EVERY rejection produces the identical
//! generic Display literal — `"PIN does not meet entropy requirements"` —
//! regardless of which specific check fired (PITFALLS #23/#24 / D-P8-12
//! supersession of REQUIREMENTS PIN-02 wording).

use cipherpost::error::{exit_code, Error};
use cipherpost::pin::validate_pin;

const REJECT_MSG: &str = "PIN does not meet entropy requirements";

fn assert_rejected(pin: &str) {
    match validate_pin(pin).unwrap_err() {
        Error::Config(msg) => assert_eq!(
            msg,
            REJECT_MSG,
            "PIN rejection produced non-generic Display (oracle leak): pin len={} msg={:?}",
            pin.len(),
            msg
        ),
        other => panic!("PIN rejection wrong variant: {:?}", other),
    }
}

#[test]
fn rejects_too_short() {
    for s in &["", "a", "ab", "abcdefg"] {
        assert_rejected(s);
    }
}

#[test]
fn rejects_all_same() {
    for s in &["aaaaaaaa", "00000000", "ZZZZZZZZ", "!!!!!!!!"] {
        assert_rejected(s);
    }
}

#[test]
fn rejects_ascending() {
    for s in &["12345678", "abcdefgh", "0123456789"] {
        assert_rejected(s);
    }
}

#[test]
fn rejects_descending() {
    for s in &["87654321", "hgfedcba", "9876543210"] {
        assert_rejected(s);
    }
}

#[test]
fn rejects_blocklist() {
    for s in &[
        "password", "PASSWORD", "Password", "qwertyui", "QWERTYUI", "letmein", "LetMeIn",
        "asdfghjk",
    ] {
        assert_rejected(s);
    }
}

#[test]
fn accepts_strong_pins() {
    for s in &[
        "validpin1",
        "correct-horse",
        "cp@8h0rse",
        "ZxCvBnM!",
        "T3st-PIN!",
    ] {
        validate_pin(s).unwrap_or_else(|e| panic!("strong PIN {:?} was rejected: {:?}", s, e));
    }
}

#[test]
fn rejection_maps_to_exit_1() {
    // PIN-02: validation failure is exit 1 (Config), NOT exit 4 (DecryptFailed).
    let err = validate_pin("short").unwrap_err();
    assert_eq!(
        exit_code(&err),
        1,
        "validate_pin rejection must map to exit 1 (Error::Config), got exit {}",
        exit_code(&err)
    );
}

#[test]
fn display_is_generic_across_all_rejection_classes() {
    // Each class of rejection (length / all-same / ascending / descending /
    // blocklist) must produce the IDENTICAL Display string. Oracle hygiene:
    // an attacker cannot tell which check fired from the user-facing output.
    let samples = [
        "short",    // length
        "aaaaaaaa", // all-same
        "12345678", // ascending (also blocklist)
        "87654321", // descending (also blocklist)
        "password", // blocklist
    ];
    let mut displays = Vec::new();
    for s in &samples {
        let e = validate_pin(s).unwrap_err();
        displays.push(format!("{}", e));
    }
    let first = &displays[0];
    for d in &displays {
        assert_eq!(
            d, first,
            "PIN rejection Display strings diverge — oracle hygiene violated"
        );
    }
    // The inner Config(_) string is the generic literal; full Display also
    // contains the variant's `#[error("configuration error: {0}")]` prefix.
    // Both invariants matter: (a) inner literal is generic and constant
    // across rejection classes, (b) full Display is constant across classes.
    assert!(
        first.contains(REJECT_MSG),
        "Display must embed generic reject literal, got {:?}",
        first
    );
}
