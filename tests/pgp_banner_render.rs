//! PGP-04: golden-string tests for preview::render_pgp_preview.
//!
//! Pins:
//!   - Line-prefix ordering (separator + 5 field lines)
//!   - SECRET-key warning placement for tag-5 inputs
//!   - Fingerprint hex length (40 for v4, 64 for v5/v6) — UPPER case via
//!     rpgp's Fingerprint UpperHex impl
//!   - UID content
//!   - No leading/trailing newline
//!   - Separator dash count = 53

use cipherpost::preview;

const FIXTURE_PGP_PUBLIC: &[u8] = include_bytes!("fixtures/material_pgp_fixture.pgp");
const FIXTURE_PGP_SECRET: &[u8] = include_bytes!("fixtures/material_pgp_secret_fixture.pgp");

#[test]
fn render_pgp_preview_public_key_contains_all_expected_fields() {
    let s = preview::render_pgp_preview(FIXTURE_PGP_PUBLIC).expect("valid fixture");
    let lines: Vec<&str> = s.lines().collect();

    assert!(
        lines[0].starts_with("--- OpenPGP "),
        "line 0 separator, got: {:?}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("Fingerprint: "),
        "line 1, got: {:?}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("Primary UID: "),
        "line 2, got: {:?}",
        lines[2]
    );
    assert!(
        lines[3].starts_with("Key:         "),
        "line 3, got: {:?}",
        lines[3]
    );
    assert!(
        lines[4].starts_with("Subkeys:     "),
        "line 4, got: {:?}",
        lines[4]
    );
    assert!(
        lines[5].starts_with("Created:     "),
        "line 5, got: {:?}",
        lines[5]
    );
}

#[test]
fn render_pgp_preview_public_key_no_warning_line() {
    let s = preview::render_pgp_preview(FIXTURE_PGP_PUBLIC).unwrap();
    assert!(
        !s.starts_with("[WARNING:"),
        "public-key fixture must NOT have a SECRET warning line, got: {:?}",
        &s[..s.len().min(80)]
    );
    assert!(
        s.starts_with("--- OpenPGP "),
        "public-key preview must start directly with separator"
    );
}

#[test]
fn render_pgp_preview_secret_key_includes_warning_line() {
    let s = preview::render_pgp_preview(FIXTURE_PGP_SECRET).expect("valid secret fixture");
    assert!(
        s.starts_with("[WARNING: SECRET key — unlocks cryptographic operations]\n\n--- OpenPGP "),
        "secret-key preview must start with the SECRET warning line + blank + separator, got: {:?}",
        &s[..s.len().min(120)]
    );
}

#[test]
fn render_pgp_preview_fingerprint_matches_expected_v4_40_hex() {
    let s = preview::render_pgp_preview(FIXTURE_PGP_PUBLIC).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    let fp_line = lines[1]; // "Fingerprint: <hex>"
    let hex = fp_line.trim_start_matches("Fingerprint: ");
    assert_eq!(
        hex.len(),
        40,
        "v4 Ed25519 fingerprint must be 40 hex chars (SHA-1 over key material), got {} chars: {}",
        hex.len(),
        hex
    );
    // rpgp's Fingerprint UpperHex impl emits UPPER-case (hex::encode_upper) per
    // 07-02-SUMMARY hand-off note. Asserting upper-case avoids drift if future
    // rpgp versions change the case convention.
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_uppercase())),
        "fingerprint must be UPPER-case hex (rpgp Fingerprint UpperHex impl), got: {hex}"
    );
}

#[test]
fn render_pgp_preview_uid_contains_fixture_identity() {
    let s = preview::render_pgp_preview(FIXTURE_PGP_PUBLIC).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    // Fixture UID is "cp <f@cp.t>" (10 chars). Match contained substring rather
    // than exact equality — the prefix is locked, the suffix is the UID.
    assert!(
        lines[2].contains("cp <f@cp.t>"),
        "Primary UID line must contain the fixture's UID, got: {:?}",
        lines[2]
    );
}

#[test]
fn render_pgp_preview_no_leading_or_trailing_newline() {
    let s = preview::render_pgp_preview(FIXTURE_PGP_PUBLIC).unwrap();
    assert!(
        !s.starts_with('\n'),
        "public preview must NOT start with newline"
    );
    assert!(
        !s.ends_with('\n'),
        "public preview must NOT end with newline"
    );

    let s = preview::render_pgp_preview(FIXTURE_PGP_SECRET).unwrap();
    assert!(
        s.starts_with('['),
        "secret preview starts with [WARNING: — not a newline"
    );
    assert!(
        !s.ends_with('\n'),
        "secret preview must NOT end with newline"
    );
}

#[test]
fn render_pgp_preview_separator_line_is_53_dashes_after_prefix() {
    let s = preview::render_pgp_preview(FIXTURE_PGP_PUBLIC).unwrap();
    let sep_line = s.lines().next().unwrap();
    assert!(sep_line.starts_with("--- OpenPGP "), "prefix check");
    let dashes = &sep_line["--- OpenPGP ".len()..];
    assert_eq!(
        dashes.len(),
        53,
        "separator dash count must be 53, got {}",
        dashes.len()
    );
    assert!(
        dashes.chars().all(|c| c == '-'),
        "separator must be all dashes"
    );
}
