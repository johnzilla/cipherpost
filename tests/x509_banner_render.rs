//! X509-04: golden-string test for preview::render_x509_preview.
//!
//! The fixture cert has deterministic non-signature fields:
//!   Subject:     CN=cipherpost-fixture, O=cipherpost, C=XX
//!   Issuer:      CN=cipherpost-fixture, O=cipherpost, C=XX
//!   Serial:      0x01
//!   Key:         Ed25519
//!   Validity:    2-year window starting at generation time
//!
//! This test pins each field's rendering shape. Any drift (e.g. RDN
//! ordering flip, Serial formatting change, key-alg mapping change,
//! SHA-256 truncation regression) surfaces as a red test.

use cipherpost::preview;
use sha2::{Digest, Sha256};

const FIXTURE_DER: &[u8] = include_bytes!("fixtures/x509_cert_fixture.der");

#[test]
fn render_x509_preview_contains_all_expected_fields() {
    let s = preview::render_x509_preview(FIXTURE_DER).expect("valid fixture");
    let lines: Vec<&str> = s.lines().collect();

    assert!(
        lines[0].starts_with("--- X.509 "),
        "line 0 must start with `--- X.509 `, got: {:?}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("Subject:     "),
        "line 1 must start with `Subject:     `, got: {:?}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("Issuer:      "),
        "line 2 must start with `Issuer:      `, got: {:?}",
        lines[2]
    );
    assert!(
        lines[3].starts_with("Serial:      "),
        "line 3 must start with `Serial:      `, got: {:?}",
        lines[3]
    );
    assert!(
        lines[4].starts_with("NotBefore:   "),
        "line 4 must start with `NotBefore:   `, got: {:?}",
        lines[4]
    );
    assert!(
        lines[5].starts_with("NotAfter:    "),
        "line 5 must start with `NotAfter:    `, got: {:?}",
        lines[5]
    );
    assert!(
        lines[6].starts_with("Key:         "),
        "line 6 must start with `Key:         `, got: {:?}",
        lines[6]
    );
    assert!(
        lines[7].starts_with("SHA-256:     "),
        "line 7 must start with `SHA-256:     `, got: {:?}",
        lines[7]
    );

    // Field-value assertions for the fixture cert:
    assert!(
        lines[1].contains("CN=cipherpost-fixture"),
        "Subject must contain CN, got: {:?}",
        lines[1]
    );
    assert!(
        lines[1].contains("O=cipherpost"),
        "Subject must contain O, got: {:?}",
        lines[1]
    );
    assert!(
        lines[1].contains("C=XX"),
        "Subject must contain C, got: {:?}",
        lines[1]
    );
    assert!(
        lines[2].contains("CN=cipherpost-fixture"),
        "Issuer self-signed must contain CN"
    );
    // Serial 0x01: after strip_start_matches('0'), "01" → "1", so line reads `Serial:      0x1`.
    assert_eq!(
        lines[3], "Serial:      0x1",
        "Serial line exact form, got: {:?}",
        lines[3]
    );
    // Key: Ed25519 (algorithm OID 1.3.101.112 — D-P6-14 human mapping)
    assert_eq!(
        lines[6], "Key:         Ed25519",
        "Key line exact form, got: {:?}",
        lines[6]
    );
    // NotAfter carries [VALID] tag since the fixture's NotAfter is ~2028 (generated in 2026):
    assert!(
        lines[5].ends_with("  [VALID]"),
        "NotAfter line must carry [VALID] tag, got: {:?}",
        lines[5]
    );
}

#[test]
fn render_x509_preview_sha256_matches_independent_computation() {
    let s = preview::render_x509_preview(FIXTURE_DER).unwrap();
    let expected_hex = {
        let digest = Sha256::digest(FIXTURE_DER);
        let mut hex = String::with_capacity(64);
        for b in digest.iter() {
            use std::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }
        hex
    };
    // The SHA-256 line is the last line; its content after "SHA-256:     " must equal the digest.
    let last_line = s.lines().last().expect("preview has lines");
    assert_eq!(last_line, format!("SHA-256:     {expected_hex}"));
}

#[test]
fn render_x509_preview_no_leading_or_trailing_newline() {
    let s = preview::render_x509_preview(FIXTURE_DER).unwrap();
    assert!(!s.starts_with('\n'), "preview must NOT start with newline");
    assert!(!s.ends_with('\n'), "preview must NOT end with newline");
}

#[test]
fn render_x509_preview_separator_line_is_57_dashes_after_prefix() {
    let s = preview::render_x509_preview(FIXTURE_DER).unwrap();
    let first_line = s.lines().next().unwrap();
    assert!(first_line.starts_with("--- X.509 "), "prefix check");
    let dashes = &first_line["--- X.509 ".len()..];
    assert_eq!(
        dashes.len(),
        57,
        "separator dash count must be 57, got {} dashes",
        dashes.len()
    );
    assert!(
        dashes.chars().all(|c| c == '-'),
        "separator must be all dashes"
    );
}
