//! PGP-01, PGP-03, PGP-08: ingest pipeline coverage.
//!
//! Exercises payload::ingest::pgp_key across happy-path binary input, armor
//! rejection (public/private/signature blocks), multi-primary keyring
//! rejection with N count, malformed, trailing-bytes, empty, cross-variant
//! accessor mismatch, and Display oracle hygiene.

use cipherpost::payload::{ingest, Material};
use cipherpost::Error;

const FIXTURE_PGP: &[u8] = include_bytes!("fixtures/material_pgp_fixture.pgp");

/// Hand-rolled ASCII-armor wrapper for testing armor-reject paths.
/// Emits the classic PGP armor envelope around arbitrary bytes (they need not
/// be valid PGP — the strict-prefix sniff in ingest rejects before any parse).
fn pgp_armor_wrap(bytes: &[u8], block: &str) -> Vec<u8> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN PGP {}-----\n", block));
    out.push_str("Version: CipherpostTest\n\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END PGP {}-----\n", block));
    out.into_bytes()
}

#[test]
fn pgp_key_happy_path_produces_pgp_variant() {
    let m = ingest::pgp_key(FIXTURE_PGP).expect("valid PGP fixture");
    match m {
        Material::PgpKey { bytes } => {
            assert_eq!(
                bytes, FIXTURE_PGP,
                "PGP ingest must store input bytes verbatim (no canonical re-encode)"
            );
        }
        other => panic!("expected PgpKey variant, got {:?}", other),
    }
}

#[test]
fn pgp_key_armor_public_block_rejected() {
    let armored = pgp_armor_wrap(FIXTURE_PGP, "PUBLIC KEY BLOCK");
    let err = ingest::pgp_key(&armored).unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "pgp_key");
            assert_eq!(
                reason,
                "ASCII-armored input rejected — supply binary packet stream"
            );
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn pgp_key_armor_private_block_rejected() {
    let armored = pgp_armor_wrap(FIXTURE_PGP, "PRIVATE KEY BLOCK");
    let err = ingest::pgp_key(&armored).unwrap_err();
    match err {
        Error::InvalidMaterial { reason, .. } => {
            assert_eq!(
                reason,
                "ASCII-armored input rejected — supply binary packet stream"
            );
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn pgp_key_armor_signature_block_rejected() {
    // Strict `-----BEGIN PGP` prefix catches all PGP armor types, including
    // ones that aren't keys — we reject anything that looks like PGP armor.
    let armored = pgp_armor_wrap(b"signature bytes", "SIGNATURE");
    let err = ingest::pgp_key(&armored).unwrap_err();
    match err {
        Error::InvalidMaterial { reason, .. } => {
            assert_eq!(
                reason,
                "ASCII-armored input rejected — supply binary packet stream"
            );
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn pgp_key_multi_primary_rejected() {
    // Concatenate the fixture with itself — two top-level primary public key
    // packets (tag 6) present. D-P7-06 / PGP-03 requires rejection with the
    // count substituted.
    let mut combined = FIXTURE_PGP.to_vec();
    combined.extend_from_slice(FIXTURE_PGP);
    let err = ingest::pgp_key(&combined).unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "pgp_key");
            assert!(
                reason.starts_with("PgpKey must contain exactly one primary key"),
                "reason must start with the canonical prefix, got: {}",
                reason
            );
            assert!(
                reason.contains("found 2 primary keys"),
                "reason must include substituted count 'found 2', got: {}",
                reason
            );
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn pgp_key_malformed_packet_rejected_with_generic_reason() {
    let err = ingest::pgp_key(b"this is not a PGP packet stream at all").unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "pgp_key");
            // Curated literals only — either malformed or trailing-bytes is acceptable
            // depending on how PacketParser interprets the byte soup. Both are oracle-clean.
            assert!(
                reason == "malformed PGP packet stream"
                    || reason == "trailing bytes after PGP packet stream",
                "expected curated reason literal, got: {}",
                reason
            );
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn pgp_key_trailing_bytes_rejected() {
    let mut tampered = FIXTURE_PGP.to_vec();
    tampered.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    let err = ingest::pgp_key(&tampered).unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "pgp_key");
            assert_eq!(reason, "trailing bytes after PGP packet stream");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn pgp_key_empty_input_rejected() {
    let err = ingest::pgp_key(b"").unwrap_err();
    assert!(matches!(err, Error::InvalidMaterial { .. }));
}

#[test]
fn pgp_key_accessor_wrong_variant_returns_invalid_material() {
    let m = Material::generic_secret(vec![1, 2, 3]);
    let err = m.as_pgp_key_bytes().unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "generic_secret");
            assert_eq!(reason, "accessor called on wrong variant");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn pgp_key_error_display_contains_no_parser_internals() {
    let forbidden: &[&str] = &[
        "pgp::errors",
        "PgpError",
        "packet::Error",
        "pgp::Error",
        "Incomplete",
        "Needed",
        "pgp::packet",
        "rpgp",
    ];

    let errors = vec![
        ingest::pgp_key(b"garbage").unwrap_err(),
        ingest::pgp_key(b"").unwrap_err(),
        ingest::pgp_key(&pgp_armor_wrap(b"x", "PUBLIC KEY BLOCK")).unwrap_err(),
        {
            let mut tampered = FIXTURE_PGP.to_vec();
            tampered.extend_from_slice(&[0xFF]);
            ingest::pgp_key(&tampered).unwrap_err()
        },
        {
            let mut combined = FIXTURE_PGP.to_vec();
            combined.extend_from_slice(FIXTURE_PGP);
            ingest::pgp_key(&combined).unwrap_err()
        },
    ];

    for err in errors {
        let disp = format!("{}", err);
        for tok in forbidden {
            assert!(
                !disp.contains(tok),
                "PGP ingest Error::Display leaked forbidden token '{}' in: {:?}",
                tok,
                disp
            );
        }
    }
}
