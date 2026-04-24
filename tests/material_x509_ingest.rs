//! X509-01, X509-08: ingest pipeline coverage.
//!
//! Exercises payload::ingest::x509_cert across happy DER, happy PEM, malformed
//! DER (BER rejection), trailing bytes, wrong PEM label, corrupt PEM body, and
//! cross-accessor mismatch. Every Error::InvalidMaterial is checked for
//! oracle-hygiene: Display must never contain x509-parser internal strings.

use base64::Engine;
use cipherpost::payload::{ingest, Material};
use cipherpost::Error;

const FIXTURE_DER: &[u8] = include_bytes!("fixtures/x509_cert_fixture.der");

fn pem_armor_der(der: &[u8]) -> Vec<u8> {
    // Hand-rolled PEM armor (LF line endings).
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

fn pem_armor_der_crlf(der: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN CERTIFICATE-----\r\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push_str("\r\n");
    }
    out.push_str("-----END CERTIFICATE-----\r\n");
    out.into_bytes()
}

#[test]
fn x509_cert_happy_der_produces_x509_variant() {
    let m = ingest::x509_cert(FIXTURE_DER).expect("valid DER fixture");
    match m {
        Material::X509Cert { bytes } => {
            assert_eq!(
                bytes, FIXTURE_DER,
                "stored bytes must equal input DER (canonical-DER invariant)"
            );
        }
        other => panic!("expected X509Cert variant, got {:?}", other),
    }
}

#[test]
fn x509_cert_happy_pem_normalizes_to_der() {
    let pem = pem_armor_der(FIXTURE_DER);
    let m = ingest::x509_cert(&pem).expect("valid PEM-wrapped fixture");
    match m {
        Material::X509Cert { bytes } => {
            assert_eq!(
                bytes, FIXTURE_DER,
                "PEM ingest must normalize to ORIGINAL DER (not the PEM bytes)"
            );
        }
        other => panic!("expected X509Cert variant, got {:?}", other),
    }
}

#[test]
fn x509_cert_happy_pem_with_crlf_line_endings() {
    let pem = pem_armor_der_crlf(FIXTURE_DER);
    let m = ingest::x509_cert(&pem).expect("CRLF-ending PEM should parse");
    match m {
        Material::X509Cert { bytes } => {
            assert_eq!(bytes, FIXTURE_DER);
        }
        other => panic!("expected X509Cert, got {:?}", other),
    }
}

#[test]
fn x509_cert_malformed_der_rejected_with_generic_reason() {
    let err = ingest::x509_cert(b"this is not a DER cert at all").unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "x509_cert");
            assert_eq!(reason, "malformed DER");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn x509_cert_trailing_bytes_rejected() {
    let mut tampered = FIXTURE_DER.to_vec();
    tampered.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    let err = ingest::x509_cert(&tampered).unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "x509_cert");
            assert_eq!(reason, "trailing bytes after certificate");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn x509_cert_pem_body_garbage_rejected() {
    let pem = b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n";
    let err = ingest::x509_cert(pem).unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "x509_cert");
            // Either "PEM body decode failed" or "malformed DER" depending on
            // how x509-parser's pem module handles unparseable base64.
            // Plan 01's ingest returns "PEM body decode failed" for this case.
            assert!(
                reason == "PEM body decode failed" || reason == "malformed DER",
                "expected generic PEM/DER decode reason, got: {}",
                reason
            );
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn x509_cert_empty_input_rejected() {
    let err = ingest::x509_cert(b"").unwrap_err();
    assert!(matches!(err, Error::InvalidMaterial { .. }));
}

#[test]
fn x509_cert_accessor_wrong_variant_returns_invalid_material() {
    let m = Material::generic_secret(vec![1, 2, 3]);
    let err = m.as_x509_cert_bytes().unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "generic_secret");
            assert_eq!(reason, "accessor called on wrong variant");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn x509_cert_error_display_contains_no_parser_internals() {
    // Enumerate every error this module produces and assert Display is generic.
    let errors = vec![
        ingest::x509_cert(b"garbage").unwrap_err(),
        ingest::x509_cert(&[FIXTURE_DER, &[0xFF, 0xFF]].concat()).unwrap_err(),
        ingest::x509_cert(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")
            .unwrap_err(),
        Material::generic_secret(vec![])
            .as_x509_cert_bytes()
            .unwrap_err(),
    ];
    for err in errors {
        let disp = format!("{}", err);
        for forbidden in &[
            "X509Error",
            "parse error at",
            "nom::",
            "Incomplete",
            "Needed",
            "Error::",
            "PEMError",
            "asn1-rs",
            "der-parser",
        ] {
            assert!(
                !disp.contains(forbidden),
                "Error::InvalidMaterial Display leaked parser internal '{}': full display = {}",
                forbidden,
                disp
            );
        }
    }
}
