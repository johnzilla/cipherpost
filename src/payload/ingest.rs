//! src/payload/ingest.rs — Phase 6 raw-bytes → typed Material normalization.
//!
//! `x509_cert(raw)` sniffs PEM vs DER, normalizes PEM → DER, validates via
//! `x509-parser`'s strict-DER profile, and explicitly rejects trailing bytes
//! after the certificate (D-P6-07). Returns `Material::X509Cert { bytes: canonical_der }`.
//!
//! The `bytes` field always carries canonical DER regardless of CLI input format
//! (X509-01 invariant) — so `share_ref` remains deterministic across re-sends
//! of semantically identical certs.
//!
//! Error contract: every failure path returns `Error::InvalidMaterial { variant,
//! reason }` with a short, generic `reason` string. NEVER wrap an `x509-parser`
//! error chain — the `reason: String` is the oracle-hygiene gate (D-P6-03 /
//! X509-08).
//!
//! Pitfalls addressed:
//!   #19 — X.509 BER / PEM / DER non-canonicity: x509-parser's strict profile
//!         rejects indefinite-length BER; trailing-bytes check catches
//!         concatenated-cert attacks.
//!   #7  — no leakage of parser internals via Display.

use super::Material;
use crate::error::Error;

/// Trivial wrapper for symmetry with `x509_cert()`. `run_send` dispatches through
/// this function for the GenericSecret branch so the call site is uniform.
pub fn generic_secret(bytes: Vec<u8>) -> Result<Material, Error> {
    Ok(Material::GenericSecret { bytes })
}

/// Normalize raw bytes (DER or PEM) into a canonical-DER `Material::X509Cert`.
///
/// Pipeline:
///   1. Sniff: after `trim_start()`, does the input start with `-----BEGIN CERTIFICATE-----`?
///      Yes → PEM path; no → DER path. (D-P6-06)
///   2. PEM path: `x509_parser::pem::parse_x509_pem` → `pem.contents` is the DER bytes.
///      Reject if `pem.label != "CERTIFICATE"`.
///   3. DER path: treat input as DER directly.
///   4. Parse DER via `x509_parser::parse_x509_certificate` — this is the strict-profile
///      BER rejection per D-P6-07.
///   5. Assert the parser consumed the entire input (trailing-bytes check, D-P6-07).
///   6. Return `Material::X509Cert { bytes: <canonical DER> }`.
pub fn x509_cert(raw: &[u8]) -> Result<Material, Error> {
    // Sniff — find the first non-whitespace byte and check for PEM header.
    // trim_start is on &str but our input is &[u8]; hand-roll a whitespace-skip
    // that only skips ASCII whitespace (matches trim_start's behavior on ASCII).
    let first_non_ws = raw
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let trimmed = &raw[first_non_ws..];
    let is_pem = trimmed.starts_with(b"-----BEGIN CERTIFICATE-----");

    let der_bytes: Vec<u8> = if is_pem {
        // PEM path
        let (pem_rem, pem) =
            x509_parser::pem::parse_x509_pem(raw).map_err(|_| Error::InvalidMaterial {
                variant: "x509_cert".into(),
                reason: "PEM body decode failed".into(),
            })?;
        if pem.label != "CERTIFICATE" {
            return Err(Error::InvalidMaterial {
                variant: "x509_cert".into(),
                reason: "PEM label is not CERTIFICATE".into(),
            });
        }
        // D-P6-07 for the PEM path: reject trailing bytes after the first
        // `-----END CERTIFICATE-----`. `parse_x509_pem` decodes only the first
        // PEM block; without this check a concatenated-cert input like
        // `<cert-A-PEM>\n<cert-B-PEM>\n` would silently ingest cert A and
        // discard cert B, contradicting the trailing-bytes invariant the
        // module docstring promises across BOTH DER and PEM paths.
        if pem_rem.iter().any(|b| !b.is_ascii_whitespace()) {
            return Err(Error::InvalidMaterial {
                variant: "x509_cert".into(),
                reason: "trailing bytes after certificate".into(),
            });
        }
        pem.contents
    } else {
        // DER path
        raw.to_vec()
    };

    // Strict-DER validation + trailing-bytes check (D-P6-07).
    let (remainder, _cert) =
        x509_parser::parse_x509_certificate(&der_bytes).map_err(|_| Error::InvalidMaterial {
            variant: "x509_cert".into(),
            reason: "malformed DER".into(),
        })?;
    if !remainder.is_empty() {
        return Err(Error::InvalidMaterial {
            variant: "x509_cert".into(),
            reason: "trailing bytes after certificate".into(),
        });
    }

    Ok(Material::X509Cert { bytes: der_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal valid DER certificate fixture is generated and checked in by
    // Plan 04 at tests/fixtures/x509_cert_fixture.der. For unit tests here,
    // use a self-signed cert generated via openssl and inlined as bytes to
    // avoid a test-time filesystem dep inside this module. The full
    // integration suite (round-trip + JCS-fixture) lives in plan 04's tests.

    // Placeholder — Plan 04 adds `tests/material_x509_ingest.rs` covering:
    //   - happy DER path
    //   - happy PEM path (LF + CRLF line endings)
    //   - PEM wrong label rejected
    //   - malformed DER rejected
    //   - trailing bytes rejected
    //   - generic_secret() returns GenericSecret variant
    //
    // This inline block only asserts the trivial generic_secret() path so
    // `cargo test --lib` has something green without a fixture file.

    #[test]
    fn generic_secret_wraps_input_bytes() {
        let m = generic_secret(vec![1, 2, 3]).unwrap();
        match m {
            Material::GenericSecret { bytes } => assert_eq!(bytes, vec![1, 2, 3]),
            other => panic!("expected GenericSecret, got {:?}", other),
        }
    }

    #[test]
    fn x509_cert_malformed_der_returns_invalid_material() {
        let err = x509_cert(b"this is not a DER cert").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "x509_cert");
                assert_eq!(reason, "malformed DER");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn x509_cert_non_pem_non_der_empty_input_rejected() {
        // Empty input: falls to DER path, parse fails -> malformed DER.
        let err = x509_cert(b"").unwrap_err();
        assert!(matches!(err, Error::InvalidMaterial { .. }));
    }
}
