//! src/preview.rs — Acceptance-banner subblock renderers for typed Material variants.
//!
//! Phase 6 ships `render_x509_preview(bytes)`. Phase 7 will add
//! `render_pgp_preview(bytes)` and `render_ssh_preview(bytes)` as siblings.
//!
//! Design invariants (D-P6-09, D-P6-13, D-P6-17):
//!   - Pure function: no I/O, no side effects. Returns `Result<String, Error>`.
//!   - `x509-parser` imports live ONLY in this module (not in payload, not in flow).
//!     `flow.rs::TtyPrompter::render_and_confirm` calls us via Plan 03's wiring.
//!   - No leading or trailing `\n` — caller owns outer banner layout.
//!   - Parse failures return `Error::InvalidMaterial { variant: "x509_cert",
//!     reason: "<short generic>" }` with NO x509-parser internal strings.
//!   - SHA-256 is computed over the canonical DER bytes passed in — matches
//!     `share_ref` determinism domain per D-P6-13.

use crate::error::Error;
use crate::flow::format_unix_as_iso_utc;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_NIST_EC_P521,
    OID_PKCS1_RSAENCRYPTION, OID_PKCS1_RSASSAPSS, OID_SIG_ED25519, OID_SIG_ED448,
};

/// Truncation limit for Subject / Issuer DN rendering (D-P6-10).
/// Keeps the 80-column TTY-friendly constraint with one `…` char budget.
const DN_TRUNC_LIMIT: usize = 80;

/// Truncation limit for hex SerialNumber (D-P6-11).
/// Short serials (≤16 hex) render whole; longer ones prepend `0x`, take the first 16 hex,
/// and append `… (truncated)`.
const SERIAL_HEX_TRUNC: usize = 16;

/// 57 dashes after `--- X.509 ` per CONTEXT.md §specifics (authoritative).
/// The full separator line reads `--- X.509 ` + 57 dashes = 61 chars, matching
/// the `===` banner border width.
const SEPARATOR_DASH_COUNT: usize = 57;

/// Render an X.509 acceptance-banner subblock from canonical DER cert bytes.
///
/// Returns a multi-line String (no leading or trailing newline) for the caller
/// (TtyPrompter) to emit between the `Size:` and `TTL:` banner lines.
///
/// Lines (in order):
///   - `--- X.509 ` + 57 dashes (61-char separator)
///   - `Subject:     <OpenSSL-forward DN, truncated ≤80 chars with …>`
///   - `Issuer:      <same format>`
///   - `Serial:      0x<hex, truncated at 16 hex chars with `… (truncated)`>`
///   - `NotBefore:   YYYY-MM-DD HH:MM UTC`
///   - `NotAfter:    YYYY-MM-DD HH:MM UTC  [VALID]` (or `[EXPIRED]`)
///   - `Key:         Ed25519 | RSA-2048 | ECDSA P-256 | ...` (or `<dotted.oid>`)
///   - `SHA-256:     <64 hex chars lowercase>`
pub fn render_x509_preview(bytes: &[u8]) -> Result<String, Error> {
    let (rem, cert) =
        x509_parser::parse_x509_certificate(bytes).map_err(|_| Error::InvalidMaterial {
            variant: "x509_cert".into(),
            reason: "malformed DER".into(),
        })?;
    if !rem.is_empty() {
        return Err(Error::InvalidMaterial {
            variant: "x509_cert".into(),
            reason: "trailing bytes after certificate".into(),
        });
    }

    let subject = truncate_display(&cert.subject().to_string(), DN_TRUNC_LIMIT);
    let issuer = truncate_display(&cert.issuer().to_string(), DN_TRUNC_LIMIT);

    let serial_hex = render_serial_hex(cert.tbs_certificate.raw_serial());

    let not_before_iso = format_unix_as_iso_utc(cert.validity().not_before.timestamp());
    let not_after_iso = format_unix_as_iso_utc(cert.validity().not_after.timestamp());
    let not_after_tag = expired_or_valid_tag(cert.validity().not_after.timestamp());

    let key_alg = render_key_algorithm(&cert);

    let fingerprint_hex = {
        let digest = Sha256::digest(bytes);
        let mut s = String::with_capacity(64);
        for b in digest.iter() {
            write!(s, "{:02x}", b).expect("writing to String cannot fail");
        }
        s
    };

    // Build subblock — multi-line String, no leading/trailing \n.
    let separator: String = format!("--- X.509 {}", "-".repeat(SEPARATOR_DASH_COUNT));
    let mut out = String::new();
    out.push_str(&separator);
    out.push('\n');
    writeln!(out, "Subject:     {}", subject).expect("String write");
    writeln!(out, "Issuer:      {}", issuer).expect("String write");
    writeln!(out, "Serial:      {}", serial_hex).expect("String write");
    writeln!(out, "NotBefore:   {}", not_before_iso).expect("String write");
    writeln!(out, "NotAfter:    {}  {}", not_after_iso, not_after_tag).expect("String write");
    writeln!(out, "Key:         {}", key_alg).expect("String write");
    // SHA-256 is the final line — no trailing newline per D-P6-17.
    write!(out, "SHA-256:     {}", fingerprint_hex).expect("String write");
    Ok(out)
}

/// Truncate a display string at `limit` chars, appending `…` if truncation applies.
/// Counts Unicode scalar values (not bytes) to avoid splitting codepoints.
fn truncate_display(s: &str, limit: usize) -> String {
    let count = s.chars().count();
    if count <= limit {
        s.to_string()
    } else {
        // Reserve 1 char for the `…` marker.
        let prefix: String = s.chars().take(limit.saturating_sub(1)).collect();
        format!("{}…", prefix)
    }
}

/// Render serial number as lowercase hex with `0x` prefix. Truncate at 16 hex chars
/// with `… (truncated)` suffix for long serials (D-P6-11).
fn render_serial_hex(raw: &[u8]) -> String {
    let mut hex = String::with_capacity(raw.len() * 2);
    for b in raw {
        write!(hex, "{:02x}", b).expect("String write");
    }
    // Strip leading zeros for readability, but keep at least one digit.
    let stripped = hex.trim_start_matches('0');
    let normalized = if stripped.is_empty() { "0" } else { stripped };
    if normalized.len() <= SERIAL_HEX_TRUNC {
        format!("0x{}", normalized)
    } else {
        let head: String = normalized.chars().take(SERIAL_HEX_TRUNC).collect();
        format!("0x{}… (truncated)", head)
    }
}

/// Compare NotAfter against system clock; return `"[VALID]"` or `"[EXPIRED]"` (D-P6-12).
/// On clock failure, return `"[VALID]"` — fail-open is the safer UX default (the user
/// still sees the NotAfter timestamp and can decide). NotBefore in the future is NOT
/// tagged in v1.1 (see Deferred Ideas in CONTEXT.md — `[NOT_YET_VALID]` out of scope).
fn expired_or_valid_tag(not_after_unix: i64) -> &'static str {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if not_after_unix < now {
        "[EXPIRED]"
    } else {
        "[VALID]"
    }
}

/// Render the certificate's Subject Public Key Info algorithm as a human-readable
/// string (D-P6-14). Per RESEARCH CORRECTION 2: Ed25519 / Ed448 come through
/// `PublicKey::Unknown` — match on the OID directly rather than the parsed enum.
///
/// Coverage (top ~10 per CONTEXT.md discretion row):
///   Ed25519, Ed448, RSA-2048/3072/4096, ECDSA P-256/P-384/P-521, ECDSA secp256k1,
///   RSA-PSS. Unknown OIDs fall back to dotted-OID rendering.
fn render_key_algorithm(cert: &x509_parser::certificate::X509Certificate<'_>) -> String {
    let spki = &cert.tbs_certificate.subject_pki;
    let alg_oid = &spki.algorithm.algorithm;

    // Ed25519 — RESEARCH CORRECTION 2 + Focus Item 4 VERIFIED table:
    // detected via OID match, not PublicKey variant (keys come through PublicKey::Unknown).
    if *alg_oid == OID_SIG_ED25519 {
        return "Ed25519".to_string();
    }
    // Ed448 — OID_SIG_ED448 IS exported by x509-parser 0.16 oid_registry
    // (RESEARCH Focus Item 4 line 432). 1.3.101.113.
    if *alg_oid == OID_SIG_ED448 {
        return "Ed448".to_string();
    }

    // RSA — pkcs1 rsaEncryption OID (1.2.840.113549.1.1.1).
    // Bit size from the parsed public key per RESEARCH Focus Item 4 lines 430, 445-449:
    // call spki.parsed() → PublicKey::RSA(rsa) → rsa.key_size() → bits.
    if *alg_oid == OID_PKCS1_RSAENCRYPTION {
        use x509_parser::public_key::PublicKey;
        if let Ok(PublicKey::RSA(rsa)) = spki.parsed() {
            return format!("RSA-{}", rsa.key_size());
        }
        return "RSA".to_string();
    }

    // RSA-PSS
    if *alg_oid == OID_PKCS1_RSASSAPSS {
        return "RSA-PSS".to_string();
    }

    // EC: check the curve via the algorithm parameters (an OID for named curves).
    if *alg_oid == OID_KEY_TYPE_EC_PUBLIC_KEY {
        if let Some(params) = spki.algorithm.parameters.as_ref() {
            if let Ok(curve_oid) = params.as_oid() {
                if curve_oid == OID_EC_P256 {
                    return "ECDSA P-256".to_string();
                }
                if curve_oid == OID_NIST_EC_P384 {
                    return "ECDSA P-384".to_string();
                }
                if curve_oid == OID_NIST_EC_P521 {
                    return "ECDSA P-521".to_string();
                }
                // secp256k1 = 1.3.132.0.10 — no exported constant in oid-registry 0.7
                // per RESEARCH Focus 4 line 428; dotted-OID fallback is the documented path.
                if curve_oid.to_id_string() == "1.3.132.0.10" {
                    return "ECDSA secp256k1".to_string();
                }
                return format!("ECDSA <{}>", curve_oid.to_id_string());
            }
        }
        return "ECDSA <unknown curve>".to_string();
    }

    // Unknown algorithm: dotted-OID fallback.
    format!("<{}>", alg_oid.to_id_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_x509_preview_rejects_garbage_generically() {
        let err = render_x509_preview(b"this is not a cert").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "x509_cert");
                assert_eq!(reason, "malformed DER");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn truncate_display_leaves_short_strings_unchanged() {
        assert_eq!(truncate_display("short", 80), "short");
        assert_eq!(truncate_display("CN=a, O=b, C=US", 80), "CN=a, O=b, C=US");
    }

    #[test]
    fn truncate_display_truncates_long_strings_with_ellipsis() {
        let long = "x".repeat(100);
        let out = truncate_display(&long, 80);
        assert_eq!(out.chars().count(), 80);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn render_serial_hex_short_serial_renders_whole() {
        assert_eq!(render_serial_hex(&[0x01]), "0x1");
        assert_eq!(render_serial_hex(&[0x0a, 0x1b, 0x2c, 0x3d]), "0xa1b2c3d");
    }

    #[test]
    fn render_serial_hex_long_serial_truncates_at_16_hex() {
        // 20-byte serial = 40 hex. First 16 hex + "… (truncated)".
        // Bytes: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13
        // Hex string: "000102030405060708090a0b0c0d0e0f10111213"
        // After strip_start_matches('0'): "102030405060708090a0b0c0d0e0f10111213" (37 chars)
        // First 16 chars: "1020304050607080"
        let raw: Vec<u8> = (0..20).collect();
        let out = render_serial_hex(&raw);
        assert!(out.starts_with("0x"));
        assert!(out.ends_with("… (truncated)"));
        assert!(out.contains("102030405060708"));
    }

    #[test]
    fn expired_or_valid_tag_past_is_expired() {
        // Unix epoch 2020-01-01 = 1577836800; long in the past.
        assert_eq!(expired_or_valid_tag(1_577_836_800), "[EXPIRED]");
    }

    #[test]
    fn expired_or_valid_tag_far_future_is_valid() {
        // 2100-01-01 = 4102444800
        assert_eq!(expired_or_valid_tag(4_102_444_800), "[VALID]");
    }

    #[test]
    fn separator_line_uses_57_dashes() {
        // This exact width is asserted in golden-string tests when a fixture cert is
        // available; here we assert the constant alone.
        assert_eq!(SEPARATOR_DASH_COUNT, 57);
    }

    // --- Phase 7 Plan 02 — render_pgp_preview tests --------------------------
    //
    // Helper-and-error-path tests live here. Full fixture-backed golden-string
    // tests for the public-key + secret-key happy paths land in Plan 04 in
    // `tests/pgp_banner_render.rs` once a real PGP fixture is committed.
    //
    // Behavior contract under test:
    //   1. Garbage input → Err(InvalidMaterial { variant: "pgp_key",
    //      reason: "malformed PGP packet stream" }), never panics.
    //   2. Empty input → same.
    //   3. PGP_SEPARATOR_DASH_COUNT constant pinned at 53 (CONTEXT.md §specifics).
    //   4. PGP_UID_TRUNC_LIMIT constant pinned at 64 (D-P7-08).

    #[test]
    fn render_pgp_preview_rejects_garbage_generically() {
        let err = render_pgp_preview(b"this is not a PGP packet stream").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(reason, "malformed PGP packet stream");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn render_pgp_preview_rejects_empty_input() {
        let err = render_pgp_preview(b"").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(reason, "malformed PGP packet stream");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn pgp_separator_dash_count_is_53() {
        assert_eq!(PGP_SEPARATOR_DASH_COUNT, 53);
    }

    #[test]
    fn pgp_uid_trunc_limit_is_64() {
        assert_eq!(PGP_UID_TRUNC_LIMIT, 64);
    }
}
