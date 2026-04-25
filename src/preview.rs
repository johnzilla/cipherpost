//! src/preview.rs — Acceptance-banner subblock renderers for typed Material variants.
//!
//! Phase 6 ships `render_x509_preview(bytes)`. Phase 7 Plan 02 adds
//! `render_pgp_preview(bytes)`. Plan 06 will add `render_ssh_preview(bytes)`.
//!
//! Design invariants (D-P6-09, D-P6-13, D-P6-17, D-P7-09):
//!   - Pure function: no I/O, no side effects. Returns `Result<String, Error>`.
//!   - `x509-parser` AND `pgp` crate imports live ONLY in this module (and in
//!     `payload/ingest.rs` for `pgp`). `flow.rs::TtyPrompter::render_and_confirm`
//!     calls us via Plan 03's wiring.
//!   - No leading or trailing `\n` — caller owns outer banner layout.
//!   - Parse failures return `Error::InvalidMaterial { variant: "<tag>",
//!     reason: "<short generic>" }` with NO crate internal strings.
//!   - X.509 SHA-256 is computed over the canonical DER bytes passed in — matches
//!     `share_ref` determinism domain per D-P6-13.
//!   - PGP fingerprint is computed by rpgp from the parsed key and rendered as
//!     UPPER-CASE hex (40 hex for v4, 64 hex for v5/v6) per PGP-04 — no leading
//!     `0x`, no spaces, matching `gpg --list-keys --with-fingerprint` output
//!     style minus the spaces.
//!   - Phase 7 PGP secret-key (top-level packet tag-5) input prepends a
//!     `[WARNING: SECRET key — unlocks cryptographic operations]` line BEFORE
//!     the separator (D-P7-07).

use crate::error::Error;
use crate::flow::format_unix_as_iso_utc;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_NIST_EC_P521,
    OID_PKCS1_RSAENCRYPTION, OID_PKCS1_RSASSAPSS, OID_SIG_ED25519, OID_SIG_ED448,
};

// Phase 7 Plan 02: rpgp imports — confined to this module per D-P7-09.
// High-level `composed` types (`SignedPublicKey`, `SignedSecretKey`) expose
// the fingerprint/UID/algorithm fields cleanly; `KeyDetails` trait gives
// uniform `.fingerprint()` / `.algorithm()` / `.created_at()` / `.public_params()`
// across both. The low-level `packet::PacketParser` + `Tag` is re-used (same
// as `payload::ingest::pgp_key`) for the tag-5 vs tag-6 primary discriminator
// — the composed API does not expose "was this a secret key?" directly because
// `SignedSecretKey::to_public_key()` collapses the distinction.
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::PacketTrait;
use pgp::types::{EcdsaPublicParams, KeyDetails, PublicParams, Tag};
use rsa::traits::PublicKeyParts;

// Phase 7 Plan 06: ssh-key imports — confined to this module + payload/ingest
// per D-P7-16. PrivateKey::from_openssh + PublicKey::fingerprint + KeyData
// give us parse, SHA-256 fingerprint, and per-algorithm bit-size derivation.
// HashAlg::Sha256 is the ONLY hash form rendered (D-P7-15: MD5/SHA-1 explicitly
// excluded; Fingerprint::Display formats as "SHA256:<base64-unpadded>").
use ssh_key::public::KeyData as SshKeyData;
use ssh_key::{Algorithm as SshAlgorithm, EcdsaCurve, HashAlg, PrivateKey as SshPrivateKey};

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

// =============================================================================
// Phase 7 Plan 02 — PGP preview renderer.
// =============================================================================

/// 53 dashes after `--- OpenPGP ` per Phase 7 CONTEXT.md §specifics.
/// Total separator line width = `--- OpenPGP ` (12 chars) + 53 dashes = 65 chars.
/// SSH subblock (Plan 06) uses `--- SSH ` (8 chars) + 57 dashes = 65 chars to
/// match. X.509 keeps its 67-char historical width.
const PGP_SEPARATOR_DASH_COUNT: usize = 53;

/// UID truncation limit per D-P7-08 — PGP UIDs are RFC 4880 free-form UTF-8
/// (typically `Name <email>` at 40-80 chars). Mirrors Phase 6's
/// `DN_TRUNC_LIMIT = 80` shape but tighter for the 80-col TTY constraint with
/// the existing `Primary UID: ` 13-char field-label budget.
const PGP_UID_TRUNC_LIMIT: usize = 64;

/// Render a PGP acceptance-banner subblock from a binary OpenPGP packet stream.
///
/// Returns a multi-line String (no leading or trailing newline). For a
/// primary-secret-key input (top-level packet tag-5) the string starts with
/// the SECRET warning line followed by a blank line, then the separator. For
/// a primary-public-key input (tag-6) the string starts with the separator
/// directly. Caller (run_receive — Plan 03 wires it) passes the returned
/// string through `Option<&str>` to `TtyPrompter::render_and_confirm`'s
/// `preview_subblock` parameter.
///
/// Lines (after any warning) in order:
///   --- OpenPGP -----------------------------------------------  (53 dashes)
///   Fingerprint: <40-hex v4 OR 64-hex v5/v6>      (UPPER-case)
///   Primary UID: <UID, truncated at 64 chars with `…`>
///   Key:         <Ed25519 | RSA-2048 | ECDSA P-256 | ... | <dotted-OID>>
///   Subkeys:     N (type1, type2, ...)            // or `0`
///   Created:     YYYY-MM-DD HH:MM UTC
///
/// Error contract (D-P7-09 / PGP-08): every parse failure surfaces as
/// `Error::InvalidMaterial { variant: "pgp_key", reason: "malformed PGP packet
/// stream" }` — the ONE curated literal. NEVER wraps an rpgp internal error
/// chain (oracle hygiene gate; matches `payload::ingest::pgp_key`).
pub fn render_pgp_preview(bytes: &[u8]) -> Result<String, Error> {
    // Step 1: discriminate primary kind via raw packet tag (D-P7-07).
    // We need this BEFORE composing because the `composed` API collapses
    // SecretKey → PublicKey for uniform downstream access (`SignedSecretKey::
    // to_public_key()`); the tag is the authoritative "was this a secret?"
    // signal. Re-uses the same `pgp::packet::PacketParser` entry point as
    // `payload::ingest::pgp_key` for error-surface consistency.
    let is_secret = pgp_primary_is_secret(bytes)?;

    // Step 2: extract metadata via the high-level composed API.
    let (fingerprint_hex, primary_uid, key_alg, subkey_summary, created_unix) = if is_secret {
        extract_secret_metadata(bytes)?
    } else {
        extract_public_metadata(bytes)?
    };

    // Step 3: format the subblock string. UID truncation reuses the existing
    // Phase 6 `truncate_display` helper (D-P6-10 pattern). Created timestamp
    // reuses Phase 6 Plan 02's `pub(crate) format_unix_as_iso_utc`.
    let separator: String = format!("--- OpenPGP {}", "-".repeat(PGP_SEPARATOR_DASH_COUNT));
    let uid_truncated = truncate_display(&primary_uid, PGP_UID_TRUNC_LIMIT);
    let created_iso = format_unix_as_iso_utc(created_unix);

    let mut out = String::new();
    if is_secret {
        // D-P7-07: warning line is the FIRST line of the returned String,
        // followed by a blank line, then the separator. High visual weight.
        out.push_str("[WARNING: SECRET key — unlocks cryptographic operations]\n\n");
    }
    out.push_str(&separator);
    out.push('\n');
    writeln!(out, "Fingerprint: {}", fingerprint_hex).expect("String write");
    writeln!(out, "Primary UID: {}", uid_truncated).expect("String write");
    writeln!(out, "Key:         {}", key_alg).expect("String write");
    writeln!(out, "Subkeys:     {}", subkey_summary).expect("String write");
    // D-P6-17 mirror: Created is the LAST line — no trailing newline.
    write!(out, "Created:     {}", created_iso).expect("String write");
    Ok(out)
}

/// Tag-5 vs tag-6 discriminator. Returns Ok(true) for SecretKey (tag 5),
/// Ok(false) for PublicKey (tag 6). Errs (with the canonical sanitized
/// `malformed PGP packet stream` reason) on malformed input or no primary
/// packet found.
fn pgp_primary_is_secret(bytes: &[u8]) -> Result<bool, Error> {
    use std::io::Cursor;
    let mut cursor = Cursor::new(bytes);
    let parser = pgp::packet::PacketParser::new(&mut cursor);
    for packet_result in parser {
        let packet = packet_result.map_err(|_| pgp_parse_error())?;
        match packet.tag() {
            Tag::SecretKey => return Ok(true),
            Tag::PublicKey => return Ok(false),
            _ => continue,
        }
    }
    Err(pgp_parse_error())
}

/// Single source of truth for the PGP preview parse-failure error literal —
/// matches the `malformed PGP packet stream` reason that
/// `payload::ingest::pgp_key` uses (oracle-hygiene deduplication across
/// Plan 01 + Plan 02).
fn pgp_parse_error() -> Error {
    Error::InvalidMaterial {
        variant: "pgp_key".into(),
        reason: "malformed PGP packet stream".into(),
    }
}

/// Extract the PGP banner-fields tuple from a public-key packet stream
/// (top-level Tag::PublicKey).
fn extract_public_metadata(bytes: &[u8]) -> Result<(String, String, String, String, i64), Error> {
    let key = SignedPublicKey::from_bytes(bytes).map_err(|_| pgp_parse_error())?;
    let fp_hex = format_fingerprint_upper(&key.fingerprint());
    let primary_uid = first_uid_string(&key.details.users);
    let key_alg = render_pgp_key_algorithm(key.algorithm(), key.public_params());
    let subkey_summary = render_pgp_public_subkey_summary(&key.public_subkeys);
    let created = i64::from(key.created_at().as_secs());
    Ok((fp_hex, primary_uid, key_alg, subkey_summary, created))
}

/// Extract the PGP banner-fields tuple from a secret-key packet stream
/// (top-level Tag::SecretKey). Re-uses the public-key view via
/// `SignedSecretKey::to_public_key()` for uniform field extraction (the public
/// half is always present alongside the secret material per RFC 4880 §5.5.3).
fn extract_secret_metadata(bytes: &[u8]) -> Result<(String, String, String, String, i64), Error> {
    let key = SignedSecretKey::from_bytes(bytes).map_err(|_| pgp_parse_error())?;
    let fp_hex = format_fingerprint_upper(&key.fingerprint());
    let primary_uid = first_uid_string(&key.details.users);
    let key_alg = render_pgp_key_algorithm(key.algorithm(), key.public_params());
    // SecretKey carries BOTH public-subkey records AND secret-subkey records
    // (the secret-subkey set is the secret half; the public-subkey set holds
    // the public-encryption-only subkeys). Surface both counts together so the
    // user sees the true subkey topology.
    let mut total_subkeys: Vec<&pgp::types::PublicParams> = Vec::new();
    let mut algos: Vec<PublicKeyAlgorithm> = Vec::new();
    for sk in &key.public_subkeys {
        algos.push(sk.key.algorithm());
        total_subkeys.push(sk.key.public_params());
    }
    for sk in &key.secret_subkeys {
        algos.push(sk.key.algorithm());
        total_subkeys.push(sk.key.public_params());
    }
    let subkey_summary = if algos.is_empty() {
        "0".to_string()
    } else {
        let names: Vec<String> = algos
            .iter()
            .zip(total_subkeys.iter())
            .map(|(a, p)| render_pgp_key_algorithm(*a, p))
            .collect();
        format!("{} ({})", algos.len(), names.join(", "))
    };
    let created = i64::from(key.created_at().as_secs());
    Ok((fp_hex, primary_uid, key_alg, subkey_summary, created))
}

/// Render a `pgp::types::Fingerprint` as UPPER-CASE hex with no leading `0x`,
/// no spaces — matches GnuPG `--list-keys --with-fingerprint` output minus the
/// 4-char-group spacing. v4 keys → 40 hex chars; v5/v6 keys → 64 hex chars.
fn format_fingerprint_upper(fp: &pgp::types::Fingerprint) -> String {
    // Fingerprint impls UpperHex (see pgp/src/types/fingerprint.rs):
    //   `format!("{:X}", fp)` produces hex::encode_upper(fp.as_bytes()).
    format!("{:X}", fp)
}

/// First user's UID string, or `(no user id)` placeholder if the key has no
/// SignedUser records (defensive — well-formed transferable keys always have
/// at least one). Strips control characters defensively to prevent ANSI/CR
/// banner-injection through a hostile UID.
fn first_uid_string(users: &[pgp::types::SignedUser]) -> String {
    let raw = users
        .first()
        .and_then(|u| u.id.as_str())
        .unwrap_or("(no user id)");
    strip_control_chars(raw)
}

/// Filter out ASCII control characters (< 0x20 or 0x7F) — matches the same
/// hardening pattern Phase 2 applies to the `purpose` field. Keeps the
/// printable + extended-UTF8 range.
fn strip_control_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Render an OpenPGP public-key algorithm + parameters as a human-readable
/// string. Coverage maps to D-P7-08:
///   Ed25519, Ed448, RSA-<bits>, ECDSA P-256/P-384/P-521/secp256k1,
///   ECDH-X25519/Curve25519/<curve-name>, X25519/X448, EdDSALegacy, DSA,
///   Elgamal — anything else falls through to a numeric algorithm-OID
///   placeholder of the form `<algo-N>`.
fn render_pgp_key_algorithm(alg: PublicKeyAlgorithm, params: &PublicParams) -> String {
    match alg {
        PublicKeyAlgorithm::Ed25519 => "Ed25519".to_string(),
        PublicKeyAlgorithm::Ed448 => "Ed448".to_string(),
        PublicKeyAlgorithm::EdDSALegacy => "EdDSA-Legacy".to_string(),
        PublicKeyAlgorithm::X25519 => "X25519".to_string(),
        PublicKeyAlgorithm::X448 => "X448".to_string(),
        PublicKeyAlgorithm::DSA => "DSA".to_string(),
        PublicKeyAlgorithm::ElgamalEncrypt | PublicKeyAlgorithm::Elgamal => "Elgamal".to_string(),
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            render_rsa_with_size(params)
        }
        PublicKeyAlgorithm::ECDSA => render_ecdsa(params),
        PublicKeyAlgorithm::ECDH => render_ecdh(params),
        // Catch-all for the remaining `#[non_exhaustive]` PQC + Private*
        // variants and any future additions — render the numeric algorithm ID
        // (RFC 9580 §9.1 assigns 1-byte values) as a stable placeholder.
        _ => format!("<algo-{}>", u8::from(alg)),
    }
}

/// `RSA-<bits>` rendering. The bit-size comes from the modulus length via
/// `PublicKeyParts::n` from the `rsa` crate — pgp's `PublicParams::RSA(rsa)`
/// holds the parsed `rsa::RsaPublicKey` directly. Falls back to plain `RSA`
/// if the params variant doesn't match (defensive — should be unreachable
/// when `algorithm()` returned RSA*).
fn render_rsa_with_size(params: &PublicParams) -> String {
    if let PublicParams::RSA(rsa_params) = params {
        // n() is from the PublicKeyParts trait; bit-size is the length in
        // bits of the modulus. RSA modulus bit-count is the conventional
        // "RSA key size" (2048, 3072, 4096, etc.).
        let bits = rsa_params.key.n().bits();
        format!("RSA-{}", bits)
    } else {
        "RSA".to_string()
    }
}

/// `ECDSA <curve-name>` rendering. P-256/P-384/P-521 are spelled with the
/// `P-` prefix (matches OpenSSH + OpenPGP convention); secp256k1 keeps its
/// canonical name; unsupported curves fall back to the curve's display name.
fn render_ecdsa(params: &PublicParams) -> String {
    if let PublicParams::ECDSA(ecdsa) = params {
        match ecdsa {
            EcdsaPublicParams::P256 { .. } => "ECDSA P-256".to_string(),
            EcdsaPublicParams::P384 { .. } => "ECDSA P-384".to_string(),
            EcdsaPublicParams::P521 { .. } => "ECDSA P-521".to_string(),
            EcdsaPublicParams::Secp256k1 { .. } => "ECDSA secp256k1".to_string(),
            EcdsaPublicParams::Unsupported { curve, .. } => {
                format!("ECDSA <{}>", curve.oid_str())
            }
        }
    } else {
        "ECDSA".to_string()
    }
}

/// `ECDH-<curve-name>` rendering. Mirrors the ECDSA shape but for the ECDH
/// key-agreement variant.
fn render_ecdh(params: &PublicParams) -> String {
    if let PublicParams::ECDH(ecdh) = params {
        format!("ECDH-{}", ecdh.curve().name())
    } else {
        "ECDH".to_string()
    }
}

/// Wrap a binary OpenPGP packet stream in the RFC 4880 ASCII-armor envelope.
///
/// PGP armor is crate-specific: rpgp chooses the `-----BEGIN PGP PUBLIC KEY
/// BLOCK-----` vs `-----BEGIN PGP PRIVATE KEY BLOCK-----` header automatically
/// based on the primary packet type (tag-6 → public, tag-5 → private). We
/// delegate to rpgp's `to_armored_bytes` API rather than hand-rolling like we
/// do for X.509 PEM (where the `-----BEGIN CERTIFICATE-----` header is
/// universal regardless of key type).
///
/// This is the only armor emitter for PGP; armor on INPUT is permanently
/// rejected at ingest (D-P7-05 / PGP-01) so the round-trip is binary-in /
/// optionally-armored-out.
///
/// Threat T-07-15 mitigation: the BEGIN/END headers MATCH the actual primary
/// kind because rpgp's `SignedPublicKey::to_armored_bytes` calls
/// `armor::write(self, BlockType::PublicKey, ...)` and
/// `SignedSecretKey::to_armored_bytes` calls
/// `armor::write(self, BlockType::PrivateKey, ...)`. We choose the right
/// constructor by re-using `pgp_primary_is_secret` (the same tag-5/tag-6
/// discriminator already used by `render_pgp_preview`).
///
/// Error contract: every parse/serialize failure surfaces as the canonical
/// `Error::InvalidMaterial { variant: "pgp_key", reason: "malformed PGP
/// packet stream" }` literal — funnels through `pgp_parse_error()`, the same
/// single source of truth shared with `render_pgp_preview` and
/// `payload::ingest::pgp_key` (oracle-hygiene gate).
pub fn pgp_armor(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    use pgp::composed::ArmorOptions;

    // Step 1: decide block-type via the same tag-5/tag-6 discriminator used by
    // render_pgp_preview. This is the authoritative "secret or public" signal —
    // even if the composed parse below could in principle be tried both ways,
    // dispatching by tag gives a single deterministic path AND ensures we never
    // emit a PUBLIC KEY armor envelope around a SECRET KEY packet stream.
    let is_secret = pgp_primary_is_secret(bytes)?;

    // Step 2: parse via the matching composed type and re-emit as armored bytes.
    // rpgp's to_armored_bytes() picks the BEGIN/END header from the type itself
    // (BlockType::PublicKey vs BlockType::PrivateKey), so we don't pass headers
    // explicitly. ArmorOptions::default() keeps include_checksum=true (CRC24
    // line — RFC 4880 § 6.1) and headers=None.
    if is_secret {
        let key = SignedSecretKey::from_bytes(bytes).map_err(|_| pgp_parse_error())?;
        key.to_armored_bytes(ArmorOptions::default())
            .map_err(|_| pgp_parse_error())
    } else {
        let key = SignedPublicKey::from_bytes(bytes).map_err(|_| pgp_parse_error())?;
        key.to_armored_bytes(ArmorOptions::default())
            .map_err(|_| pgp_parse_error())
    }
}

/// Subkey summary for the public-key path: `0`, or `N (alg1, alg2, ...)`.
fn render_pgp_public_subkey_summary(subkeys: &[pgp::composed::SignedPublicSubKey]) -> String {
    if subkeys.is_empty() {
        return "0".to_string();
    }
    let names: Vec<String> = subkeys
        .iter()
        .map(|sk| render_pgp_key_algorithm(sk.key.algorithm(), sk.key.public_params()))
        .collect();
    format!("{} ({})", subkeys.len(), names.join(", "))
}

// =============================================================================
// Phase 7 Plan 06 — SSH preview renderer.
// =============================================================================

/// 57 dashes after `--- SSH ` per Phase 7 CONTEXT.md §specifics.
/// Total separator line width = `--- SSH ` (8 chars) + 57 dashes = 65 chars,
/// matching the PGP subblock width (12 + 53 = 65).
const SSH_SEPARATOR_DASH_COUNT: usize = 57;

/// Comment truncation limit per D-P7-15 — SSH key comments are free-form
/// UTF-8 (typically `user@host`, often longer for deploy keys). Mirrors
/// PGP_UID_TRUNC_LIMIT for visual consistency in the acceptance banner.
const SSH_COMMENT_TRUNC_LIMIT: usize = 64;

/// Algorithms that get the `[DEPRECATED]` display tag on the Key: line per
/// D-P7-14. Display-only — never blocks acceptance (a user MAY legitimately
/// be migrating legacy infra). Detection rules:
///   - `ssh-dss` (DSA): always deprecated, regardless of size. OpenSSH 7.0+
///     rejects DSA outright; we keep it as a soft warning to surface the
///     legacy nature without blocking.
///   - `ssh-rsa` with bit-size <2048: deprecated per NIST SP 800-131A.
///     RSA at 1024/1536 bits is below the modern minimum.
///   - All other algorithms (ed25519, ecdsa-sha2-nistp{256,384,521},
///     sk-* FIDO variants, AlgorithmName::Other): not flagged.
fn is_deprecated_ssh_algorithm(algorithm: &str, bits: Option<u32>) -> bool {
    if algorithm == "ssh-dss" {
        return true;
    }
    if algorithm == "ssh-rsa" {
        if let Some(b) = bits {
            if b < 2048 {
                return true;
            }
        }
    }
    false
}

/// Derive the bit size of an SSH public key based on its algorithm and
/// raw key data. ssh-key 0.6.7's `Algorithm` enum exposes the algorithm
/// shape; bits are computed per-variant:
///   - Ed25519 / SkEd25519: 256 (Curve25519)
///   - ECDSA NistP256 / SkEcdsaSha2NistP256: 256
///   - ECDSA NistP384: 384
///   - ECDSA NistP521: 521
///   - RSA: derive from the modulus (`KeyData::Rsa(rsa).n`) — `Mpint`'s
///     positive-bytes length × 8 is the conventional RSA key size
///     (2048 / 3072 / 4096 / etc.).
///   - DSA: derive from the prime modulus (`KeyData::Dsa(dsa).p`) — same
///     positive-bytes-times-8 derivation. Conventional `ssh-dss` keys are
///     1024 bits.
///   - `Algorithm::Other(_)`: unknown — return `None`.
fn ssh_public_key_bit_size(key_data: &SshKeyData, algorithm: &SshAlgorithm) -> Option<u32> {
    match algorithm {
        SshAlgorithm::Ed25519 => Some(256),
        SshAlgorithm::SkEd25519 => Some(256),
        SshAlgorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => Some(256),
            EcdsaCurve::NistP384 => Some(384),
            EcdsaCurve::NistP521 => Some(521),
        },
        SshAlgorithm::SkEcdsaSha2NistP256 => Some(256),
        SshAlgorithm::Rsa { .. } => key_data
            .rsa()
            .map(|rsa| mpint_bit_size(rsa.n.as_ref()) as u32),
        SshAlgorithm::Dsa => key_data
            .dsa()
            .map(|dsa| mpint_bit_size(dsa.p.as_ref()) as u32),
        // `Algorithm::Other(_)` (alloc-feature variant; unknown crate-internal
        // names like `ssh-rsa-cert-v01@openssh.com` etc.). No bit derivation.
        _ => None,
    }
}

/// Compute the bit length of an `Mpint`-encoded big-integer byte slice.
/// SSH `Mpint` may carry a leading `0x00` byte to disambiguate a positive
/// number whose MSB is set. We strip that leading zero before counting bits.
/// Bit count is `bytes.len() * 8` (conventional "modulus bit size") — we do
/// not subtract leading-zero bits inside the most-significant byte because
/// the conventional "RSA key size" is rounded up to the byte boundary
/// (`RSA-2048` = 256-byte modulus regardless of MSB density).
fn mpint_bit_size(raw_bytes: &[u8]) -> usize {
    let trimmed = match raw_bytes.first() {
        Some(0x00) => &raw_bytes[1..],
        _ => raw_bytes,
    };
    trimmed.len() * 8
}

/// Render an SSH acceptance-banner subblock from the canonical OpenSSH v1
/// wire blob (`Material::SshKey.bytes` after Plan 05's re-encode).
///
/// Returns a multi-line String (no leading or trailing newline). Field
/// ordering: Key (algorithm + size + optional `[DEPRECATED]`) → Fingerprint
/// (SHA-256 base64-unpadded) → Comment ([sender-attested] + truncated).
///
/// Lines (in order):
///   --- SSH -------------------------------------------------    (57 dashes after prefix)
///   Key:         ssh-ed25519 256 | ssh-rsa 4096 | ssh-rsa 1024 [DEPRECATED] | ssh-dss [DEPRECATED] | ...
///   Fingerprint: SHA256:<base64-unpadded>
///   Comment:     [sender-attested] <comment, truncated 64 chars with …>
///                       (or "(none)" if empty)
///
/// NO SECRET-key warning line: OpenSSH v1 ALWAYS contains a private key
/// (the format is for private keys); warning every time would be noise.
/// D-P7-14 chose the lighter `[DEPRECATED]` treatment for legacy algorithms
/// (DSA any size, RSA<2048) instead.
///
/// Caller (run_receive in Plan 07) passes the returned string through
/// `Option<&str>` to TtyPrompter's `preview_subblock` parameter.
///
/// Error contract (D-P7-12 mirror): every parse failure surfaces as
/// `Error::InvalidMaterial { variant: "ssh_key", reason: "malformed OpenSSH
/// v1 blob" }` — the same curated literal used by `payload::ingest::ssh_key`.
/// NEVER wraps an ssh-key crate error chain (oracle hygiene; D-P7-16).
pub fn render_ssh_preview(bytes: &[u8]) -> Result<String, Error> {
    // --- Step 1: parse via ssh-key. ---------------------------------
    // bytes are UTF-8 PEM-armored OpenSSH v1 (per Plan 05's canonical
    // re-encode). ssh-key's PrivateKey::from_openssh accepts impl AsRef<[u8]>
    // directly — no UTF-8 conversion needed.
    let key = SshPrivateKey::from_openssh(bytes).map_err(|_| Error::InvalidMaterial {
        variant: "ssh_key".into(),
        reason: "malformed OpenSSH v1 blob".into(),
    })?;

    // --- Step 2: extract fields. ------------------------------------
    let public_key = key.public_key();
    let algorithm = public_key.algorithm();
    let algorithm_str = algorithm.as_str().to_string();
    let bits = ssh_public_key_bit_size(public_key.key_data(), &algorithm);
    let deprecated = is_deprecated_ssh_algorithm(&algorithm_str, bits);

    // SHA-256 fingerprint — Fingerprint's Display impl outputs
    // "SHA256:<base64-unpadded>" (matches `ssh-keygen -lf`).
    // D-P7-15: MD5 and SHA-1 are explicitly NOT called.
    let fingerprint = public_key.fingerprint(HashAlg::Sha256);
    let fingerprint_str = format!("{}", fingerprint);

    // Comment is the sender-attested label; ssh-key's PrivateKey::comment()
    // returns &str (empty string for no comment, not Option).
    let comment_raw = key.comment();
    let comment_display = if comment_raw.is_empty() {
        "(none)".to_string()
    } else {
        truncate_display(comment_raw, SSH_COMMENT_TRUNC_LIMIT)
    };

    // --- Step 3: format. --------------------------------------------
    let separator: String = format!("--- SSH {}", "-".repeat(SSH_SEPARATOR_DASH_COUNT));
    let key_line = match (bits, deprecated) {
        (Some(b), true) => format!("{} {} [DEPRECATED]", algorithm_str, b),
        (Some(b), false) => format!("{} {}", algorithm_str, b),
        (None, true) => format!("{} [DEPRECATED]", algorithm_str),
        (None, false) => algorithm_str,
    };

    let mut out = String::new();
    out.push_str(&separator);
    out.push('\n');
    writeln!(out, "Key:         {}", key_line).expect("String write");
    writeln!(out, "Fingerprint: {}", fingerprint_str).expect("String write");
    // Last line — no trailing newline (caller owns outer banner layout).
    write!(out, "Comment:     [sender-attested] {}", comment_display).expect("String write");
    Ok(out)
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

    // --- Phase 7 Plan 03 — pgp_armor helper tests ----------------------------
    //
    // The full happy-path test (a real PGP fixture round-trips through
    // pgp_armor() and yields output starting with `-----BEGIN PGP PUBLIC KEY
    // BLOCK-----` for a public-key fixture, or `-----BEGIN PGP PRIVATE KEY
    // BLOCK-----` for a secret-key fixture) lands in Plan 04 once a real
    // fixture is committed. Plan 03's scope is the error-path contract: any
    // malformed input MUST surface as the same curated `Error::InvalidMaterial
    // { variant: "pgp_key", reason: "malformed PGP packet stream" }` literal
    // already used by `payload::ingest::pgp_key` and `render_pgp_preview`
    // (oracle-hygiene single-source-of-truth across all three call sites).
    //
    // Threats addressed: T-07-15 (header-mismatch on hand-rolled armor — we
    // delegate to rpgp's `to_armored_bytes` so the BEGIN header matches the
    // detected primary tag), T-07-10 / oracle-hygiene mirror (no rpgp internal
    // error chain leaks through pgp_armor's error path).

    #[test]
    fn pgp_armor_rejects_garbage_with_curated_error() {
        let err = pgp_armor(b"this is not a PGP packet stream").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(reason, "malformed PGP packet stream");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn pgp_armor_rejects_empty_input() {
        let err = pgp_armor(b"").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(reason, "malformed PGP packet stream");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    // --- Phase 7 Plan 06 — render_ssh_preview tests --------------------------
    //
    // Helper-and-error-path tests live here. Full fixture-backed golden-string
    // tests for the per-algorithm Key line content + SHA-256 fingerprint shape +
    // [DEPRECATED] tag placement land in Plan 08 in `tests/ssh_banner_render.rs`.
    //
    // Behavior contract under test:
    //   1. Garbage input → Err(InvalidMaterial { variant: "ssh_key",
    //      reason: "malformed OpenSSH v1 blob" }), never panics.
    //   2. Empty input → same.
    //   3. SSH_SEPARATOR_DASH_COUNT constant pinned at 57 (CONTEXT.md §specifics).
    //   4. SSH_COMMENT_TRUNC_LIMIT constant pinned at 64 (D-P7-15 mirror of D-P7-08).
    //   5. is_deprecated_ssh_algorithm: DSA any size → true; RSA<2048 → true;
    //      RSA>=2048 → false; modern algorithms (ed25519, ecdsa-*) → false.

    #[test]
    fn render_ssh_preview_rejects_garbage_generically() {
        let err = render_ssh_preview(b"this is not an OpenSSH v1 blob").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "ssh_key");
                assert_eq!(reason, "malformed OpenSSH v1 blob");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn render_ssh_preview_rejects_empty_input() {
        let err = render_ssh_preview(b"").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "ssh_key");
                assert_eq!(reason, "malformed OpenSSH v1 blob");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn ssh_separator_dash_count_is_57() {
        assert_eq!(SSH_SEPARATOR_DASH_COUNT, 57);
    }

    #[test]
    fn ssh_comment_trunc_limit_is_64() {
        assert_eq!(SSH_COMMENT_TRUNC_LIMIT, 64);
    }

    #[test]
    fn is_deprecated_ssh_algorithm_dsa_always_deprecated() {
        assert!(is_deprecated_ssh_algorithm("ssh-dss", None));
        assert!(is_deprecated_ssh_algorithm("ssh-dss", Some(1024)));
        assert!(is_deprecated_ssh_algorithm("ssh-dss", Some(2048)));
    }

    #[test]
    fn is_deprecated_ssh_algorithm_rsa_below_2048_deprecated() {
        assert!(is_deprecated_ssh_algorithm("ssh-rsa", Some(1024)));
        assert!(is_deprecated_ssh_algorithm("ssh-rsa", Some(1536)));
        assert!(!is_deprecated_ssh_algorithm("ssh-rsa", Some(2048)));
        assert!(!is_deprecated_ssh_algorithm("ssh-rsa", Some(4096)));
    }

    #[test]
    fn is_deprecated_ssh_algorithm_modern_algorithms_not_deprecated() {
        assert!(!is_deprecated_ssh_algorithm("ssh-ed25519", Some(256)));
        assert!(!is_deprecated_ssh_algorithm(
            "ecdsa-sha2-nistp256",
            Some(256)
        ));
        assert!(!is_deprecated_ssh_algorithm(
            "ecdsa-sha2-nistp384",
            Some(384)
        ));
        assert!(!is_deprecated_ssh_algorithm(
            "ecdsa-sha2-nistp521",
            Some(521)
        ));
    }
}
