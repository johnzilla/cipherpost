//! src/payload/ingest.rs — raw-bytes → typed Material normalization.
//!
//! `x509_cert(raw)` sniffs PEM vs DER, normalizes PEM → DER, validates via
//! `x509-parser`'s strict-DER profile, and explicitly rejects trailing bytes
//! after the certificate (D-P6-07). Returns `Material::X509Cert { bytes: canonical_der }`.
//!
//! `pgp_key(raw)` strictly rejects ASCII armor (D-P7-05), parses the binary
//! OpenPGP packet stream via `pgp::packet::PacketParser`, counts top-level
//! Tag::PublicKey + Tag::SecretKey packets (rejects keyrings per D-P7-06 /
//! PGP-03), and asserts the parser consumed the entire input (WR-01 mirror /
//! D-P7-07). Returns `Material::PgpKey { bytes: raw.to_vec() }` — no canonical
//! re-encode; the binary packet stream IS canonical per RFC 4880 §4.2.
//!
//! The `bytes` field always carries canonical DER regardless of CLI input format
//! (X509-01 invariant) — so `share_ref` remains deterministic across re-sends
//! of semantically identical certs.
//!
//! Error contract: every failure path returns `Error::InvalidMaterial { variant,
//! reason }` with a short, generic `reason` string. NEVER wrap an `x509-parser`
//! or `pgp` error chain — the `reason: String` is the oracle-hygiene gate
//! (D-P6-03 / X509-08 / D-P7-09 / PGP-08).
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

/// Normalize raw bytes (binary OpenPGP packet stream) into `Material::PgpKey { bytes }`.
///
/// No canonical re-encode — the binary packet stream IS canonical (RFC 4880 §4.2 +
/// RFC 9580 §4.2). Re-encoding through rpgp could alter insignificant bits that
/// would drift `share_ref` across sender toolchains; storing input bytes verbatim
/// (after validation) is the correctness-preserving choice.
///
/// Pipeline:
///   1. Sniff: after skipping leading ASCII whitespace, reject if the input
///      begins with `-----BEGIN PGP` (catches PUBLIC KEY BLOCK and PRIVATE KEY
///      BLOCK both — D-P7-05).
///   2. Parse: iterate top-level packets via rpgp's `pgp::packet::PacketParser`.
///      Count `Tag::PublicKey` (RFC tag 6) + `Tag::SecretKey` (RFC tag 5) at
///      the top level — subkeys (`PublicSubkey` tag 14 / `SecretSubkey` tag 7)
///      are NOT counted (subkeys are legitimate; we're rejecting keyrings).
///   3. If zero primaries (or zero packets): malformed → reject.
///   4. If primary count > 1: keyring → reject per D-P7-06 / PGP-03.
///   5. Assert the parser consumed the entire input — trailing bytes after
///      the last valid packet are rejected (WR-01 invariant mirror).
///   6. Return `Material::PgpKey { bytes: raw.to_vec() }`.
///
/// Error contract: every failure path returns `Error::InvalidMaterial { variant:
/// "pgp_key", reason: "<short generic>" }`. NEVER wrap a `pgp` crate error —
/// the `reason: String` is the oracle-hygiene gate (PGP-08 / D-P7-09 extension).
pub fn pgp_key(raw: &[u8]) -> Result<Material, Error> {
    // --- Step 1: armor-prefix sniff (D-P7-05 / PGP-01). ----------------------
    let first_non_ws = raw
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let trimmed = &raw[first_non_ws..];
    if trimmed.starts_with(b"-----BEGIN PGP") {
        return Err(Error::InvalidMaterial {
            variant: "pgp_key".into(),
            reason: "ASCII-armored input rejected — supply binary packet stream".into(),
        });
    }

    // --- Step 2: parse top-level packets, count primaries. -------------------
    // PacketParser wraps a BufRead; we wrap `raw` in a Cursor and keep ownership
    // via `&mut cursor` so `cursor.position()` is available for the trailing-
    // bytes check after iteration finishes. `PacketTrait` is brought in-scope
    // so `packet.tag()` resolves (method lives on the trait, not the enum).
    //
    // We additionally sum the SERIALIZED length of each yielded packet (via
    // `pgp::ser::Serialize::to_writer`) and compare to raw.len() in step 3.
    // Cursor.position() alone is insufficient: rpgp 0.19.0's PacketParser
    // silently advances the cursor past trailing 0xFF bytes (interpreting them
    // as a stream-end magic), so a fixture+`[0xFF, 0xFF, 0xFF]` ends with
    // cursor.position() == raw.len() despite the trailing garbage. Summing
    // serialized lengths is the WR-01 invariant mirror that catches this case
    // — only bytes that round-trip through the parser+serializer count toward
    // "consumed".
    use pgp::packet::PacketTrait;
    use pgp::ser::Serialize;
    use std::io::Cursor;
    let mut cursor = Cursor::new(raw);
    let mut primary_count: usize = 0;
    let mut total_packets: usize = 0;
    let mut bytes_serialized: usize = 0;

    {
        let parser = pgp::packet::PacketParser::new(&mut cursor);
        for packet_result in parser {
            let packet = packet_result.map_err(|_| Error::InvalidMaterial {
                variant: "pgp_key".into(),
                reason: "malformed PGP packet stream".into(),
            })?;
            total_packets += 1;
            match packet.tag() {
                pgp::types::Tag::PublicKey | pgp::types::Tag::SecretKey => {
                    primary_count += 1;
                }
                _ => {}
            }
            // Sum the canonical serialized length of each packet. This is the
            // WR-01 trailing-bytes oracle that doesn't rely on cursor.position
            // (which rpgp may advance past 0xFF stream-end magic).
            let mut sink = Vec::new();
            packet
                .to_writer(&mut sink)
                .map_err(|_| Error::InvalidMaterial {
                    variant: "pgp_key".into(),
                    reason: "malformed PGP packet stream".into(),
                })?;
            bytes_serialized += sink.len();
        }
    }

    if total_packets == 0 {
        return Err(Error::InvalidMaterial {
            variant: "pgp_key".into(),
            reason: "malformed PGP packet stream".into(),
        });
    }
    if primary_count == 0 {
        return Err(Error::InvalidMaterial {
            variant: "pgp_key".into(),
            reason: "malformed PGP packet stream".into(),
        });
    }
    if primary_count > 1 {
        return Err(Error::InvalidMaterial {
            variant: "pgp_key".into(),
            reason: format!(
                "PgpKey must contain exactly one primary key; keyrings are not supported in v1.1 (found {primary_count} primary keys)"
            ),
        });
    }

    // --- Step 3: trailing-bytes check (WR-01 invariant / D-P7-07). -----------
    // The total bytes consumed by yielded packets (sum of serialized lengths)
    // must equal raw.len(). PacketParser::next returns None on UnexpectedEof
    // cleanly AND silently swallows trailing 0xFF stream-end bytes, so cursor
    // position alone misses garbage tails. Summed serialized length closes
    // the oracle: any byte that does not round-trip is "trailing" and rejected.
    if bytes_serialized != raw.len() {
        return Err(Error::InvalidMaterial {
            variant: "pgp_key".into(),
            reason: "trailing bytes after PGP packet stream".into(),
        });
    }

    Ok(Material::PgpKey {
        bytes: raw.to_vec(),
    })
}

/// Normalize raw bytes (OpenSSH v1 ASCII-armored private key) into
/// `Material::SshKey { bytes: <canonical re-encoded> }`.
///
/// Pipeline:
///   1. Sniff: after skipping leading ASCII whitespace, if the input does NOT
///      start with `-----BEGIN OPENSSH PRIVATE KEY-----`, reject with
///      `Error::SshKeyFormatNotSupported` (D-P7-12). This catches legacy PEM
///      (`-----BEGIN RSA/DSA/EC PRIVATE KEY-----`), RFC 4716 (`---- BEGIN
///      SSH2 ENCRYPTED PRIVATE KEY ----`), FIDO (`-----BEGIN OPENSSH-FIDO
///      PRIVATE KEY-----`), and arbitrary garbage in one rejection.
///   2. Trailing-bytes check (WR-01 mirror / D-P7-07): locate the first
///      `-----END OPENSSH PRIVATE KEY-----` marker. Any bytes after it must
///      be all-whitespace; non-whitespace trailers → `Error::InvalidMaterial
///      { reason: "trailing bytes after OpenSSH v1 blob" }`. ssh-key 0.6.7
///      is strict and rejects ALL post-marker bytes (even whitespace), so we
///      slice the input to the BEGIN..=END region before handing it off,
///      tolerating harmless newline-trailers from text-editor saves.
///   3. Parse: `ssh_key::PrivateKey::from_openssh(parse_input)` validates the
///      OpenSSH v1 framing + algorithm + key-data structure. Parse failure
///      (header IS OpenSSH-v1 but body is malformed) → return
///      `Error::InvalidMaterial { variant: "ssh_key", reason: "malformed
///      OpenSSH v1 blob" }`.
///   4. Re-encode: `parsed.to_openssh(LineEnding::LF)` produces the canonical
///      OpenSSH v1 output as a `Zeroizing<String>`. We store the UTF-8 bytes
///      of this string in `Material::SshKey.bytes` (D-P7-11 canonical wire blob).
///   5. Return `Material::SshKey { bytes }`.
///
/// Error contract: every failure path returns either `Error::SshKeyFormatNotSupported`
/// (format-rejection) OR `Error::InvalidMaterial { variant: "ssh_key", reason:
/// "<short generic>" }` (parse / trailing-bytes). NEVER wrap an `ssh-key` crate
/// error chain — the curated literals are the oracle-hygiene gate (D-P7-12 /
/// PGP-08 mirror).
pub fn ssh_key(raw: &[u8]) -> Result<Material, Error> {
    // --- Step 1: format sniff (D-P7-12). -------------------------------------
    let first_non_ws = raw
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let trimmed = &raw[first_non_ws..];
    if !trimmed.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Err(Error::SshKeyFormatNotSupported);
    }

    // --- Step 2: trailing-bytes check (WR-01 mirror / D-P7-07). --------------
    // ssh-key 0.6.7's PrivateKey::from_openssh is STRICT — it rejects any
    // input containing bytes after the END marker, EVEN whitespace newlines
    // (which are normal from any text-editor save). To produce a specific
    // user-facing diagnostic AND to tolerate harmless whitespace trailers,
    // we slice the input to end exactly AT the END marker before calling
    // from_openssh, AND reject if any post-marker bytes are non-whitespace
    // (T-07-39: share_ref drift via attacker-appended trailers).
    //
    // Pipeline:
    //   - Locate the first `-----END OPENSSH PRIVATE KEY-----`.
    //   - If absent: hand raw to ssh-key, which will reject as malformed.
    //   - If present + non-whitespace tail: explicit trailing-bytes rejection.
    //   - If present + whitespace-only tail: pass `raw[..=end_of_marker]`
    //     (BEGIN..=END region with no trailers) to from_openssh.
    let end_marker = b"-----END OPENSSH PRIVATE KEY-----";
    let parse_input: &[u8] = match raw.windows(end_marker.len()).position(|w| w == end_marker) {
        None => raw, // ssh-key will reject as malformed below
        Some(end_pos) => {
            let after_end_pos = end_pos + end_marker.len();
            let after_end = &raw[after_end_pos..];
            if !after_end.iter().all(|b| b.is_ascii_whitespace()) {
                return Err(Error::InvalidMaterial {
                    variant: "ssh_key".into(),
                    reason: "trailing bytes after OpenSSH v1 blob".into(),
                });
            }
            // Hand ssh-key exactly the BEGIN..=END region (no trailing
            // whitespace) — matches the canonical re-encode it produces.
            &raw[..after_end_pos]
        }
    };

    // --- Step 3: parse via ssh-key. ------------------------------------------
    // ssh-key 0.6.7 PrivateKey::from_openssh accepts impl AsRef<[u8]>.
    let parsed =
        ssh_key::PrivateKey::from_openssh(parse_input).map_err(|_| Error::InvalidMaterial {
            variant: "ssh_key".into(),
            reason: "malformed OpenSSH v1 blob".into(),
        })?;

    // --- Step 4: re-encode canonically (D-P7-11). ----------------------------
    // Returns Zeroizing<String>. LineEnding::LF is the OpenSSH v1 standard.
    let encoded =
        parsed
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|_| Error::InvalidMaterial {
                variant: "ssh_key".into(),
                reason: "malformed OpenSSH v1 blob".into(),
            })?;

    Ok(Material::SshKey {
        bytes: encoded.as_bytes().to_vec(),
    })
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
            other => panic!("expected GenericSecret, got {other:?}"),
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
            other => panic!("expected InvalidMaterial, got {other:?}"),
        }
    }

    #[test]
    fn x509_cert_non_pem_non_der_empty_input_rejected() {
        // Empty input: falls to DER path, parse fails -> malformed DER.
        let err = x509_cert(b"").unwrap_err();
        assert!(matches!(err, Error::InvalidMaterial { .. }));
    }

    // Phase 7 Plan 01 — pgp_key() inline tests. Full fixture-based happy-path +
    // multi-primary + trailing-bytes tests land in Plan 04 via
    // tests/material_pgp_ingest.rs; this block covers the synthetic-input negative
    // paths that don't need a real key fixture.

    #[test]
    fn pgp_key_armor_public_block_rejected() {
        let err = pgp_key(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: X\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(
                    reason,
                    "ASCII-armored input rejected — supply binary packet stream"
                );
            }
            other => panic!("expected InvalidMaterial, got {other:?}"),
        }
    }

    #[test]
    fn pgp_key_armor_private_block_rejected() {
        let err = pgp_key(
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----\n",
        )
        .unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(
                    reason,
                    "ASCII-armored input rejected — supply binary packet stream"
                );
            }
            other => panic!("expected InvalidMaterial, got {other:?}"),
        }
    }

    #[test]
    fn pgp_key_armor_with_leading_whitespace_still_rejected() {
        // Whitespace is skipped before the prefix check.
        let err = pgp_key(b"  \n\t-----BEGIN PGP PUBLIC KEY BLOCK-----\nfoo").unwrap_err();
        assert!(matches!(err, Error::InvalidMaterial { .. }));
    }

    #[test]
    fn pgp_key_garbage_rejected_generically() {
        // Non-PGP byte soup — parser should reject with generic reason.
        // Every reason must be one of the curated literals (oracle hygiene).
        let err = pgp_key(b"not a PGP packet stream").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert!(
                    reason == "malformed PGP packet stream"
                        || reason == "trailing bytes after PGP packet stream",
                    "unexpected reason literal: {reason}"
                );
            }
            other => panic!("expected InvalidMaterial, got {other:?}"),
        }
    }

    #[test]
    fn pgp_key_empty_input_rejected() {
        let err = pgp_key(b"").unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(reason, "malformed PGP packet stream");
            }
            other => panic!("expected InvalidMaterial, got {other:?}"),
        }
    }

    #[test]
    fn pgp_key_oracle_hygiene_no_internal_errors_in_reason() {
        // Confirm no arm allows rpgp internal strings through. Each failure
        // path reason must match one of the four curated literals from the
        // source code (not the rpgp Error::PacketParsing / MpiTooLarge etc).
        let inputs: &[&[u8]] = &[
            b"-----BEGIN PGP MESSAGE-----",
            b"garbage",
            b"",
            b"\x00\x00\x00",
        ];
        for raw in inputs {
            if let Err(Error::InvalidMaterial { reason, .. }) = pgp_key(raw) {
                assert!(
                    !reason.contains("pgp::")
                        && !reason.contains("PacketParsing")
                        && !reason.contains("MpiTooLarge"),
                    "reason leaked crate internals: {reason}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 7 Plan 05 — payload::ingest::ssh_key inline tests.
//
// Fixture-based happy-path + multi-format negative paths covered here.
// Plan 08 lands tests/material_ssh_ingest.rs (full integration) using the
// same fixture file committed by this plan.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod ssh_tests {
    use super::*;

    /// Empirical byte-determinism guard test — research GAP 4 / D-P7-11.
    /// If this assertion fails, the canonical-re-encode strategy is invalid
    /// for ssh-key 0.6.7 and the SUMMARY must record a fallback (verbatim
    /// storage with LF normalization).
    const FIXTURE_OPENSSH: &[u8] =
        include_bytes!("../../tests/fixtures/material_ssh_fixture.openssh-v1");

    #[test]
    fn ssh_key_legacy_pem_rsa_rejected() {
        let err =
            ssh_key(b"-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n")
                .unwrap_err();
        assert!(matches!(err, Error::SshKeyFormatNotSupported));
    }

    #[test]
    fn ssh_key_legacy_pem_dsa_rejected() {
        let err = ssh_key(b"-----BEGIN DSA PRIVATE KEY-----\n...\n-----END DSA PRIVATE KEY-----\n")
            .unwrap_err();
        assert!(matches!(err, Error::SshKeyFormatNotSupported));
    }

    #[test]
    fn ssh_key_legacy_pem_ec_rejected() {
        let err = ssh_key(b"-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n")
            .unwrap_err();
        assert!(matches!(err, Error::SshKeyFormatNotSupported));
    }

    #[test]
    fn ssh_key_rfc4716_rejected() {
        let err = ssh_key(b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n...\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n").unwrap_err();
        assert!(matches!(err, Error::SshKeyFormatNotSupported));
    }

    #[test]
    fn ssh_key_fido_rejected() {
        let err = ssh_key(b"-----BEGIN OPENSSH-FIDO PRIVATE KEY-----\n...\n-----END OPENSSH-FIDO PRIVATE KEY-----\n").unwrap_err();
        assert!(matches!(err, Error::SshKeyFormatNotSupported));
    }

    #[test]
    fn ssh_key_garbage_rejected_as_format_not_supported() {
        // No OpenSSH v1 header → format rejection (NOT InvalidMaterial)
        let err = ssh_key(b"random bytes that are not any kind of key").unwrap_err();
        assert!(matches!(err, Error::SshKeyFormatNotSupported));
    }

    #[test]
    fn ssh_key_empty_input_rejected_as_format_not_supported() {
        let err = ssh_key(b"").unwrap_err();
        assert!(matches!(err, Error::SshKeyFormatNotSupported));
    }

    #[test]
    fn ssh_key_format_not_supported_display_omits_internals() {
        let disp = format!("{}", Error::SshKeyFormatNotSupported);
        assert!(
            disp.contains("ssh-keygen -p -o"),
            "Display must include the ssh-keygen hint, got: {disp}"
        );
        for forbidden in &["ssh-key::", "ssh_encoding", "ssh_cipher", "PemError"] {
            assert!(
                !disp.contains(forbidden),
                "Display leaked '{forbidden}': {disp}"
            );
        }
    }

    #[test]
    fn ssh_key_malformed_openssh_v1_body_returns_invalid_material() {
        // Header IS the OpenSSH-v1 marker, body is garbage → InvalidMaterial,
        // NOT SshKeyFormatNotSupported. The user supplied the right format
        // but the contents don't parse — different remediation than format
        // rejection (no ssh-keygen conversion will fix corrupt body).
        let err = ssh_key(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nGARBAGE\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "ssh_key");
                assert_eq!(reason, "malformed OpenSSH v1 blob");
            }
            other => panic!("expected InvalidMaterial, got {other:?}"),
        }
    }

    #[test]
    fn ssh_key_fixture_round_trips_into_material() {
        let m = ssh_key(FIXTURE_OPENSSH).expect("fixture must parse");
        match m {
            Material::SshKey { bytes } => {
                // Re-parse stored bytes — must succeed (canonical re-encode is valid).
                let _reparsed =
                    ssh_key::PrivateKey::from_openssh(&bytes).expect("canonical bytes reparse");
                // Stored bytes must contain the BEGIN/END markers (UTF-8 PEM text).
                assert!(bytes.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
                assert!(
                    bytes
                        .windows(b"-----END OPENSSH PRIVATE KEY-----".len())
                        .any(|w| w == b"-----END OPENSSH PRIVATE KEY-----"),
                    "stored canonical bytes must contain END marker"
                );
            }
            other => panic!("expected Material::SshKey, got {other:?}"),
        }
    }

    /// Research GAP 4: empirical byte-determinism of from_openssh + to_openssh
    /// round-trip on ssh-key 0.6.7. If this fails, D-P7-11 is invalid and the
    /// SUMMARY must document the fallback path.
    #[test]
    fn ssh_key_canonical_re_encode_is_byte_deterministic() {
        let parsed1 = ssh_key::PrivateKey::from_openssh(FIXTURE_OPENSSH).unwrap();
        let bytes1 = parsed1.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let parsed2 = ssh_key::PrivateKey::from_openssh(bytes1.as_str()).unwrap();
        let bytes2 = parsed2.to_openssh(ssh_key::LineEnding::LF).unwrap();
        assert_eq!(
            bytes1.as_str(),
            bytes2.as_str(),
            "ssh-key 0.6.7 re-encode is NOT byte-deterministic. \
             D-P7-11 canonical-blob strategy is invalid; switch to fallback. \
             See SUMMARY.md for the deviation record."
        );
    }

    #[test]
    fn ssh_key_trailing_garbage_after_end_marker_rejected() {
        // Append non-whitespace bytes after the END marker → trailing-bytes
        // rejection (InvalidMaterial). This guards against share_ref drift
        // via attacker-appended trailers (T-07-39).
        let mut tampered = FIXTURE_OPENSSH.to_vec();
        tampered.extend_from_slice(b"GARBAGE_TRAILER");
        let err = ssh_key(&tampered).unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "ssh_key");
                assert_eq!(reason, "trailing bytes after OpenSSH v1 blob");
            }
            other => panic!("expected InvalidMaterial trailing-bytes, got {other:?}"),
        }
    }

    #[test]
    fn ssh_key_trailing_whitespace_after_end_marker_accepted() {
        // Whitespace-only trailers (newlines from text editors) are normal
        // and must NOT trigger rejection.
        let mut padded = FIXTURE_OPENSSH.to_vec();
        padded.extend_from_slice(b"\n\n  \t\n");
        ssh_key(&padded).expect("whitespace trailer must be accepted");
    }
}
