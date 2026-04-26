//! SSH-04: golden-string tests for preview::render_ssh_preview.
//!
//! Pins:
//!   - Field-prefix ordering (separator + Key + Fingerprint + Comment)
//!   - SHA-256 fingerprint format (43-char base64-unpadded)
//!   - Empty-comment rendering as `(none)`
//!   - `[DEPRECATED]` tag for RSA-1024 (per D-P7-14)
//!   - No leading/trailing newline
//!   - Separator dash count = 57
//!
//! NOTE on DSA: the DSA-deprecation banner test is INTENTIONALLY OMITTED.
//! Modern OpenSSH refuses DSA generation, and adding the `dsa` feature to
//! ssh-key 0.6.7 to generate a fixture via the crate's KeyGen API would
//! expand supply-chain surface (D-P7-10's verified-clean shape uses
//! `default-features = false, features = ["alloc"]` only). DSA-deprecation
//! rendering is covered by:
//!   - src/preview.rs::tests::is_deprecated_ssh_algorithm_dsa_always_deprecated
//!     (Plan 06 unit test pinning the predicate logic — DSA at any size is
//!     flagged deprecated).
//! See SUMMARY.md for the rationale.

use cipherpost::preview;

const SSH_FIXTURE_ED25519: &[u8] = include_bytes!("fixtures/material_ssh_fixture.openssh-v1");
const SSH_FIXTURE_RSA1024: &[u8] =
    include_bytes!("fixtures/material_ssh_fixture_rsa1024.openssh-v1");

#[test]
fn render_ssh_preview_ed25519_contains_all_expected_fields() {
    let s = preview::render_ssh_preview(SSH_FIXTURE_ED25519).expect("Ed25519 fixture must render");
    let lines: Vec<&str> = s.lines().collect();
    assert!(
        lines.len() >= 4,
        "expected ≥4 lines (separator + Key + Fingerprint + Comment), got {}: {:?}",
        lines.len(),
        lines
    );
    assert!(
        lines[0].starts_with("--- SSH "),
        "line 0 must be the SSH separator, got: {:?}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("Key:         "),
        "line 1 must be the Key prefix, got: {:?}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("Fingerprint: "),
        "line 2 must be the Fingerprint prefix, got: {:?}",
        lines[2]
    );
    assert!(
        lines[3].starts_with("Comment:     "),
        "line 3 must be the Comment prefix, got: {:?}",
        lines[3]
    );
    assert!(
        !lines[1].contains("[DEPRECATED]"),
        "Ed25519 must NOT carry the [DEPRECATED] tag, got: {:?}",
        lines[1]
    );
}

#[test]
fn render_ssh_preview_ed25519_fingerprint_is_sha256_format() {
    let s = preview::render_ssh_preview(SSH_FIXTURE_ED25519).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    let fp_line = lines[2];
    let fp_value = fp_line.trim_start_matches("Fingerprint: ");
    assert!(
        fp_value.starts_with("SHA256:"),
        "Fingerprint must start with `SHA256:`, got: {}",
        fp_value
    );
    let b64 = fp_value.trim_start_matches("SHA256:");
    // SHA-256 = 32 bytes; base64-unpadded = 43 chars (matches `ssh-keygen -lf`).
    assert_eq!(
        b64.len(),
        43,
        "SHA-256 base64-unpadded must be 43 chars, got {}: {:?}",
        b64.len(),
        b64
    );
    // No padding chars
    assert!(
        !b64.contains('='),
        "SHA-256 fingerprint must not include `=` padding, got: {:?}",
        b64
    );
}

#[test]
fn render_ssh_preview_ed25519_key_line_includes_size() {
    let s = preview::render_ssh_preview(SSH_FIXTURE_ED25519).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    let key_line = lines[1];
    assert_eq!(
        key_line, "Key:         ssh-ed25519 256",
        "Ed25519 key line must be exact (algorithm wire-name + bits), got: {:?}",
        key_line
    );
}

#[test]
fn render_ssh_preview_ed25519_empty_comment_renders_as_none() {
    let s = preview::render_ssh_preview(SSH_FIXTURE_ED25519).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    let comment_line = lines[3];
    assert_eq!(
        comment_line, "Comment:     [sender-attested] (none)",
        "Empty-comment fixture must render as `[sender-attested] (none)`, got: {:?}",
        comment_line
    );
}

#[test]
fn render_ssh_preview_rsa1024_carries_deprecated_tag() {
    let s = preview::render_ssh_preview(SSH_FIXTURE_RSA1024).expect("RSA-1024 fixture must render");
    let lines: Vec<&str> = s.lines().collect();
    let key_line = lines[1];
    assert!(
        key_line.ends_with("[DEPRECATED]"),
        "RSA-1024 key line must end with `[DEPRECATED]`, got: {:?}",
        key_line
    );
    assert!(
        key_line.contains("ssh-rsa 1024"),
        "RSA-1024 key line must contain `ssh-rsa 1024`, got: {:?}",
        key_line
    );
}

#[test]
fn render_ssh_preview_no_leading_or_trailing_newline() {
    let s = preview::render_ssh_preview(SSH_FIXTURE_ED25519).unwrap();
    assert!(
        !s.starts_with('\n'),
        "render_ssh_preview output must NOT start with a newline, got: {:?}",
        &s[..s.len().min(40)]
    );
    assert!(
        !s.ends_with('\n'),
        "render_ssh_preview output must NOT end with a newline, got: {:?}",
        &s[s.len().saturating_sub(40)..]
    );
}

#[test]
fn render_ssh_preview_separator_line_is_57_dashes_after_prefix() {
    let s = preview::render_ssh_preview(SSH_FIXTURE_ED25519).unwrap();
    let sep = s.lines().next().unwrap();
    assert!(sep.starts_with("--- SSH "));
    let dashes = &sep["--- SSH ".len()..];
    assert_eq!(
        dashes.len(),
        57,
        "separator dash count must be 57 (SSH_SEPARATOR_DASH_COUNT const), got {}: {:?}",
        dashes.len(),
        dashes
    );
    assert!(
        dashes.chars().all(|c| c == '-'),
        "separator suffix must be all dashes, got: {:?}",
        dashes
    );
}
