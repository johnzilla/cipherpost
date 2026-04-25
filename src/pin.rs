//! PIN-derived second-factor share encryption (Phase 8 Plan 01).
//!
//! ## Architectural lineage
//!
//! Direct fork of cclink's `pin_derive_key` (cclink/src/crypto/mod.rs:144-163):
//! - **KDF shape:** Argon2id(pin, salt[32]) → HKDF-SHA256 → 32-byte scalar — REUSED VERBATIM.
//! - **HKDF info namespace:** cclink uses `cclink-pin-v1`; cipherpost adapts to
//!   `cipherpost/v1/pin` per the project's domain-separation convention
//!   (CLAUDE.md `cipherpost/v1/<context>` load-bearing).
//! - **AEAD path:** cclink's `pin_encrypt` calls `chacha20poly1305` directly;
//!   cipherpost cannot — CLAUDE.md `chacha20poly1305 only via age` invariant
//!   prohibits direct AEAD calls. Cipherpost wraps the derived 32-byte scalar
//!   into an `age::x25519::Identity` and uses nested `age::Encryptor::with_recipients`
//!   in `src/flow.rs::run_send` (D-P8-06).
//!
//! Validation rules (`validate_pin`) and the TTY prompt (`prompt_pin`) ship in
//! Plan 02. This module ships only the KDF.

use crate::crypto::hkdf_infos;
use crate::error::Error;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use zeroize::Zeroizing;

/// PIN-specific Argon2id parameters (matches cclink's pin_derive_key shape; matches
/// `crypto::default_argon2_params()` numerically). Distinct from the identity-KEK
/// params (which are read from the PHC header per Pitfall #8 — DIFFERENT lifecycle).
///
/// Locked: 64 MiB memory, 3 iterations, 1 lane, 32-byte output.
fn pin_argon2_params() -> Params {
    Params::new(65536, 3, 1, Some(32))
        .expect("static PIN argon2 params (65536, 3, 1, Some(32)) are always valid")
}

/// Helper: map any error into Error::Crypto with a leak-safe wrapper.
fn str_err(s: impl std::fmt::Display) -> Error {
    Error::Crypto(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        s.to_string(),
    )))
}

/// Derive a 32-byte X25519 scalar from a PIN and a 32-byte salt.
///
/// Returns a `Zeroizing<[u8; 32]>` so the caller cannot accidentally leak via
/// Display/Debug/panic. The Argon2 intermediate buffer is also `Zeroizing`.
///
/// The returned scalar is intended to be wrapped via
/// [`crate::crypto::identity_from_x25519_bytes`] into an `age::x25519::Identity`,
/// then `to_public()` to produce a `Recipient` for nested age encryption.
///
/// PIN-09 invariants:
/// - Argon2id 64 MiB / 3 iter / 1 lane / 32-byte output (matches cclink).
/// - HKDF-SHA256 with info `cipherpost/v1/pin` (referenced via `hkdf_infos::PIN`,
///   never inline-literal).
/// - Salt-as-HKDF-salt: matches `derive_kek` shape (`Hkdf::new(Some(salt), ikm)`).
pub fn pin_derive_key(
    pin: &SecretBox<String>,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, pin_argon2_params());
    let mut argon_out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pin.expose_secret().as_bytes(), salt, &mut argon_out[..])
        .map_err(str_err)?;

    let hk = Hkdf::<Sha256>::new(Some(salt), &argon_out[..]);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(hkdf_infos::PIN.as_bytes(), &mut okm[..])
        .map_err(|e| str_err(format!("hkdf expand: {}", e)))?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// PIN validation + TTY prompt (Phase 8 Plan 02).
//
// PIN-02 / PIN-01 / PIN-06: validate_pin enforces an entropy floor (8-char
// minimum, no all-same, no monotonic sequential, no blocklist). prompt_pin
// reads a PIN from a TTY (no echo) with optional double-entry confirmation.
// AD-5: tests can inject a PIN via the cfg-gated `CIPHERPOST_TEST_PIN` env
// var (compiled out of production builds).
//
// Oracle hygiene (Pitfalls #23/#24): every rejection path produces the SAME
// generic Display literal — never names which check fired. The specific
// reason is asserted at the test layer (`tests/pin_validation.rs`) and may
// appear in source comments, but NEVER in user-facing output.
// ---------------------------------------------------------------------------

/// Anti-pattern blocklist (case-insensitive). Direct fork of cclink's
/// validate_pin blocklist (cclink/src/commands/publish.rs:19-67).
const PIN_BLOCKLIST: &[&str] = &[
    "password", "qwerty", "letmein", "12345678", "87654321", "qwertyui", "asdfghjk",
];

/// Validate a candidate PIN (PIN-02).
///
/// Rejects: length < 8, all-same characters, monotonic ascending sequential,
/// monotonic descending sequential, blocklist (case-insensitive).
///
/// Every rejection returns the IDENTICAL generic Display via
/// `Error::Config("PIN does not meet entropy requirements")` — the specific
/// reason is NEVER named in user-facing output (oracle hygiene per
/// PITFALLS #23/#24, supersedes REQUIREMENTS PIN-02 wording per D-P8-12).
///
/// Length check runs FIRST so length-failures don't leak via Argon2id timing
/// (T-08-15).
pub fn validate_pin(pin: &str) -> Result<(), Error> {
    const REJECT: &str = "PIN does not meet entropy requirements";

    let len = pin.chars().count();
    if len < 8 {
        return Err(Error::Config(REJECT.to_string()));
    }

    let first = pin.chars().next().expect("len >= 8 implies non-empty");
    if pin.chars().all(|c| c == first) {
        return Err(Error::Config(REJECT.to_string()));
    }

    let chars: Vec<char> = pin.chars().collect();
    let asc = chars
        .windows(2)
        .all(|w| (w[1] as i32) - (w[0] as i32) == 1);
    let desc = chars
        .windows(2)
        .all(|w| (w[0] as i32) - (w[1] as i32) == 1);
    if asc || desc {
        return Err(Error::Config(REJECT.to_string()));
    }

    let lower = pin.to_lowercase();
    if PIN_BLOCKLIST.iter().any(|b| *b == lower.as_str()) {
        return Err(Error::Config(REJECT.to_string()));
    }

    Ok(())
}

/// AD-5 test-mode PIN injection. Cfg-gated; production builds always return
/// `None` (so the env var is never consulted).
fn test_pin_override() -> Option<String> {
    #[cfg(any(test, feature = "mock"))]
    {
        std::env::var("CIPHERPOST_TEST_PIN").ok()
    }
    #[cfg(not(any(test, feature = "mock")))]
    {
        None
    }
}

/// TTY-only PIN prompt (PIN-01, PIN-06).
///
/// `confirm=true` at send time (double-entry — protects against typos that
/// would silently brick a share's decryptability). `confirm=false` at receive
/// time (single-shot — wrong PIN funnels through `Error::DecryptFailed` at
/// the inner age-decrypt step, exit 4).
///
/// Non-TTY context HARD-REJECTS with `Error::Config` (exit 1). Non-interactive
/// PIN sources (`--pin-file`, `--pin-fd`, `CIPHERPOST_PIN` env) are deferred
/// to v1.2 — v1.1 keeps PIN as an intentionally human-in-the-loop second
/// factor.
///
/// AD-5: under `cfg(test)` or `feature = "mock"`, the `CIPHERPOST_TEST_PIN`
/// env var bypasses the prompt entirely (used by integration tests). The
/// override still runs `validate_pin` so test PINs are subject to the same
/// entropy floor (catches accidental empty / weak test fixtures).
pub fn prompt_pin(confirm: bool) -> Result<SecretBox<String>, Error> {
    if let Some(test_pin) = test_pin_override() {
        validate_pin(&test_pin)?;
        return Ok(SecretBox::new(Box::new(test_pin)));
    }

    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(Error::Config(
            "--pin requires interactive TTY (non-interactive PIN sources deferred to v1.2)"
                .to_string(),
        ));
    }

    let theme = dialoguer::theme::ColorfulTheme::default();
    let mut builder = dialoguer::Password::with_theme(&theme);
    builder = builder.with_prompt("Enter PIN (8+ chars, no all-same, no sequential)");
    if confirm {
        builder = builder.with_confirmation("Confirm PIN", "PINs do not match");
    }
    let pin: String = builder
        .interact()
        .map_err(|e| Error::Config(format!("PIN prompt failed: {}", e)))?;

    validate_pin(&pin)?;
    Ok(SecretBox::new(Box::new(pin)))
}
