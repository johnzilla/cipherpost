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
