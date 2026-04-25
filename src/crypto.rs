//! Crypto primitives — vendored logic from cclink with domain-separated HKDF,
//! JCS canonical JSON, and PHC-encoded Argon2 params.
//!
//! Pitfalls addressed:
//!   #1  (Ed25519→X25519 via spec'd Edwards→Montgomery conversion)
//!   #3  (canonical JSON via RFC 8785 / JCS using serde_canonical_json)
//!   #4  (HKDF versioning — every info string in `hkdf_infos` module)
//!   #7  (Zeroize / no Debug derive on secret-holding types)
//!   #8  (Argon2 params in PHC header, not hardcoded in code)
//!   #9  (AEAD only through age's API — no direct chacha20poly1305 import)
//!
//! INVARIANT: every `Hkdf::<Sha256>::new` / `hk.expand(info, ...)` call in this
//! file MUST use a constant from `hkdf_infos`. Passing a non-module-resident info
//! string bypasses `tests/hkdf_info_enumeration.rs`. If you need a new context,
//! add a new constant to `hkdf_infos` first.

use crate::error::Error;
use age::x25519;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params,
};
use bech32::{ToBase32, Variant};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use serde::Serialize;
use serde_canonical_json::CanonicalFormatter;
use sha2::Sha256;
use std::io::Write as IoWrite;
use std::str::FromStr;
use zeroize::Zeroizing;

/// All HKDF info strings used in this crate.
///
/// INVARIANT: every `Hkdf::<Sha256>::new` / `hk.expand(info, ...)` call MUST
/// pass one of these constants as the `info` argument. Tests in
/// `tests/hkdf_info_enumeration.rs` grep `src/` for literal strings prefixed
/// `"cipherpost/v1/"` and assert they are all distinct, non-empty, and versioned.
/// Adding a non-constant info string (e.g. via `format!(...)`) will silently bypass
/// that test — document it in the test file and as a Phase-2+ todo instead.
pub mod hkdf_infos {
    /// Key-encryption key for the identity file's CIPHPOSK envelope.
    ///
    /// INVARIANT: this string appears in `tests/hkdf_info_enumeration.rs` scan.
    /// Never use a different string for the identity KEK derivation.
    pub const IDENTITY_KEK: &str = "cipherpost/v1/identity-kek";

    /// HKDF domain for sender-side share-key derivation (reserved in Phase 2).
    /// Not currently referenced in code — age handles its own internal KDF — but
    /// registered here so any future call site uses a versioned, unique info string.
    pub const SHARE_SENDER: &str = "cipherpost/v1/share-sender";

    /// HKDF domain for recipient-side share-key derivation (reserved in Phase 2).
    pub const SHARE_RECIPIENT: &str = "cipherpost/v1/share-recipient";

    /// HKDF domain for inner-payload key derivation (reserved in Phase 2).
    pub const INNER_PAYLOAD: &str = "cipherpost/v1/inner-payload";

    /// Phase 8 Plan 01 (D-P8-02): HKDF info string for PIN-derived second-factor
    /// share encryption. Shape: Argon2id(pin, salt) → HKDF-SHA256 with this info
    /// → 32-byte X25519 scalar wrapped into an age Identity.
    ///
    /// INVARIANT: never inline the literal in `hk.expand(...)` calls — always
    /// reference this constant. The grep-based `tests/hkdf_info_enumeration.rs`
    /// scan only sees module constants; an inline literal silently bypasses
    /// the namespace-prefix invariant test.
    pub const PIN: &str = "cipherpost/v1/pin";

    // Phase 3 adds: RECEIPT_SIGN
}

/// Version byte written into the CIPHPOSK envelope header.
pub const CIPHPOSK_ENVELOPE_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Ed25519 ↔ X25519 conversion (Pitfall #1)
//
// MUST match libsodium / cclink byte-for-byte. The committed fixture vectors in
// tests/fixtures/ed25519_x25519_vectors.json are the source of truth.
// If this changes, every past identity becomes unreachable.
// ---------------------------------------------------------------------------

/// Convert an Ed25519 public key (32 raw bytes) to its X25519 counterpart via
/// the Edwards→Montgomery map. Matches cclink v1.3.0's output byte-for-byte.
pub fn ed25519_to_x25519_public(ed_pub_bytes: &[u8; 32]) -> Result<[u8; 32], Error> {
    use ed25519_dalek::VerifyingKey;
    let vk = VerifyingKey::from_bytes(ed_pub_bytes).map_err(|e| Error::Crypto(Box::new(e)))?;
    Ok(vk.to_montgomery().to_bytes())
}

/// Convert an Ed25519 signing-key seed to the clamped X25519 scalar.
///
/// Uses `SigningKey::to_scalar_bytes()` from ed25519-dalek 3.x: computes
/// SHA-512(seed) and returns the clamped first 32 bytes (the X25519 private
/// scalar). The returned value is `Zeroizing` so drop zeroes memory.
pub fn ed25519_to_x25519_secret(signing_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let sk = ed25519_dalek::SigningKey::from_bytes(signing_seed);
    Zeroizing::new(sk.to_scalar_bytes())
}

// ---------------------------------------------------------------------------
// age X25519 recipient / identity constructors (Pitfall #9)
//
// All AEAD operations go through age's Encryptor/Decryptor API.
// No direct `chacha20poly1305` or `aes_gcm` imports anywhere in src/.
// ---------------------------------------------------------------------------

/// Helper: map a string error into Error::Crypto.
fn str_err(s: impl std::fmt::Display) -> Error {
    struct StrError(String);
    // Manual Debug impl — never derived in this file (acceptance criteria, no derive-Debug on any type here).
    impl std::fmt::Debug for StrError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::fmt::Display for StrError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for StrError {}
    Error::Crypto(Box::new(StrError(s.to_string())))
}

/// Convert raw X25519 public-key bytes into an age::x25519::Recipient.
///
/// Uses bech32 encoding with the "age" HRP — the same encoding age uses for
/// public recipients. This is the pattern from cclink v1.3.0.
pub fn recipient_from_x25519_bytes(bytes: &[u8; 32]) -> Result<x25519::Recipient, Error> {
    let encoded = bech32::encode("age", bytes.to_base32(), Variant::Bech32).map_err(str_err)?;
    x25519::Recipient::from_str(&encoded).map_err(str_err)
}

/// Convert raw X25519 secret-key bytes into an age::x25519::Identity.
///
/// Uses bech32 encoding with the "age-secret-key-" HRP.
/// The secret is uppercased per age's canonical format.
pub fn identity_from_x25519_bytes(bytes: &[u8; 32]) -> Result<x25519::Identity, Error> {
    let encoded =
        bech32::encode("age-secret-key-", bytes.to_base32(), Variant::Bech32).map_err(str_err)?;
    x25519::Identity::from_str(&encoded.to_uppercase()).map_err(str_err)
}

/// age-encrypt `plaintext` to a single X25519 recipient.
///
/// All AEAD goes through age's Encryptor API (Pitfall #9). No direct
/// `chacha20poly1305` usage.
pub fn age_encrypt(plaintext: &[u8], recipient: &x25519::Recipient) -> Result<Vec<u8>, Error> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(str_err)?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).map_err(str_err)?;
    writer.write_all(plaintext).map_err(Error::Io)?;
    writer.finish().map_err(str_err)?;
    Ok(out)
}

/// age-decrypt `ciphertext` using an X25519 identity.
///
/// Returns the plaintext in a `Zeroizing<Vec<u8>>` so it is zeroed on drop.
pub fn age_decrypt(
    ciphertext: &[u8],
    identity: &x25519::Identity,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|_| Error::DecryptFailed)?;
    let mut plaintext = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| Error::DecryptFailed)?;
    std::io::copy(&mut reader, &mut plaintext).map_err(|_| Error::DecryptFailed)?;
    Ok(Zeroizing::new(plaintext))
}

// ---------------------------------------------------------------------------
// Argon2id + HKDF-SHA256 KEK derivation (Pitfalls #4, #8)
// ---------------------------------------------------------------------------

/// Default Argon2id params used at generate-time.
///
/// Per PROJECT.md: m=64MB, t=3 iterations, p=1 lane, 32-byte output.
/// These are ONLY used when creating a new identity; unlock reads params
/// from the file's PHC header (Pitfall #8).
pub fn default_argon2_params() -> Params {
    Params::new(65536, 3, 1, Some(32)).expect("static Argon2 params are always valid")
}

/// Derive a 32-byte key-encryption key via Argon2id → HKDF-SHA256.
///
/// Uses `hkdf_infos::IDENTITY_KEK` as the info string (Pitfall #4).
/// `Zeroizing` ensures the KEK is zeroed on drop.
pub fn derive_kek(
    passphrase: &SecretBox<String>,
    salt: &[u8],
    params: &Params,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );
    let mut argon_out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(
            passphrase.expose_secret().as_bytes(),
            salt,
            &mut argon_out[..],
        )
        .map_err(str_err)?;

    // HKDF-SHA256 with domain-separated info string (Pitfall #4).
    // INVARIANT: info MUST come from `hkdf_infos` — do not inline a literal here.
    let hk = Hkdf::<Sha256>::new(Some(salt), &argon_out[..]);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(hkdf_infos::IDENTITY_KEK.as_bytes(), &mut okm[..])
        .map_err(|e| str_err(format!("hkdf expand: {}", e)))?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// CIPHPOSK envelope encode/decode (Pitfall #8)
//
// Layout: MAGIC(8) || VER(1) || PHC_LEN(2 BE) || PHC_STRING(N) || age_ciphertext
//
// The PHC string stores the Argon2id params (m, t, p, salt, hash) so that
// decrypt can read them back without hardcoding. (Pitfall #8.)
// ---------------------------------------------------------------------------

/// Encrypt a 32-byte seed into a CIPHPOSK envelope using the default Argon2 params.
///
/// Convenience wrapper over `encrypt_key_envelope_with_params` using
/// `default_argon2_params()`.
pub fn encrypt_key_envelope(
    seed: &Zeroizing<[u8; 32]>,
    passphrase: &SecretBox<String>,
) -> Result<Vec<u8>, Error> {
    encrypt_key_envelope_impl(seed, passphrase, &default_argon2_params())
}

/// Encrypt a 32-byte seed into a CIPHPOSK envelope using explicit Argon2 params.
///
/// Intended for tests and tooling that need to generate identities with non-default
/// Argon2 params (e.g., to prove `decrypt_key_envelope` reads params from the PHC
/// header rather than code constants — Pitfall #8).
///
/// Safe to expose unconditionally: the caller must supply both a `Zeroizing<[u8;32]>`
/// seed and a `SecretBox<String>` passphrase; neither is derivable without legitimate
/// key material.
pub fn encrypt_key_envelope_with_params(
    seed: &Zeroizing<[u8; 32]>,
    passphrase: &SecretBox<String>,
    params: &Params,
) -> Result<Vec<u8>, Error> {
    encrypt_key_envelope_impl(seed, passphrase, params)
}

/// Shared envelope encryption implementation.
fn encrypt_key_envelope_impl(
    seed: &Zeroizing<[u8; 32]>,
    passphrase: &SecretBox<String>,
    params: &Params,
) -> Result<Vec<u8>, Error> {
    use rand::RngCore;

    // 1. Generate a random 16-byte salt.
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);

    // 2. Produce a PHC-format PasswordHash string so params are stored in the envelope.
    let salt_str = SaltString::encode_b64(&salt_bytes).map_err(str_err)?;
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );
    let phc_hash = argon
        .hash_password(passphrase.expose_secret().as_bytes(), &salt_str)
        .map_err(str_err)?;
    let phc_string = phc_hash.to_string();

    // 3. Derive the KEK from the passphrase + salt + params.
    let kek = derive_kek(passphrase, &salt_bytes, params)?;

    // 4. Convert the KEK into an age X25519 identity and encrypt the seed to "self".
    //    The KEK bytes are treated as the X25519 secret key bytes.
    let age_identity = identity_from_x25519_bytes(&kek)?;
    let age_recipient = age_identity.to_public();
    let age_ciphertext = age_encrypt(seed.as_ref(), &age_recipient)?;

    // 5. Build the envelope: MAGIC || VER || PHC_LEN(2 BE) || PHC_STRING || age_ciphertext
    let phc_bytes = phc_string.as_bytes();
    let phc_len = phc_bytes.len();
    assert!(phc_len <= u16::MAX as usize, "PHC string too long");

    let mut envelope = Vec::new();
    envelope.extend_from_slice(crate::ENVELOPE_MAGIC);
    envelope.push(CIPHPOSK_ENVELOPE_VERSION);
    envelope.extend_from_slice(&(phc_len as u16).to_be_bytes());
    envelope.extend_from_slice(phc_bytes);
    envelope.extend_from_slice(&age_ciphertext);

    Ok(envelope)
}

/// Decrypt a CIPHPOSK envelope and return the 32-byte seed.
///
/// Reads Argon2 params from the envelope's PHC header — does NOT use
/// hardcoded constants (Pitfall #8). Wrong passphrase → `Error::DecryptFailed`.
pub fn decrypt_key_envelope(
    blob: &[u8],
    passphrase: &SecretBox<String>,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    // 1. Validate magic and version.
    if blob.len() < 11 {
        return Err(Error::IdentityCorrupt);
    }
    if &blob[..8] != crate::ENVELOPE_MAGIC {
        return Err(Error::IdentityCorrupt);
    }
    if blob[8] != CIPHPOSK_ENVELOPE_VERSION {
        return Err(Error::IdentityCorrupt);
    }

    // 2. Parse PHC_LEN and PHC_STRING.
    let phc_len = u16::from_be_bytes([blob[9], blob[10]]) as usize;
    if blob.len() < 11 + phc_len {
        return Err(Error::IdentityCorrupt);
    }
    let phc_str =
        std::str::from_utf8(&blob[11..11 + phc_len]).map_err(|_| Error::IdentityCorrupt)?;

    // 3. Parse the PHC hash → extract Argon2 params and salt.
    use argon2::password_hash::PasswordHash;
    let phc_hash = PasswordHash::new(phc_str).map_err(|_| Error::IdentityCorrupt)?;

    // Extract params from the PHC structure.
    let params = argon2_params_from_phc(&phc_hash)?;

    // Extract the raw salt bytes from the PHC salt field.
    let phc_salt = phc_hash.salt.ok_or(Error::IdentityCorrupt)?;
    let mut salt_buf = [0u8; 64];
    let salt_raw = phc_salt
        .decode_b64(&mut salt_buf)
        .map_err(|_| Error::IdentityCorrupt)?;

    // 4. Derive the KEK using params from the header (Pitfall #8).
    let kek = derive_kek(passphrase, salt_raw, &params)?;

    // 5. Reconstruct the age identity from the KEK, decrypt the seed.
    let age_identity = identity_from_x25519_bytes(&kek)?;
    let age_ciphertext = &blob[11 + phc_len..];

    let plaintext = age_decrypt(age_ciphertext, &age_identity).map_err(|_| Error::DecryptFailed)?;
    if plaintext.len() != 32 {
        return Err(Error::IdentityCorrupt);
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Extract `argon2::Params` from a `PasswordHash` PHC structure.
fn argon2_params_from_phc(hash: &argon2::password_hash::PasswordHash) -> Result<Params, Error> {
    let get_param = |name: &str| -> Result<u32, Error> {
        hash.params
            .get(name)
            .ok_or(Error::IdentityCorrupt)?
            .decimal()
            .map_err(|_| Error::IdentityCorrupt)
    };
    let m_cost = get_param("m")?;
    let t_cost = get_param("t")?;
    let p_cost = get_param("p")?;
    Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(str_err)
}

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785 / JCS)
// ---------------------------------------------------------------------------

/// Serialize a value to RFC 8785 canonical JSON bytes using `serde_canonical_json`.
///
/// This is the ONLY path for producing bytes that will be signed. Any struct
/// serialized through this function MUST NOT contain `f32`/`f64` fields —
/// `tests/crypto_no_floats_in_signable.rs` enforces this via Value introspection.
pub fn jcs_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value
        .serialize(&mut ser)
        .map_err(|e| Error::Crypto(Box::new(e)))?;
    Ok(buf)
}
