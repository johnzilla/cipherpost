//! Identity: ~/.cipherpost/secret_key — Argon2id-passphrase-wrapped at mode 0600.
//!
//! Pitfalls addressed:
//!   #7  (no Debug derive on Identity or Passphrase — manual redacted impls)
//!   #8  (Argon2 params live in envelope PHC header, not code constants)
//!   #14 (passphrase never accepted via argv — rejected in resolve_passphrase)
//!   #15 (identity file written atomically at mode 0600; load refuses 0644+)
//!
//! The `CIPHERPOST_HOME` env var overrides the default `~/.cipherpost/` path. Tests
//! set this to a TempDir so they do not pollute $HOME.

use crate::crypto;
use crate::error::Error;
use secrecy::{ExposeSecret, SecretBox};
use std::fs;
use std::io::Write as IoWrite;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Return the cipherpost key directory.
///
/// Consults `CIPHERPOST_HOME` env var first; falls back to `~/.cipherpost/`.
/// Tests set `CIPHERPOST_HOME` to a `TempDir` path to avoid polluting `$HOME`.
pub fn key_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("CIPHERPOST_HOME") {
        PathBuf::from(custom)
    } else {
        dirs::home_dir()
            .expect("no home directory found")
            .join(".cipherpost")
    }
}

/// Return the path to the identity file (`{key_dir}/secret_key`).
pub fn key_path() -> PathBuf {
    key_dir().join("secret_key")
}

// ---------------------------------------------------------------------------
// Identity struct
// ---------------------------------------------------------------------------

/// An Ed25519 identity wrapping a pkarr `Keypair`.
///
/// Debug is NOT derived — the manual impl below shows `[REDACTED Identity]`
/// so that `format!("{:?}", id)` never leaks key material. (Pitfall #7.)
pub struct Identity {
    keypair: pkarr::Keypair,
}

// Manual Debug: never derive on a type holding secret material. (Pitfall #7.)
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED Identity]")
    }
}

impl Identity {
    /// Return the Ed25519 public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.keypair.public_key().to_bytes()
    }

    /// Return the z-base-32 encoding of the public key (the PKARR DHT address).
    pub fn z32_pubkey(&self) -> String {
        self.keypair.public_key().to_z32()
    }

    /// Return the Ed25519 signing seed (32 bytes) in a Zeroizing wrapper.
    ///
    /// This is the clean accessor for downstream flow code (payload encrypt/decrypt
    /// derives X25519 from this seed via `crypto::ed25519_to_x25519_secret`). The
    /// Zeroizing wrapper drops the bytes from memory when the borrow ends.
    ///
    /// Use in preference to `secret_key_bytes_for_leak_test` — the latter name is
    /// preserved only because Phase 1's `tests/debug_leak_scan.rs` calls it.
    pub fn signing_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.keypair.secret_key())
    }

    /// Test-only accessor: returns the raw secret key seed bytes for the Debug-leak test.
    ///
    /// Only accessible when compiled with `cfg(any(test, feature = "mock"))`. Integration
    /// tests (a separate crate from the library) do NOT satisfy `cfg(test)` on the library
    /// side, so we also gate on the `mock` feature — or simply expose unconditionally here
    /// since the name makes the intent clear and the caller still needs a constructed `Identity`.
    ///
    /// Do NOT use this in application code.
    pub fn secret_key_bytes_for_leak_test(&self) -> [u8; 32] {
        self.keypair.secret_key()
    }
}

// ---------------------------------------------------------------------------
// generate / load
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 identity, wrap it with Argon2id+HKDF KEK derived from
/// `passphrase`, and atomically write the CIPHPOSK envelope to `key_path()` at
/// mode 0600. Returns the in-memory `Identity`.
///
/// Creates `key_dir()` at mode 0700 if it does not exist.
pub fn generate(pw: &SecretBox<String>) -> Result<Identity, Error> {
    let dir = key_dir();
    fs::create_dir_all(&dir).map_err(Error::Io)?;
    // Ensure the directory itself is 0700.
    let mut dir_perms = fs::metadata(&dir).map_err(Error::Io)?.permissions();
    dir_perms.set_mode(0o700);
    fs::set_permissions(&dir, dir_perms).map_err(Error::Io)?;

    let keypair = pkarr::Keypair::random();
    let seed = Zeroizing::new(keypair.secret_key());

    let blob = crypto::encrypt_key_envelope(&seed, pw)?;

    // Atomic write to a temp path, then rename.
    let dest = key_path();
    let tmp = dest.with_extension("tmp");

    // Remove stale tmp if it exists.
    let _ = fs::remove_file(&tmp);

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(Error::Io)?;
    file.write_all(&blob).map_err(Error::Io)?;
    file.sync_all().map_err(Error::Io)?;
    drop(file);

    fs::rename(&tmp, &dest).map_err(Error::Io)?;

    // Re-apply 0600 after rename in case the umask affected the final file.
    let mut perms = fs::metadata(&dest).map_err(Error::Io)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&dest, perms).map_err(Error::Io)?;

    Ok(Identity { keypair })
}

/// Load and decrypt the identity from `key_path()`.
///
/// Enforces mode 0600 (Pitfall #15): returns `Error::IdentityPermissions` if the
/// file mode is anything other than exactly 0600.
///
/// Wrong passphrase or corrupt file returns `Error::DecryptFailed` /
/// `Error::IdentityCorrupt` (D-15: the binary dispatcher never walks source chains).
pub fn load(pw: &SecretBox<String>) -> Result<Identity, Error> {
    let path = key_path();
    if !path.exists() {
        return Err(Error::IdentityNotFound {
            path: path.display().to_string(),
        });
    }
    // Pitfall #15: reject files not at exactly 0600.
    let meta = fs::metadata(&path).map_err(Error::Io)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(Error::IdentityPermissions);
    }

    let blob = fs::read(&path).map_err(Error::Io)?;
    let seed = crypto::decrypt_key_envelope(&blob, pw)?;

    // Reconstruct the keypair from the seed.
    let keypair = pkarr::Keypair::from_secret_key(&seed);
    Ok(Identity { keypair })
}

// ---------------------------------------------------------------------------
// Fingerprints (IDENT-05)
// ---------------------------------------------------------------------------

/// Return both fingerprints for an identity:
/// - `openssh`: `ed25519:SHA256:<base64(sha256(encoded_pk))>` per RFC 4253/4716.
/// - `z32`: z-base-32 PKARR pubkey (the DHT address).
pub fn show_fingerprints(id: &Identity) -> (String, String) {
    let pk_bytes = id.public_key_bytes();
    let openssh = openssh_fingerprint(&pk_bytes);
    let z32 = id.z32_pubkey();
    (openssh, z32)
}

/// Compute the OpenSSH-style Ed25519 fingerprint.
///
/// Wire format: `uint32(len("ssh-ed25519")) || "ssh-ed25519" || uint32(32) || pk_bytes`.
/// Fingerprint: `ed25519:SHA256:<base64url-no-pad(sha256(wire))>`.
fn openssh_fingerprint(pk: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};

    let algo = b"ssh-ed25519";
    let mut encoded = Vec::with_capacity(4 + algo.len() + 4 + 32);
    encoded.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    encoded.extend_from_slice(algo);
    encoded.extend_from_slice(&32u32.to_be_bytes());
    encoded.extend_from_slice(pk);

    let digest = Sha256::digest(&encoded);
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, digest);
    format!("ed25519:SHA256:{}", b64)
}

// ---------------------------------------------------------------------------
// Passphrase type and resolution (IDENT-04 / Pitfall #14)
// ---------------------------------------------------------------------------

/// Opaque passphrase wrapper with redacted Debug.
///
/// Debug is NOT derived — manual impl below shows `[REDACTED]`. (Pitfall #7.)
pub struct Passphrase(SecretBox<String>);

impl Passphrase {
    /// Construct from a plain `String`.
    pub fn from_string(s: String) -> Self {
        Passphrase(SecretBox::new(Box::new(s)))
    }

    /// Expose the passphrase as a `&str`.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Return the inner `SecretBox<String>` for passing to `crypto::*` functions.
    pub fn as_secret(&self) -> &SecretBox<String> {
        &self.0
    }
}

// Manual Debug: Passphrase must never derive Debug — it holds a SecretBox. (Pitfall #7.)
impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Passphrase([REDACTED])")
    }
}

/// Resolve a passphrase from the available inputs, in priority order:
///
/// 1. `inline_argv` — ALWAYS rejected (Pitfall #14). Returns `Error::PassphraseInvalidInput`
///    immediately if `Some`. The `--passphrase <value>` clap flag is `hide = true` and exists
///    only so this path can fire.
/// 2. `fd` — read from a numeric file descriptor (process-provided secret).
/// 3. `file` — read from `--passphrase-file <path>` (file must be mode 0600 or 0400).
/// 4. `env_var_name` — read from the named env var (default: `CIPHERPOST_PASSPHRASE`).
/// 5. TTY prompt — interactive `dialoguer::Password` prompt. When `confirm_on_tty` is
///    `true`, the user is prompted a second time and the two entries must match; mismatch
///    re-prompts. This is critical for `identity generate` because a silently-typo'd
///    passphrase bricks the newly-created key (no recovery path). Unlock operations
///    (`show`, `send`, `receive`) pass `false` — a typo surfaces as
///    `Error::PassphraseIncorrect` against the existing identity, so double-entry is
///    wasted keystrokes.
pub fn resolve_passphrase(
    inline_argv: Option<&str>,
    env_var_name: Option<&str>,
    file: Option<&Path>,
    fd: Option<i32>,
    confirm_on_tty: bool,
) -> Result<Passphrase, Error> {
    // Priority 1: reject argv-inline (Pitfall #14 / IDENT-04).
    if inline_argv.is_some() {
        return Err(Error::PassphraseInvalidInput);
    }

    // Priority 2: fd.
    if let Some(n) = fd {
        use std::io::BufRead;
        use std::os::unix::io::FromRawFd;
        // SAFETY: we trust the caller-provided fd. We do NOT close the fd after reading
        // because the caller (main.rs) might share stdin (fd=0). We rely on the process
        // exiting to clean up. If n == 0 that's stdin, which is fine.
        let file = unsafe { fs::File::from_raw_fd(n) };
        let mut reader = std::io::BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(Error::Io)?;
        // Prevent the file from being closed (drop would close the raw fd).
        std::mem::forget(reader);
        return Ok(Passphrase::from_string(
            line.trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string(),
        ));
    }

    // Priority 3: passphrase-file.
    if let Some(path) = file {
        let meta = fs::metadata(path).map_err(Error::Io)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o400 {
            return Err(Error::IdentityPermissions);
        }
        let s = fs::read_to_string(path).map_err(Error::Io)?;
        return Ok(Passphrase::from_string(
            s.trim_end_matches('\n').trim_end_matches('\r').to_string(),
        ));
    }

    // Priority 4: environment variable.
    if let Some(name) = env_var_name {
        if let Ok(v) = std::env::var(name) {
            return Ok(Passphrase::from_string(v));
        }
    }

    // Priority 5: TTY prompt via dialoguer.
    let mut prompt = dialoguer::Password::new();
    prompt = prompt.with_prompt("Cipherpost passphrase");
    if confirm_on_tty {
        prompt = prompt.with_confirmation("Confirm passphrase", "Passphrases don't match");
    }
    let pw = prompt
        .interact()
        .map_err(|_| Error::Config("TTY not available for passphrase prompt".into()))?;
    Ok(Passphrase::from_string(pw))
}
