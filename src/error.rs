//! Single library error enum (D-14). Source chains preserved via `#[source]`
//! but NEVER Displayed in user-facing output (D-15). Binary in src/main.rs
//! matches on the top-level variant to pick exit code and sanitized message.
//!
//! All signature-verification failures share ONE user-facing message (D-16)
//! to prevent distinguishing-oracle attacks — internal variants may be distinct.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error")]
    Io(#[from] std::io::Error),

    #[error("identity file not found at {path}")]
    IdentityNotFound { path: String },

    #[error("identity file permissions too permissive (refuses to open)")]
    IdentityPermissions,

    #[error("identity file corrupted or unreadable")]
    IdentityCorrupt,

    #[error("wrong passphrase or identity decryption failed")]
    DecryptFailed,

    #[error("signature verification failed")] // D-16: same Display for all sig-fail variants below
    SignatureOuter,

    #[error("signature verification failed")] // D-16
    SignatureInner,

    #[error("signature verification failed")] // D-16
    SignatureCanonicalMismatch,

    #[error("signature verification failed")] // D-16
    SignatureTampered,

    #[error("share expired")]
    Expired,

    #[error("record not found on DHT")]
    NotFound,

    #[error("network error or DHT timeout")]
    Network,

    #[error("user declined acceptance")]
    Declined,

    #[error("payload exceeds 64 KB limit: actual={actual}, cap={limit}")]
    PayloadTooLarge { actual: usize, limit: usize },

    #[error("share_ref in URI does not match resolved record")]
    ShareRefMismatch,

    #[error("share too large for PKARR packet: encoded={encoded} bytes, budget={budget} bytes (plaintext was {plaintext} bytes)")]
    WireBudgetExceeded {
        encoded: usize,
        budget: usize,
        plaintext: usize,
    },

    /// D-P6-03 (Phase 6): typed-material ingest failure OR variant-accessor mismatch.
    /// `variant` is the snake-case wire tag (e.g. `"x509_cert"`); `reason` is a curated
    /// short string — NEVER wraps an x509-parser / nom / parse-position string.
    /// Maps to exit 1 per X509-08 (distinct from exit 3 signature failures).
    ///
    /// Do NOT use `#[source]` or `#[from]` here — that would bait a Display-chain leak
    /// of `X509Error::InvalidCertificate` etc. via `err.source()`. The `reason: String`
    /// is the sanitation gate.
    #[error("invalid material: variant={variant}, reason={reason}")]
    InvalidMaterial { variant: String, reason: String },

    /// D-P7-12 (Phase 7 Plan 05): SSH input format not OpenSSH v1.
    /// Distinct variant (not InvalidMaterial) because the user-facing message
    /// embeds a copy-pasteable `ssh-keygen` hint that is variant-specific —
    /// users in legacy-PEM/RFC4716/FIDO format need to convert before retry.
    ///
    /// Display intentionally omits both the rejected format (avoiding an
    /// info-disclosure oracle: "your input looked like RSA-PEM") and any
    /// ssh-key crate internals (oracle hygiene; mirrors InvalidMaterial rule).
    ///
    /// Maps to exit 1 — same content-error class as InvalidMaterial.
    #[error(
        "SSH key format not supported — convert to OpenSSH v1 via `ssh-keygen -p -o -f <path>`"
    )]
    SshKeyFormatNotSupported,

    #[error("invalid share URI: {0}")]
    InvalidShareUri(String),

    #[error("invalid passphrase input method (inline argv rejected)")]
    PassphraseInvalidInput,

    #[error("not implemented yet (phase {phase})")]
    NotImplemented { phase: u8 },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("crypto error")]
    Crypto(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("transport error")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Exit-code taxonomy (CLI-02, locked in Phase 2 REQ but defined here for the
/// match-to-exit-code dispatcher in main.rs). D-16: all Signature* variants → 3.
pub fn exit_code(err: &Error) -> i32 {
    match err {
        Error::Expired => 2,
        Error::SignatureOuter
        | Error::SignatureInner
        | Error::SignatureCanonicalMismatch
        | Error::SignatureTampered => 3,
        Error::DecryptFailed | Error::IdentityPermissions | Error::PassphraseInvalidInput => 4,
        Error::NotFound => 5,
        Error::Network => 6,
        Error::Declined => 7,
        Error::ShareRefMismatch | Error::WireBudgetExceeded { .. } | Error::InvalidShareUri(_) => 1,
        Error::InvalidMaterial { .. } => 1, // X509-08: content error, NOT sig (exit 3)
        Error::SshKeyFormatNotSupported => 1, // D-P7-12: distinct format-rejection class
        _ => 1,
    }
}

/// User-facing message (D-15: never walks source chain). Callers in src/main.rs
/// print this to stderr instead of Display'ing source chains.
pub fn user_message(err: &Error) -> String {
    // D-16 invariant: Signature* variants all produce the identical string.
    format!("{err}")
}
