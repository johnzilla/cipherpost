//! Cipherpost — self-sovereign, serverless, accountless cryptographic-material handoff.
//!
//! See PROJECT.md, REQUIREMENTS.md, and ROADMAP.md in `.planning/` for scope.
//!
//! Architectural lineage: fork-and-diverge from https://github.com/johnzilla/cclink
//! (mothballed). No live dependency relationship — cclink is reference-only.

pub mod cli;
pub mod crypto;
pub mod error;
pub mod flow;
pub mod identity;
pub mod payload;
pub mod receipt;
pub mod record;
pub mod transport;

pub use error::Error;

/// Wire protocol version. Written into every signed OuterRecordSignable and Envelope.
/// Bumping this invalidates every previously issued share.
pub const PROTOCOL_VERSION: u16 = 1;

/// HKDF info namespace prefix (D-08). Every HKDF call-site must use an info string of the
/// form `<HKDF_INFO_PREFIX><context>` e.g. `{HKDF_INFO_PREFIX}identity-kek`.
/// Enforced by tests/hkdf_info_enum.rs (Plan 02).
pub const HKDF_INFO_PREFIX: &str = "cipherpost/v1/";

/// Envelope magic (on-disk identity file — CIPHPOSK wraps the passphrase-encrypted seed).
/// Locked wire/disk constant per D-04.
pub const ENVELOPE_MAGIC: &[u8; 8] = b"CIPHPOSK";

/// DHT label for outer share records (under the SENDER's PKARR key). D-05.
pub const DHT_LABEL_OUTER: &str = "_cipherpost";

/// DHT label prefix for receipts (under the RECIPIENT's PKARR key). D-06.
/// Full label: format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex).
pub const DHT_LABEL_RECEIPT_PREFIX: &str = "_cprcpt-";
