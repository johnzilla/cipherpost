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

/// Envelope magic bytes for on-disk identity file (passphrase-encrypted seed wrapper).
/// Locked wire/disk constant per D-04.
pub const ENVELOPE_MAGIC: &[u8; 8] = b"CIPHPOSK";

/// DHT label for outer share records (under the SENDER's PKARR key). D-05.
pub const DHT_LABEL_OUTER: &str = "_cipherpost";

/// DHT label prefix for receipts (under the RECIPIENT's PKARR key). D-06.
/// Full label: format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex).
pub const DHT_LABEL_RECEIPT_PREFIX: &str = "_cprcpt-";

/// Scheme marker for share URIs (D-URI-01). Full URI shape:
/// `cipherpost://<sender-z32>/<share_ref_hex>`.
pub const SHARE_URI_SCHEME: &str = "cipherpost://";

/// Parsed share URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareUri {
    pub sender_z32: String,
    pub share_ref_hex: String,
}

impl ShareUri {
    /// Parse a strict `cipherpost://<z32>/<32-hex>` URI (D-URI-03 — no trailing
    /// path / query / fragment; no bare-z32 convenience).
    pub fn parse(input: &str) -> Result<Self, Error> {
        let body = input.strip_prefix(SHARE_URI_SCHEME).ok_or_else(|| {
            Error::InvalidShareUri(
                "expected cipherpost:// URI, got bare pubkey; use the URI that `send` printed"
                    .into(),
            )
        })?;
        let (z32, hex) = body.split_once('/').ok_or_else(|| {
            Error::InvalidShareUri("URI missing /<share_ref_hex> component".into())
        })?;
        if z32.len() != 52 {
            return Err(Error::InvalidShareUri(format!(
                "sender z32 must be 52 chars, got {}",
                z32.len()
            )));
        }
        if hex.len() != crate::record::SHARE_REF_HEX_LEN {
            return Err(Error::InvalidShareUri(format!(
                "share_ref_hex must be {} chars, got {}",
                crate::record::SHARE_REF_HEX_LEN,
                hex.len()
            )));
        }
        if !hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Error::InvalidShareUri(
                "share_ref_hex must be lowercase hex".into(),
            ));
        }
        // D-URI-03: strict form; no trailing path / query / fragment components.
        if hex.contains('?') || hex.contains('#') || hex.contains('/') {
            return Err(Error::InvalidShareUri(
                "unexpected trailing URI components (strict form required)".into(),
            ));
        }
        Ok(ShareUri {
            sender_z32: z32.to_string(),
            share_ref_hex: hex.to_string(),
        })
    }

    /// Format a share URI from its components.
    pub fn format(sender_z32: &str, share_ref_hex: &str) -> String {
        format!("{}{}/{}", SHARE_URI_SCHEME, sender_z32, share_ref_hex)
    }
}
