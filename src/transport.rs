//! Transport seam — the only architectural delta from cclink. `Transport` trait
//! admits both `DhtTransport` (wraps pkarr::ClientBlocking for real DHT) and
//! `MockTransport` (in-memory HashMap, cfg-gated) so integration tests in this
//! crate and downstream plans do not touch the real DHT.
//!
//! Phase 1 locks the three method signatures (publish / resolve / publish_receipt).
//! Phase 3 upgrades `publish_receipt` to do resolve-merge-republish (TRANS-03);
//! Phase 1 ships a simpler clobber-replace implementation that is sufficient for
//! TRANS-01/02/04/05 tests.
//!
//! pkarr API notes (5.0.4 — resolves 5.0.3 requirement; API compatible):
//! - ClientBlocking is obtained via: Client::builder().no_relays().request_timeout(t).build()?.as_blocking()
//! - ClientBuilder methods are &mut self builders (mutable, not chainable like Into<Self>)
//! - resolve_most_recent returns Option<SignedPacket> with no Result wrapper
//! - publish returns Result<(), PublishError> where PublishError::Query(QueryError::Timeout) = timeout
//! - TXT strings are split into 255-byte CharacterString chunks; String::try_from(txt.clone()) concatenates

use crate::error::Error;
use crate::record::{verify_record, OuterRecord};
use crate::{DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX};
use std::time::Duration;

/// Default DHT request timeout per TRANS-04 (exit code 6 on expiry).
pub const DEFAULT_DHT_TIMEOUT: Duration = Duration::from_secs(30);

// ---- Transport trait --------------------------------------------------------

/// Transport trait — TRANS-01. Phases 2 and 3 code against this interface;
/// `DhtTransport` is the production impl and `MockTransport` is the test impl.
///
/// Method signatures are locked here so Phase 2/3 do not re-litigate them.
pub trait Transport {
    /// Publish an `OuterRecord` to the DHT (or mock store) under the sender's pubkey.
    fn publish(&self, keypair: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error>;

    /// Resolve the most recent `OuterRecord` for a given pubkey (z-base-32 string).
    ///
    /// Returns `Error::NotFound` if no record exists; `Error::Network` on timeout;
    /// `Error::SignatureInner` if inner signature verification fails.
    fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error>;

    /// Publish a receipt TXT record for a given `share_ref_hex` under the keypair's pubkey.
    ///
    /// Phase 1 implementation: simple clobber-replace (publishes a new SignedPacket
    /// containing only the receipt TXT). Phase 3 MUST upgrade BOTH `DhtTransport`
    /// and `MockTransport` to resolve-merge-republish per TRANS-03 so that receipts
    /// for different share_refs coexist under the same key.
    fn publish_receipt(
        &self,
        keypair: &pkarr::Keypair,
        share_ref_hex: &str,
        receipt_json: &str,
    ) -> Result<(), Error>;

    /// Resolve all receipt TXT records (label prefix `_cprcpt-`) under the given pubkey.
    ///
    /// Returns the raw JSON bodies in iteration order. For `DhtTransport`, this
    /// calls `resolve_most_recent` and iterates `all_resource_records()`, filtering
    /// by `DHT_LABEL_RECEIPT_PREFIX` prefix (pkarr normalizes names to
    /// `<label>.<origin-z32>`; both bare and suffixed forms start with the bare label).
    /// For `MockTransport`, this filters the in-memory `resolve_all_txt` output.
    ///
    /// Returns `Error::NotFound` if the pubkey has no packet OR has a packet
    /// with zero matching `_cprcpt-*` TXT records. Callers (`run_receipts` in
    /// Plan 03) map this to exit code 5.
    fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error>;
}

// ---- DhtTransport -----------------------------------------------------------

/// Production transport wrapping `pkarr::ClientBlocking`.
///
/// `DhtTransport::new` builds a DHT-only client (no relay servers) per the
/// "no servers" constraint (CLAUDE.md Principle 1). Timeout is configurable;
/// defaults to `DEFAULT_DHT_TIMEOUT`.
pub struct DhtTransport {
    client: pkarr::ClientBlocking,
    #[allow(dead_code)] // stored for future per-request timeout configuration
    timeout: Duration,
}

impl DhtTransport {
    /// Create a new `DhtTransport` with the given request timeout.
    pub fn new(timeout: Duration) -> Result<Self, Error> {
        let mut builder = pkarr::Client::builder();
        builder.no_relays().request_timeout(timeout);
        let client = builder
            .build()
            .map_err(|e| Error::Transport(Box::new(e)))?
            .as_blocking();
        Ok(Self { client, timeout })
    }

    /// Create a `DhtTransport` with the default 30-second timeout.
    pub fn with_default_timeout() -> Result<Self, Error> {
        Self::new(DEFAULT_DHT_TIMEOUT)
    }
}

impl Transport for DhtTransport {
    fn publish(&self, keypair: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error> {
        eprintln!("Publishing to DHT..."); // TRANS-05
        let rdata = serde_json::to_string(record)
            .map_err(|e| Error::Transport(Box::new(e)))?;
        let name: pkarr::dns::Name<'_> = DHT_LABEL_OUTER
            .try_into()
            .map_err(|e| Error::Transport(map_dns_err(e)))?;
        let txt: pkarr::dns::rdata::TXT<'_> = rdata
            .as_str()
            .try_into()
            .map_err(|e| Error::Transport(map_dns_err(e)))?;
        let packet = pkarr::SignedPacket::builder()
            .txt(name, txt, 300)
            .sign(keypair)
            .map_err(|e| Error::Transport(Box::new(e)))?;
        self.client
            .publish(&packet, None)
            .map_err(map_pkarr_publish_error)?;
        Ok(())
    }

    fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error> {
        eprintln!("Resolving from DHT..."); // TRANS-05
        let pk = pkarr::PublicKey::try_from(pubkey_z32).map_err(|_| Error::NotFound)?;
        let packet = self
            .client
            .resolve_most_recent(&pk)
            .ok_or(Error::NotFound)?;

        for rr in packet.resource_records(DHT_LABEL_OUTER) {
            if let Some(rdata_str) = extract_txt_string(&rr.rdata) {
                let record: OuterRecord = serde_json::from_str(&rdata_str)
                    .map_err(|_| Error::SignatureCanonicalMismatch)?;
                verify_record(&record)?; // inner sig check
                return Ok(record);
            }
        }
        Err(Error::NotFound)
    }

    fn publish_receipt(
        &self,
        keypair: &pkarr::Keypair,
        share_ref_hex: &str,
        receipt_json: &str,
    ) -> Result<(), Error> {
        // D-MRG-01: resolve → rebuild builder from existing RRs (replacing same-label
        // duplicates) → add new receipt TXT → sign → publish with optional CAS.
        // D-MRG-03: 300-second TXT TTL matches the outer-share TTL.
        // D-MRG-06: SignedPacketBuildError::PacketTooLarge → WireBudgetExceeded{plaintext:0}.
        eprintln!("Publishing receipt to DHT..."); // TRANS-05

        let receipt_label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex);
        let new_name: pkarr::dns::Name<'_> = receipt_label
            .as_str()
            .try_into()
            .map_err(|e| Error::Transport(map_dns_err(e)))?;
        let new_txt: pkarr::dns::rdata::TXT<'_> = receipt_json
            .try_into()
            .map_err(|e| Error::Transport(map_dns_err(e)))?;

        // 1. Resolve most recent — may be None if recipient has never published.
        let pk = keypair.public_key();
        let existing = self.client.resolve_most_recent(&pk);

        // 2. Rebuild builder from existing RRs, skipping any whose normalized name
        //    matches this receipt's label (the new one supersedes it).
        let mut builder = pkarr::SignedPacket::builder();
        let mut cas: Option<pkarr::Timestamp> = None;
        if let Some(ref packet) = existing {
            cas = Some(packet.timestamp());
            let origin_z32 = pk.to_z32();
            for rr in packet.all_resource_records() {
                let rr_name = rr.name.to_string();
                if matches_receipt_label(&rr_name, &receipt_label, &origin_z32) {
                    continue;
                }
                builder = builder.record(rr.clone());
            }
        }
        builder = builder.txt(new_name, new_txt, 300);

        // 3. Sign — D-MRG-06: PacketTooLarge → WireBudgetExceeded with plaintext=0
        //    (marker that the overflow is a receipt, not a share).
        let packet = match builder.sign(keypair) {
            Ok(p) => p,
            Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) => {
                return Err(Error::WireBudgetExceeded {
                    encoded,
                    budget: crate::flow::WIRE_BUDGET_BYTES,
                    plaintext: 0,
                });
            }
            Err(other) => return Err(Error::Transport(Box::new(other))),
        };

        // 4. Publish with optional CAS (D-MRG-02: no retry in skeleton).
        self.client
            .publish(&packet, cas)
            .map_err(map_pkarr_publish_error)?;
        Ok(())
    }

    fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error> {
        eprintln!("Resolving receipts from DHT..."); // TRANS-05
        let pk = pkarr::PublicKey::try_from(pubkey_z32).map_err(|_| Error::NotFound)?;
        let packet = self
            .client
            .resolve_most_recent(&pk)
            .ok_or(Error::NotFound)?;

        let mut out = Vec::new();
        for rr in packet.all_resource_records() {
            let name = rr.name.to_string();
            let trimmed = name.trim_end_matches('.');
            // After pkarr normalization, labels are either bare "<label>" (at-origin)
            // or "<label>.<origin-z32>". Both start with the bare prefix.
            if trimmed.starts_with(DHT_LABEL_RECEIPT_PREFIX) {
                if let Some(json) = extract_txt_string(&rr.rdata) {
                    out.push(json);
                }
            }
        }
        if out.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(out)
    }
}

// ---- Label matching --------------------------------------------------------

/// Returns true if a DNS name (normalized to `<label>.<z32>.`) matches the given
/// receipt label. pkarr 5.0.4 normalizes names to `<label>.<origin-z32>` relative
/// to the keypair's pubkey (signed_packet.rs:256-271); either the bare label or
/// the suffixed form may appear depending on pkarr's internal state.
fn matches_receipt_label(rr_name: &str, receipt_label: &str, origin_z32: &str) -> bool {
    let trimmed = rr_name.trim_end_matches('.');
    trimmed == format!("{}.{}", receipt_label, origin_z32) || trimmed == receipt_label
}

// ---- RData TXT extraction --------------------------------------------------

/// Extract the full string content of a TXT rdata record.
///
/// TXT records split long content into 255-byte character strings.
/// `String::try_from` concatenates them, which is the correct semantic
/// for our JSON payload (which may exceed 255 bytes).
fn extract_txt_string(rdata: &pkarr::dns::rdata::RData<'_>) -> Option<String> {
    if let pkarr::dns::rdata::RData::TXT(txt) = rdata {
        // String::try_from concatenates all CharacterString chunks in the TXT record.
        String::try_from(txt.clone()).ok()
    } else {
        None
    }
}

// ---- Error mapping ---------------------------------------------------------

/// Map a pkarr PublishError to our Error type.
///
/// Phase 1 limitation: `QueryError::Timeout` → `Error::Network` is matched on the
/// enum variant directly. Other errors collapse to `Error::Transport`. Phase 2+
/// should refine if pkarr exposes more error taxonomy. (SUMMARY: map_pkarr_error note)
fn map_pkarr_publish_error(e: pkarr::errors::PublishError) -> Error {
    use pkarr::errors::{PublishError, QueryError};
    match e {
        PublishError::Query(QueryError::Timeout) => Error::Network,
        other => Error::Transport(Box::new(other)),
    }
}

/// Map a simple_dns error (from Name/TXT TryFrom conversions) to a boxed error.
fn map_dns_err(e: impl std::error::Error + Send + Sync + 'static) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(e)
}

// ---- MockTransport (cfg-gated) ---------------------------------------------

#[cfg(any(test, feature = "mock"))]
pub use mock::MockTransport;

#[cfg(any(test, feature = "mock"))]
mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// `pubkey_z32` → list of `(dns_label, rdata_json)` pairs stored in the mock.
    type MockStore = Arc<Mutex<HashMap<String, Vec<(String, String)>>>>;

    /// In-memory transport for tests. Stores a map of `pubkey_z32` →
    /// `Vec<(label, rdata-string)>`. `publish` stores the outer record JSON under
    /// label `_cipherpost`; `publish_receipt` appends under `_cprcpt-<share_ref>`.
    ///
    /// Also enforces the 1000-byte ceiling that pkarr's `SignedPacket::new` enforces,
    /// so tests that pass locally will also pass against the real DHT (T-01-03-05).
    #[derive(Clone, Default)]
    pub struct MockTransport {
        store: MockStore,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self {
                store: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        /// Test helper: list every `(label, rdata)` under a given pubkey.
        /// Used by Phase 3 `receipts --from` tests to iterate all receipts.
        pub fn resolve_all_txt(&self, pubkey_z32: &str) -> Vec<(String, String)> {
            self.store
                .lock()
                .unwrap()
                .get(pubkey_z32)
                .cloned()
                .unwrap_or_default()
        }
    }

    impl Transport for MockTransport {
        fn publish(&self, kp: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error> {
            let rdata = serde_json::to_string(record)
                .map_err(|e| Error::Transport(Box::new(e)))?;
            // Enforce the same ceiling pkarr enforces — prevents tests-pass-locally-fail-on-publish
            // (T-01-03-05). 1000 bytes is pkarr's MAX encoded DNS packet size.
            if rdata.len() > 1000 {
                return Err(Error::Config(format!(
                    "MockTransport: record too large for PKARR packet: {} > 1000 bytes",
                    rdata.len()
                )));
            }
            let z32 = kp.public_key().to_z32();
            let mut store = self.store.lock().unwrap();
            let entry = store.entry(z32).or_default();
            // Replace any existing _cipherpost record (sender publishes one record at a time)
            entry.retain(|(label, _)| label != DHT_LABEL_OUTER);
            entry.push((DHT_LABEL_OUTER.to_string(), rdata));
            Ok(())
        }

        fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error> {
            let store = self.store.lock().unwrap();
            let entries = store.get(pubkey_z32).ok_or(Error::NotFound)?;
            for (label, rdata) in entries {
                if label == DHT_LABEL_OUTER {
                    let record: OuterRecord = serde_json::from_str(rdata)
                        .map_err(|_| Error::SignatureCanonicalMismatch)?;
                    verify_record(&record)?;
                    return Ok(record);
                }
            }
            Err(Error::NotFound)
        }

        fn publish_receipt(
            &self,
            kp: &pkarr::Keypair,
            share_ref_hex: &str,
            receipt_json: &str,
        ) -> Result<(), Error> {
            // Phase 1: store under the receipt label, replacing any existing entry for
            // this share_ref. Phase 3 upgrades to append-preserving semantics so that
            // receipts for different share_refs coexist (TRANS-03; T-01-03-08).
            let z32 = kp.public_key().to_z32();
            let label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex);
            let mut store = self.store.lock().unwrap();
            let entry = store.entry(z32).or_default();
            // Replace any existing receipt for this share_ref
            entry.retain(|(l, _)| l != &label);
            entry.push((label, receipt_json.to_string()));
            Ok(())
        }

        fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error> {
            let store = self.store.lock().unwrap();
            let entries = store.get(pubkey_z32).ok_or(Error::NotFound)?;
            let out: Vec<String> = entries
                .iter()
                .filter(|(label, _)| label.starts_with(DHT_LABEL_RECEIPT_PREFIX))
                .map(|(_, json)| json.clone())
                .collect();
            if out.is_empty() {
                return Err(Error::NotFound);
            }
            Ok(out)
        }
    }
}
