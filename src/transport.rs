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

// ---- Phase 9 CAS retry primitives (D-P9-A1/A2/A3/A4) ----------------------

/// Phase 9 (D-P9-A2/A3): internal-only signal; never crosses the Transport
/// trait boundary. The trait method's single-retry loop pattern-matches on
/// this; final-conflict failures collapse into `Error::Transport` (no public
/// `Error::CasConflict` variant — preserves error-oracle hygiene per
/// PITFALLS.md #16).
enum PublishOutcome {
    Ok,
    CasConflict,
    Other(Error),
}

/// Phase 9 (D-P9-A4): CAS retry events log to stderr ONLY when
/// `CIPHERPOST_DEBUG=1`. Default-silent. Narrowly scoped — does not become a
/// multi-purpose debug flag (deferred to v1.2 per CONTEXT.md Discretion).
fn cipherpost_debug_enabled() -> bool {
    std::env::var("CIPHERPOST_DEBUG").as_deref() == Ok("1")
}

/// Phase 9 (D-P9-A1): private marker error returned via
/// `Box<dyn std::error::Error>` when both publish attempts CAS-fail. The
/// outer `Error::Transport(Box<...>)` collapses this to the generic
/// "transport error" Display (oracle hygiene). The inner Display is only
/// observable if a debugging caller walks `err.source()` — which
/// `error::user_message` deliberately does not (src/error.rs:131-134).
#[derive(Debug)]
struct CasConflictFinal;

impl std::fmt::Display for CasConflictFinal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CAS conflict on merge-republish (after one retry)")
    }
}

impl std::error::Error for CasConflictFinal {}

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

    /// Shared resolve-merge-republish attempt for BOTH the share-publish and the
    /// receipt-publish paths. Resolves the key's current SignedPacket, rebuilds it
    /// from every existing resource record EXCEPT the one whose `label` we're
    /// replacing, adds the new TXT under `label`, signs, and publishes with CAS.
    ///
    /// This is what keeps a sender's outgoing `_cipherpost` share and their inbound
    /// `_cprcpt-*` receipts coexisting in the single per-key packet — publishing
    /// one label must NOT clobber the others. (The share path formerly built a
    /// from-scratch packet and wiped every receipt; only the receipt path merged.)
    ///
    /// Returns `PublishOutcome` so the caller's single-retry loop can absorb
    /// `CasConflict` without crossing the public Error surface (PITFALLS.md #16
    /// oracle hygiene). `what` is only for the TRANS-05 progress line. A merged
    /// `PacketTooLarge` (e.g. a share plus accumulated receipts exceeding the
    /// 1000-byte budget) surfaces as `WireBudgetExceeded{plaintext:0}`.
    fn merge_republish_attempt(
        &self,
        keypair: &pkarr::Keypair,
        label: &str,
        rdata: &str,
        what: &str,
    ) -> PublishOutcome {
        eprintln!("Publishing {what} to DHT..."); // TRANS-05

        let new_name: pkarr::dns::Name<'_> = match label.try_into() {
            Ok(n) => n,
            Err(e) => return PublishOutcome::Other(Error::Transport(map_dns_err(e))),
        };
        let new_txt: pkarr::dns::rdata::TXT<'_> = match rdata.try_into() {
            Ok(t) => t,
            Err(e) => return PublishOutcome::Other(Error::Transport(map_dns_err(e))),
        };

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
                if matches_label(&rr_name, label, &origin_z32) {
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
                return PublishOutcome::Other(Error::WireBudgetExceeded {
                    encoded,
                    budget: crate::flow::WIRE_BUDGET_BYTES,
                    plaintext: 0,
                });
            }
            Err(other) => return PublishOutcome::Other(Error::Transport(Box::new(other))),
        };

        // 4. Publish with optional CAS. Phase 9 D-P9-A1: catch the full
        //    `PublishError::Concurrency(_)` family (ConflictRisk +
        //    NotMostRecent + CasFailed per RESEARCH.md OQ-1) and signal a
        //    retry; all other errors collapse into Error::Transport via the
        //    existing helper.
        match self.client.publish(&packet, cas) {
            Ok(()) => PublishOutcome::Ok,
            Err(pkarr::errors::PublishError::Concurrency(_)) => PublishOutcome::CasConflict,
            Err(other) => PublishOutcome::Other(map_pkarr_publish_error(other)),
        }
    }

    /// Single-retry-then-fail wrapper around `merge_republish_attempt`, shared by
    /// `publish` and `publish_receipt`. A first-attempt CasConflict is retried
    /// once with a fresh resolve; a second conflict collapses to `Error::Transport`
    /// (no public `Error::CasConflict` — oracle hygiene).
    fn merge_republish(
        &self,
        keypair: &pkarr::Keypair,
        label: &str,
        rdata: &str,
        what: &str,
    ) -> Result<(), Error> {
        match self.merge_republish_attempt(keypair, label, rdata, what) {
            PublishOutcome::Ok => return Ok(()),
            PublishOutcome::Other(e) => return Err(e),
            PublishOutcome::CasConflict => {
                if cipherpost_debug_enabled() {
                    eprintln!("{what} publish: CAS conflict, retrying once...");
                }
            }
        }
        match self.merge_republish_attempt(keypair, label, rdata, what) {
            PublishOutcome::Ok => Ok(()),
            PublishOutcome::Other(e) => Err(e),
            PublishOutcome::CasConflict => Err(Error::Transport(Box::new(CasConflictFinal))),
        }
    }
}

impl Transport for DhtTransport {
    fn publish(&self, keypair: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error> {
        // Resolve-merge-republish (NOT a from-scratch packet) so publishing a
        // share preserves the sender's `_cprcpt-*` receipts and any other records.
        // Previously this clobbered the whole packet, silently deleting every
        // receipt the same identity had published.
        let rdata = serde_json::to_string(record).map_err(|e| Error::Transport(Box::new(e)))?;
        self.merge_republish(keypair, DHT_LABEL_OUTER, &rdata, "share")
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
        // Same resolve-merge-republish + single-retry-then-fail discipline as the
        // share path (shared helper). Receipts for different share_refs — and any
        // outgoing `_cipherpost` share — coexist under the one per-key packet.
        let receipt_label = format!("{DHT_LABEL_RECEIPT_PREFIX}{share_ref_hex}");
        self.merge_republish(keypair, &receipt_label, receipt_json, "receipt")
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

/// Returns true if a DNS name (normalized to `<label>.<z32>.`) matches `label`.
/// pkarr normalizes names to `<label>.<origin-z32>` relative to the keypair's
/// pubkey (signed_packet.rs:256-271); either the bare label or the suffixed form
/// may appear. Generic over any label — the `_cipherpost` share label and the
/// `_cprcpt-*` receipt labels both flow through here.
fn matches_label(rr_name: &str, label: &str, origin_z32: &str) -> bool {
    let trimmed = rr_name.trim_end_matches('.');
    trimmed == format!("{label}.{origin_z32}") || trimmed == label
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
fn map_dns_err(
    e: impl std::error::Error + Send + Sync + 'static,
) -> Box<dyn std::error::Error + Send + Sync> {
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

    /// Phase 9 (D-P9-A3): per-key entry combining the existing record list
    /// with a per-key `seq: u64` modeling pkarr's CAS semantics. The seq is
    /// bumped on every successful `publish_receipt`; a stale seq observed
    /// during the cas-check half of `publish_receipt_attempt_mock` triggers
    /// `PublishOutcome::CasConflict`, which the trait method's outer
    /// single-retry loop absorbs (matches `pkarr::Timestamp` semantics
    /// behaviorally).
    #[derive(Default)]
    struct MockStoreEntry {
        records: Vec<(String, String)>,
        seq: u64,
    }

    /// `pubkey_z32` → `MockStoreEntry { records, seq }`.
    type MockStore = Arc<Mutex<HashMap<String, MockStoreEntry>>>;

    /// In-memory transport for tests. Stores a map of `pubkey_z32` →
    /// `MockStoreEntry { records, seq }`. `publish` stores the outer record JSON
    /// under label `_cipherpost`; `publish_receipt` appends under
    /// `_cprcpt-<share_ref>` via lock → read-seq → drop-lock → merge → re-lock
    /// → cas-check → bump-and-write (D-P9-A3 + Pitfall #28).
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
        ///
        /// Phase 9: entry shape became `MockStoreEntry { records, seq }`;
        /// this helper still returns the records vector (test API preserved).
        pub fn resolve_all_txt(&self, pubkey_z32: &str) -> Vec<(String, String)> {
            self.store
                .lock()
                .unwrap()
                .get(pubkey_z32)
                .map(|entry| entry.records.clone())
                .unwrap_or_default()
        }

        /// Phase 9 D-P9-A3: lock → read seq → drop lock → build merged set →
        /// re-lock → cas-check → bump-and-write OR signal CasConflict.
        /// Pitfall #28 invariant: the lock is RELEASED between the seq read
        /// and the seq re-check so a Barrier-synced racer thread can grab the
        /// lock in between and bump the seq.
        ///
        /// Used by both `Transport::publish_receipt`'s first attempt AND its
        /// single retry — the retry observes the most recent merged state via
        /// the same lock-read-drop-rebuild-recheck dance, exactly mirroring
        /// pkarr's resolve-merge-republish flow.
        fn merge_attempt_mock(
            &self,
            kp: &pkarr::Keypair,
            label: &str,
            rdata: &str,
        ) -> PublishOutcome {
            let z32 = kp.public_key().to_z32();

            // 1. Lock; read current seq + clone records; release.
            let (seq_at_read, mut merged) = {
                let store = self.store.lock().unwrap();
                match store.get(&z32) {
                    Some(entry) => (entry.seq, entry.records.clone()),
                    None => (0u64, Vec::new()),
                }
            };

            // 2. Build merged record set (no lock held — analog of pkarr's
            //    resolve-merge-republish). Replace ONLY the same-label record;
            //    every OTHER label (an outgoing share, other receipts) is kept.
            merged.retain(|(l, _)| l.as_str() != label);
            merged.push((label.to_string(), rdata.to_string()));

            // 3. Re-lock; cas-check the seq; commit or signal conflict.
            let mut store = self.store.lock().unwrap();
            let entry = store.entry(z32).or_default();
            if entry.seq != seq_at_read {
                return PublishOutcome::CasConflict;
            }
            entry.seq = entry.seq.saturating_add(1);
            entry.records = merged;
            PublishOutcome::Ok
        }

        /// Single-retry-then-fail wrapper (mirrors `DhtTransport::merge_republish`),
        /// used by both mock `publish` and `publish_receipt`.
        fn merge_mock(&self, kp: &pkarr::Keypair, label: &str, rdata: &str) -> Result<(), Error> {
            match self.merge_attempt_mock(kp, label, rdata) {
                PublishOutcome::Ok => return Ok(()),
                PublishOutcome::Other(e) => return Err(e),
                PublishOutcome::CasConflict => {
                    if cipherpost_debug_enabled() {
                        eprintln!("{label} publish: CAS conflict, retrying once...");
                    }
                }
            }
            match self.merge_attempt_mock(kp, label, rdata) {
                PublishOutcome::Ok => Ok(()),
                PublishOutcome::Other(e) => Err(e),
                PublishOutcome::CasConflict => Err(Error::Transport(Box::new(CasConflictFinal))),
            }
        }
    }

    impl Transport for MockTransport {
        fn publish(&self, kp: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error> {
            let rdata = serde_json::to_string(record).map_err(|e| Error::Transport(Box::new(e)))?;
            // Enforce the same ceiling pkarr enforces — prevents tests-pass-locally-fail-on-publish
            // (T-01-03-05). 1000 bytes is pkarr's MAX encoded DNS packet size. NOTE:
            // this checks the share record ALONE, not the merged packet — the mock
            // does not model merged-packet overflow (the real DhtTransport surfaces
            // that as WireBudgetExceeded).
            if rdata.len() > 1000 {
                return Err(Error::Config(format!(
                    "MockTransport: record too large for PKARR packet: {} > 1000 bytes",
                    rdata.len()
                )));
            }
            // Merge-republish (preserve `_cprcpt-*` receipts) via the shared seq-CAS
            // path — matches the fixed DhtTransport::publish so tests exercise the
            // real behavior, not the old clobber where a share wiped every receipt.
            self.merge_mock(kp, DHT_LABEL_OUTER, &rdata)
        }

        fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error> {
            let store = self.store.lock().unwrap();
            let entry = store.get(pubkey_z32).ok_or(Error::NotFound)?;
            for (label, rdata) in &entry.records {
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
            // D-P9-A3: model PKARR cas semantics via per-key seq:u64. The racer
            // test (tests/cas_racer.rs) exercises this via two Barrier-synced
            // threads — exactly one wins, the loser observes a stale seq and
            // retries (shared merge_mock, same discipline as the share path).
            let label = format!("{DHT_LABEL_RECEIPT_PREFIX}{share_ref_hex}");
            self.merge_mock(kp, &label, receipt_json)
        }

        fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error> {
            let store = self.store.lock().unwrap();
            let entry = store.get(pubkey_z32).ok_or(Error::NotFound)?;
            let out: Vec<String> = entry
                .records
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
