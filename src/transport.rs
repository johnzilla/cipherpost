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

    // ---- Derived-key addressing (v2; docs/design/derived-key-addressing.md) ----
    //
    // Phase 2: a share/receipt gets its OWN key `derive(parent_pub, share_ref)`, so
    // each PKARR packet holds exactly ONE record — lifting the one-record-per-key
    // ceiling. These carry the CAPABILITY only; the send/receive flow does not use
    // them until Phase 3.

    /// Publish `rdata` at `label` under the DERIVED key `signer.public()`, signing
    /// the BEP44 packet with the derived scalar (pkarr's seed-based `Keypair`
    /// cannot). Each derived key is written by a single writer and holds one
    /// record, so — unlike the parent-key path — there is NO resolve-merge-
    /// republish and NO CAS. Over-budget rdata surfaces `PacketBudgetExceeded`.
    fn publish_derived(
        &self,
        signer: &crate::derive::DerivedSigner,
        label: &str,
        rdata: &str,
    ) -> Result<(), Error>;

    /// Resolve the TXT `rdata` at `label` under the derived key `derived_pub`
    /// (compressed Ed25519 bytes, from `derive::derive_public`). `Ok(None)` if the
    /// key has no packet or no matching label. Verification of the record body is
    /// the caller's job (Phase 3), exactly as with `resolve`.
    fn resolve_derived(&self, derived_pub: &[u8; 32], label: &str)
        -> Result<Option<String>, Error>;
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
    /// 1000-byte budget) surfaces as `PacketBudgetExceeded` (accumulated-records
    /// overflow — distinct from the payload-too-big `WireBudgetExceeded`).
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

        // 3. Sign — D-MRG-06: the MERGED packet (existing records under this key +
        //    the new one) is what pkarr sizes here. PacketTooLarge means the
        //    accumulated records (outgoing share + receipts) overflow the single
        //    per-key budget — NOT that the caller's payload is too big — so it maps
        //    to `PacketBudgetExceeded`, distinct from the payload-too-big
        //    `WireBudgetExceeded` and carrying no misleading `plaintext` field.
        let packet = match builder.sign(keypair) {
            Ok(p) => p,
            Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) => {
                return PublishOutcome::Other(Error::PacketBudgetExceeded {
                    encoded,
                    budget: crate::flow::WIRE_BUDGET_BYTES,
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

    fn publish_derived(
        &self,
        signer: &crate::derive::DerivedSigner,
        label: &str,
        rdata: &str,
    ) -> Result<(), Error> {
        eprintln!("Publishing to derived key on DHT..."); // TRANS-05
        let packet = build_derived_signed_packet(signer, label, rdata)?;
        // No CAS: a derived key is single-writer, single-record.
        self.client
            .publish(&packet, None)
            .map_err(map_pkarr_publish_error)
    }

    fn resolve_derived(
        &self,
        derived_pub: &[u8; 32],
        label: &str,
    ) -> Result<Option<String>, Error> {
        eprintln!("Resolving derived key from DHT..."); // TRANS-05
        let pk = pkarr::PublicKey::try_from(derived_pub).map_err(|_| Error::NotFound)?;
        let Some(packet) = self.client.resolve_most_recent(&pk) else {
            return Ok(None);
        };
        for rr in packet.resource_records(label) {
            if let Some(rdata) = extract_txt_string(&rr.rdata) {
                return Ok(Some(rdata));
            }
        }
        Ok(None)
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

// ---- Derived-key packet signing (v2) ---------------------------------------

/// BEP44 mutable-item signable bytes. MUST match pkarr's private `signable()`
/// byte-for-byte — guarded by the unit test
/// `derived_tests::signable_replication_matches_pkarr` (below, in this file),
/// which verifies a pkarr-built packet's own signature against these bytes. If
/// pkarr ever changes this encoding, that test fails loudly.
fn bep44_signable(timestamp: u64, v: &[u8]) -> Vec<u8> {
    let mut s = format!("3:seqi{}e1:v{}:", timestamp, v.len()).into_bytes();
    s.extend_from_slice(v);
    s
}

/// Build a `SignedPacket` carrying one TXT (`label` → `rdata`) under the DERIVED
/// key `signer.public()`. pkarr's `Keypair` is seed-based and cannot sign under a
/// blinded key, so we hand-sign the BEP44 bytes with `hazmat::raw_sign` (raw
/// scalar) and assemble via the public `from_relay_payload` (which re-verifies the
/// signature under the public key — a built-in correctness gate). The signature is
/// self-verified first: `raw_sign` leaks the scalar if the passed verifying key is
/// not `scalar·G` (ed25519-unsafe-libs), so a mismatch fails closed here.
fn build_derived_signed_packet(
    signer: &crate::derive::DerivedSigner,
    label: &str,
    rdata: &str,
) -> Result<pkarr::SignedPacket, Error> {
    let derived_pub = signer.public();
    let derived_pk = pkarr::PublicKey::try_from(&derived_pub)
        .map_err(|_| Error::Config("derived pubkey is not a valid PKARR key".into()))?;
    let origin = derived_pk.to_z32();

    // One TXT record at `<label>.<origin>` — the form pkarr's builder normalizes a
    // bare label to (we can't use the builder here; it requires a seed Keypair).
    let rec_name = format!("{label}.{origin}");
    let name: pkarr::dns::Name<'_> = rec_name
        .as_str()
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;
    let txt: pkarr::dns::rdata::TXT<'_> = rdata
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;
    let mut packet = pkarr::dns::Packet::new_reply(0);
    packet.answers.push(pkarr::dns::ResourceRecord::new(
        name,
        pkarr::dns::CLASS::IN,
        300,
        pkarr::dns::rdata::RData::TXT(txt),
    ));
    let v = packet
        .build_bytes_vec_compressed()
        .map_err(|e| Error::Transport(Box::new(e)))?;
    // Each derived key holds ONE record; enforce the BEP44 budget defensively.
    if v.len() > crate::flow::WIRE_BUDGET_BYTES {
        return Err(Error::PacketBudgetExceeded {
            encoded: v.len(),
            budget: crate::flow::WIRE_BUDGET_BYTES,
        });
    }

    let ts: u64 = pkarr::Timestamp::now().into();
    let signable = bep44_signable(ts, &v);

    // Reconstruct the derived expanded key and sign. `a'` is canonical (reduced),
    // so `from_bytes_mod_order` is a no-op reduction.
    let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(*signer.scalar_bytes());
    let esk = ed25519_dalek::hazmat::ExpandedSecretKey {
        scalar,
        hash_prefix: *signer.prefix(),
    };
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&derived_pub)
        .map_err(|e| Error::Crypto(Box::new(e)))?;
    let sig = ed25519_dalek::hazmat::raw_sign::<ed25519_dalek::Sha512>(&esk, &signable, &vk);
    vk.verify_strict(&signable, &sig)
        .map_err(|e| Error::Crypto(Box::new(e)))?; // ed25519-unsafe-libs guard

    let mut payload = Vec::with_capacity(64 + 8 + v.len());
    payload.extend_from_slice(&sig.to_bytes());
    payload.extend_from_slice(&ts.to_be_bytes());
    payload.extend_from_slice(&v);
    pkarr::SignedPacket::from_relay_payload(&derived_pk, &bytes::Bytes::from(payload))
        .map_err(|e| Error::Transport(Box::new(e)))
}

/// z-base-32 of a derived compressed Ed25519 key.
// Maps a bad key to `Error::NotFound` so `MockTransport::resolve_derived` agrees
// taxonomically with `DhtTransport::resolve_derived` (both: unresolvable key →
// NotFound, composing with the `Ok(None)` absent-key case). On the mock PUBLISH
// path this is unreachable — `build_derived_signed_packet` validates the same key
// first and fails with `Config` — so publish stays `Config` on both impls.
// (In practice every derived key is a valid curve point, so neither fires.)
fn derived_z32(derived_pub: &[u8; 32]) -> Result<String, Error> {
    Ok(pkarr::PublicKey::try_from(derived_pub)
        .map_err(|_| Error::NotFound)?
        .to_z32())
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

        /// Test-only: store an `OuterRecord` under `_cipherpost` WITHOUT the
        /// 1000-byte publish size check, so tests can exercise the receive path
        /// for records that legitimately exceed the DHT wire budget (e.g. a
        /// PIN-protected share, whose nested-age + salt prefix `publish` refuses).
        pub fn inject_outer_record_for_test(&self, kp: &pkarr::Keypair, record: &OuterRecord) {
            let rdata = serde_json::to_string(record).expect("serialize OuterRecord");
            let z32 = kp.public_key().to_z32();
            let mut store = self.store.lock().unwrap();
            let entry = store.entry(z32).or_default();
            entry.records.retain(|(label, _)| label != DHT_LABEL_OUTER);
            entry.records.push((DHT_LABEL_OUTER.to_string(), rdata));
        }

        /// v2 test helper: inject a raw `rdata` at `label` under a DERIVED key
        /// (compressed Ed25519 bytes), bypassing `publish_derived`'s budget/signing
        /// so tests can place wire-budget-exceeding records (e.g. PIN shares) at the
        /// exact key `run_receive` resolves from. Mirrors
        /// `inject_outer_record_for_test` for the derived-addressing world.
        pub fn inject_derived_record_for_test(
            &self,
            derived_pub: &[u8; 32],
            label: &str,
            rdata: &str,
        ) {
            let z32 = pkarr::PublicKey::try_from(derived_pub)
                .expect("valid derived pubkey")
                .to_z32();
            let mut store = self.store.lock().unwrap();
            let entry = store.entry(z32).or_default();
            entry.records.retain(|(l, _)| l != label);
            entry.records.push((label.to_string(), rdata.to_string()));
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

            // 2b. Model the REAL merged-packet budget, not per-rdata. Build the
            //     actual SignedPacket from ALL records now under this key and let
            //     pkarr's encoder reject an over-budget total — this is the exact
            //     sizing DhtTransport::merge_republish_attempt uses. Without this
            //     the mock was blind to share+accumulated-receipt overflow (the
            //     same class of blind spot as the original clobber bug).
            {
                let mut builder = pkarr::SignedPacket::builder();
                for (l, rd) in &merged {
                    let name: pkarr::dns::Name<'_> = match l.as_str().try_into() {
                        Ok(n) => n,
                        Err(e) => return PublishOutcome::Other(Error::Transport(map_dns_err(e))),
                    };
                    let txt: pkarr::dns::rdata::TXT<'_> = match rd.as_str().try_into() {
                        Ok(t) => t,
                        Err(e) => return PublishOutcome::Other(Error::Transport(map_dns_err(e))),
                    };
                    builder = builder.txt(name, txt, 300);
                }
                if let Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) =
                    builder.sign(kp)
                {
                    return PublishOutcome::Other(Error::PacketBudgetExceeded {
                        encoded,
                        budget: crate::flow::WIRE_BUDGET_BYTES,
                    });
                }
            }

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
            // Merge-republish (preserve `_cprcpt-*` receipts) via the shared seq-CAS
            // path — matches the fixed DhtTransport::publish so tests exercise the
            // real behavior, not the old clobber where a share wiped every receipt.
            // The 1000-byte ceiling is enforced inside merge_attempt_mock against the
            // REAL merged packet (share + accumulated receipts), matching pkarr — so
            // an over-budget total surfaces as `PacketBudgetExceeded`, exactly as on
            // the DHT (was previously a lax per-rdata check that missed the merge).
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

        fn publish_derived(
            &self,
            signer: &crate::derive::DerivedSigner,
            label: &str,
            rdata: &str,
        ) -> Result<(), Error> {
            // Fidelity (design §9): BUILD the real derived-key SignedPacket purely
            // for its validation side effects — the exact hazmat signing + budget +
            // from_relay_payload (pkarr re-verify) path the DHT uses — then DISCARD
            // it. The in-memory store holds the rdata, not the packet; building it
            // here means the mock can't hide a signing/budget bug (the class the
            // clobber + merged-budget blind spots belonged to). Only the network hop
            // is mocked; storage is keyed by the SAME derived z32 the real derivation
            // produces (shared code, no re-impl).
            let _ = build_derived_signed_packet(signer, label, rdata)?;
            let z32 = derived_z32(&signer.public())?;
            let mut store = self.store.lock().unwrap();
            let entry = store.entry(z32).or_default();
            // Single record per derived key: replace any prior record at this label.
            // No `seq` bump: a derived key is no-CAS by design (single writer,
            // single record); `seq` is receipt-CAS bookkeeping (D-P9-A3) for the
            // merge path and stays untouched here.
            entry.records.retain(|(l, _)| l != label);
            entry.records.push((label.to_string(), rdata.to_string()));
            Ok(())
        }

        fn resolve_derived(
            &self,
            derived_pub: &[u8; 32],
            label: &str,
        ) -> Result<Option<String>, Error> {
            let z32 = derived_z32(derived_pub)?;
            let store = self.store.lock().unwrap();
            Ok(store.get(&z32).and_then(|e| {
                e.records
                    .iter()
                    .find(|(l, _)| l == label)
                    .map(|(_, rd)| rd.clone())
            }))
        }
    }
}

// ---- Derived-key transport tests (Phase 2) ---------------------------------

#[cfg(test)]
mod derived_tests {
    use super::*;
    use crate::derive::{derive_public, derive_signer};

    const LABEL: &str = "_cipherpost";

    fn parent_pub(seed: &[u8; 32]) -> [u8; 32] {
        pkarr::Keypair::from_secret_key(seed)
            .public_key()
            .to_bytes()
    }

    // A 32-char lowercase-hex share_ref made of a single repeated byte.
    fn ref_hex(b: u8) -> String {
        (0..16).map(|_| format!("{b:02x}")).collect()
    }

    /// R1 guard (design §10.2 / §12): pkarr's OWN signature over a builder-made
    /// packet must verify against transport's `bep44_signable()` — i.e. our
    /// replication of pkarr's PRIVATE BEP44 encoder is byte-exact. NON-ignored:
    /// a pkarr bump that changed the encoding would silently break every
    /// hand-signed derived-key packet; this fails loudly instead.
    #[test]
    fn signable_replication_matches_pkarr() {
        let kp = pkarr::Keypair::random();
        let sp = pkarr::SignedPacket::builder()
            .txt(
                "_cipherpost".try_into().unwrap(),
                "hello".try_into().unwrap(),
                300,
            )
            .sign(&kp)
            .unwrap();
        let ts: u64 = sp.timestamp().into();
        let v = sp.encoded_packet();
        let ours = bep44_signable(ts, &v);
        kp.public_key()
            .verify(&ours, &sp.signature())
            .expect("pkarr's signature must verify against transport::bep44_signable — byte-exact");
    }

    /// Publish a record under a derived key; the counterparty resolves it via
    /// PUBLIC derivation only. Exercises the real hazmat signing +
    /// `from_relay_payload` path inside `MockTransport::publish_derived`.
    #[test]
    fn derived_publish_resolve_roundtrip() {
        let transport = MockTransport::new();
        let seed = [9u8; 32];
        let share_ref = ref_hex(0x22);

        let signer = derive_signer(&seed, &share_ref).unwrap();
        transport
            .publish_derived(&signer, LABEL, "derived-payload")
            .expect("publish under derived key");

        // Counterparty derives the SAME key from PUBLIC data only.
        let derived_pub = derive_public(&parent_pub(&seed), &share_ref).unwrap();
        assert_eq!(derived_pub, signer.public(), "public == secret derivation");
        assert_eq!(
            transport
                .resolve_derived(&derived_pub, LABEL)
                .unwrap()
                .as_deref(),
            Some("derived-payload"),
        );

        // A never-published key resolves to None (not an error).
        let unused = derive_public(&parent_pub(&seed), &ref_hex(0x33)).unwrap();
        assert_eq!(transport.resolve_derived(&unused, LABEL).unwrap(), None);
    }

    /// The ceiling-lifting property: two share_refs from the SAME parent land
    /// under DIFFERENT keys — independent packets, no clobber, no shared budget.
    #[test]
    fn distinct_share_refs_are_independent_packets() {
        let transport = MockTransport::new();
        let seed = [4u8; 32];
        transport
            .publish_derived(&derive_signer(&seed, &ref_hex(0x01)).unwrap(), LABEL, "one")
            .unwrap();
        transport
            .publish_derived(&derive_signer(&seed, &ref_hex(0x02)).unwrap(), LABEL, "two")
            .unwrap();
        let k1 = derive_public(&parent_pub(&seed), &ref_hex(0x01)).unwrap();
        let k2 = derive_public(&parent_pub(&seed), &ref_hex(0x02)).unwrap();
        assert_eq!(
            transport.resolve_derived(&k1, LABEL).unwrap().as_deref(),
            Some("one")
        );
        assert_eq!(
            transport.resolve_derived(&k2, LABEL).unwrap().as_deref(),
            Some("two")
        );
    }

    /// An over-budget record surfaces `PacketBudgetExceeded` (the mock builds the
    /// real packet, so it sees the same budget the DHT would).
    #[test]
    fn oversized_derived_record_rejected() {
        let transport = MockTransport::new();
        let signer = derive_signer(&[1u8; 32], &ref_hex(0x00)).unwrap();
        let err = transport
            .publish_derived(&signer, LABEL, &"x".repeat(1100))
            .unwrap_err();
        assert!(
            matches!(err, Error::PacketBudgetExceeded { .. }),
            "got {err:?}"
        );
    }
}
