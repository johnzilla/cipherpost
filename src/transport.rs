//! Transport seam — the only architectural delta from cclink. `Transport` trait
//! admits both `DhtTransport` (wraps pkarr::ClientBlocking for real DHT) and
//! `MockTransport` (in-memory HashMap, cfg-gated) so integration tests in this
//! crate and downstream plans do not touch the real DHT.
//!
//! v2 addressing: every share and receipt lives under its OWN derived key
//! `derive(parent_pub, share_ref)` (docs/design/derived-key-addressing.md,
//! SPEC.md §3.8), so each PKARR packet holds exactly one record. The trait
//! exposes only the derived-key methods; the v1.1 parent-key
//! publish / resolve / publish_receipt / resolve_all_cprcpt surface and its
//! merge-republish + CAS machinery were removed once the flow moved entirely to
//! derived keys.
//!
//! pkarr API notes (5.0.4 — resolves 5.0.3 requirement; API compatible):
//! - ClientBlocking is obtained via: Client::builder().no_relays().request_timeout(t).build()?.as_blocking()
//! - ClientBuilder methods are &mut self builders (mutable, not chainable like Into<Self>)
//! - resolve_most_recent returns Option<SignedPacket> with no Result wrapper
//! - publish returns Result<(), PublishError> where PublishError::Query(QueryError::Timeout) = timeout
//! - TXT strings are split into 255-byte CharacterString chunks; String::try_from(txt.clone()) concatenates

use crate::error::Error;
use std::time::Duration;

/// Default DHT request timeout per TRANS-04 (exit code 6 on expiry).
pub const DEFAULT_DHT_TIMEOUT: Duration = Duration::from_secs(30);

// ---- Transport trait --------------------------------------------------------

/// Transport trait — TRANS-01. `DhtTransport` is the production impl and
/// `MockTransport` is the test impl. Under v2 derived-key addressing a
/// share/receipt gets its OWN key `derive(parent_pub, share_ref)`, so each PKARR
/// packet holds exactly ONE record — there is no resolve-merge-republish and no
/// CAS on this path.
pub trait Transport {
    /// Publish `rdata` at `label` under the DERIVED key `signer.public()`, signing
    /// the BEP44 packet with the derived scalar (pkarr's seed-based `Keypair`
    /// cannot). Each derived key is written by a single writer and holds one
    /// record. Over-budget rdata surfaces `PacketBudgetExceeded`.
    fn publish_derived(
        &self,
        signer: &crate::derive::DerivedSigner,
        label: &str,
        rdata: &str,
    ) -> Result<(), Error>;

    /// Resolve the TXT `rdata` at `label` under the derived key `derived_pub`
    /// (compressed Ed25519 bytes, from `derive::derive_public`). `Ok(None)` if the
    /// key has no packet or no matching label. Verification of the record body is
    /// the caller's job.
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
}

impl Transport for DhtTransport {
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
/// `QueryError::Timeout` → `Error::Network` is matched on the enum variant
/// directly. Other errors collapse to `Error::Transport`.
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
// Only the mock keys its store by z32; the DHT impl uses `pkarr::PublicKey`
// directly, so this helper is mock-only (cfg-gated to keep release builds clean).
#[cfg(any(test, feature = "mock"))]
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

    /// `pubkey_z32` → list of `(label, rdata)` records. Under v2 derived-key
    /// addressing the map is keyed by the DERIVED z32 and each key holds a single
    /// record (one per label); there is no CAS / seq bookkeeping.
    type MockStore = Arc<Mutex<HashMap<String, Vec<(String, String)>>>>;

    /// In-memory transport for tests, keyed by (derived) `pubkey_z32`. Building the
    /// stored record goes through `build_derived_signed_packet`, so the mock enforces
    /// the same 1000-byte ceiling + hazmat signing path pkarr does — tests that pass
    /// locally also pass against the real DHT (T-01-03-05).
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

        /// Test helper: list every `(label, rdata)` under a given (derived) pubkey.
        pub fn resolve_all_txt(&self, pubkey_z32: &str) -> Vec<(String, String)> {
            self.store
                .lock()
                .unwrap()
                .get(pubkey_z32)
                .cloned()
                .unwrap_or_default()
        }

        /// v2 test helper: inject a raw `rdata` at `label` under a DERIVED key
        /// (compressed Ed25519 bytes), bypassing `publish_derived`'s budget/signing
        /// so tests can place wire-budget-exceeding records (e.g. PIN shares) at the
        /// exact key `run_receive` resolves from.
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
            let records = store.entry(z32).or_default();
            records.retain(|(l, _)| l != label);
            records.push((label.to_string(), rdata.to_string()));
        }
    }

    impl Transport for MockTransport {
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
            // here means the mock can't hide a signing/budget bug. Storage is keyed
            // by the SAME derived z32 the real derivation produces (shared code,
            // no re-impl); only the network hop is mocked.
            let _ = build_derived_signed_packet(signer, label, rdata)?;
            let z32 = derived_z32(&signer.public())?;
            let mut store = self.store.lock().unwrap();
            let records = store.entry(z32).or_default();
            // Single record per derived key: replace any prior record at this label.
            records.retain(|(l, _)| l != label);
            records.push((label.to_string(), rdata.to_string()));
            Ok(())
        }

        fn resolve_derived(
            &self,
            derived_pub: &[u8; 32],
            label: &str,
        ) -> Result<Option<String>, Error> {
            let z32 = derived_z32(derived_pub)?;
            let store = self.store.lock().unwrap();
            Ok(store.get(&z32).and_then(|records| {
                records
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
