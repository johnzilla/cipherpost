---
phase: 01-foundation-scaffold-vendored-primitives-and-transport-seam
plan: "03"
subsystem: transport-record
tags: [transport, record, pkarr, dht, mock, ed25519, jcs, bep44, outer-record, share-ref]
dependency_graph:
  requires:
    - Cargo.toml with pinned stack (Plan 01)
    - src/lib.rs with DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX, PROTOCOL_VERSION constants (Plan 01)
    - src/error.rs with Error::SignatureInner, SignatureCanonicalMismatch, NotFound, Network, Transport variants (Plan 01)
  provides:
    - src/record.rs — OuterRecord + OuterRecordSignable, sign_record, verify_record, share_ref_from_bytes, SHARE_REF_BYTES
    - src/transport.rs — Transport trait, DhtTransport (pkarr::ClientBlocking), MockTransport (cfg-gated)
    - tests/mock_transport_roundtrip.rs — integration round-trip + not-found + receipt-label tests
    - tests/signed_packet_budget.rs — 550-byte blob fits within BEP44 1000-byte DNS packet budget
    - tests/outer_record_canonical_form.rs — JCS fixture byte-match test
    - tests/fixtures/outer_record_signable.bin — committed 192-byte JCS fixture
  affects:
    - Phase 2 (send/receive) calls Transport::publish/resolve with OuterRecord
    - Phase 3 (receipts) calls Transport::publish_receipt; must upgrade BOTH DhtTransport AND MockTransport to resolve-merge-republish
    - Phase 2 tests import MockTransport (via --features mock) for integration tests
    - Phase 2 flow::send computes share_ref via share_ref_from_bytes(ciphertext, created_at)
tech_stack:
  added:
    - pkarr::ClientBlocking via Client::builder().no_relays().request_timeout(t).build()?.as_blocking()
    - pkarr::SignedPacket::builder().txt(Name, TXT, ttl).sign(keypair) for DHT publishing
    - pkarr::dns::Name<'_> + pkarr::dns::rdata::TXT<'_> via TryFrom<&str>
    - String::try_from(txt.clone()) to concatenate multi-chunk TXT CharacterString entries
    - pkarr::errors::PublishError + QueryError for typed error matching
    - sha2::Sha256 for share_ref derivation
    - serde_canonical_json::CanonicalFormatter inlined in record.rs (parallel-safe with crypto.rs)
    - Arc<Mutex<HashMap<String, Vec<(String, String)>>>> as MockStore type alias
  patterns:
    - Transport trait with 3 locked method signatures — Phase 2/3 code against this interface only
    - MockTransport behind #[cfg(any(test, feature = "mock"))] with [[test]] required-features in Cargo.toml
    - verify_record: parse → verify_strict → re-canonicalize check (T-01-03-02 mitigation)
    - share_ref = sha256(ciphertext || created_at_be_bytes)[..16] as 32 lowercase hex chars
    - JCS inlined in record.rs (not imported from crypto.rs) — parallel execution safety
key_files:
  created:
    - src/record.rs
    - src/transport.rs
    - tests/mock_transport_roundtrip.rs
    - tests/signed_packet_budget.rs
    - tests/outer_record_canonical_form.rs
    - tests/fixtures/outer_record_signable.bin
  modified:
    - Cargo.toml (added [[test]] sections with required-features = ["mock"] for mock_transport_roundtrip)
decisions:
  - "pkarr 5.0.4 is the resolved version (Cargo.lock); spec says 5.0.3 — API is compatible, all methods confirmed identical"
  - "ClientBlocking obtained via Client::builder().no_relays().request_timeout(t).build()?.as_blocking() — ClientBlocking has no builder() method of its own"
  - "resolve_most_recent returns Option<SignedPacket> with no Result wrapper — no error to map on DHT miss"
  - "PublishError::Query(QueryError::Timeout) matched via enum variant (typed), not string matching — Phase 1 does NOT do string matching; SUMMARY note about string matching is superseded"
  - "TXT rdata multi-chunk extraction via String::try_from(txt.clone()) — concatenates all CharacterString chunks correctly for JSON > 255 bytes"
  - "MockTransport required-features = mock in Cargo.toml — cfg(test) does not propagate across crate boundaries (same fix as Plan 02 encrypt_key_envelope_with_params)"
  - "MockStore type alias added to satisfy clippy::type_complexity"
  - "550-byte blob (not 600) is the empirical max for worst-case record — see deviations"
  - "JCS inlined in record.rs as private fn jcs() rather than imported from crypto.rs — parallel-safe; can be consolidated post-merge"
metrics:
  duration_minutes: 8
  completed_date: "2026-04-20"
  tasks_completed: 2
  tasks_total: 2
  files_created: 6
  files_modified: 2
requirements-completed:
  - TRANS-01
  - TRANS-02
  - TRANS-04
  - TRANS-05
---

# Phase 01 Plan 03: Transport Seam and OuterRecord Wire Format Summary

**One-liner:** Transport trait with three locked method signatures, DhtTransport over pkarr::ClientBlocking (DHT-only, 30s timeout), MockTransport behind cfg-gate, OuterRecord + OuterRecordSignable with Ed25519+JCS dual-signing, 128-bit share_ref, and committed JCS fixture bytes enforcing wire format stability.

## What Was Built

### Task 1: src/record.rs — OuterRecord / OuterRecordSignable schema

**Struct schema (alphabetical field order for JCS stability):**

`OuterRecord`: `blob`, `created_at`, `protocol_version`, `pubkey`, `recipient`, `share_ref`, `signature`, `ttl_seconds`

`OuterRecordSignable`: identical minus `signature`

**share_ref derivation (D-06, PAYL-05):**
- `sha256(ciphertext_bytes || created_at.to_be_bytes())[..16]` as 32 lowercase hex chars
- Phase 2 `flow::send` uses this exact formula when constructing the outer record

**sign_record:**
- JCS-serialize via `serde_canonical_json::CanonicalFormatter` (inlined — parallel-safe with crypto.rs)
- Sign via `pkarr::Keypair::sign(&bytes)` → base64-encode `Signature::to_bytes()`

**verify_record (T-01-03-01, T-01-03-02, D-16):**
1. Parse z-base-32 pubkey → `VerifyingKey::from_bytes(pk.as_bytes())`
2. Decode base64 signature → `Signature::from_slice`
3. Build `OuterRecordSignable`, JCS-serialize
4. `VerifyingKey::verify_strict(&bytes, &sig)` — strict mode (no legacy Ed25519 relaxations)
5. Re-canonicalize: parse JCS bytes back → re-serialize → assert byte-identical (canonicalization bypass guard)
6. All failures → `Error::SignatureInner` which Displays as "signature verification failed" (D-16)

**JCS fixture (T-01-03-01):**
- `tests/fixtures/outer_record_signable.bin`: 192 bytes, committed
- `tests/outer_record_canonical_form.rs`: byte-match assertion on every run; `#[ignore]` regenerate test
- Any field reorder, serde attribute change, or library update that shifts the bytes fails this test at PR time

**4 inline tests pass:** `share_ref_is_32_hex_chars`, `share_ref_is_deterministic`, `sign_verify_round_trip`, `tampered_blob_fails_verify`

### Task 2: src/transport.rs — Transport trait, DhtTransport, MockTransport

**Transport trait (TRANS-01) — locked method signatures:**
```rust
pub trait Transport {
    fn publish(&self, keypair: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error>;
    fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error>;
    fn publish_receipt(&self, keypair: &pkarr::Keypair, share_ref_hex: &str, receipt_json: &str) -> Result<(), Error>;
}
```

**DhtTransport (TRANS-04, TRANS-05):**
- `DEFAULT_DHT_TIMEOUT = Duration::from_secs(30)`
- Built via `Client::builder().no_relays().request_timeout(timeout).build()?.as_blocking()`
- `no_relays()` enforces the "no servers" constraint (CLAUDE.md Principle 1)
- `publish`: serialize to JSON → `SignedPacket::builder().txt("_cipherpost", json, 300).sign(kp)`
- `resolve`: `resolve_most_recent(&pk)` → find `_cipherpost` TXT → `String::try_from(txt.clone())` → `serde_json::from_str` → `verify_record`
- `publish_receipt`: Phase 1 simple publish (see Phase 3 obligation below)
- stderr progress before each DHT call: "Publishing to DHT...", "Resolving from DHT...", "Publishing receipt to DHT..."
- Error mapping: `PublishError::Query(QueryError::Timeout)` → `Error::Network` (exit 6, typed enum match)

**MockTransport (TRANS-02, D-03):**
- `#[cfg(any(test, feature = "mock"))]` gate; accessible via `--features mock`
- `Arc<Mutex<MockStore>>` where `MockStore = HashMap<String, Vec<(String, String)>>`
- `publish`: serialize, check 1000-byte ceiling, store under z32 key with `_cipherpost` label
- `resolve`: find `_cipherpost` entry, deserialize, `verify_record`
- `publish_receipt`: store under `_cprcpt-<share_ref>` label
- `resolve_all_txt(z32) -> Vec<(label, rdata)>`: Phase 3 uses for receipt enumeration

**3 integration tests pass (TRANS-01 + TRANS-02):**
- `mock_publish_then_resolve_roundtrips_verified_record`: byte-identical round-trip
- `mock_resolve_unpublished_returns_not_found`: `Error::NotFound` on empty store
- `mock_publish_receipt_stores_under_cprcpt_label`: receipt under correct label

**1 budget test passes (SEND-05):**
- 550-byte blob (worst-case: share mode with recipient) → dns_packet=999 bytes ≤ 1000 — OK
- See deviation section for why 600 bytes was changed to 550

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocker] cfg(test) does not propagate across crate boundaries**
- **Found during:** Task 2, building integration tests
- **Issue:** `use cipherpost::transport::MockTransport` in integration tests fails — `cfg(test)` in the library is not active when integration tests compile against it (same root cause as Plan 02 deviation #1)
- **Fix:** Added `[[test]] required-features = ["mock"]` for `mock_transport_roundtrip` in Cargo.toml; run integration tests with `--features mock`. `MockTransport` itself stays behind `#[cfg(any(test, feature = "mock"))]` as required.
- **Files modified:** `Cargo.toml`

**2. [Rule 1 - Bug] clippy::type_complexity on MockStore field**
- **Found during:** Task 2, clippy run
- **Issue:** `Arc<Mutex<HashMap<String, Vec<(String, String)>>>>` flagged as too complex
- **Fix:** Added `type MockStore = Arc<Mutex<HashMap<String, Vec<(String, String)>>>>` alias
- **Files modified:** `src/transport.rs`

**3. [Rule 1 - Discovery] 600-byte blob exceeds BEP44 1000-byte DNS packet budget**
- **Found during:** Task 2, signed_packet_budget test
- **Issue:** The plan's "representative ~600 bytes base64" assumption exceeds the actual limit. Empirical measurement shows:
  - blob=550 → dns_packet=999 bytes (OK, within 1000-byte limit)
  - blob=600 → dns_packet=1049 bytes (exceeds limit, pkarr rejects at `SignedPacket::new`)
- **Fix:** Updated test to use 550-byte blob with a comment explaining the discovery. No schema change needed — Phase 2 must enforce this at the payload layer or use two-tier storage for larger payloads.
- **Impact for Phase 2:** `flow::send` must validate that `age_ciphertext_base64.len() ≤ 550` before attempting to publish, or document that larger payloads go through two-tier storage (envelope reference in DHT, ciphertext elsewhere). This is SEND-05.
- **Files modified:** `tests/signed_packet_budget.rs`

**4. [Rule 1 - Note] pkarr error mapping uses typed enum, not string matching**
- **Context:** The plan's pseudocode showed string-matching ("timeout", "timed out", "not found") as a known limitation. pkarr 5.0.4 exposes `PublishError::Query(QueryError::Timeout)` as a typed variant.
- **Action:** Used typed variant matching directly in `map_pkarr_publish_error`. The "Phase 2+ migrate to typed matching" note in the plan is already satisfied by Phase 1.
- **Remaining limitation:** `resolve_most_recent` returns `Option<SignedPacket>` (no error type), so network failures during resolve are silently converted to `None` (NotFound). This is a pkarr API limitation — resolve failures are indistinguishable from not-found at the blocking API level.

## pkarr 5.0.4 API Reference (for Phase 2 consumption)

| API | Method | Notes |
|-----|--------|-------|
| Build blocking client | `Client::builder().no_relays().request_timeout(d).build()?.as_blocking()` | Builder methods are `&mut self` — not chainable in traditional sense; but can chain because they return `&mut Self` |
| Publish | `ClientBlocking::publish(&SignedPacket, Option<Timestamp>) -> Result<(), PublishError>` | `None` for CAS (compare-and-swap) |
| Resolve | `ClientBlocking::resolve_most_recent(&PublicKey) -> Option<SignedPacket>` | No Result — network errors silently → None |
| Build packet | `SignedPacket::builder().txt(Name, TXT, ttl).sign(&Keypair) -> Result<SignedPacket, SignedPacketBuildError>` | Fails if encoded DNS packet > 1000 bytes |
| Packet size | `packet.as_bytes().len()` | Full: 32+64+8+dns_packet |
| DNS packet size | `packet.encoded_packet().len()` | BEP44 "v" value; must be ≤ 1000 bytes |
| TXT from string | `TXT::try_from(json_str: &str)` | Splits into 255-byte CharacterString chunks automatically |
| TXT to string | `String::try_from(txt.clone())` | Concatenates all chunks |
| PublicKey from z32 | `PublicKey::try_from(z32_str: &str)` | Also accepts URIs and URLs |
| Keypair sign | `Keypair::sign(&[u8]) -> Signature` | Delegates to ed25519_dalek::SigningKey::sign |
| Verifying key | `PublicKey::as_bytes() -> &[u8; 32]` | Then `VerifyingKey::from_bytes(pk.as_bytes())` |

## Phase 3 Upgrade Obligations

### CRITICAL: MockTransport::publish_receipt resolve-merge-republish (T-01-03-08)

Phase 1 ships `MockTransport::publish_receipt` with clobber-replace semantics: publishing receipt R2 for a different `share_ref` than R1 will REPLACE R1 in the store (the `entry.retain` call removes any existing entry matching the label, which is per-share_ref — BUT the store is per-keypair-z32, so R1 for `share_ref_A` and R2 for `share_ref_B` will coexist because they have different labels).

Wait — re-reading the implementation: `entry.retain(|(l, _)| l != &label)` where `label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex)`. Since each share_ref produces a unique label, multiple receipts for DIFFERENT share_refs DO coexist in Phase 1 MockTransport. The clobber-replace only applies to re-publishing the SAME share_ref's receipt.

However, Phase 1 `DhtTransport::publish_receipt` publishes a NEW SignedPacket containing ONLY the receipt TXT. On real DHT, this would overwrite the sender's existing packet (losing any other TXT records, including `_cipherpost` and other receipts). Phase 3 MUST upgrade `DhtTransport::publish_receipt` to:
1. Resolve the current packet (`resolve_most_recent`)
2. Copy all existing TXT records
3. Replace/add the receipt TXT
4. Publish the merged packet

Phase 3 MUST ALSO ensure `MockTransport::publish_receipt` semantics match `DhtTransport::publish_receipt` for the TRANS-03 coexistence integration test. Specifically: after upgrading `DhtTransport`, verify the mock mirrors the same invariant (publishing R2 preserves R1 from different share_refs). The current Phase 1 MockTransport already has this property — but the Phase 3 TRANS-03 integration test will verify it explicitly.

## Known Stubs

| File | Reason | Filled by |
|------|--------|-----------|
| `src/payload.rs` | Phase 2+ per D-02 | Phase 2 Plan |
| `src/receipt.rs` | Phase 3 per D-02 | Phase 3 Plan |
| `src/flow.rs` | Phase 2+ per D-02 | Phase 2 Plan |
| `DhtTransport::publish_receipt` body | Phase 1 simple clobber; Phase 3 upgrades | Phase 3 Plan |

## Threat Flags

None — no new network endpoints or auth paths beyond what the plan's threat register covers. All T-01-03-* mitigations implemented:
- T-01-03-01: `tests/outer_record_canonical_form.rs` + fixture
- T-01-03-02: `verify_record` re-canonicalization check
- T-01-03-03: All Signature* variants Display as "signature verification failed" (D-16)
- T-01-03-04: `DEFAULT_DHT_TIMEOUT = 30s`; typed `PublishError::Query(QueryError::Timeout)` → `Error::Network`
- T-01-03-05: MockTransport 1000-byte ceiling + `tests/signed_packet_budget.rs`
- T-01-03-06: `map_pkarr_publish_error` collapses pkarr errors
- T-01-03-07: Accepted (out of scope)
- T-01-03-08: Phase 1 simple implementation; Phase 3 must upgrade both impls
- T-01-03-09: Accepted (inherent DHT property)

## Self-Check

### Created files exist:
- src/record.rs: FOUND
- src/transport.rs: FOUND
- tests/mock_transport_roundtrip.rs: FOUND
- tests/signed_packet_budget.rs: FOUND
- tests/outer_record_canonical_form.rs: FOUND
- tests/fixtures/outer_record_signable.bin: FOUND

### Commits exist:
- 683f2e2: feat(01-03): implement src/record.rs — FOUND
- 4928a13: feat(01-03): implement src/transport.rs — FOUND

## Self-Check: PASSED
