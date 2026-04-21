# Phase 3: Signed receipt — the cipherpost delta - Research

**Researched:** 2026-04-21
**Domain:** Rust cipherpost library — PKARR SignedPacket merge semantics, receipt wire schema, DHT TXT-record iteration, receipts CLI fetch/verify/filter
**Confidence:** HIGH (pkarr 5.0.4 API verified by direct source inspection; Phase 2 patterns verified in-tree)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions (NON-NEGOTIABLE — plans MUST follow these verbatim)

**Receipt wire schema (D-RS-01..07):**
- **D-RS-01:** Two structs in `src/receipt.rs` mirroring `OuterRecord` / `OuterRecordSignable`: `ReceiptSignable` (9 alphabetical fields: `accepted_at: i64`, `ciphertext_hash: String`, `cleartext_hash: String`, `nonce: String`, `protocol_version: u16`, `purpose: String`, `recipient_pubkey: String`, `sender_pubkey: String`, `share_ref: String`) and `Receipt` (adds `signature: String` alphabetically after `share_ref`). `From<&Receipt> for ReceiptSignable` required.
- **D-RS-02:** `accepted_at` on-wire = `i64` unix seconds. Ledger's ISO-8601 string stays ledger-local. `receipts` command renders both local + UTC from the unix seconds at display time.
- **D-RS-03:** `nonce` = 128-bit random, 32-char lowercase hex. Source: `rand::rngs::OsRng.fill_bytes(&mut [0u8; 16])`. Defense against attacker-synthesized receipts, not replay.
- **D-RS-04:** `ciphertext_hash` / `cleartext_hash` = raw lowercase sha256 hex (64 chars, no prefix). Matches Phase 2 ledger exactly. Forward-compat via `protocol_version`, NOT an in-band multihash prefix.
- **D-RS-05:** `signature` = base64 STANDARD (Ed25519 64 raw bytes → 88 chars padded). Matches `OuterRecord.signature`.
- **D-RS-06:** Exactly the 10 RCPT-01 fields. No `receipt_version`, no `sender_share_uri`, no additions without a `protocol_version` bump.
- **D-RS-07:** `sign_receipt(signable, &pkarr::Keypair) -> Result<String, Error>` and `verify_receipt(receipt: &Receipt) -> Result<(), Error>` mirror `record::sign_record` / `record::verify_record` exactly, including the round-trip-reserialize + byte-compare guard (T-01-03-02). All sig failures produce `Error::SignatureInner` — no new `Error::SignatureReceipt` variant.

**publish_receipt merge (TRANS-03) (D-MRG-01..06):**
- **D-MRG-01:** Strategy = **resolve → rebuild builder → re-sign**. `DhtTransport::publish_receipt` calls `client.resolve_most_recent(&pk)`. If `Some(existing)`, iterate all resource records and re-add each via builder, REPLACING any existing TXT whose label equals this receipt's `_cprcpt-<share_ref>`. Add the new receipt TXT. Sign. If `None`, publish alone.
- **D-MRG-02:** Concurrent-publish race = documented known limitation, not mitigated. No retry loop, no in-process mutex in skeleton. Phase 4 THREAT-MODEL.md owns the language.
- **D-MRG-03:** TXT TTL on published receipts = **300 seconds**, matching outer-share TTL (`src/transport.rs:100` and `:146`). Single TTL constant in codebase.
- **D-MRG-04:** pkarr 5.0.3 SignedPacket iteration API is to be confirmed via prototype spike. Planner's first task is to verify `packet.all_resource_records()` exists and builder supports per-record re-add. **(Resolved in this research — §1 below.)**
- **D-MRG-05:** `MockTransport::publish_receipt` is already append-preserving per-share_ref (`src/transport.rs:271-288`). Upgrade needed: confirming test only; no body change expected.
- **D-MRG-06:** Receipt wire budget inherits from outer-share `WIRE_BUDGET_BYTES = 1000`. If merged packet exceeds, `publish_receipt` returns `Error::WireBudgetExceeded { encoded, budget, plaintext: 0 }` (plaintext=0 indicates receipt, not share).

**Publish sequencing + failure handling (D-SEQ-01..07):**
- **D-SEQ-01:** `run_receive` strict step order is extended with **step 13: publish_receipt** AFTER step 12 (sentinel + ledger). On publish success, update the ledger line's `receipt_published_at` to ISO-8601 UTC.
- **D-SEQ-02:** Publish failure = **warn + degrade, exit 0**. `run_receive` catches any error from `publish_receipt`, prints `receipt publish failed: <user_message>` to stderr, and continues. Ledger stays at `receipt_published_at: null`.
- **D-SEQ-03:** No auto-retry in skeleton.
- **D-SEQ-04:** Ledger schema adds ONE field: `receipt_published_at: Option<String>`. Alphabetical position between `purpose` and `sender`. Backwards-compatible via `Option`.
- **D-SEQ-05:** Ledger is append-only. Updating `receipt_published_at` = **append a new ledger line** (not rewrite). `check_already_accepted` already handles 2-rows-per-share — last match wins.
- **D-SEQ-06:** Self-mode publishes via the same path. `sender_pubkey == recipient_pubkey` is valid.
- **D-SEQ-07:** `run_receive` signature grows to accept `&pkarr::Keypair`. `main.rs` Receive dispatch reconstructs it from `id.signing_seed()` (same pattern as Send branch `src/main.rs:94-96`).

**receipts output + verify (D-OUT-01..04):**
- **D-OUT-01:** Default output = human-readable table on stdout; `--json` flag emits canonical-JSON array. Columns: `share_ref` (first 16 chars), `accepted_at` (local + UTC), `purpose` (truncated to 40 chars with `…`, ctrl-stripped), `recipient_fp` (OpenSSH style).
- **D-OUT-02:** `--share-ref <hex>` filter. Single-result view (not `--json`) shows ALL 10 Receipt fields ("audit detail" view). Multi-result stays in 4-column table.
- **D-OUT-03:** Bad-sig handling = **warn + skip, exit 0 if any verify**. Exit codes: at-least-one-valid → 0; zero-valid + some-invalid-sig → 3 (SignatureInner); zero-valid + only-malformed → 1; zero TXT records found → 5 (NotFound). `--share-ref` filter applied AFTER verification.
- **D-OUT-04:** New `run_receipts(transport, from_z32, share_ref_filter, json_mode) -> Result<(), Error>` in `src/flow.rs`. Does NOT require `Identity` (no decrypt path — passphrase-free).

**Integration tests (D-IT-01..03):**
- **D-IT-01:** 3 MockTransport integration tests (must-have): (1) two-identity end-to-end round trip, (2) TRANS-03 coexistence (B's outgoing `_cipherpost` + incoming `_cprcpt-*` both resolvable), (3) `--share-ref` filter + concurrent sender self-share.
- **D-IT-02:** 1 HUMAN-UAT test: real-DHT A → B → receipt round trip. Script in `03-HUMAN-UAT.md`.
- **D-IT-03:** Tamper-verify test = nice-to-have, keep if cheap.

### Claude's Discretion (planner picks)

- pkarr 5.0.3 SignedPacket iteration API — actual method names. (Now resolved — §1.)
- `rand` source wiring — `OsRng` direct vs alternatives.
- Table column widths / truncation lengths.
- Ledger append-line strategy for `receipt_published_at` update (alternative: atomic-rename rewrite).
- Error variant introduction — reuse existing catch-alls vs new `Error::ReceiptPublish`.
- `--json` output canonicalization — strict JCS vs `to_string_pretty`.
- Receipts stable ordering — alphabetical / by `accepted_at` / insertion order.
- Human-UAT exact script.

### Deferred Ideas (OUT OF SCOPE for Phase 3)

- `cipherpost republish-receipt --share-ref <ref>` — v1.0
- Concurrent publish retry loop / in-process mutex — v1.1+
- Receipt rotation / GC under wire-budget pressure — v1.0
- `cipherpost receipts --watch` — v2 (V2-OPS-06)
- Receipt encryption to sender — rejected (receipts are public by design)
- Encrypt-then-sign inner-layer reshaping — v2
- Receipt carries full `cipherpost://` URI — rejected
- `receipt_publish_error` persisted in ledger — rejected
- `sha256:` multihash prefix on hash fields — rejected
- `receipt_version` separate from `protocol_version` — rejected
- Ledger in-place rewrite via atomic rename — deferred unless append-duplication becomes ugly
- Tamper-verify integration test as must-have — currently nice-to-have
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TRANS-03 | `publish_receipt` resolves recipient's existing SignedPacket, merges receipt TXT under `_cprcpt-<share_ref>`, re-signs with recipient's key, republishes | §1 (resolve-merge-republish sketch — pkarr 5.0.4 API verified); §2 (wire-budget under accumulation); §7 (MockTransport already append-preserving per `src/transport.rs:271-288`) |
| RCPT-01 | On successful acceptance, construct 10-field Receipt, sign with recipient's Ed25519, publish under recipient's PKARR at `_cprcpt-<share_ref>` | §3 (Receipt struct template mirroring `record::OuterRecord`); §4 (nonce gen via `OsRng.fill_bytes`); §6 (ledger extension for `receipt_published_at`) |
| RCPT-02 | `cipherpost receipts --from <z32> [--share-ref <ref>]` resolves recipient, filters `_cprcpt-*` TXT, verifies each sig, prints structured summary | §5 (fetch iteration shape via `all_resource_records()` + label-prefix filter); §3 (`verify_receipt` signature takes only `&Receipt`, no Identity) |
| RCPT-03 | End-to-end integration test: A→B via MockTransport, B accepts via scripted Prompter, B publishes receipt, A fetches+verifies | §7 (Phase 2 test-harness reusables: `AutoConfirmPrompter`, `deterministic_identity_at`, `MockTransport::resolve_all_txt`) |
</phase_requirements>

## Summary

Phase 3 is the single-module, single-flow extension that makes cipherpost the cipherpost. The receipt body is a straightforward mirror of `record::OuterRecord`'s struct-pair + JCS-sign + strict-verify pattern (§3); all API questions surfaced as "research flags" in `SUMMARY.md` Phase 8 and `CONTEXT.md` D-MRG-04 are now answered by direct inspection of pkarr 5.0.4 source (§1). The resolve-merge-republish body is **directly supported by a canonical example in pkarr's own rustdoc** (`Client::publish` doc comment) — the API shape cipherpost needs is literally the advertised pattern: `for record in most_recent.all_resource_records() { builder = builder.record(record.clone()); }`, then add the new TXT, then sign. `all_resource_records()` iterates every label; `builder.record(rr)` accepts a full `ResourceRecord`; CAS is optional via `publish(&packet, Some(most_recent.timestamp()))`. No prototype spike needed — the API is confirmed.

The second open question — wire budget under accumulation — resolves cleanly: per-receipt TXT overhead is empirically ~280-320 bytes (JSON body ~240 bytes + DNS framing ~50 bytes + label ~40 bytes). The 1000-byte PKARR packet budget, minus ~100 bytes of pubkey/sig/timestamp headers, leaves ~900 bytes for records. A recipient can accumulate **approximately 2–3 receipts** before overflow if they also hold their own outgoing `_cipherpost` share; **approximately 3 receipts** on an empty key. Rotation is deferred; `Error::WireBudgetExceeded { plaintext: 0, ... }` surfaces the condition via the already-locked D-MRG-06 mapping.

Phase 2's test harness (`AutoConfirmPrompter`, `deterministic_identity_at`, `MockTransport::resolve_all_txt`) drops in unmodified for all three D-IT-01 integration tests. `run_receipts` can be `&dyn Transport`-only (no `Identity`) per D-OUT-04, which eliminates the passphrase prompt for listing and maps cleanly onto `main.rs` (§5).

**Primary recommendation:** 2 plans, 2 waves.
- **Wave 1 (P01):** `src/receipt.rs` body (Receipt + ReceiptSignable + sign_receipt + verify_receipt + nonce helper) + `DhtTransport::publish_receipt` + `MockTransport::publish_receipt` upgrade + `run_receive` step-13 wiring + ledger `receipt_published_at` field. Unit tests for each primitive.
- **Wave 2 (P02):** `src/flow.rs::run_receipts` + `main.rs::dispatch` Receipts arm replacement + `--json` clap flag addition + 3 MockTransport integration tests + HUMAN-UAT script.

A single-plan split is also defensible (the two waves share a small enough surface area) but would cost parallelism.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Receipt wire schema (struct-pair + JCS + sign/verify) | `receipt` module (NEW body) | `crypto::jcs_serialize` | Pure data; mirrors `record.rs` exactly. |
| Nonce generation (128-bit random hex) | `receipt` module helper | `rand::rngs::OsRng` (already transitive via `ed25519-dalek` + `Cargo.toml:44`) | Small pure function; no policy. |
| Resolve-merge-republish (`publish_receipt`) | `transport::DhtTransport` | pkarr 5.0.4 `all_resource_records()` + `builder.record()` | Only architectural delta this phase owns; MockTransport already compliant. |
| Publish-after-acceptance sequencing (step 13) | `flow::run_receive` | `transport::Transport::publish_receipt` | Strict D-RECV-01 ordering; publish is best-effort and MUST NOT unwind local state writes. |
| Ledger extension (`receipt_published_at`) | `flow::LedgerEntry` + `append_ledger_entry` | `check_already_accepted` (already last-wins) | Existing Phase 2 append helper; one new field. |
| receipts CLI fetch + verify + filter | `flow::run_receipts` (NEW) | `transport::DhtTransport::resolve_most_recent` + `receipt::verify_receipt` | No Identity needed — passphrase-free. |
| `--json` output canonicalization | `flow::run_receipts` + `main.rs::dispatch::Receipts` | `crypto::jcs_serialize` or `serde_json::to_string_pretty` | Display path; not signed. |
| Receipts table rendering | `flow::run_receipts` | `flow::sender_openssh_fingerprint_and_z32` (already reusable at `flow.rs:622`) | Render-only; D-OUT-01 column set. |
| Integration test harness reuse | `tests/phase3_*.rs` | `flow::test_helpers::AutoConfirmPrompter`, `tests/phase2_share_round_trip.rs::deterministic_identity_at` pattern | All Phase 2 fixtures apply unchanged. |

## Standard Stack

### Core — already pinned (Phase 1+2, unchanged)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `pkarr` | 5.0.4 | SignedPacket + builder + `resolve_most_recent` + `all_resource_records` + `publish(&packet, cas)` | `[VERIFIED: Cargo.lock + /home/john/.cargo/registry/src/.../pkarr-5.0.4/src/signed_packet.rs:460]` — the API cipherpost needs is all present and stable |
| `ed25519-dalek` | `=3.0.0-pre.5` | Ed25519 sign + verify (via `pkarr::Keypair::sign` + `VerifyingKey::verify_strict`) | `[VERIFIED: Cargo.lock]` hard pin — unchanged |
| `serde_canonical_json` | 1.0.0 | JCS canonicalization (receipt signing) | `[VERIFIED: Cargo.lock]` — already used in `record.rs:18` and `crypto.rs::jcs_serialize` |
| `sha2` | 0.10.9 | Hashes (receipts carry pre-computed ciphertext_hash / cleartext_hash from ledger — no new sha2 calls) | `[VERIFIED: Cargo.lock]` — Phase 2 already hashes at ledger-write time (`flow.rs:552-553`) |
| `base64` | 0.22.1 | Base64 STANDARD for signature encoding | `[VERIFIED: Cargo.lock]` — D-RS-05 mandates STANDARD; no URL_SAFE |
| `rand` | 0.8.x | `OsRng` for 128-bit nonce | `[VERIFIED: Cargo.toml:44]` — Phase 2 added `rand = "0.8"` as a direct dep. `OsRng::fill_bytes` stable on rand 0.8 |
| `chrono` | 0.4 (`clock`) | Already used for Phase 2 acceptance-screen local+UTC rendering (`flow.rs:755-761`). D-OUT-01 reuses the exact same `format_unix_as_iso_local` + `format_unix_as_iso_utc` helpers for receipts table | `[VERIFIED: Cargo.toml:48]` |
| `thiserror` | 2.0.18 | Error enum — **no new variants needed** (D-RS-07 mandates reuse of `Error::SignatureInner`; D-SEQ-02 allows reuse of `Error::Transport` / `Error::Network`) | `[VERIFIED: Cargo.lock]` |
| `serde` / `serde_json` | 1 / 1.0.149 | Receipt serde + `_cprcpt-*` TXT parse | `[VERIFIED: Cargo.lock]` |
| `clap` | 4.6.1 | `Receipts { from, share_ref }` already final at `src/cli.rs:81-89`. **Phase 3 ONLY adds `#[arg(long)] json: bool` to the `Receipts` variant** | `[VERIFIED: Cargo.lock + src/cli.rs:78-89]` |

### Supporting — NO new dependencies required for Phase 3

The one new dep Phase 3 needed (`rand` for nonce) was already pulled in during Phase 2 Plan 02-02 for grease-retry determinism. `Cargo.toml:44` has `rand = "0.8"`. `[VERIFIED: Cargo.toml read on 2026-04-21]`

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `OsRng::fill_bytes(&mut [0u8; 16])` for nonce | `pkarr::Keypair::random().secret_key()[..16]` | Abuses pkarr's RNG; generates a full Ed25519 keypair (64B SHA-512 work) just to discard 48 bytes. Wasteful. **Reject.** |
| `OsRng::fill_bytes` | HKDF-derived nonce (`cipherpost/v1/receipt-nonce`) | Adds an HKDF call-site + enum-registration burden (enforced by `tests/hkdf_info_enumeration.rs`) for no threat-model payoff. Nonce is not a key; domain separation is moot. **Reject.** |
| Strict JCS for `--json` output | `serde_json::to_string_pretty` | JCS preserves cross-platform byte-stability but less human-readable. `--json` output is display-only (not signed). Planner's call — recommend `serde_json::to_string_pretty` for UX, reserve JCS for the signature path. |
| `cprefix` iter filter | Hand-rolled `for rr in packet.all_resource_records() { if rr.name.to_string().starts_with("_cprcpt-") { ... } }` | pkarr's `resource_records(name)` filters by exact name or `*` wildcard; it does NOT support a `_cprcpt-*` prefix glob for TXT labels. Hand-rolled is the idiomatic answer. §5 code sketch. |
| Error variant `Error::ReceiptPublish { cause }` | Reuse `Error::Transport(Box<dyn ...>)` or `Error::Network` | D-SEQ-02's "warn + degrade, exit 0" contract catches and prints — exit code never surfaces for publish failure. New variant adds no user-visible value. **Reject** per CONTEXT.md "no new error variants expected." |

**Installation:** No `cargo add` / `Cargo.toml` edits required. Verified by enumerating Phase 3's needs against the existing `[dependencies]` block at `Cargo.toml:21-48`.

**Version verification:** `rand = "0.8"` present (Cargo.toml:44). No new deps to verify against crates.io.

## Architecture Patterns

### System Architecture Diagram

```
                        ┌────────────────────────────────────┐
                        │    cli.rs (clap tree)              │  [Phase 1/2 — FINAL + `--json` flag add]
                        │    Receipts { from, share_ref }    │
                        │      + json: bool  (NEW)           │
                        └─────────────┬──────────────────────┘
                                      │ match arm
                                      ▼
                        ┌────────────────────────────────────┐
                        │  main.rs::dispatch::Receipts {..}  │  [Phase 3 — replaces stub arm at main.rs:216-219]
                        │  NO passphrase prompt (D-OUT-04)   │
                        │  → build DhtTransport              │
                        │  → call run_receipts               │
                        └─────────────┬──────────────────────┘
                                      │
                                      ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                          flow.rs                                          │
    │  ┌─────────────────┐       ┌──────────────────────┐                     │
    │  │ run_receive     │       │ run_receipts (NEW)   │                     │
    │  │                 │       │                      │                     │
    │  │ ...steps 1-11   │       │ 1. transport.resolve_│                     │
    │  │ 12. sentinel+   │       │    most_recent(z32) │                     │
    │  │     ledger write│       │ 2. all_resource_    │                     │
    │  │ 13. publish_    │       │    records()        │                     │
    │  │     receipt(NEW)│       │ 3. filter label     │                     │
    │  │     → on OK,    │       │    starts_with      │                     │
    │  │     append new  │       │    "_cprcpt-"       │                     │
    │  │     ledger line │       │ 4. json_parse each  │                     │
    │  │     with        │       │ 5. verify_receipt   │                     │
    │  │     receipt_    │       │    each             │                     │
    │  │     published_at│       │ 6. filter --share-  │                     │
    │  │     = now ISO   │       │    ref (after verify)│                     │
    │  │     → on Err,   │       │ 7. render table or  │                     │
    │  │     warn+exit 0 │       │    json             │                     │
    │  └────────┬────────┘       └──────┬───────────────┘                     │
    └───────────┼─────────────────────────┼───────────────────────────────────┘
                │                          │
                ▼                          ▼
       ┌────────────────────┐     ┌──────────────────────────┐
       │ receipt.rs (NEW    │     │ transport.rs             │
       │  body — replaces   │     │  - Transport trait (UNCHG)│
       │  4-line stub)      │     │  - DhtTransport          │
       │                    │     │    publish_receipt BODY  │
       │ - Receipt struct   │     │    UPGRADED (D-MRG-01)   │
       │ - ReceiptSignable  │     │    resolve-merge-republish│
       │ - sign_receipt     │     │  - MockTransport         │
       │ - verify_receipt   │     │    publish_receipt       │
       │ - nonce_hex()      │     │    already append-preserv│
       │ - From<&Receipt>   │     │    (D-MRG-05; test only) │
       │   for ReceiptSignable    │                          │
       └────────┬───────────┘     └──────────┬───────────────┘
                │                              │
                ▼                              ▼
       ┌─────────────────────────────────────────────────────┐
       │   pkarr 5.0.4  (Mainline DHT / cache)                │
       │   - SignedPacket::builder()                         │
       │     .record(rr.clone())                             │
       │     .txt(name, txt, 300)                            │
       │     .sign(&keypair)                                 │
       │   - all_resource_records()                          │
       │   - client.publish(&packet, Some(most_recent.timestamp()))  │
       └─────────────────────────────────────────────────────┘
```

### Recommended Project Structure (post-Phase 3)
```
src/
├── lib.rs                  # UNCHANGED (DHT_LABEL_RECEIPT_PREFIX already present at lib.rs:38)
├── main.rs                 # replaces Receipts stub arm (main.rs:216-219)
├── cli.rs                  # ADD `#[arg(long)] json: bool` to Receipts variant
├── crypto.rs               # UNCHANGED
├── error.rs                # UNCHANGED (no new variants)
├── identity.rs             # UNCHANGED
├── record.rs               # UNCHANGED (template for receipt.rs)
├── transport.rs            # REPLACE DhtTransport::publish_receipt body (transport.rs:128-153)
│                           # MockTransport::publish_receipt already compliant (D-MRG-05)
├── payload.rs              # UNCHANGED
├── flow.rs                 # EXTEND: run_receive step 13 + ledger receipt_published_at + run_receipts (NEW)
└── receipt.rs              # REPLACE BODY (currently 4-line placeholder at receipt.rs:1-5)

tests/
├── (all Phase 1 + Phase 2 tests)
├── phase3_end_to_end_a_sends_b_receipt.rs       # NEW — D-IT-01 test 1 (RCPT-01 + RCPT-02 + RCPT-03)
├── phase3_coexistence_b_self_share_and_receipt.rs  # NEW — D-IT-01 test 2 (TRANS-03, SC3)
├── phase3_share_ref_filter.rs                   # NEW — D-IT-01 test 3 (RCPT-02 + SC4)
├── phase3_receipt_canonical_form.rs             # NEW — JCS fixture for Receipt (matches outer_record_canonical_form.rs)
├── phase3_receipt_sign_verify.rs                # NEW — unit test round trip + tampered
└── fixtures/
    └── receipt_signable.bin                     # NEW — committed JCS fixture
```

### Pattern 1: Mirror `record::OuterRecord` for `receipt::Receipt`

**What:** The struct-pair + `From<&Receipt> for ReceiptSignable` + `sign_receipt` + `verify_receipt` is a line-for-line clone of `record.rs`, with field-set changes only. The round-trip-reserialize guard is load-bearing and MUST be preserved.

**When to use:** Every receipt sign/verify call site.

**Example:** See §3 below for the full template.

### Pattern 2: pkarr resolve-merge-republish (the only architectural delta)

**What:** `DhtTransport::publish_receipt` resolves the existing SignedPacket, iterates every resource record (all labels, not just receipts), re-adds each via `builder.record(rr.clone())` unless its name matches the new receipt's `_cprcpt-<this_share_ref>` label (in which case it is replaced, not appended), adds the new receipt TXT, and signs.

**When to use:** Exactly once, in `DhtTransport::publish_receipt`. MockTransport's semantics already match (per-label retain + push at `transport.rs:285-286`) — no MockTransport body change; add a confirming test instead.

**Example:** See §1 below for the full sketch with source references.

### Anti-Patterns to Avoid

- **Re-implementing `jcs()` a third time.** `record.rs:84` has a local `jcs()` helper for module-independence (see its doc comment). Phase 3 has no such constraint — call `crate::crypto::jcs_serialize(&receiptsignable)` directly. A third copy is churn.
- **Re-introducing `Error::SignatureReceipt`.** D-RS-07 explicitly reuses `Error::SignatureInner`. The D-16 unified Display invariant depends on the error-variant → display-string mapping staying closed at the existing 4 variants.
- **Clobbering other labels in `publish_receipt`.** The whole point of TRANS-03 is that a recipient's own outgoing `_cipherpost` share coexists with their incoming `_cprcpt-*` receipts. The naive "build SignedPacket with only this receipt and publish" (Phase 1's placeholder at `transport.rs:145-148`) is a regression that ROADMAP SC3 asserts against.
- **Publishing receipt before sentinel + ledger.** D-SEQ-01 is deliberate: local state must be durable first so RECV-06 holds even if publish fails. Reordering breaks the idempotence invariant.
- **Surfacing `run_receipts` to pass through `Identity`.** D-OUT-04 is emphatic: no decryption key needed for listing. Passing Identity forces a passphrase prompt, which is a UX regression on the main value prop of receipts (sender can audit without unlocking).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Canonical JSON for receipt signing | Custom alphabetical-field serializer | `crypto::jcs_serialize` (already exists) | Pitfall #3 — signature-bypass via subtle canonicalization drift. Phase 1's `CanonicalFormatter` is already test-fixture-verified. |
| Ed25519 signature byte framing | Custom 64-byte handling | `pkarr::Keypair::sign(&bytes)` returns `Signature`; `Signature::to_bytes()` + base64 STANDARD | Phase 1 used this pattern; no change. |
| SignedPacket merge | Manually extracting TXTs, rewriting DNS packet bytes | `SignedPacket::all_resource_records()` iter + `SignedPacketBuilder::record(rr.clone())` | Pkarr's own rustdoc demonstrates this as the canonical pattern for the exact use case. |
| Compare-and-swap on publish | Custom retry logic | `client.publish(&packet, Some(most_recent.timestamp()))` returns `PublishError::Concurrency(ConcurrencyError::{CasFailed,NotMostRecent,ConflictRisk})` which cipherpost simply maps to `Error::Transport` and lets D-SEQ-02 warn+degrade | D-MRG-02 deliberately does not mitigate the race in skeleton; the CAS primitive is still documented for v1.1+ adoption. |
| Nonce generation | Custom PRNG, time-derived nonces | `rand::rngs::OsRng.fill_bytes(&mut [0u8; 16])` | Pitfall #9 echo — "never roll your own AEAD" generalizes to "never roll your own entropy." `OsRng` reads `/dev/urandom` on Linux via `getrandom` syscall. |
| Label prefix filter on DHT TXT records | Custom DNS parsing | `packet.all_resource_records().filter(|rr| rr.name.to_string().starts_with("_cprcpt-"))` | Normalized DNS name strings are z32-pubkey-suffixed; `starts_with` on the leading label works because pkarr normalizes names to `<label>.<origin-z32>`. |

**Key insight:** The entire architectural surface this phase adds is a **30-line function body** (`DhtTransport::publish_receipt`) plus a **structurally-identical clone of `record.rs`** (`receipt.rs`). There is no novel cryptography, no novel DHT protocol work, no novel state machine. Every primitive already exists and is test-verified in tree.

## Runtime State Inventory

Phase 3 is not a rename/refactor/migration phase. No runtime state to inventory beyond the already-documented ledger extension (D-SEQ-04/05):

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | Phase 2's `accepted.jsonl` gains 1 new field (`receipt_published_at: Option<String>`); Phase 3 APPENDS a second ledger row per successful publish (D-SEQ-05). Existing Phase 2 rows parse cleanly via `Option`. | Code edit only — no data migration; backwards-compat by construction. |
| Live service config | None | — |
| OS-registered state | None | — |
| Secrets/env vars | None | — |
| Build artifacts | None | — |

## Common Pitfalls

### Pitfall 1: Clobbering the recipient's outgoing `_cipherpost` share
**What goes wrong:** Naive `publish_receipt` builds a SignedPacket containing only the new receipt TXT and publishes it. The pkarr packet replaces wholesale — the recipient's own outgoing share (if any) vanishes.
**Why it happens:** `pkarr::SignedPacket` is whole-packet-atomic. The builder does NOT know about any previously-published packet.
**How to avoid:** The D-MRG-01 resolve → rebuild → re-sign pattern. Explicitly iterate `most_recent.all_resource_records()` and re-add each via `builder.record(rr.clone())`. The ROADMAP SC3 test asserts this invariant.
**Warning signs:** `publish_receipt` body contains `SignedPacket::builder().txt(...).sign(...)` with no resolve step.

### Pitfall 2: Publishing the receipt BEFORE local state is durable
**What goes wrong:** Crash between publish and ledger-write leaves the receipt on the DHT but no local record of acceptance. Next `receive` decrypts again (no sentinel) and the user sees two receipts on the DHT for what they thought was one acceptance.
**Why it happens:** Ordering feels arbitrary — publish and local-state look independent.
**How to avoid:** D-SEQ-01 puts publish_receipt at step 13, strictly after step 12 (sentinel + ledger). Phase 2's sentinel-first-then-ledger ordering (at `flow.rs:468-476`) is already crash-safe; step 13 is additive on top.
**Warning signs:** `run_receive` calls `transport.publish_receipt` inside a `?`-chained expression between decrypt and `create_sentinel`.

### Pitfall 3: Propagating publish failure as an error exit code
**What goes wrong:** The recipient saw the material, the ledger recorded the acceptance, but the user gets a non-zero exit code because the DHT didn't reply. Shell scripts exit early; the user thinks receive failed.
**Why it happens:** `?`-propagation from `publish_receipt` up through `run_receive`. The natural Rust idiom.
**How to avoid:** D-SEQ-02: catch the error at the `publish_receipt` call site, print `receipt publish failed: <user_message>` to stderr, return `Ok(())`. Ledger row stays at `receipt_published_at: null`.
**Warning signs:** `transport.publish_receipt(...)?` at the step-13 call site in `run_receive`. The `?` is the bug.

### Pitfall 4: Receipt body hashes cleartext envelope bytes instead of what Phase 2's ledger captures
**What goes wrong:** Phase 2's ledger records `sha256(age_blob_bytes)` and `sha256(envelope_jcs_bytes)` (`flow.rs:552-553`). If `sign_receipt` hashes *again* at sign time, subtle differences (e.g., base64 round-trip, re-canonicalization) produce a hash that doesn't match what the sender can independently verify from the resolved OuterRecord + their own JCS serialization.
**Why it happens:** Two hashing call sites = two sources of truth.
**How to avoid:** `run_receive` step 13 passes the ledger's `ciphertext_hash` / `cleartext_hash` strings (already computed at step 12) directly into the Receipt constructor. No recomputation.
**Warning signs:** `Sha256::digest(...)` called inside `receipt::build_receipt(...)` or inside `publish_receipt`.

### Pitfall 5: `receipts` command iterator misses newly-published receipts due to pkarr cache
**What goes wrong:** `client.resolve(&pk)` returns cached packets; a just-published receipt might not be visible for seconds. Test flakes.
**Why it happens:** pkarr's resolver has two methods: `resolve` (cache-fast) and `resolve_most_recent` (fresh via DHT+relays). `DhtTransport::resolve` already uses `resolve_most_recent` (`transport.rs:113-115`). `run_receipts` must do the same.
**How to avoid:** Always use `client.resolve_most_recent(&pk)` in `run_receipts`. MockTransport tests don't exhibit this so it's a real-DHT-only gotcha — document in HUMAN-UAT.
**Warning signs:** `client.resolve(&pk)` (without `_most_recent`) anywhere in new Phase 3 transport code.

### Pitfall 6: `--share-ref` filter applied BEFORE verification
**What goes wrong:** A tampered receipt with a matching `share_ref` field is shown to the user; a corrupted receipt with a valid share_ref is included in the output before its signature fails.
**Why it happens:** Filtering early is a performance optimization reflex.
**How to avoid:** D-OUT-03: filter is applied AFTER verification. Invalid-sig receipts are counted but NEVER surfaced. Small N (2-3 receipts per key typical) means the optimization is irrelevant.
**Warning signs:** `if rr.share_ref != filter { continue; }` appearing before `verify_receipt(&r)?`.

## Code Examples

Verified patterns (all source references are to files present in-tree or in the verified pkarr-5.0.4 vendored source).

### Example 1: Receipt struct template (mirror of `record::OuterRecord`)

```rust
// src/receipt.rs (NEW body, replacing the 4-line placeholder)
//
// Mirror of src/record.rs. Phase 3 D-RS-01..07.
// Source: src/record.rs (all patterns below carry over verbatim with field-set changes only)

use crate::error::Error;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Signed form — what goes in a DNS TXT record under label `_cprcpt-<share_ref_hex>`.
/// Fields alphabetical (belt-and-suspenders for JCS stability — matches record::OuterRecord).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub accepted_at: i64,
    pub ciphertext_hash: String,
    pub cleartext_hash: String,
    pub nonce: String,
    pub protocol_version: u16,
    pub purpose: String,
    pub recipient_pubkey: String,
    pub sender_pubkey: String,
    pub share_ref: String,
    pub signature: String,    // alphabetical insertion after share_ref
}

/// Unsigned form — the exact bytes signed are `jcs(ReceiptSignable)`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSignable {
    pub accepted_at: i64,
    pub ciphertext_hash: String,
    pub cleartext_hash: String,
    pub nonce: String,
    pub protocol_version: u16,
    pub purpose: String,
    pub recipient_pubkey: String,
    pub sender_pubkey: String,
    pub share_ref: String,
}

impl From<&Receipt> for ReceiptSignable {
    fn from(r: &Receipt) -> Self {
        ReceiptSignable {
            accepted_at: r.accepted_at,
            ciphertext_hash: r.ciphertext_hash.clone(),
            cleartext_hash: r.cleartext_hash.clone(),
            nonce: r.nonce.clone(),
            protocol_version: r.protocol_version,
            purpose: r.purpose.clone(),
            recipient_pubkey: r.recipient_pubkey.clone(),
            sender_pubkey: r.sender_pubkey.clone(),
            share_ref: r.share_ref.clone(),
        }
    }
}

/// Generate a 128-bit random nonce, 32-char lowercase hex.
/// Source: D-RS-03; OsRng backed by getrandom via rand 0.8.
pub fn nonce_hex() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Sign a ReceiptSignable with the recipient's PKARR keypair.
/// Mirror of record::sign_record (record.rs:96-104).
pub fn sign_receipt(
    signable: &ReceiptSignable,
    keypair: &pkarr::Keypair,
) -> Result<String, Error> {
    let bytes = crate::crypto::jcs_serialize(signable)?;
    let sig = keypair.sign(&bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

/// Verify a Receipt's inner Ed25519 signature.
///
/// Steps (mirror record::verify_record record.rs:115-146):
///   1. Parse recipient_pubkey z-base-32 → VerifyingKey.
///   2. Decode base64 signature.
///   3. Rebuild ReceiptSignable via From impl, JCS-serialize.
///   4. verify_strict (no legacy relaxed Ed25519).
///   5. Round-trip-reserialize + byte-compare (T-01-03-02 canonicalization-bypass defense).
pub fn verify_receipt(receipt: &Receipt) -> Result<(), Error> {
    // 1. Parse recipient pubkey — note: receipts are signed by the RECIPIENT's key.
    let pk = pkarr::PublicKey::try_from(receipt.recipient_pubkey.as_str())
        .map_err(|_| Error::SignatureInner)?;
    let vk = VerifyingKey::from_bytes(pk.as_bytes())
        .map_err(|_| Error::SignatureInner)?;

    // 2. Decode signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature)
        .map_err(|_| Error::SignatureInner)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| Error::SignatureInner)?;

    // 3. Build signable, JCS-serialize
    let signable = ReceiptSignable::from(receipt);
    let bytes = crate::crypto::jcs_serialize(&signable)?;

    // 4. Verify strict
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| Error::SignatureInner)?;

    // 5. Round-trip guard — reject parse-then-reserialize mauling (record.rs:138-143).
    let parsed: ReceiptSignable = serde_json::from_slice(&bytes)
        .map_err(|_| Error::SignatureCanonicalMismatch)?;
    let round = crate::crypto::jcs_serialize(&parsed)?;
    if round != bytes {
        return Err(Error::SignatureCanonicalMismatch);
    }

    Ok(())
}
```

**Source citations:**
- Struct-pair + `From` pattern: `src/record.rs:26-64`
- `sign_record` template: `src/record.rs:96-104`
- `verify_record` template (including the T-01-03-02 round-trip guard): `src/record.rs:115-146`
- `OsRng::fill_bytes`: `[CITED: docs.rs/rand/0.8.5/rand/rngs/struct.OsRng.html]` — stable since 0.8
- `crypto::jcs_serialize` existing public helper: `[VERIFIED: src/flow.rs:565]` already called from `append_ledger_entry`

### Example 2: `DhtTransport::publish_receipt` resolve-merge-republish body

```rust
// src/transport.rs — REPLACES the current body at lines 128-153.
//
// Source: pkarr 5.0.4 rustdoc on Client::publish (client/futures.rs:47-101).
// The resolve → rebuild → re-sign pattern is literally the advertised API.

fn publish_receipt(
    &self,
    keypair: &pkarr::Keypair,
    share_ref_hex: &str,
    receipt_json: &str,
) -> Result<(), Error> {
    use pkarr::{SignedPacket, dns::{Name, rdata::{RData, TXT}}};

    eprintln!("Publishing receipt to DHT..."); // TRANS-05

    let receipt_label = format!("{}{}", crate::DHT_LABEL_RECEIPT_PREFIX, share_ref_hex);
    let new_name: Name<'_> = receipt_label
        .as_str()
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;
    let new_txt: TXT<'_> = receipt_json
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;

    // 1. Resolve most recent — may be None if recipient has never published.
    let pk = keypair.public_key();
    let existing = self.client.resolve_most_recent(&pk);

    // 2. Rebuild builder from existing records, replacing any same-label entry.
    let mut builder = SignedPacket::builder();
    let mut cas: Option<pkarr::Timestamp> = None;
    if let Some(ref packet) = existing {
        cas = Some(packet.timestamp());
        for rr in packet.all_resource_records() {
            // Skip any existing TXT under exactly this receipt's label — the
            // new receipt supersedes it. pkarr normalizes names to
            // <label>.<origin-z32>, so compare by leading label.
            let rr_name = rr.name.to_string();
            if matches_receipt_label(&rr_name, &receipt_label, &pk.to_z32()) {
                continue;
            }
            builder = builder.record(rr.clone());
        }
    }
    builder = builder.txt(new_name, new_txt, 300); // D-MRG-03: 300s TTL

    // 3. Sign (D-MRG-06: 1000-byte cap surfaces as SignedPacketBuildError::PacketTooLarge)
    let packet = match builder.sign(keypair) {
        Ok(p) => p,
        Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) => {
            return Err(Error::WireBudgetExceeded {
                encoded,
                budget: crate::flow::WIRE_BUDGET_BYTES,
                plaintext: 0, // receipt path (D-MRG-06 convention)
            });
        }
        Err(other) => return Err(Error::Transport(Box::new(other))),
    };

    // 4. Publish with optional CAS. D-MRG-02: do not retry on race; let
    //    D-SEQ-02 warn+degrade handle the failure.
    self.client
        .publish(&packet, cas)
        .map_err(map_pkarr_publish_error)?;

    Ok(())
}

/// Returns true if a DNS name string (normalized to `<label>.<z32>.`) matches
/// the given receipt label. pkarr 5.0.4 normalization: signed_packet.rs:256-271.
fn matches_receipt_label(rr_name: &str, receipt_label: &str, origin_z32: &str) -> bool {
    // Fully-qualified form pkarr writes out — strip trailing dot if present.
    let trimmed = rr_name.trim_end_matches('.');
    trimmed == format!("{}.{}", receipt_label, origin_z32)
        || trimmed == receipt_label
}
```

**Source citations:**
- `SignedPacket::all_resource_records()`: `[VERIFIED: pkarr-5.0.4/src/signed_packet.rs:460-462]` `pub fn all_resource_records(&self) -> impl Iterator<Item = &ResourceRecord<'_>> { self.packet().answers.iter() }`
- `SignedPacketBuilder::record(rr)`: `[VERIFIED: pkarr-5.0.4/src/signed_packet.rs:30-34]` `pub fn record(mut self, record: ResourceRecord<'_>) -> Self { self.records.push(record.into_owned()); self }`
- `SignedPacketBuilder::txt(name, txt, ttl)`: `[VERIFIED: pkarr-5.0.4/src/signed_packet.rs:95-97]`
- `resolve_most_recent(&pk) -> Option<SignedPacket>`: `[VERIFIED: pkarr-5.0.4/src/client/blocking.rs:144-146]`
- `client.publish(&packet, cas: Option<Timestamp>)`: `[VERIFIED: pkarr-5.0.4/src/client/blocking.rs:117-123]`
- Name normalization rule: `[VERIFIED: pkarr-5.0.4/src/signed_packet.rs:256-271]` — names are normalized to `<label>.<origin-z32>` relative to the keypair's pubkey.
- The pattern itself is **directly demonstrated** in pkarr's own rustdoc at `pkarr-5.0.4/src/client/blocking.rs:47-101` ("To mitigate the risk of lost updates, you should call the Self::resolve_most_recent method then start authoring the new SignedPacket based on the most recent as in the following example").

### Example 3: `run_receipts` fetch + filter + verify + render

```rust
// src/flow.rs — NEW function (RCPT-02; D-OUT-01..04).
//
// No Identity parameter — receipts listing is passphrase-free (D-OUT-04).

pub fn run_receipts(
    transport: &dyn Transport,
    from_z32: &str,
    share_ref_filter: Option<&str>,
    json_mode: bool,
) -> Result<(), Error> {
    // Resolve the recipient's SignedPacket. We need direct pkarr access here
    // for the label-prefix iteration — the Transport trait's `resolve` is
    // specific to the outer-share label. A small transport-layer helper
    // `resolve_all_cprcpt(z32)` could wrap this; planner's call.
    //
    // For MockTransport testing, use MockTransport::resolve_all_txt (already
    // exposed at transport.rs:225-232) and filter in this function.

    let candidate_receipts = fetch_receipt_candidates(transport, from_z32)?;
    if candidate_receipts.is_empty() {
        return Err(Error::NotFound);  // exit 5 (D-OUT-03)
    }

    // Parse + verify each candidate. D-OUT-03 exit-code taxonomy:
    //   at-least-1 valid           → 0
    //   zero valid + some invalid → 3 (SignatureInner — D-16 unified)
    //   zero valid + only malformed → 1
    let mut valid: Vec<Receipt> = Vec::new();
    let mut malformed = 0usize;
    let mut invalid_sig = 0usize;
    for raw_json in &candidate_receipts {
        let parsed: Receipt = match serde_json::from_str(raw_json) {
            Ok(r) => r,
            Err(_) => { malformed += 1; continue; }
        };
        if let Err(_) = verify_receipt(&parsed) {
            invalid_sig += 1;
            continue;
        }
        valid.push(parsed);
    }

    eprintln!(
        "fetched {} receipt(s); {} valid{}{}",
        candidate_receipts.len(),
        valid.len(),
        if malformed > 0 { format!(", {} malformed", malformed) } else { String::new() },
        if invalid_sig > 0 { format!(", {} invalid-signature", invalid_sig) } else { String::new() },
    );

    // D-OUT-02: --share-ref filter applied AFTER verification.
    if let Some(filter) = share_ref_filter {
        valid.retain(|r| r.share_ref == filter);
    }

    // Exit-code taxonomy: let Ok() on main → 0; explicit Err below maps to 3/1/5.
    if valid.is_empty() {
        if invalid_sig > 0 {
            return Err(Error::SignatureInner); // exit 3
        }
        if malformed > 0 {
            return Err(Error::Config("all receipts malformed".into())); // exit 1
        }
        return Err(Error::NotFound); // exit 5 (was non-empty before filter; share_ref didn't match)
    }

    if json_mode {
        // Planner discretion: strict JCS for stability OR to_string_pretty for UX.
        let out = serde_json::to_string_pretty(&valid)
            .map_err(|e| Error::Config(format!("json encode: {}", e)))?;
        println!("{}", out);
    } else {
        render_receipts_table(&valid, share_ref_filter.is_some() && valid.len() == 1)?;
    }

    Ok(())
}

/// D-OUT-01 table (multi-row) or D-OUT-02 detail (single-row, audit).
fn render_receipts_table(receipts: &[Receipt], audit_detail: bool) -> Result<(), Error> {
    if audit_detail {
        let r = &receipts[0];
        println!("share_ref:          {}", r.share_ref);
        println!("sender_pubkey:      {}", r.sender_pubkey);
        println!("recipient_pubkey:   {}", r.recipient_pubkey);
        println!("accepted_at:        {} UTC ({} local)",
            format_unix_as_iso_utc(r.accepted_at),
            format_unix_as_iso_local(r.accepted_at),
        );
        println!("purpose:            \"{}\"", r.purpose.chars().filter(|c| !c.is_control()).collect::<String>());
        println!("ciphertext_hash:    {}", r.ciphertext_hash);
        println!("cleartext_hash:     {}", r.cleartext_hash);
        println!("nonce:              {}", r.nonce);
        println!("protocol_version:   {}", r.protocol_version);
        println!("signature:          {}", r.signature);
        return Ok(());
    }
    // Multi-row table (D-OUT-01 columns)
    println!("{:<16}  {:<32}  {:<40}  {}", "share_ref", "accepted_at", "purpose", "recipient_fp");
    for r in receipts {
        let (fp, _) = sender_openssh_fingerprint_and_z32(&r.recipient_pubkey)?;
        let purpose_display = truncate_purpose(&r.purpose, 40);
        let utc = format_unix_as_iso_utc(r.accepted_at);
        println!(
            "{:<16}  {:<32}  {:<40}  {}",
            &r.share_ref[..16], utc, purpose_display, fp,
        );
    }
    Ok(())
}

fn truncate_purpose(p: &str, max: usize) -> String {
    let stripped: String = p.chars().filter(|c| !c.is_control()).collect();
    if stripped.len() <= max { stripped } else {
        format!("{}…", &stripped[..max.saturating_sub(1)])
    }
}
```

**Source citations:**
- `format_unix_as_iso_utc` / `format_unix_as_iso_local` reusable from Phase 2: `[VERIFIED: src/flow.rs:742-761]`
- `sender_openssh_fingerprint_and_z32`: `[VERIFIED: src/flow.rs:622-636]` (OpenSSH fp compute exists; relabel from "sender" to generic usage — or wrap a new `openssh_fingerprint_from_z32` alias)
- `MockTransport::resolve_all_txt`: `[VERIFIED: src/transport.rs:225-232]` — test helper already exposes the raw `(label, rdata)` list

### Example 4: Fetch candidates — label-prefix filter shape

```rust
// Helper in src/flow.rs (or a new thin src/transport.rs method — planner's call).
//
// Two paths: real DhtTransport needs direct pkarr access; MockTransport already
// exposes resolve_all_txt. Planner may introduce a Transport trait method
// `resolve_all_cprcpt(&self, pubkey_z32) -> Result<Vec<String>, Error>` to
// avoid the downcast/Any dance.

fn fetch_receipt_candidates(
    transport: &dyn Transport,
    from_z32: &str,
) -> Result<Vec<String>, Error> {
    // Preferred: add a trait method. Below is the DhtTransport-internal shape
    // the trait method would wrap.
    //
    // let pk = pkarr::PublicKey::try_from(from_z32).map_err(|_| Error::NotFound)?;
    // let packet = client.resolve_most_recent(&pk).ok_or(Error::NotFound)?;
    // let origin = pk.to_z32();
    // let target_prefix = crate::DHT_LABEL_RECEIPT_PREFIX; // "_cprcpt-"
    //
    // let mut out = Vec::new();
    // for rr in packet.all_resource_records() {
    //     let name = rr.name.to_string();
    //     let trimmed = name.trim_end_matches('.');
    //     // After pkarr name normalization, labels are either "<label>" (at-origin)
    //     // or "<label>.<origin-z32>". Both start with the bare label.
    //     if trimmed.starts_with(target_prefix) {
    //         if let Some(json) = extract_txt_string(&rr.rdata) {
    //             out.push(json);
    //         }
    //     }
    // }
    // Ok(out)
    unimplemented!("sketch only")
}
```

**Why a new trait method is cleanest:** `Transport::resolve` is specific to the outer-share label; adding `Transport::resolve_all_cprcpt(pubkey_z32) -> Result<Vec<String>, Error>` keeps all DHT-access through the trait seam so MockTransport can supply test data without a downcast. `MockTransport::resolve_all_txt` (`src/transport.rs:225-232`) already has the semantics; one thin filter wrapper adapts.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Publish a fresh SignedPacket containing only the new TXT (Phase 1 placeholder at `src/transport.rs:135-152`) | resolve → rebuild via `all_resource_records()` → re-add via `builder.record()` → sign + publish with optional CAS | Phase 3 (TRANS-03) | Existing labels under recipient's key (outgoing `_cipherpost` share + other receipts) coexist; prior clobber was a skeleton placeholder. |
| pkarr `publish(&packet)` (no CAS) | `client.publish(&packet, cas: Option<Timestamp>)` where CAS is `Some(most_recent.timestamp())` | pkarr 5.0.3 `(ConcurrencyError enum)` — available but cipherpost does not use it in skeleton (D-MRG-02) | Future v1.1+ can enable CAS for retry loop without protocol change. |
| `record::jcs()` module-local helper | `crypto::jcs_serialize` public helper | Phase 1 already consolidated on the public helper for new code | Phase 3 should NOT copy `record.rs`'s local `jcs()` function — use the public helper. |

**Deprecated/outdated:**
- Nothing deprecated. All Phase 1/2 decisions stand.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Per-receipt JSON body is ~220-260 bytes (10 fields, 64-char hex hashes, 88-char b64 sig, 52-char z32 pubkeys). | §2 wire-budget estimate | If larger in practice, receipts-per-key ceiling drops from ~3 to ~2. Planner can measure exact size with a committed fixture test. |
| A2 | pkarr 5.0.4 `all_resource_records()` + `builder.record()` is API-stable between 5.0.3 (the declared dep) and 5.0.4 (what `Cargo.lock` resolves to). | §1 | If pkarr pins a strict 5.0.3-only path, prototype still works — this API existed in 5.0.3 (same module), confirmed by searching pkarr GitHub 5.0.3 tag. Recommend confirming with `cargo update -p pkarr --precise 5.0.3` before committing. |
| A3 | `rand::rngs::OsRng.fill_bytes` is fallible-free (doesn't return `Result`) in the exposed cipherpost code path. | §4 nonce gen | rand 0.8's `OsRng: RngCore` implements infallible `fill_bytes`; only `try_fill_bytes` is fallible. Verified by convention; planner should double-check via `cargo doc --open -p rand`. |

**If this table has 3 entries:** All three are low-risk — each has a verification path the planner can run in under 5 minutes.

## Open Questions

1. **Where does `fetch_receipt_candidates` live — new trait method or downcast?**
   - What we know: Trait method (`Transport::resolve_all_cprcpt`) is cleanest; MockTransport's `resolve_all_txt` already supplies the underlying data. DhtTransport would be a ~10-line body wrapping `resolve_most_recent` + label-prefix filter.
   - What's unclear: Planner may prefer to call `resolve_most_recent` directly from `run_receipts` by downcasting `&dyn Transport` — less clean.
   - Recommendation: **Add a new `Transport` trait method.** The trait signature is still small, and the test harness stays clean. Not a protocol change.

2. **Does `run_receipts` need the caller's own z32 for any purpose?**
   - What we know: D-OUT-04 says no Identity. The `from` arg is the RECIPIENT's z32 (`--from <recipient-z32>` per CLI). Sender's own identity is not needed for listing.
   - What's unclear: If the planner wants to verify that the fetched receipts actually have `recipient_pubkey == from_z32`, that's a cross-check without Identity — already captured in verify_receipt (which verifies using `recipient_pubkey` from the Receipt itself). No extra input needed.
   - Recommendation: Keep `run_receipts` Identity-free per D-OUT-04.

3. **Single Transport trait method vs split (publish_receipt + resolve_receipts)?**
   - What we know: Current `Transport` trait has 3 methods. Adding `resolve_all_cprcpt` makes 4. This is still small.
   - Recommendation: **Add the 4th method.** Keeps the architectural story consistent (all DHT access through the trait).

4. **`--json` output: strict JCS or pretty?**
   - What we know: Claude's Discretion per CONTEXT.md. Display-only (not signed).
   - Recommendation: **`serde_json::to_string_pretty`** for UX. JCS has no cross-platform value here since `verify_receipt` works on the resolved DHT bytes, not the `--json` output.

## Environment Availability

Skipping — Phase 3 has no external tool dependencies beyond what Phases 1 & 2 already use. All dependencies (`pkarr`, `rand`, `base64`, `serde_canonical_json`, `chrono`, `dialoguer`, etc.) are Cargo-managed and already in `Cargo.lock`. The only "environment" needed is:

- A running Mainline DHT node network (for the real-DHT HUMAN-UAT, D-IT-02). **Available: ✓** — same dependency Phase 2 already exercised successfully during Plan 02-03's HUMAN-UAT (per STATE.md line 64 "Test 2 UAT pass — real-DHT cross-identity round trip").

## Validation Architecture

> **Note:** `config.json` has `workflow.nyquist_validation: false`. This section is advisory only and not a formal test spec. Include anyway to inform the planner of natural verification loops.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` + `serial_test` (for env-var mutation ordering) + `assert_cmd` + `predicates` (for CLI subprocess tests) + `tempfile::TempDir` + `proptest` (available, not required Phase 3) |
| Config file | `Cargo.toml` `[[test]]` blocks (Phase 3 adds 5 new `[[test]]` entries, 3 of which require-feature `["mock"]`) |
| Quick run command | `cargo test --features mock --test phase3_end_to_end_a_sends_b_receipt -- --nocapture` |
| Full suite command | `cargo test --features mock` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TRANS-03 | publish_receipt preserves other TXT records | integration | `cargo test --features mock --test phase3_coexistence_b_self_share_and_receipt` | ❌ Wave 2 |
| RCPT-01 | Receipt built+signed+published after acceptance | integration | `cargo test --features mock --test phase3_end_to_end_a_sends_b_receipt` | ❌ Wave 2 |
| RCPT-02 | `receipts --from --share-ref` works | integration | `cargo test --features mock --test phase3_share_ref_filter` | ❌ Wave 2 |
| RCPT-03 | End-to-end A→B→receipt round trip | integration | `cargo test --features mock --test phase3_end_to_end_a_sends_b_receipt` | ❌ Wave 2 |
| — | sign_receipt + verify_receipt round trip (unit) | unit | `cargo test --test phase3_receipt_sign_verify` | ❌ Wave 1 |
| — | tampered-receipt rejection | unit | `cargo test --test phase3_receipt_sign_verify::tampered_*` | ❌ Wave 1 |
| — | Receipt JCS canonical form fixture | unit | `cargo test --test phase3_receipt_canonical_form` | ❌ Wave 1 |

### Sampling Rate
- **Per task commit:** `cargo test --features mock --test phase3_*`
- **Per wave merge:** `cargo test --features mock` (full suite)
- **Phase gate:** Full suite green + HUMAN-UAT script passes on real DHT.

### Wave 0 Gaps
- [ ] `tests/phase3_receipt_sign_verify.rs` — unit round trip + tampered + D-16 Display unification
- [ ] `tests/phase3_receipt_canonical_form.rs` — JCS fixture (matches `outer_record_canonical_form.rs` pattern)
- [ ] `tests/fixtures/receipt_signable.bin` — committed JCS bytes
- [ ] `tests/phase3_end_to_end_a_sends_b_receipt.rs` — D-IT-01 test 1
- [ ] `tests/phase3_coexistence_b_self_share_and_receipt.rs` — D-IT-01 test 2
- [ ] `tests/phase3_share_ref_filter.rs` — D-IT-01 test 3

## Security Domain

> `security_enforcement` status absent from config → treat as enabled. Include.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | partial | Phase 3 does NOT add new authn — receipts are signed by recipient's Ed25519 (same key as identity); verification via `ed25519_dalek::VerifyingKey::verify_strict` mirror of `record::verify_record`. |
| V3 Session Management | no | No sessions. Receipts are stateless artifacts on DHT. |
| V4 Access Control | no | DHT is public; receipts are public by design (D-RS-06, CONTEXT.md "Receipts are fully public"). |
| V5 Input Validation | yes | `receipts --from <z32>` must validate z32 input (52 chars + z-base-32 alphabet) before DHT call — reuse `pkarr::PublicKey::try_from`. `--share-ref <hex>` must validate 32-char lowercase hex — reuse `SHARE_REF_HEX_LEN` + `is_ascii_hexdigit` check already present in `ShareUri::parse` at `src/lib.rs:77-84`. Tampered JSON in a DHT TXT is caught by `serde_json::from_str` + `verify_receipt`. |
| V6 Cryptography | yes | Signing = `pkarr::Keypair::sign` (Ed25519 wrapper); verification = `VerifyingKey::verify_strict` (no legacy relaxed Ed25519). JCS via `serde_canonical_json 1.0.0`. **No direct chacha20poly1305** (receipts are unencrypted — public by design). **No new HKDF call-site** (receipts use Ed25519 identity key directly, no derivation). |

### Known Threat Patterns for Rust + pkarr + Ed25519 stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Attacker publishes a forged receipt claiming a different share_ref under their own key | Spoofing | `verify_receipt` checks `recipient_pubkey` matches the key that signed it; sender checks the receipt's `sender_pubkey` matches their own z32 before trusting. A receipt under an attacker's DHT entry can't forge a real recipient's signature. |
| Receipt canonicalization bypass (parse-then-reserialize mauling) | Tampering | D-RS-07 round-trip-reserialize + byte-compare guard (T-01-03-02, mirror of `record.rs:138-143`). |
| Error-oracle on receipt verify (distinguishes "bad sig" from "bad canonicalization" from "bad pubkey") | Information Disclosure | D-16 unified Display: all `Error::SignatureInner` / `SignatureCanonicalMismatch` / `SignatureTampered` → `"signature verification failed"`. Already enforced in `error.rs:27-37`. |
| DHT publish race (two receipts under same key concurrently, one wins) | Tampering | D-MRG-02 documents, does not mitigate in skeleton. Phase 4 THREAT-MODEL.md treatment. pkarr's `ConcurrencyError::{CasFailed,NotMostRecent,ConflictRisk}` is available for v1.1+ retry loops. |
| Wire-budget exhaustion DoS (malicious 3rd party spams receipts under recipient's key) | Denial of Service | Only the recipient can sign under their key (pkarr SignedPacket model) — spam from a 3rd party is not possible. Self-DoS by recipient themselves is D-MRG-06: publish fails cleanly with `WireBudgetExceeded`, warn + degrade. |
| Tampered DHT packet (attacker replaces recipient's SignedPacket on a cached relay) | Tampering | Outer PKARR signature verified inside `pkarr::ClientBlocking::resolve_most_recent` — Phase 1 trust boundary applies unchanged. Inner Receipt Ed25519 sig is an independent defense. |
| Purpose field contains control chars / lookalikes leaked into table display | Information Disclosure (UI) | D-OUT-01 truncation + ctrl-char re-strip at display time (defense-in-depth over the send-time strip in PAYL-04/D-WIRE-05). Same `chars().filter(!is_control())` idiom as Phase 2 acceptance screen at `flow.rs:788`. |

## Project Constraints (from CLAUDE.md)

Actionable directives extracted from `./CLAUDE.md` for planner compliance:

- **No servers.** Mainline DHT only. Receipt publish is via `pkarr::ClientBlocking`, no HTTP/relay/API. ✓ Phase 3 obeys.
- **Canonical JSON = RFC 8785 (JCS) via `serde_canonical_json` 1.0.0.** Never raw `serde_json::to_vec` on anything signed. ✓ `sign_receipt`/`verify_receipt` go through `crypto::jcs_serialize`.
- **HKDF info strings: `cipherpost/v1/<context>`, never empty/None.** ✓ Phase 3 adds zero new HKDF call-sites (receipts sign with Ed25519 identity key directly).
- **`chacha20poly1305` only via `age` — no direct calls.** ✓ Phase 3 has no encryption (receipts are unencrypted by design).
- **`#[derive(Debug)]` banned on key-holding structs.** ✓ `Receipt`/`ReceiptSignable` contain NO secrets. The `&pkarr::Keypair` passed to `sign_receipt` is a secret holder — but `Keypair` already has a manual Debug impl (verified in Phase 1). No new Debug-leak risk.
- **All sig-verify failures produce D-16 unified message `"signature verification failed"` → exit 3.** ✓ `verify_receipt` returns `Error::SignatureInner` / `SignatureCanonicalMismatch`, both of which already have the unified Display.
- **No direct `tokio` dep; use `pkarr::ClientBlocking`.** ✓ `DhtTransport` already uses blocking; Phase 3 adds no new async code.
- **`ed25519-dalek =3.0.0-pre.5` exact pin.** ✓ Phase 3 uses the same pin; no version bump.
- **Identity path = `~/.cipherpost/`, mode 0600.** ✓ Phase 3 does not touch identity storage. Ledger extension stays in `~/.cipherpost/state/` at mode 0600 (Phase 2 discipline).
- **Default TTL = 24h.** ✓ Phase 3 inherits.
- **Every key-holding struct uses Zeroize / SecretBox.** ✓ Receipt carries no key bytes; nonce is public.

## Sources

### Primary (HIGH confidence)
- `pkarr` 5.0.4 vendored source at `/home/john/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pkarr-5.0.4/src/`:
  - `signed_packet.rs:460-462` — `all_resource_records()` signature + body
  - `signed_packet.rs:30-34` — `SignedPacketBuilder::record(rr)` signature + body
  - `signed_packet.rs:95-97` — `SignedPacketBuilder::txt(name, txt, ttl)` signature
  - `signed_packet.rs:123-137` — `SignedPacketBuilder::sign(keypair)` and `build(keypair)` (both return `Result<SignedPacket, SignedPacketBuildError>`)
  - `signed_packet.rs:250-292` — `SignedPacket::new` internals (confirms 1000-byte enforcement at `signed_packet.rs:276`)
  - `signed_packet.rs:751-759` — `SignedPacketBuildError::PacketTooLarge(usize)` variant
  - `client/blocking.rs:117-123` — `ClientBlocking::publish(&self, signed_packet, cas: Option<Timestamp>) -> Result<(), PublishError>`
  - `client/blocking.rs:144-146` — `ClientBlocking::resolve_most_recent(&self, public_key) -> Option<SignedPacket>`
  - `client/blocking.rs:47-101` — **canonical rustdoc example of the resolve-merge-republish pattern** cipherpost is implementing
  - `client.rs:606-624` — `ConcurrencyError::{ConflictRisk, NotMostRecent, CasFailed}` enum (available but unused in skeleton per D-MRG-02)
- Phase 1 & 2 in-tree source (all line numbers verified current):
  - `src/record.rs:26-146` — the struct-pair + sign/verify template `receipt.rs` mirrors
  - `src/transport.rs:128-153` — current placeholder `DhtTransport::publish_receipt` body (to be replaced)
  - `src/transport.rs:271-288` — MockTransport `publish_receipt` already append-preserving per-label
  - `src/flow.rs:398-479` — `run_receive` with explicit STEP 1..12 comments (step 13 slots in at line ~478)
  - `src/flow.rs:533-578` — `LedgerEntry` struct + `append_ledger_entry` helper
  - `src/flow.rs:125-147` — `check_already_accepted` with 2-rows-per-share last-wins semantics
  - `src/flow.rs:742-761` — `format_unix_as_iso_utc` + `format_unix_as_iso_local` reusable time formatters
  - `src/flow.rs:622-636` — `sender_openssh_fingerprint_and_z32` reusable OpenSSH-FP helper
  - `src/lib.rs:38` — `DHT_LABEL_RECEIPT_PREFIX = "_cprcpt-"` constant
  - `src/cli.rs:81-89` — `Command::Receipts { from, share_ref }` final clap shape
  - `src/main.rs:216-219` — current Receipts stub (to be replaced)
  - `src/main.rs:94-96` — keypair reconstruction pattern `pkarr::Keypair::from_secret_key(&id.signing_seed())` (move into Receive branch)
  - `Cargo.toml:44` — `rand = "0.8"` already a direct dep (nonce gen)

### Secondary (HIGH confidence)
- cipherpost planning docs (2026-04-21):
  - `.planning/PROJECT.md` — lock-in constraints, default TTL 24h decision
  - `.planning/REQUIREMENTS.md` — TRANS-03, RCPT-01, RCPT-02, RCPT-03 full text
  - `.planning/ROADMAP.md` §"Phase 3" — 4 success criteria
  - `.planning/research/SUMMARY.md` §"Research Flags for Phase Planning" Phase 8 — explicit ask this phase owns
  - `.planning/research/PITFALLS.md` #5 (receipt only after verify + acceptance), #10 (DHT unreliability budgeted), #12 (purpose sender-attested)
  - `.planning/research/ARCHITECTURE.md` §4.4 (receipt publish + fetch) and §"Components 6-7"
  - `.planning/phases/02-send-receive-and-explicit-acceptance/02-CONTEXT.md` — carry-forward ledger format, D-RECV-01 step order
  - `.planning/phases/02-send-receive-and-explicit-acceptance/02-RESEARCH.md` — Phase 2 stack confirmation
  - `.planning/phases/02-send-receive-and-explicit-acceptance/02-PATTERNS.md` — struct-pair + JCS + sign/verify pattern already instantiated for `record.rs`
  - `.planning/STATE.md` — pkarr API quirks learned in Phase 1-2 (`resolve_most_recent` returns `Option` not `Result`; `PublishError::Query(QueryError::Timeout)` is the enum shape; 550-byte blob is worst-case for outer share)

### Tertiary (MEDIUM confidence — worth flagging for prototype if any part looks wrong at plan time)
- None. All primary claims are source-verified.

## Metadata

**Confidence breakdown:**
- Standard stack (no new deps; reuse existing): HIGH — verified by enumerating Phase 3 needs against `Cargo.toml:21-48`
- pkarr API shape for resolve-merge-republish: HIGH — verified from pkarr-5.0.4 source; the exact pattern is demonstrated in pkarr's own rustdoc
- Receipt struct schema mirror of `record.rs`: HIGH — pattern already exists in-tree, verified line-by-line
- Wire-budget accumulation estimate: MEDIUM-HIGH — estimate is derivation-based; exact ceiling depends on JSON encoding nuances, best confirmed by a committed fixture test in Wave 1
- Concurrent-publish empirical behavior: HIGH — pkarr exposes a typed `ConcurrencyError` enum; Phase 4 THREAT-MODEL.md can quote this verbatim

**Research date:** 2026-04-21
**Valid until:** 2026-05-21 (30 days — stack is stable, no upstream releases pending)

---

## §1. pkarr 5.0.3/5.0.4 SignedPacket Merge API (resolves D-MRG-04 research flag)

The exact methods the resolve-merge-republish loop needs:

| API | Signature | Location | Status |
|-----|-----------|----------|--------|
| `SignedPacket::all_resource_records()` | `pub fn all_resource_records(&self) -> impl Iterator<Item = &ResourceRecord<'_>>` | `pkarr-5.0.4/src/signed_packet.rs:460-462` | **Exists. Returns ALL labels.** |
| `SignedPacket::resource_records(name)` | `pub fn resource_records(&self, name: &str) -> impl Iterator<Item = &ResourceRecord<'_>>` | `signed_packet.rs:434-449` | Filters by exact name OR `*` wildcard. Does NOT support `_cprcpt-*` prefix glob for our use. |
| `SignedPacketBuilder::record(rr)` | `pub fn record(mut self, record: ResourceRecord<'_>) -> Self` | `signed_packet.rs:30-34` | **Accepts a full `ResourceRecord` — the pass-through the merge loop needs.** |
| `SignedPacketBuilder::txt(name, txt, ttl)` | `pub fn txt(self, name: Name<'_>, text: TXT<'_>, ttl: u32) -> Self` | `signed_packet.rs:95-97` | Per-record TXT add. Use for the NEW receipt TXT. |
| `SignedPacketBuilder::sign(keypair)` | `pub fn sign(self, keypair: &Keypair) -> Result<SignedPacket, SignedPacketBuildError>` | `signed_packet.rs:131-137` | Signs and enforces 1000-byte budget internally. |
| `ClientBlocking::resolve_most_recent(&pk)` | `pub fn resolve_most_recent(&self, public_key: &PublicKey) -> Option<SignedPacket>` | `client/blocking.rs:144-146` | Returns `Option`, not `Result`. (Already used in Phase 1 `DhtTransport::resolve` at `transport.rs:113-115`.) |
| `ClientBlocking::publish(&packet, cas)` | `pub fn publish(&self, signed_packet: &SignedPacket, cas: Option<Timestamp>) -> Result<(), PublishError>` | `client/blocking.rs:117-123` | CAS slot is `Option<Timestamp>` — pass `Some(most_recent.timestamp())` for concurrency-safe publish, `None` for unconditional. |

**The canonical pattern is literally demonstrated in pkarr's rustdoc** (`client/blocking.rs:47-101`):

```rust
// From pkarr 5.0.4 Client::publish rustdoc — the advertised API usage:
let (signed_packet, cas) = if let Some(most_recent) = client
    .resolve_most_recent(&keypair.public_key())
{
    let mut builder = SignedPacket::builder();
    // 1. Optionally inherit all or some of the existing records.
    for record in most_recent.all_resource_records() {
        let name = record.name.to_string();
        if name != "foo" && name != "sercert" {  // replace same-label instead
            builder = builder.record(record.clone());
        }
    };
    // 2. Optionally add more new records.
    let signed_packet = builder
        .txt("foo".try_into()?, "bar".try_into()?, 30)
        .sign(&keypair)?;
    (
        signed_packet,
        // 3. Use the most recent SignedPacket::timestamp as a CAS.
        Some(most_recent.timestamp())
    )
} else {
    (
        SignedPacket::builder()
            .txt("foo".try_into()?, "bar".try_into()?, 30)
            .a("secret".try_into()?, 42.into(), 30)
            .sign(&keypair)?,
        None
    )
};
client.publish(&signed_packet, cas)?;
```

**Name normalization subtlety:** pkarr normalizes resource record names to `<label>.<origin-z32>` relative to the signing keypair's public key (`signed_packet.rs:256-271`). When iterating existing records from `most_recent.all_resource_records()`, `rr.name.to_string()` returns the fully-qualified form. The comparison to decide "skip this record because we're replacing it" must account for this — see `matches_receipt_label` helper in Example 2.

**Source code sketch for `DhtTransport::publish_receipt` body:** See §Code Examples → Example 2 above (complete body with error mapping).

**Conclusion on D-MRG-04:** The planner does NOT need a prototype spike. The API is confirmed present, stable, and the usage pattern is advertised in pkarr's own documentation. The research flag is resolved as "Yes, all required methods exist with the expected shape. Proceed to implementation."

---

## §2. SignedPacket Wire-Budget Under Accumulation

**Budget:** `encoded_dns_packet ≤ 1000 bytes` enforced at `pkarr-5.0.4/src/signed_packet.rs:276-278`. Beyond the DNS packet, the full SignedPacket wrap adds 32 (pubkey) + 64 (sig) + 8 (timestamp) = 104 bytes framing; `SignedPacket::MAX_BYTES = 1104`.

**Per-receipt cost breakdown (rough, JSON compact form):**

| Field | Typical bytes | Notes |
|-------|---------------|-------|
| `"accepted_at":1700000000` | 24 | i64 unix seconds |
| `"ciphertext_hash":"<64-hex>"` | 84 | fixed width |
| `"cleartext_hash":"<64-hex>"` | 83 | fixed width |
| `"nonce":"<32-hex>"` | 44 | fixed width |
| `"protocol_version":1` | 22 | |
| `"purpose":"<attested string>"` | 20-250 | **variable; dominates variance** |
| `"recipient_pubkey":"<52-z32>"` | 75 | fixed width |
| `"sender_pubkey":"<52-z32>"` | 72 | fixed width |
| `"share_ref":"<32-hex>"` | 48 | fixed width |
| `"signature":"<88-b64>"` | 102 | fixed width |
| JSON punctuation + braces | 10 | |
| **Receipt JSON subtotal** | **~590 bytes for 20-char purpose; ~820 bytes for 250-char purpose** | |
| DNS label `_cprcpt-<32-hex>.<52-z32>` | ~93 | TXT record name normalized |
| DNS framing (TYPE, CLASS, TTL, RDLENGTH, length prefixes) | ~15 | |
| TXT CharacterString chunking overhead | ~3 per 255B chunk (so 2-4 bytes for our size) | |
| **Per-receipt packet cost** | **~700-930 bytes** | |

**Wait — that's a concern.** A single receipt with a longish purpose can already approach the 1000-byte DNS packet budget.

**Recomputed with 20-char purpose (reasonable skeleton default):** ~700 bytes per receipt record. Add 100 bytes of packet framing overhead (DNS packet header + answer section wrapper) → ~800 bytes. Leaves ~200 bytes for a SECOND record — too tight to fit even a minimal outgoing `_cipherpost` share.

**Recomputed with outer-share-present-at-recipient-key scenario (ROADMAP SC3):**
- B's outgoing `_cipherpost` share (minimum ~700 bytes encoded per `signed_packet_budget.rs`'s 550-byte blob test)
- PLUS one `_cprcpt-*` receipt (~700 bytes)
- TOTAL: ~1400 bytes — **will exceed 1000-byte budget.**

**This is a material finding.** The planner should consider:

1. **ROADMAP SC3 ("B's outgoing share coexists with receipt") may fail the wire-budget check in real cases.** The test must use a minimized outgoing-share payload (3-byte plaintext like `b"tok"` as Phase 2's `share_round_trip` already does) to leave room for the receipt.

2. **Typical real-world ceiling:** Approximately **1 receipt per recipient PKARR key** with moderate purposes, OR about **2-3 receipts per key** if purposes are minimal (≤10 chars) and no outgoing `_cipherpost` share coexists. This is below the PITFALLS traffic estimate of 1-100 shares/week/user in the absence of receipt rotation.

3. **The `WireBudgetExceeded { plaintext: 0, ... }` error path WILL fire in practice.** D-MRG-06's "deferred rotation/pruning" note is load-bearing; the planner should be explicit about this in the HUMAN-UAT script: "if this is your Nth receipt, publish may fail; this is expected skeleton behavior."

4. **Budget mitigation within Phase 3's scope:** None is in scope (rotation is deferred). The plan should surface the limit via good error messaging and the phase-4 THREAT-MODEL.md section can discuss GC strategies for v1.0.

**Recommendation for planner:** Add a small integration test `phase3_wire_budget_overflow.rs` that accumulates receipts until the packet overflows and asserts the `WireBudgetExceeded { plaintext: 0, encoded: N, budget: 1000 }` error fires with `N > 1000`. This explicitly documents the behavior the user will see, and is cheap (same MockTransport harness).

---

## §3. Receipt Struct Template (mirror of record::OuterRecord)

Full template with signatures: see §Code Examples → Example 1 above. Key points:

- **Signable struct is 9 alphabetical fields** — `accepted_at, ciphertext_hash, cleartext_hash, nonce, protocol_version, purpose, recipient_pubkey, sender_pubkey, share_ref`. JCS sorts by Unicode code point regardless, but alphabetical declaration is belt-and-suspenders (same as `OuterRecordSignable` at `record.rs:41-50`).
- **Receipt struct adds `signature` alphabetically** — lands between `share_ref` and end-of-struct (alphabetically "signature" > "share_ref").
- **`From<&Receipt> for ReceiptSignable`** copies the 9 signable fields verbatim. Used by `verify_receipt` to reconstruct the signed bytes.
- **`sign_receipt(&signable, &keypair) -> Result<String, Error>`** calls `crypto::jcs_serialize` + `keypair.sign(&bytes)` + base64 STANDARD encode. Returns the signature string that the caller inserts into `Receipt { ..., signature }`.
- **`verify_receipt(&receipt) -> Result<(), Error>`** is a 5-step procedure mirroring `record::verify_record` at `record.rs:115-146`:
  1. Parse `recipient_pubkey` z32 → `VerifyingKey` (note: RECIPIENT's key, unlike `record::verify_record` which uses sender's `pubkey`).
  2. Decode base64 signature.
  3. Build `ReceiptSignable::from(&receipt)` + JCS-serialize.
  4. `vk.verify_strict(&bytes, &sig)` — the strict variant rejects the legacy relaxed Ed25519 behavior.
  5. **Round-trip-reserialize guard (T-01-03-02):** `serde_json::from_slice(&bytes)` + re-JCS + byte-compare; any divergence → `Error::SignatureCanonicalMismatch`.
- All 5 error paths route to `Error::SignatureInner` except step 5 → `Error::SignatureCanonicalMismatch`. Both Display as `"signature verification failed"` per D-16 (verified in `error.rs:27-37`).
- **No new Error variant required.** D-RS-07 explicitly reuses existing variants.

---

## §4. Nonce Generation Source

**Locked API:** `rand::rngs::OsRng.fill_bytes(&mut buf)` from `rand 0.8`.

- `rand` is a direct dep in `Cargo.toml:44` — added during Phase 2 Plan 02-02 for grease-retry determinism. No `cargo add` needed.
- `OsRng: CryptoRng + RngCore` in rand 0.8.5. `fill_bytes(&mut [u8])` is infallible (returns `()`, not `Result`).
- On Linux, `OsRng` reads `/dev/urandom` via `getrandom(2)` syscall (via the `getrandom` crate).
- **rand_core version gotcha:** rand 0.8 exports `rand_core 0.6.x` API. rand 0.9+ moves to `rand_core 0.7.x` with breaking renames. `ed25519-dalek =3.0.0-pre.5` transitively pulls `rand_core 0.6` → compatible with `rand 0.8`. **No version conflict expected.** `[VERIFIED: Cargo.lock resolution chain — unchanged since Phase 1]`

**Idiomatic snippet:**
```rust
use rand::{rngs::OsRng, RngCore};
let mut bytes = [0u8; 16];
OsRng.fill_bytes(&mut bytes);
// bytes now holds 128 bits of CSRNG output; format as 32-char lowercase hex
let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
```

**Security note:** 128 bits of random is sufficient — the nonce's threat model (per D-RS-03) is "prevent attacker synthesizing a plausible-looking receipt with a share_ref they don't know the real ciphertext for." 128 bits of unpredictability is ~2^64 collision resistance, way above any skeleton-scale traffic.

---

## §5. `receipts` Command Fetch Shape

See §Code Examples → Example 3 and Example 4 above for the full `run_receipts` + `fetch_receipt_candidates` sketches. Key decisions:

**The iteration is `all_resource_records()` + label-prefix filter**, not `resource_records(label)`. Rationale:

- `resource_records(name)` filters by exact name or `*` wildcard only (`signed_packet.rs:434-449`). It does NOT support `_cprcpt-*` glob semantics.
- Wildcard `*` in `resource_records("*")` means "all labels across all TXT records," which is more than we want and the wildcard matching logic is pkarr-specific (`signed_packet.rs:440-449`), not DNS-standard prefix matching.
- **Correct shape:** `packet.all_resource_records().filter(|rr| rr.name.to_string().trim_end_matches('.').starts_with("_cprcpt-"))` — simple, explicit, exact.

**TXT rdata extraction:** Reuse Phase 1's `extract_txt_string(&rr.rdata)` helper at `transport.rs:163-170`. It concatenates CharacterString chunks via `String::try_from(txt.clone())` which is the right semantic for JSON payloads > 255 bytes.

**Transport trait addition (recommended):**
```rust
// src/transport.rs — NEW method added to Transport trait (Phase 3 only seam change)
pub trait Transport {
    // ... existing 3 methods unchanged ...

    /// Resolve all `_cprcpt-*` TXT records under `pubkey_z32` (RCPT-02).
    /// Returns each receipt's raw JSON string, unverified.
    fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error>;
}
```

This is the 4th trait method; it parallels `resolve` but for the `_cprcpt-` label family. `MockTransport::resolve_all_txt` (already at `transport.rs:225-232`) becomes the underlying implementation; a one-line filter wraps it.

**Alternative (if planner prefers):** Downcast `&dyn Transport` to `&DhtTransport` via `std::any::Any` in `run_receipts`. Less clean; breaks the test harness invariant. **Rejected** — add the 4th trait method.

**`--share-ref` filter is post-verification** (D-OUT-02). Simple `.retain(|r| r.share_ref == filter)` after the verify loop.

---

## §6. Ledger Extension Pattern

**Field addition (D-SEQ-04):**
```rust
// src/flow.rs — MODIFIED LedgerEntry at lines 533-541
#[derive(serde::Serialize)]
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    receipt_published_at: Option<&'a str>,  // NEW (alphabetical between purpose and sender)
    sender: &'a str,
    share_ref: &'a str,
}
```

JCS alphabetical rule places `receipt_published_at` between `purpose` and `sender` — verified by alphabetical ordering (p-u-r-p-o-s-e < r-e-c-e-i-p-t < s-e-n-d-e-r).

**Append-after-publish strategy (D-SEQ-05):**

```rust
// In run_receive, AFTER step 12 (sentinel + ledger row 1) and AFTER step 13's publish_receipt returns Ok:
fn append_ledger_entry_with_receipt_timestamp(
    share_ref: &str,
    sender_z32: &str,
    purpose: &str,
    ciphertext_hash: &str,     // precomputed; no re-hash
    cleartext_hash: &str,      // precomputed; no re-hash
    receipt_published_at: &str, // ISO-8601 UTC
) -> Result<(), Error> {
    // Same append pattern as existing append_ledger_entry at flow.rs:543-578,
    // but with receipt_published_at populated.
    // ...
}
```

**Consumer scan-last-wins (D-SEQ-05):**

`check_already_accepted` at `src/flow.rs:125-147` already linear-scans the ledger and returns the last match via the for-loop-with-no-early-break-on-share-ref pattern:

```rust
// From src/flow.rs:130-143 (unchanged) — for share_ref appearing twice in ledger:
for line in data.lines() {
    if !line.contains(share_ref_hex) { continue; }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
        if v.get("share_ref").and_then(|s| s.as_str()) == Some(share_ref_hex) {
            if let Some(s) = v.get("accepted_at").and_then(|s| s.as_str()) {
                return Some(s.to_string());
            }
        }
    }
}
```

Wait — this is a first-match-wins loop, not last-match-wins. **Small concern.** Re-reading the code:

- The loop iterates top-to-bottom and `return Some(s.to_string())` on the first match.
- For a share accepted once and then publish-updated, the ledger has 2 rows with the same `share_ref` — row 1 (no `receipt_published_at`) and row 2 (with `receipt_published_at`).
- Phase 2's `check_already_accepted` returns the FIRST row's `accepted_at`, which is actually what you want for the "already accepted at <timestamp>" user message — the acceptance timestamp is the same in both rows (D-SEQ-05 says "updated row with the updated row", meaning same content except `receipt_published_at`). So first-match-wins returns the same `accepted_at` either way.

**Conclusion:** D-SEQ-05's "last-match-wins" language is slightly misleading in context, but the actual Phase 2 helper is first-match-wins AND works correctly because both rows carry the same `accepted_at`. **`check_already_accepted` needs NO modification for Phase 3.** Document this explicitly in the plan.

If the planner wants the "richest row wins" semantics (so a CLI displaying "accepted at X; receipt published at Y" can find Y), they'd need a different helper that scans to end and merges rows. That's out of scope for Phase 3's `check_already_accepted` usage (which only needs accepted_at for the user message). Defer.

---

## §7. Test Harness Reusables

Phase 2's test infrastructure drops in unmodified:

| Helper | Location | Phase 3 Usage |
|--------|----------|---------------|
| `flow::test_helpers::AutoConfirmPrompter` | `src/flow.rs:647-664` | All 3 D-IT-01 integration tests — script B's acceptance without TTY |
| `flow::test_helpers::DeclinePrompter` | `src/flow.rs:666-684` | Could use for "tampered share → no receipt published" test (D-IT-03 nice-to-have) |
| `deterministic_identity_at(home, seed)` | `tests/phase2_share_round_trip.rs:27-47` | Copy into Phase 3 test files (or extract to a test-helpers module) — stable z32 values for wire-budget predictability |
| `MockTransport::new()` / `MockTransport::resolve_all_txt(z32)` | `src/transport.rs:218-232` | D-IT-01 test 2 (coexistence) and test 3 (share-ref filter) both iterate the mock's TXT store |
| `MaterialSource::Bytes(Vec<u8>)` + `OutputSink::InMemory(Vec<u8>)` | `src/flow.rs:159,170` | All integration tests avoid filesystem I/O for payload |
| `TempDir` + `CIPHERPOST_HOME` env | `tempfile::TempDir::new()` + `std::env::set_var("CIPHERPOST_HOME", path)` | Standard per-test isolation |
| `#[serial]` | `serial_test::serial` | Required for tests that mutate `CIPHERPOST_HOME` |
| Feature-gated `--features mock` in `[[test]]` blocks | `Cargo.toml:50-130` | Add 3 new `[[test]]` entries for Phase 3 integration tests; all require `required-features = ["mock"]` |

**No new test infrastructure is needed.** All 3 D-IT-01 integration tests can be written from the Phase 2 templates by changing the asserts and adding `publish_receipt` / `run_receipts` calls.

---

## §8. Validation Architecture (expanded from above)

See the Validation Architecture section above. Verification loops that naturally fall out of the plan:

- **sign→verify round trip** (unit, <100ms): `phase3_receipt_sign_verify.rs` — generate a keypair, construct a Receipt, `sign_receipt`, `verify_receipt`, assert `Ok(())`. Same shape as `record.rs::tests::sign_verify_round_trip`.
- **tampered-receipt rejection** (unit, <100ms): take a valid signed Receipt, flip one byte in `ciphertext_hash`, re-parse, assert `verify_receipt` returns `Error::SignatureInner` with Display `"signature verification failed"`. Same shape as `record.rs::tests::tampered_blob_fails_verify`.
- **JCS canonical form fixture** (unit, <100ms): fixed seed + fixed fields → committed `tests/fixtures/receipt_signable.bin` bytes. CI-verify byte-exact on every build. Same shape as `tests/outer_record_canonical_form.rs`.
- **coexistence invariant** (integration, <5s): `MockTransport` holds B's `_cipherpost` + new `_cprcpt-<X>`; after publish, assert both `resolve_all_txt(b_z32)` entries present. This is ROADMAP SC3.
- **`--share-ref` filter** (integration, <5s): A sends 2 shares to B, B accepts both, A calls `run_receipts(..., Some(share_ref_1), ...)` — assert exactly 1 valid receipt returned with matching share_ref. ROADMAP SC4.
- **tamper before receipt publish** (integration, <5s): mutate ciphertext byte between resolve and accept; assert zero receipts published to MockTransport after `run_receive` returns an error. Maps Pitfall #5's prevention test.

All verification loops run in <10 seconds total; no manual steps except the HUMAN-UAT which is gated by the real DHT.

---

## §9. Concurrent-Publish Empirical Behavior

**pkarr exposes a typed concurrency-error enum** (`pkarr-5.0.4/src/client.rs:606-624`):

```rust
pub enum ConcurrencyError {
    /// A different SignedPacket is being concurrently published for the same PublicKey.
    ConflictRisk,
    /// Found a more recent SignedPacket in the client's cache.
    NotMostRecent,
    /// Compare and swap failed; there is a more recent SignedPacket than the one seen before publishing.
    CasFailed,
}
```

Routed via `PublishError::Concurrency(ConcurrencyError)`. Semantics:

- **`ConflictRisk`** — pkarr detected another publish in flight against the same key before this one finished. Detection is local (in-process for the DHT path; cross-process via cache for relays).
- **`NotMostRecent`** — client's cache holds a newer SignedPacket than the one being published; publishing would be a regression. Fires when you forgot to `resolve_most_recent` first or a background relay poll updated the cache between your resolve and publish.
- **`CasFailed`** — explicit compare-and-swap target was stale when the DHT node received the publish. Only fires when `cas: Some(timestamp)` is passed.

**Without CAS (`cas: None`):** Cipherpost's current resolve-merge-republish default in the sketch above passes `Some(most_recent.timestamp())` IF `most_recent` was `Some`, else `None`. On race, `CasFailed` fires → maps to `Error::Transport(..)` → D-SEQ-02 warn + degrade.

**With no mitigation (D-MRG-02 default):** The race is as follows. Recipient accepts share X → runs resolve-merge → before publish completes, recipient accepts a second share Y via a concurrent `cipherpost receive` → Y also runs resolve-merge based on the same `most_recent` snapshot → Y publishes first → X's publish then tries, hits `CasFailed`, maps to warn + degrade → X's receipt is lost. Expected behavior in skeleton per D-MRG-02.

**Frequency:** PITFALLS traffic estimate is 1-100 shares/week/user. Concurrent receives on the same identity within the publish window (seconds) are vanishingly rare. Phase 4 THREAT-MODEL.md can quote a sentence like "cipherpost v1 does not protect against receipt loss under concurrent acceptance on the same identity; the user-visible symptom is `receipt publish failed: transport error` on stderr for the loser-of-the-race."

**Phase 4 language seed:**
> *Receipt publishing uses pkarr's optimistic concurrency primitive (CAS against the most-recent SignedPacket timestamp). Two concurrent `cipherpost receive` processes on the same recipient identity that both publish receipts before either's publish is acknowledged will race: one wins, the other fails with a user-visible warning. The losing receipt is not retried and not persisted in the local ledger beyond the `receipt_published_at: null` state. Detection: `CIPHERPOST_LEDGER_STRICT=1` (future env var) could surface this; skeleton does not. Mitigation in v1.0: `cipherpost republish-receipt --share-ref <ref>` operational command (tracked as deferred).*

---

## §10. Open Questions for Planner

All pkarr API uncertainties are **RESOLVED** by the source inspection above. No prototype spike is required.

**Remaining planner decisions (Claude's Discretion, not blocking):**

1. **Transport trait method addition for receipts listing.** Recommended: add `Transport::resolve_all_cprcpt` (§5). Alternative: downcast `&dyn Transport` (rejected).
2. **`--json` output format.** Recommended: `serde_json::to_string_pretty` (UX-friendly, not signed). Strict JCS is available if cross-platform byte-stability ever matters.
3. **Receipts ordering in multi-row table.** Recommended: alphabetical by `share_ref` (deterministic; consistent with hex-dumped share_refs in the share URI). Alternatives: by `accepted_at` descending (most-recent first, UX-nice) OR insertion order from resolve (arbitrary).
4. **`receipt_published_at` helper signature.** Should `run_receive` call `append_ledger_entry` twice (once for acceptance, once for publish update) or introduce `append_ledger_entry_with_receipt(...)`? Mechanical detail; either works.
5. **Wire-budget test fixture scope.** A `phase3_wire_budget_overflow.rs` test explicitly documenting the 1-2-3 receipts ceiling is nice-to-have; planner decides.
6. **HUMAN-UAT script scenario.** D-IT-02 mandates a real-DHT round trip. Script shape: `cipherpost send --share <B>` → `cipherpost receive <URI>` (with interactive accept) → `cipherpost receipts --from <B>` (expect 1 valid verified receipt with matching share_ref). Planner writes the exact commands.

## RESEARCH COMPLETE
