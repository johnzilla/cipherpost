# Phase 3: Signed receipt — the cipherpost delta - Context

**Gathered:** 2026-04-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver the feature that differentiates cipherpost from cclink: after `run_receive` acceptance completes, construct a `Receipt` over the 10 fields enumerated by RCPT-01 (share_ref, sender_pubkey, recipient_pubkey, accepted_at, nonce, ciphertext_hash, cleartext_hash, purpose, protocol_version, signature), sign it with the recipient's Ed25519 key, publish it under the **recipient's** PKARR key at DNS label `_cprcpt-<share_ref_hex>` via a resolve-merge-republish `publish_receipt` that preserves any other TXT records already under that key (the recipient's own outgoing `_cipherpost` share, or other receipts). Sender fetches and verifies via `cipherpost receipts --from <recipient-z32> [--share-ref <ref>]`.

This phase stands alone rather than merging into Phase 2 because the cipherpost thesis must be verifiable independent of self/share/accept mechanics; this is also where the only non-vendored transport extension lives. Phase 2 deliberately skipped receipt publication so this phase owns the full delta.

**Requirements owned:** TRANS-03, RCPT-01, RCPT-02, RCPT-03 (4 reqs).

**Out of scope for Phase 3** (captured as deferred, not to re-raise): `cipherpost republish-receipt` command, `--watch` polling, receipt encryption, receipt rotation/GC, cross-process concurrent-publish coordination, encrypt-then-sign reshaping of the inner layer.

</domain>

<decisions>
## Implementation Decisions

### Receipt wire schema

- **D-RS-01:** Two structs in `src/receipt.rs`, mirroring `OuterRecord` / `OuterRecordSignable` exactly:
  - `ReceiptSignable` — 9 fields (alphabetical): `accepted_at: i64`, `ciphertext_hash: String`, `cleartext_hash: String`, `nonce: String`, `protocol_version: u16`, `purpose: String`, `recipient_pubkey: String`, `sender_pubkey: String`, `share_ref: String`.
  - `Receipt` — `ReceiptSignable` fields + `signature: String` (alphabetical insertion keeps `signature` after `share_ref`). `From<&Receipt> for ReceiptSignable` for verify-side reconstruction, matching `record::OuterRecordSignable::from(&OuterRecord)`.
- **D-RS-02:** `accepted_at` encoded on the wire as `i64` unix seconds. Matches `OuterRecord.created_at` precedent — single integer type for all wire timestamps, JCS-stable, no locale/format fragility. The local Phase 2 ledger's `accepted_at` stays as the ISO-8601 UTC string it already is (ledger is local-only, never on the wire). Display layer in `receipts` renders both local + UTC from the unix seconds at print time (RCPT-02 requires local+UTC).
- **D-RS-03:** `nonce` = 128-bit random, 32-char lowercase hex. Same codec as `share_ref` for lexical consistency in DHT labels and log files. Sourced via `rand::rngs::OsRng.fill_bytes(&mut [0u8; 16])` (no new dep: `rand` transitively present via `ed25519-dalek`). Purpose: defense against attacker-synthesized receipt-like data, not replay (RECV-06 already blocks honest re-receive).
- **D-RS-04:** `ciphertext_hash` and `cleartext_hash` encoded as raw lowercase sha256 hex (64 chars, no prefix). Matches Phase 2 ledger exactly — `format!("{:x}", Sha256::digest(...))`. Forward-compat for v2 algorithms is carried by `protocol_version`, not by an in-band `sha256:` multihash prefix.
- **D-RS-05:** `signature` = base64 STANDARD (Ed25519, 64 raw bytes → 88 chars padded). Matches Phase 1's `OuterRecord.signature` codec exactly (D-WIRE-04 ban on mixing base64 variants applies here too).
- **D-RS-06:** Field set is exactly the 10 fields in REQUIREMENTS.md RCPT-01 — do not add `receipt_version`, do not add `sender_share_uri`, do not add any other field without bumping `protocol_version`. Locked to keep SPEC.md short and predictable.
- **D-RS-07:** Signing/verify flow mirrors `record::sign_record` / `record::verify_record` exactly:
  - `sign_receipt(signable, &pkarr::Keypair) -> Result<String, Error>`: JCS-serialize → `keypair.sign(&bytes)` → base64 STANDARD.
  - `verify_receipt(receipt: &Receipt) -> Result<(), Error>`: parse `recipient_pubkey` z32 → `VerifyingKey::from_bytes` → decode sig → build `ReceiptSignable::from(&receipt)` → JCS → `verify_strict` → round-trip-reserialize + byte-compare guard (T-01-03-02 canonicalization-bypass defense).
  - All receipt signature-verification failures produce `Error::SignatureInner` (reusing the unified D-16 variant — no new `Error::SignatureReceipt` needed) so the oracle-hygiene invariant holds end-to-end.

### publish_receipt merge (TRANS-03)

- **D-MRG-01:** Strategy = **resolve → rebuild builder → re-sign**. `DhtTransport::publish_receipt` first calls `client.resolve_most_recent(&pk)`. If `Some(existing)`, iterate all resource records from the existing packet and re-add each via `SignedPacket::builder().txt(name, txt, ttl)`, REPLACING any existing TXT whose label is exactly `_cprcpt-<this_share_ref_hex>` with the new receipt. Add the new receipt TXT. Sign with the recipient's keypair. If `None`, publish the new receipt alone.
- **D-MRG-02:** Concurrent-publish race is **documented as a known limitation**, not mitigated in code. Per PITFALLS traffic estimate (1–100 shares/week/user), concurrent receipts under the same identity are vanishingly rare in skeleton use. Phase 4's `THREAT-MODEL.md` covers this under "receipt replay / race." No retry loop, no in-process mutex in skeleton.
- **D-MRG-03:** TXT record DNS TTL on published receipts = **300 seconds**, matching the outer-share TTL already hardcoded at `src/transport.rs:100` and `:146`. DNS TTL is advisory; sender re-fetches via pkarr which resolves to freshest. Single TTL constant in the codebase.
- **D-MRG-04:** pkarr 5.0.3 SignedPacket iteration API is unconfirmed — planner's first task is a small prototype spike: verify whether `packet.all_resource_records()` (or equivalent all-labels iterator) exists, and whether the builder supports either per-record `.txt(name, txt, ttl)` re-add or a bulk `.rrs(records)` pass-through. Research flag from `.planning/research/SUMMARY.md` §"Research Flags for Phase Planning" Phase 8 is owned here. If the API forces label-by-label resolution, enumerate the two known labels (`_cipherpost`, `_cprcpt-*` prefix) — but document this as a forward-compat foot-gun (silently drops future labels).
- **D-MRG-05:** `MockTransport::publish_receipt` is already append-preserving per-share_ref (`src/transport.rs:271-288`). Upgrade needed: make the semantics match DhtTransport exactly — existing `_cipherpost` outer-share entries must coexist (already do), and `publish_receipt` must not clobber other `_cprcpt-*` entries (already doesn't). No code change expected beyond a confirming test; MockTransport already behaves correctly. The gap is in DhtTransport, not mock.
- **D-MRG-06:** Receipt wire size budget inherits from the outer-share `WIRE_BUDGET_BYTES = 1000`. The merged SignedPacket (all existing TXT + new receipt) must fit in the same PKARR/BEP44 budget. If the recipient accumulates enough receipts to exceed the budget, publish_receipt surfaces `Error::WireBudgetExceeded { encoded, budget, plaintext: 0 }` (plaintext=0 indicates a receipt, not a share, overflowed) — warn+degrade per D-SEQ-02 applies. Rotation/pruning is a deferred item (see deferred).

### Publish sequencing + failure handling

- **D-SEQ-01:** Extend the D-RECV-01 strict order with **step 13: publish_receipt**, after step 12 (sentinel + ledger). Final order inside `run_receive`:
  1. sentinel-check (no network)
  2. transport.resolve (outer + inner sig verify)
  3. (inside resolve) inner Ed25519 sig verify
  4. url_share_ref == record.share_ref
  5. TTL check (inner signed created_at + ttl_seconds)
  6. age-decrypt → Zeroizing
  7. parse JCS → Envelope (fail = SignatureCanonicalMismatch, exit 3)
  8. acceptance screen on stderr
  9. user types full sender z32 confirmation
  10. write material to output sink
  11. create_sentinel
  12. append_ledger_entry (with `receipt_published_at: null` placeholder)
  13. **publish_receipt** — construct Receipt → sign → publish → on success, update the ledger line's `receipt_published_at` to ISO-8601 UTC
  - Rationale: local state durable first (sentinel + ledger) so RECV-06 idempotence holds even if publish fails. User has the material. Publish is best-effort.
- **D-SEQ-02:** Publish failure = **warn + degrade, exit 0**. `run_receive` catches any error from `publish_receipt`, prints `receipt publish failed: <user_message>` to stderr, and continues. The overall command exits 0 because the core value (material delivered safely) succeeded. Ledger line stays at `receipt_published_at: null` — sender can ask for a re-publish via the deferred `cipherpost republish-receipt --share-ref <ref>` command (not in Phase 3 scope).
- **D-SEQ-03:** No auto-retry in skeleton. Per PITFALLS #10 (DHT unreliability budgeted), a retry loop adds code without fixing the race cause. If a user needs republish, they re-run the share URI after deleting the sentinel (operational workaround; `republish-receipt` command is the proper fix, deferred).
- **D-SEQ-04:** Ledger schema extension — add ONE new field, `receipt_published_at: Option<String>` (ISO-8601 UTC on success, `null`/absent on failure). `LedgerEntry` serde struct in `src/flow.rs:533-541` grows by one field. JCS alphabetical ordering places it between `purpose` and `sender`:
  ```json
  {"accepted_at": "...", "ciphertext_hash": "...", "cleartext_hash": "...", "purpose": "...", "receipt_published_at": "...", "sender": "...", "share_ref": "..."}
  ```
  No `receipt_publish_error` field — error details go to stderr only, not persisted (keeps the ledger's "decision record" shape, not a log). Backwards-compatible: old Phase 2 ledger lines without the field parse cleanly via `Option`.
- **D-SEQ-05:** Ledger is append-only; updating `receipt_published_at` after publish success = **append a new ledger line** with the updated row (not a rewrite). The scan in `check_already_accepted` (`src/flow.rs:125`) already linear-scans and short-circuits on share_ref match — if multiple lines exist for the same share_ref, use the last one (higher `accepted_at`). Alternative (rewrite the single line) breaks `accepted.jsonl` append-only invariant and complicates crash-safety. Accepted line growth: 1 row per accept + 1 row per successful publish-update = 2 rows per share in the common case; unchanged footprint for failed-publish cases.
- **D-SEQ-06:** Self-mode receipts are **published via the same path**. sender_pubkey == recipient_pubkey is a valid, verifiable Receipt state. Self-receipts form a personal audit log and confirm the D-RS-07 signature flow works without a branch. No `if self_mode { skip_publish() }` in `run_receive`.
- **D-SEQ-07:** `run_receive` signature grows to accept the recipient's `&pkarr::Keypair` (needed for `publish_receipt`). `main.rs` Receive dispatch already reconstructs the keypair from `id.signing_seed()` for Send (`src/main.rs:94-96`); the same line moves earlier in the Receive branch. Integration tests pass the keypair through the Phase 2 test harness (already keyed by `Identity`).

### receipts output + verify (RCPT-02)

- **D-OUT-01:** Default output = **human-readable table on stdout**. `--json` flag emits a canonical-JSON array on stdout (JCS-serialized for cross-platform byte-stability). Status/progress stay on stderr (CLI-01). Table columns (default, not `--json`):
  - `share_ref` — first 16 chars of hex (collision-unambiguous at skeleton scale)
  - `accepted_at` — `YYYY-MM-DD HH:MM:SS <local-tz> (UTC: YYYY-MM-DDTHH:MM:SSZ)` — matches Phase 2 acceptance-screen TTL rendering style (D-ACCEPT-02)
  - `purpose` — truncated to 40 chars with `…` suffix if longer; control-char-stripped (already stripped at send time per D-WIRE-05 but defense-in-depth re-strip at display)
  - `recipient_fp` — OpenSSH-style `ed25519:SHA256:<base64>` (IDENT-05 format)
- **D-OUT-02:** `--share-ref <hex>` filter reduces output to exactly one matching receipt (or empty result if no match). When a single result is shown AND `--json` is not set, the non-`--json` human output shows ALL 10 Receipt fields (no truncation) — the one-receipt view is the "audit detail" view. Listings (no `--share-ref` or `--share-ref` matching multiple) stay in the 4-column truncated table.
- **D-OUT-03:** Receipt signature-verify failure handling: **warn + skip, exit 0 if any verify**. For each receipt TXT record resolved:
  - Parse JSON → `Receipt` struct. JSON-parse failure: increment `malformed_count`, continue.
  - `verify_receipt(&r)`: on `Ok`, include in output. On `Err(Error::Signature*)`, increment `invalid_count`, continue.
  - After iteration: print to stderr `fetched N receipt(s); M valid, K malformed, L invalid-signature` (omit zero-count categories).
  - Exit codes:
    - At least one valid receipt: exit 0.
    - Zero valid + at least one invalid signature: exit 3 (SignatureInner, D-16 unified).
    - Zero valid + only malformed: exit 1 (generic).
    - Zero TXT records found at all under `_cprcpt-` prefix: exit 5 (NotFound).
  - `--share-ref` filter applied AFTER verification, so filter match count is over verified receipts only.
- **D-OUT-04:** A new flow function `run_receipts(transport, from_z32, share_ref_filter, json_mode) -> Result<(), Error>` lives in `src/flow.rs`. Signature mirrors `run_send` / `run_receive` patterns. Does NOT require the caller's `Identity` (no decrypt path; sender just fetches + verifies public signatures). `main.rs` Receipts dispatch calls it directly without a passphrase prompt.

### Integration test scope (RCPT-03)

- **D-IT-01:** Three MockTransport integration tests (must-have):
  1. **Two-identity end-to-end round trip.** Identities A and B. A sends to B via `run_send` (share mode). B accepts via `run_receive` with a scripted `AutoConfirmPrompter`. Assert a Receipt is published under B's PKARR key at `_cprcpt-<share_ref>`. A calls `run_receipts(transport, b_z32, None, false)`. Assert: (a) exactly one valid receipt returned, (b) receipt's `sender_pubkey` == A's z32, (c) receipt's `recipient_pubkey` == B's z32, (d) receipt's `ciphertext_hash` == sha256 of B's resolved ciphertext, (e) verify_receipt succeeds. Covers RCPT-01 + RCPT-02 + RCPT-03.
  2. **TRANS-03 coexistence.** B first does a self-mode `run_send` (establishes a `_cipherpost` TXT under B's key). Then A sends to B. B accepts. Assert: after `publish_receipt`, (a) B's own `_cipherpost` outer-share TXT is still resolvable under B's key (B's self-share didn't get clobbered), (b) B's `_cprcpt-<ref>` receipt TXT is findable under B's key. Covers TRANS-03 and ROADMAP SC3.
  3. **`--share-ref` filter + concurrent sender self-share.** B accepts two shares from A (different share_refs). A simultaneously has their own outgoing `_cipherpost` share under A's key. A calls `run_receipts(transport, b_z32, Some(share_ref_1), false)`: assert exactly 1 receipt returned, correct share_ref. A calls `run_receipts(transport, b_z32, None, false)`: assert both receipts returned. Covers RCPT-02 `--share-ref` + ROADMAP SC4 "fetch works even if A simultaneously holds their own unrelated outgoing share."
- **D-IT-02:** One HUMAN-UAT test (must-have): real-DHT A → B → receipt round trip with two genuine identities on two separate sessions. Matches Phase 1 HUMAN-UAT.md and Phase 2 HUMAN-UAT.md patterns. Script in `03-HUMAN-UAT.md` — sender runs `cipherpost send --share <b-z32>` (real DHT), recipient runs `cipherpost receive <uri>` (interactive accept), sender runs `cipherpost receipts --from <b-z32>` and asserts a verified receipt with the expected share_ref and purpose appears.
- **D-IT-03:** Tamper-verify test (nice-to-have, keep if cheap): inject a `MockTransport` helper that mutates a stored receipt byte; call `run_receipts` with the tampered store; assert the tampered receipt is skipped with an invalid-signature warning and exit 0 if any other receipt verifies. Planner's discretion — if adding the helper adds significant MockTransport surface, defer to Phase 4 or v1.0.

### Claude's Discretion

Downstream planning/execution agents have latitude on:
- **pkarr 5.0.3 SignedPacket iteration API.** Actual method names (`all_resource_records()` vs alternative) and whether the builder accepts bulk or per-record re-add. Planner must verify and adapt. If neither shape is ergonomic, planner may file a minor `src/transport.rs::txt_records_from_packet` helper.
- **rand source wiring.** Whether `nonce` generation uses `rand::rngs::OsRng` directly, `pkarr::Keypair::new().to_secret_key()[..16]` (abusing pkarr's RNG), or a dedicated `cipherpost/v1/receipt-nonce`-info HKDF derivation. Recommended: plain OsRng fill; HKDF-derived nonce adds complexity without a threat-model payoff.
- **Table column widths / truncation lengths.** `purpose` truncation at 40 chars, share_ref at 16 chars — adjustable if the column becomes cramped on typical 80-col terminals. Planner's call.
- **Ledger append-line strategy for `receipt_published_at` update (D-SEQ-05).** Alternative: in-place rewrite via `fs::write` of the filtered content. Strong default is append-only; planner may propose rewrite if crash-safety can be preserved via atomic rename. Risk-weighted against complexity.
- **Error variant introduction.** Whether `receipt publish failed` uses `Error::Transport(Box<dyn ...>)` (existing catch-all), `Error::Network` (if the failure is truly network), or a new `Error::ReceiptPublish { cause }`. Default: reuse existing; no new error variant unless a clear user-facing exit-code gap appears.
- **`--json` output canonicalization.** Strict JCS vs `serde_json::to_string_pretty`. JCS preserves cross-platform byte-stability but is less human-readable. Planner may choose pretty-printed non-canonical JSON for `--json` output since the output is display-only (not signed). Keep `verify_receipt` on JCS bytes for the signature path.
- **Receipts stable ordering.** Alphabetical by `share_ref`, by `accepted_at` ascending, or insertion order from resolve. Display detail; planner picks.
- **Human-UAT exact script.** The single UAT scenario; planner writes `03-HUMAN-UAT.md` with concrete commands.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project-level (all phases)
- `.planning/PROJECT.md` — vision, core value, constraints, Key Decisions table. Specifically: "Skeleton includes signed receipt, not just self/share — The receipt is the cipherpost delta from cclink." The receipt is THE deliverable that makes this project cipherpost rather than cclink.
- `.planning/REQUIREMENTS.md` — the 4 REQ-IDs this phase owns (TRANS-03, RCPT-01, RCPT-02, RCPT-03) plus Phase 2's already-shipped 21 REQs which this phase composes.
- `.planning/ROADMAP.md` §"Phase 3" — goal, dependencies, four numbered success criteria (Receipt construction + publish at `_cprcpt-<share_ref>`, tampered-share-zero-receipts invariant, coexistence, two-identity round trip).

### Prior phase context (carry-forward — do NOT re-litigate)
- `.planning/phases/01-foundation-scaffold-vendored-primitives-and-transport-seam/01-CONTEXT.md` — Phase 1 wire/on-disk constants that this phase uses: D-06 (`DHT_LABEL_RECEIPT_PREFIX = "_cprcpt-"`), D-07 (`PROTOCOL_VERSION = 1`), D-08 (`HKDF_INFO_PREFIX = "cipherpost/v1/"`), D-14/15/16 (error enum + unified sig-fail Display). The outer-share wire format stays unchanged.
- `.planning/phases/02-send-receive-and-explicit-acceptance/02-CONTEXT.md` — Phase 2 ledger format (D-STATE-01) that this phase extends with `receipt_published_at`, D-RECV-01 step order that this phase extends with step 13, D-ERR-01 error variants that this phase reuses (no new `Error::SignatureReceipt` — reuse `SignatureInner`).
- `.planning/phases/02-send-receive-and-explicit-acceptance/02-RESEARCH.md` and `02-PATTERNS.md` — the reusable-asset map from Phase 2; most assets carry forward (JCS pattern, signing/verify pattern, MockTransport shape).

### Research (read before planning)
- `.planning/research/SUMMARY.md` §"Reconciled Build Order" Phase 8 — the 10-phase skeleton that this coarse Phase 3 consolidates (receipt publishing + receipt fetching). Esp. §"Research Flags for Phase Planning" Phase 8: **PKARR SignedPacket merge-update semantics (race conditions on concurrent receipt publication) may warrant a small prototype.** This phase owns that prototype via D-MRG-04.
- `.planning/research/PITFALLS.md` — Pitfalls Phase 3 owns:
  - **#5 Receipt produced only after full verify + acceptance.** D-SEQ-01's step-13 placement (after sentinel + ledger, which are themselves after accept + decrypt + inner-sig verify) is the prevention structure.
  - **#10 DHT unreliability budgeted.** D-SEQ-02 (warn+degrade on publish failure), D-SEQ-03 (no retry loop in skeleton), D-MRG-02 (race-documented-not-mitigated).
  - **#12 Purpose as sender-attested.** Receipt carries `purpose` verbatim from Envelope; sender-attestation framing stays in SPEC.md / THREAT-MODEL.md (Phase 4 ownership, but Receipt-level impact noted here).
- `.planning/research/ARCHITECTURE.md` §"Components 6-7" — `receipt/` and `flow/receipt_fetch` module designs. Note: Phase 1 D-01/D-02 flattened directory layout; `receipt/` is a single file `src/receipt.rs`, and fetch lives inside `src/flow.rs::run_receipts`.
- `.planning/research/FEATURES.md` — "D3 signed receipt on DHT (the cipherpost delta)" is the primary differentiator this phase ships.
- `.planning/research/STACK.md` — no new deps needed. `rand` for nonce generation is transitively available via `ed25519-dalek`.

### External (reference, not dependency)
- `https://docs.rs/pkarr/5.0.3/` — SignedPacket builder + resolution API. Specific functions planner must verify: `SignedPacket::builder()`, `.txt(name, txt, ttl)`, iteration over existing resource records, `client.resolve_most_recent(&pk)`. D-MRG-04 owns the prototype.
- `https://github.com/johnzilla/cclink` — cclink has no receipt concept, so this phase has NO analogous prior art. The receipt layer is fully new code against Phase 1/2 primitives.

### Not yet written (Phase 4 output — this phase produces the source-of-truth)
- `SPEC.md` — will document: Receipt wire schema (D-RS-01..07), receipt DHT label rule (`_cprcpt-<share_ref_hex>`), resolve-merge-republish invariant (D-MRG-01..06), publish-after-acceptance ordering (D-SEQ-01), receipt-failure-warn-degrade contract (D-SEQ-02), ledger `receipt_published_at` semantics (D-SEQ-04/05), `receipts` exit-code taxonomy (D-OUT-03). Phase 3's decisions are the v1 source-of-truth.
- `THREAT-MODEL.md` — will document: concurrent-publish race (D-MRG-02), wire-budget exhaustion under receipt accumulation (D-MRG-06), tampered receipts (D-OUT-03 warn+skip defense), receipt as attestation layer for `purpose` (Pitfall #12 handoff).

</canonical_refs>

<code_context>
## Existing Code Insights

Phase 1 scaffolded the module and the `publish_receipt` trait method; Phase 2 captured the hashes the receipt needs and locked the acceptance-then-state ordering. Phase 3 fills in the receipt body, upgrades the merge semantics, and adds the fetch command. No greenfield modules.

### Reusable Assets (ready for Phase 3 consumption)

- **`src/receipt.rs`** — currently a 4-line placeholder (`// TODO: phase 2+`). Phase 3 replaces with `Receipt` + `ReceiptSignable` + `sign_receipt` + `verify_receipt` per D-RS-01/07.
- **`src/record.rs`** — canonical pattern for the struct-pair + sign/verify functions. `sign_record` (`record.rs:96`), `verify_record` (`record.rs:115`), and the inlined `jcs()` helper (`record.rs:84`) are the exact shape Phase 3's receipt signer mirrors. The round-trip-reserialize-compare guard in step 5 of `verify_record` is load-bearing (T-01-03-02 canonicalization-bypass defense) — receipt verify replicates it.
- **`src/transport.rs`** — `Transport` trait with `publish_receipt(&self, keypair, share_ref_hex, receipt_json)` signature already locked. Phase 3 upgrades the BODIES of `DhtTransport::publish_receipt` (`transport.rs:128`) and `MockTransport::publish_receipt` (`transport.rs:271`) per D-MRG-01/05. `DhtTransport::resolve` (`transport.rs:109`) is the template for the resolve-half of resolve-merge-republish. `extract_txt_string` (`transport.rs:163`) is reusable as-is for receipt TXT reads.
- **`src/flow.rs`** — `run_receive` (`flow.rs:398`) is where step 13 (publish_receipt) appends. `LedgerEntry` struct (`flow.rs:533`) is where `receipt_published_at: Option<&str>` inserts alphabetically. `append_ledger_entry` (`flow.rs:543`) is the append-write pattern D-SEQ-05 reuses for the post-publish update line. `check_already_accepted` (`flow.rs:125`) handles the 2-rows-per-share case transparently (last match wins). The `Prompter` trait (`flow.rs:81`) is the test harness for `AutoConfirmPrompter`. `now_unix_seconds` (`flow.rs:582`) and `iso8601_utc_now` (`flow.rs:589`) are reusable for Receipt `accepted_at` sourcing and ledger `receipt_published_at` sourcing respectively.
- **`src/main.rs`** — Receive dispatch (`main.rs:165-215`) already reconstructs `pkarr::Keypair` from `id.signing_seed()` in the Send branch (`main.rs:94-96`); the same 3 lines move into Receive to pass the keypair into `run_receive`. Receipts dispatch (`main.rs:216-219`) is currently a 2-line stub; Phase 3 replaces with a call to `run_receipts`.
- **`src/cli.rs`** — `Command::Receipts { from: String, share_ref: Option<String> }` (`cli.rs:81-89`) is already the final clap shape. No new flags needed from clap side. `--json` flag for D-OUT-01 is the only addition: `#[arg(long)] json: bool`.
- **`src/lib.rs`** — `DHT_LABEL_RECEIPT_PREFIX = "_cprcpt-"` (`lib.rs:38`) is the constant used to construct receipt labels (`format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex)`). Already used by both DhtTransport and MockTransport impls.
- **`src/crypto.rs`** — `jcs_serialize` is cross-crate-reused (per `LedgerEntry` ledger write path). Phase 3's receipt signer goes through the same function for consistency. No new crypto primitives needed.
- **`src/identity.rs`** — `signing_seed()` + `Identity::load` path already covers reconstructing the pkarr keypair from a loaded identity. Receipts command does NOT need Identity (public signatures, no decrypt) — significant ergonomics win (no passphrase prompt for listing).

### Established Patterns (Phase 3 follows without revisiting)

- Signable/Signed struct pair with alphabetical fields and `From<&Signed> for Signable` conversion (Phase 1 D-RS-01 mirror).
- Sign/verify inline `jcs()` helper, parse-then-reserialize-compare in verify (Phase 1 T-01-03-02).
- `Transport` trait method signature is locked; only bodies change (Phase 1 D-03).
- HKDF info namespace `cipherpost/v1/<context>` — NO new HKDF call-site needed for receipts (receipts use Ed25519 identity signing key directly, not a derived key). The existing `tests/hkdf_info_enumeration.rs` test count stays stable.
- All signature-verification failures produce `Error::SignatureInner` / `SignatureCanonicalMismatch` / etc. with unified Display "signature verification failed" (D-16). `verify_receipt` reuses these variants — no new signature-error variant.
- Errors route through `exit_code` / `user_message` in `src/error.rs`; no new exit codes added in Phase 3.
- `#[cfg(any(test, feature = "mock"))]` gating on MockTransport test helpers.
- Status/progress on stderr, payload/output on stdout (CLI-01). `cipherpost receipts` follows: stderr for "fetched N receipt(s); M valid …", stdout for the table or `--json` array.

### Integration Points

Phase 3 consumes (Phase 2 provides):
- `cipherpost::payload::Envelope` → purpose + material type for Receipt field sourcing (read-only).
- `cipherpost::flow::LedgerEntry` → extended with `receipt_published_at: Option<String>` per D-SEQ-04.
- `cipherpost::flow::check_already_accepted` → handles the 2-rows-per-share case by design (last-match wins).
- `cipherpost::flow::run_receive` → extended with step 13 (publish_receipt).
- `cipherpost::transport::{Transport, DhtTransport, MockTransport}` → `publish_receipt` method upgrades.
- `cipherpost::identity::Identity::signing_seed` → keypair reconstruction for receipt signing.
- `cipherpost::{DHT_LABEL_RECEIPT_PREFIX, PROTOCOL_VERSION}` → wire constants.
- `cipherpost::record::{sign_record-pattern, verify_record-pattern}` → template for receipt sign/verify.

Phase 4 will consume (Phase 3 provides):
- Locked Receipt wire schema (D-RS-01..07) → SPEC.md § Receipt format.
- Locked receipt DHT label derivation rule → SPEC.md § DHT labels.
- Locked resolve-merge-republish invariant (D-MRG-01..06) → SPEC.md § Transport semantics + THREAT-MODEL.md § concurrent-publish race.
- Locked publish-after-acceptance ordering (D-SEQ-01) → SPEC.md § Receive flow + THREAT-MODEL.md § "receipt produced only after full verify" defense.
- Locked ledger schema v2 (with `receipt_published_at`) → SPEC.md § State ledger.
- Locked `receipts` exit-code taxonomy (D-OUT-03) → SPEC.md § Exit codes (already lists 0, 3, 5; no new codes).

</code_context>

<specifics>
## Specific Ideas

- **The receipt IS the phase's product.** The whole point of cipherpost-vs-cclink is that a signed, independently-verifiable receipt exists on a public substrate (DHT) that the sender controls read on and the recipient controls write on. Every gray-area tie-break in this phase defers to "does this keep the receipt trustworthy end-to-end?" not "is this convenient?"
- **Receipts are fully public by design.** No field in the Receipt is a secret. This is correct and intentional: sender needs to verify without a decryption key, and receipts form a social-layer artifact (audit evidence the recipient accepted the share). Any instinct to "encrypt the receipt to the sender" contradicts the design and should be rejected.
- **The "warn + degrade, exit 0" publish-failure contract (D-SEQ-02)** is a user-value statement: the material was delivered safely; receipt-loss is a sender-visible degradation, not a recipient-visible failure. Do not regress to hard-fail just because "exit 0 on network failure feels wrong" — that violates the "DHT is best-effort" principle.
- **The merge-preserving `publish_receipt` (D-MRG-01)** is the single most load-bearing line of new code in Phase 3. Clobbering other TXT records under the recipient's key destroys their ability to operate as a sender too. ROADMAP SC3 tests this invariant; a Phase 3 PR that doesn't pass SC3 is a failing phase regardless of receipt-format correctness.
- **Appending an update row to ledger (D-SEQ-05)** is not a bug; it's consistency with Phase 2's append-only design. The small line-count growth is a non-issue at skeleton traffic (1–100 shares/week). Rewriting a single line would require atomic rename (fs::rename) and defeats the crash-safety invariant the Phase 2 author already solved for.

</specifics>

<deferred>
## Deferred Ideas

Ideas raised in discussion or implied by adjacent decisions but outside Phase 3 scope. Preserved so they are not lost and are not re-raised in Phase 4 planning:

- **`cipherpost republish-receipt --share-ref <ref>`** — operational command for sender to ask recipient to retry a failed publish. D-SEQ-02's "warn + degrade" contract makes this the proper fix for publish-failure recovery. Track for v1.0.
- **Concurrent publish retry loop / in-process mutex** — D-MRG-02 documents the race. If real-use telemetry shows concurrent-receipt accidents in cipherpost traffic, add either a retry loop (optimistic concurrency) or a per-identity mutex. Track for v1.1+.
- **Receipt rotation / GC under wire-budget pressure** — D-MRG-06 fails publish with `WireBudgetExceeded` when accumulated receipts exhaust the 1000-byte SignedPacket. If users hit this, add `cipherpost receipts --prune <criteria>` (e.g., older than 30d) or automatic FIFO trimming. Track for v1.0 operational hardening.
- **Receipt-publish retry loop** — D-SEQ-03 ships without auto-retry. If PITFALLS #10 "DHT unreliability" measurement shows meaningful publish-failure rate, revisit.
- **Tamper-verify integration test as must-have** — D-IT-03 marks it nice-to-have. If planning discovers a cheap MockTransport helper for byte-mutation, promote it to must-have.
- **`cipherpost receipts --watch`** — polling mode. V2-OPS-06 already marks deferred to v2. Not in Phase 3.
- **Ledger in-place rewrite for `receipt_published_at` update** — D-SEQ-05 chose append. If append-duplication becomes ugly operationally (>10 rows per share), revisit with atomic-rename rewrite strategy.
- **Receipt encryption to sender** — explicit non-goal; receipts are public by design. Do not propose.
- **Encrypt-then-sign reshaping of inner Envelope layer** — PITFALLS #2 forward-look. Would change what `ciphertext_hash` commits to. Protocol-version bump required. Track for v2 SPEC.
- **Receipt carries full `cipherpost://` share URI** — rejected in D-RS-06 (costs ~99 bytes; receipt is reconstructible from its other fields). If a sender-side tool needs the URI, they kept it from `cipherpost send`'s stdout.
- **`receipt_publish_error` persisted in ledger** — rejected in D-SEQ-04. Error details go to stderr. If ops tooling needs persisted failure diagnostics, add a side-log file (not the ledger).
- **`sha256:` multihash prefix on hash fields** — rejected in D-RS-04. `protocol_version` gates the algorithm choice; multihash is forward-compat churn.
- **`receipt_version` separate from `protocol_version`** — rejected in D-RS-06. Co-evolution via `protocol_version` bump is simpler.

### Reviewed Todos (not folded)

No todos existed to review (`gsd-sdk query todo.match-phase 3` returned 0).

</deferred>

---

*Phase: 03-signed-receipt-the-cipherpost-delta*
*Context gathered: 2026-04-21*
