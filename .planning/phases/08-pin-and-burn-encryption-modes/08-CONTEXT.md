# Phase 8: --pin and --burn encryption modes - Context

**Gathered:** 2026-04-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Senders can require a PIN as a second factor for decryption (`--pin`), and can mark a share single-consumption (`--burn`). Both modes compose orthogonally and layer cleanly on all typed Material variants from Phases 6–7. PIN crypto is a **cclink-fork-with-divergence**: cclink's KDF shape (Argon2id → HKDF → 32-byte key) is reused, but cipherpost wraps the derived key into an age `Identity` and uses nested age encryption — cclink's direct `chacha20poly1305` calls are forbidden by CLAUDE.md. Burn is **local-state-only**: cclink's burn publishes an empty packet over the DHT slot (revoke-style); cipherpost explicitly rejects DHT mutation per BURN-08.

**In scope (this phase):**
- `cipherpost send --pin` — TTY-only PIN prompt at send time; no echo; 8-char min + anti-pattern validation (PIN-02). Non-interactive PIN sources (`--pin-file`, `--pin-fd`, `CIPHERPOST_PIN`) deliberately deferred to v1.2+ per PIN-01 (REQUIREMENTS canonical; SUMMARY.md draft listing `CIPHERPOST_PIN` is OUTDATED).
- `cipherpost send --burn` — sets `Envelope.burn_after_read: bool = true`; inner-signed; orthogonal to `--pin`.
- PIN crypto: Argon2id(PIN + 32-byte random salt) → HKDF-SHA256 with info `cipherpost/v1/pin` → 32-byte X25519 scalar → age `Identity` → `age::Encryptor::with_recipients([pin_recipient])`. Inner age layer; outer age layer remains v1.0 identity-recipient. **Nested**, not multi-recipient.
- `OuterRecord.pin_required: bool` (outer-signed, pre-decrypt readable; `skip_serializing_if = is_false`).
- `Envelope.burn_after_read: bool` (inner-signed, post-decrypt; `skip_serializing_if = is_false`).
- PIN salt encoding: `blob = base64(salt[32] || outer_age_ct)` ONLY when `pin_required=true`; non-pin shares retain v1.0 wire shape (`blob = base64(outer_age_ct)`).
- State-ledger inversion: `accepted.jsonl` rows gain `state: "accepted"|"burned"` field (v1.0 rows default to `accepted` via serde). `burned` rows written in **emit-before-mark** order (BURN-03). Pre-receive ledger check at earliest-possible point (after share_ref derived, before any decrypt) to short-circuit already-burned shares.
- Receive flow extension: pre-decrypt PIN prompt (after outer-verify, before age-decrypt); `[BURN — you will only see this once]` marker at TOP of acceptance banner before Purpose line; PIN prompt occurs BEFORE typed-z32 acceptance per PIN-06.
- Receipt publishes ALWAYS on successful burn-receive (BURN-04 — receipt = delivery confirmation, burn does not suppress attestation).
- Error-oracle hygiene: wrong PIN, wrong identity passphrase, wrong outer-sig, wrong inner-sig — all share identical user-facing Display, exit 4 for credential failures (PIN-07). Existing `signature_failure_variants_share_display` test extended.
- THREAT-MODEL.md additions: §X.Y "PIN mode" (second-factor semantics, Argon2id offline brute-force bound, intentional indistinguishability from wrong-key errors, no PIN logging anywhere); §X.Y "Burn mode" (local-state-only semantics, DHT-ciphertext-survives-TTL caveat, multi-machine race explicitly described, burn ≠ cryptographic destruction).
- SPEC.md PIN crypto section: Argon2id params (64 MB, 3 iter — matches cclink), HKDF namespace, wire blob layout (salt || outer_age_ct), UX order (PIN before z32), error-oracle constraint, 8-char entropy floor + anti-pattern validation.
- Compose tests: pin alone, burn alone, pin+burn, pin+burn+typed-material (each material variant), wrong-PIN-on-burn-share-doesn't-mark-burned, second-receive-on-burned-share returns exit 7.

**Out of scope (deferred or rejected):**
- `--pin-file`, `--pin-fd`, `CIPHERPOST_PIN` env (REQUIREMENTS PIN-01 defers all non-interactive PIN to v1.2+; SUMMARY.md draft listing `CIPHERPOST_PIN` and `--pin-file` is superseded).
- DHT-side burn (publishing empty packet to overwrite the share slot — cclink's pattern). Cipherpost burn is local-state-only; explicit BURN-08 caveat in THREAT-MODEL.md.
- PIN recovery — wrong PIN is indistinguishable from wrong key; lost PIN means lost share. Documented contract (REQUIREMENTS Out of Scope).
- Real-DHT cross-identity round trip — Phase 9.
- CAS racer test for concurrent receipt publication — Phase 9.
- Wire-budget escape hatch (two-tier / chunking / OOB delivery) for oversized pin+burn+typed-material composites — deferred to v1.2 per Phase 6/7 wire-budget deferral pattern; pin+burn+pgp wire-budget coexistence test (DHT-07) lands in Phase 9.

</domain>

<decisions>
## Implementation Decisions

### A. cclink survey + divergence (the lineage receipt)

- **D-P8-01 · cclink survey done at discuss-phase time; full divergence write-up lands in Plan 01 SUMMARY.** The Phase 8 prerequisite "cclink pin/burn survey before planning" (REQUIREMENTS Open Question; STATE.md pending todo) was BLOCKED during research due to access denial. At this discuss-phase, the cclink directory was reachable and surveyed. Findings:
  - **PIN KDF shape:** `cclink/src/crypto/mod.rs::pin_derive_key()` — Argon2id(PIN, salt[32]) → HKDF-SHA256 with info `cclink-pin-v1` → 32-byte key. Argon2id params: as constructed by `Argon2::new(Algorithm::Argon2id, V0x13, params)`; cipherpost matches "64 MB, 3 iter" per PIN-09.
  - **PIN AEAD path (cclink):** `pin_encrypt(plaintext, pin)` calls `chacha20poly1305` DIRECTLY with the derived key, returning `(ciphertext, salt)`. **Cipherpost cannot copy this verbatim** — CLAUDE.md `chacha20poly1305 only via age` rule prohibits direct AEAD calls. Cipherpost adapts: derived 32-byte key becomes an X25519 scalar wrapped into an age `Identity`; AEAD happens through `age::Encryptor::with_recipients([pin_recipient])`.
  - **HKDF namespace translation:** cclink `cclink-pin-v1` → cipherpost `cipherpost/v1/pin` (per existing domain-separation convention `cipherpost/v1/<context>`; CLAUDE.md load-bearing).
  - **BURN (cclink):** `cclink/src/commands/pickup.rs::252` — on self-pickup of a `--burn` record, cclink publishes an empty PKARR packet over the original DHT slot (revoke-style, mutates DHT state). **Cipherpost rejects this** per BURN-08 — burn is local-state-only; DHT ciphertext survives TTL; multi-machine race documented in THREAT-MODEL.md.
  - **Net divergence:** cipherpost forks cclink's KDF *shape* (Argon2id+HKDF parameters) but DIVERGES on (a) AEAD path (age nesting, not raw chacha) and (b) burn semantics (no DHT mutation). Plan 01 SUMMARY.md MUST contain this divergence write-up — parallels Phase 7's `07-01-ed25519-dalek-tree.txt` evidence-block pattern.
  - **STATE.md pending todo "Complete cclink pin/burn survey"** is now closeable; the survey lives in this CONTEXT.md and will be expanded in Plan 01 SUMMARY.

- **D-P8-02 · HKDF info string locked: `cipherpost/v1/pin`.** Resolves the REQUIREMENTS.md vs SUMMARY.md conflict. PIN-03 wording is canonical; SUMMARY.md `cipherpost/v1/pin_wrap` is a research draft superseded by REQUIREMENTS lock-in. Plan 01 task: extend the HKDF info enumeration test (existing for v1.0 contexts) with `cipherpost/v1/pin` to enforce non-empty + namespace-prefix invariant.

### B. Wire format (locked-and-faithful)

- **D-P8-03 · `OuterRecord.pin_required: bool` field.** Outer-signed, pre-decrypt readable. `#[serde(default, skip_serializing_if = "is_false")]` preserves v1.0 byte-identity for non-pin shares (no protocol_version bump). Receiver reads this BEFORE attempting age-decrypt to know whether to prompt for PIN. Matches PIN-04 verbatim.

- **D-P8-04 · `Envelope.burn_after_read: bool` field.** Inner-signed, post-decrypt. `#[serde(default, skip_serializing_if = "is_false")]` preserves v1.0 byte-identity for non-burn shares. **NOT** placed on OuterRecord — explicit anti-goal: DHT observers must not see which shares are burn-marked (CLAUDE.md principle 3 "ciphertext only on the wire; metadata encrypted"). Matches BURN-01 verbatim. **Rejected:** promote-to-OuterRecord — violates ciphertext-only-on-wire principle.

- **D-P8-05 · PIN salt encoding: conditional embed in blob.** When `pin_required=true`: `blob = base64(salt[32] || outer_age_ct)` — salt is at the TOP of the bytestream, OUTSIDE both age layers (must be readable BEFORE any age-decrypt to derive `pin_recipient`). When `pin_required=false`: `blob = base64(outer_age_ct)` — exactly v1.0 shape. Receiver dispatches on `pin_required`: branch A strips first 32 bytes for salt, decodes rest as age_ct; branch B decodes whole thing as age_ct. **Rejected:** always-two-tone (32-byte zero prefix when no pin) — invalidates every v1.0 JCS fixture; forces protocol_version bump. **Rejected:** separate `pin_salt: Option<[u8;32]>` field on OuterRecord — diverges from PIN-05 wording; cleaner but requires REQ amendment.

- **D-P8-06 · Nested age, NOT multi-recipient.** Sender flow when `pin_required=true`:
  1. `inner_ct = age_encrypt(pin_recipient, envelope_json_bytes)` — uses PIN-derived `Identity` as the only recipient; matches PIN-03 verbatim.
  2. `outer_ct = age_encrypt(receiver_identity_recipient, inner_ct)` — uses receiver's z-base-32 pubkey-derived recipient; v1.0 outer-encryption flow, unchanged structurally.
  3. `blob = base64(salt[32] || outer_ct)`.
  This makes BOTH the receiver's identity passphrase AND the PIN required (PIN-10 second-factor semantics). **Rejected:** multi-recipient `[identity, pin]` — `age` semantics give EITHER, not BOTH; violates PIN-10. **Rejected:** outer=pin, inner=identity — works equally well crypto-wise but breaks v1.0's "outer layer is identity-encrypt" mental model and forces non-pin shares to carry an identity-encrypt-of-identity-encrypt that doesn't match v1.0 byte-identity.

### C. Compose semantics (PIN × BURN × typed-material)

- **D-P8-07 · Receive flow ordering for the worst-case compose (pin+burn+typed-material):**
  1. Fetch PKARR DHT packet → parse OuterRecord.
  2. **Outer-verify (PKARR sig).** Tamper-zero invariant — fail here = exit 3, no PIN prompt, no ledger touch.
  3. **Derive `share_ref`** from `sha256(ciphertext || created_at_be).truncate(16)`.
  4. **Earliest-possible ledger pre-check** (D-P8-09): scan for `share_ref` in `accepted.jsonl`. If state=`burned` → exit 7 immediately ("share already consumed"). If state=`accepted` → idempotent-success path (existing v1.0 behavior). If absent → continue.
  5. Read `OuterRecord.pin_required`. If true:
     a. Strip first 32 bytes from b64-decoded blob → `salt`. Rest → `outer_ct`.
     b. **Prompt for PIN on TTY** (no echo). Wrong PIN at later age-decrypt fails with exit 4 + identical Display to wrong-identity (PIN-07).
  6. **Outer age-decrypt** with receiver's identity → produces `inner_ct` (when pin_required) or `envelope_json` (when not).
  7. **PIN-derive** `pin_recipient` from PIN + salt (only when pin_required).
  8. **Inner age-decrypt** with `pin_recipient` → produces `envelope_json`.
  9. **Inner-verify** envelope (Ed25519 over canonical JSON).
  10. **TTL check.**
  11. **Preview render** (typed material subblock from Phase 6/7).
  12. **Acceptance banner emission** (TtyPrompter):
      - Header line: `=== CIPHERPOST ACCEPTANCE ===========================`
      - **If `Envelope.burn_after_read=true`: `[BURN — you will only see this once]` marker** (D-P8-08).
      - Purpose, Sender, Share ref, Type, Size lines.
      - If material has secret-key warning (PGP secret per Phase 7): `[WARNING: SECRET key — unlocks cryptographic operations]`.
      - Material subblock (Phase 6/7 preview).
      - TTL line.
      - Footer + typed-z32 prompt.
  13. **Typed-z32 acceptance** — user pastes sender pubkey verbatim. Wrong z32 → exit 6 declined. NO ledger touch, NO emit, NO receipt.
  14. **Emit decrypted bytes to stdout** (with `--armor` PEM-wrap if applicable per Phase 6/7).
  15. **Append ledger row** with `state: "burned"` (if burn) or `state: "accepted"` (if not). **Emit-before-mark** for burn per BURN-03 / D-P8-12. Touch sentinel after ledger fsync.
  16. **Publish receipt** — ALWAYS, even on burn (BURN-04). Receipt = delivery confirmation; burn does not suppress attestation.

- **D-P8-08 · Banner: `[BURN — you will only see this once]` at TOP of header, before Purpose line.** Maximum visibility. Mirrors Phase 7's elevated SECRET-key warning placement. Stacks cleanly with `[WARNING: SECRET key]` in the worst-case pin+burn+pgp-secret-key compose:
  ```
  === CIPHERPOST ACCEPTANCE ============================
  [BURN — you will only see this once]
  Purpose:     "signing key handoff"
  Sender:      ed25519:SHA256:…
               yx8a3…iq8jo
  Share ref:   f4e5d6c7…
  Type:        pgp_key
  Size:        419 bytes
  [WARNING: SECRET key — unlocks cryptographic operations]

  --- OpenPGP ---------------------------------------------
  Fingerprint: …
  ...
  =========================================================
  To accept, paste the sender's z32 pubkey and press Enter:
  ```
  **Rejected:** inline-on-Type-line `Type: pgp_key [BURN]` — skim-past risk. **Rejected:** above-z32-prompt — user already mentally committed by then.

- **D-P8-09 · Ledger pre-check: earliest possible (after share_ref derived, before any decrypt).** Saves PIN prompt + outer/inner decrypts on already-burned shares. Receiver doesn't waste their time entering PIN for a share that's going to exit 7 anyway. Pre-check returns enum {None, Accepted, Burned}; caller branches on the variant. **Rejected:** check-after-all-decrypts — wastes user time. **Rejected:** check-after-typed-z32-acceptance — opens a TOCTOU window.

### D. State ledger (the burn inversion)

- **D-P8-10 · Ledger row gains `state: "accepted"|"burned"` field.** Single `accepted.jsonl` file (v1.0 path; rename rejected — would break existing receivers). v1.0 rows missing the field deserialize to `state: "accepted"` via serde default. Burn rows write `state: "burned"`. `check_already_consumed()` (renamed from `check_already_accepted`) returns enum:
  ```rust
  enum LedgerState {
      None,
      Accepted { accepted_at: String },
      Burned { burned_at: String },
  }
  ```
  Caller branches: `Accepted` → idempotent-success (existing v1.0 behavior); `Burned` → exit 7; `None` → proceed. **Rejected:** separate `burned/` dir + `burned.jsonl` — doubles state-management surface; harder migration if semantics change. **Rejected:** sentinel-filename-encodes-state (`accepted/<share_ref>.burned`) — hides state from ledger inspection; awkward to audit.

- **D-P8-11 · Ledger row write order for burn: ledger row FIRST, then sentinel touched.** Inverts v1.0's sentinel-first / ledger-second order, but only for the BURN case — v1.0 acceptance flow is unchanged (still mark-then-emit). Burn sequence: emit bytes to stdout → fsync stdout → append `state: burned` row to `accepted.jsonl` → fsync ledger → touch sentinel. Crash between ledger-and-sentinel: next receive scans ledger, sees burned row, treats as burned (sentinel optional fast-path; ledger is canonical). **Rejected:** sentinel-first for burn — contradicts BURN-03 emit-before-mark. **Rejected:** atomic-rename-encoded-state — clever but auditing pain.

- **D-P8-12 · Emit-before-mark for burn (BURN-03 lock).** Resolves the REQUIREMENTS-vs-PITFALLS conflict: BURN-03 requires emit-then-mark; PITFALLS #26 said keep mark-then-emit. **Resolution:** PITFALLS #26 is OUTDATED (predates BURN-03 lock-in); BURN-03 wins. Rationale recorded: crash between emit and ledger-write leaves share re-receivable (user keeps access — safer failure mode); the inverse (mark before emit) loses user's data on crash. v1.0's `accepted` ordering is UNCHANGED — mark-then-emit there preserves idempotent-success semantics. The two flows have OPPOSITE atomicity contracts because `burned` represents a one-shot consume while `accepted` represents idempotent persistence. Plan 04 (BURN ship-gate) MUST update PITFALLS.md #26 to record the resolution (or supersede it with a new note).

### E. Plan structure + sequencing

- **D-P8-13 · 6 plans total: PIN core / PIN ship-gate / BURN core / BURN ship-gate / compose / docs.** Mirrors Phase 6's 4-plan core+ship-gate sequence applied twice, plus a compose plan and a docs plan. Each feature gets crypto/UX in plan N, then test+fixture+SPEC in plan N+1. Plans 5-6 are integration: compose tests cross-feature; docs consolidate THREAT-MODEL.md + SPEC.md + cclink-divergence write-up. **Rejected:** 4-plan tight (each plan too big; PIN churn slows BURN). **Rejected:** 8-plan mirror-Phase-7 (BURN's 9 reqs spread thin; make-work). **Rejected:** 5-plan compress (compose+ship-gate plan would carry too much).
  - **Plan 01 — PIN crypto core:** `src/pin.rs` module (or extension to `src/crypto.rs` — planner picks); `pin_derive_key`, `pin_encrypt_inner`, `pin_decrypt_inner`; argon2 dependency confirmation (`argon2 = "0.5"` already present per SUMMARY); HKDF info `cipherpost/v1/pin`; OuterRecord `pin_required` field; salt encoding in blob; cclink-divergence write-up in plan SUMMARY.md.
  - **Plan 02 — PIN ship-gate:** PIN validation rules (8-char min, no all-same, no sequential per PIN-02); CLI `--pin` flag; TTY prompt path; wrong-PIN error-oracle hygiene (extend existing `signature_failure_variants_share_display` test); JCS fixture `tests/fixtures/outer_record_pin_required_signable.bin`; full PIN-only round-trip integration test under MockTransport (PIN-08 (a)/(b)/(c) matrix); SPEC.md PIN crypto section.
  - **Plan 03 — BURN core:** `Envelope.burn_after_read` field; ledger `state` field migration with serde default; `check_already_consumed()` + `LedgerState` enum; CLI `--burn` flag; send-time stderr warning per BURN-05.
  - **Plan 04 — BURN ship-gate:** Receive flow burn integration (early ledger pre-check, banner [BURN] marker, emit-before-mark write order); BURN-only round-trip integration test under MockTransport (BURN-09); PITFALLS.md #26 resolution note (D-P8-12).
  - **Plan 05 — Compose tests:** pin×burn matrix on each typed-material variant (generic-secret, x509-cert, pgp-key, ssh-key); wrong-PIN-on-burn-share-doesn't-mark-burned; second-receive-on-burned-share returns exit 7; typed-z32-declined-on-burn-doesn't-mark-burned; receipt-published-on-burn (BURN-04 explicit assertion).
  - **Plan 06 — Docs:** THREAT-MODEL.md §X.Y "PIN mode" + §X.Y "Burn mode"; SPEC.md final consolidation (PIN crypto stack, blob layout, error-oracle constraint, banner UX); CLAUDE.md load-bearing additions (HKDF info, ledger state field invariant, emit-before-mark contract for burn).

- **D-P8-14 · PIN-first sequencing.** Crypto-heavy half tackled first while context is fresh. BURN inherits any scaffolding (e.g., banner-ordering helper from PIN's `[PIN required]` — wait, PIN doesn't add a banner marker per current REQ; banner only changes for BURN). cclink-divergence write-up lands in Plan 01 SUMMARY.md (parallels Phase 7's evidence-block pattern). **Rejected:** BURN-first — quick-win bias overweights for solo-builder velocity vs. crypto-correctness focus. **Rejected:** parallel-track interleave — premature optimization.

- **D-P8-15 · Worktrees stay disabled for Phase 8.** Same rationale as Phase 7 (D-P7-18). 6 plans × Phase-6-pace ≈ 1.5 hours sequentially; SPEC.md and THREAT-MODEL.md are touched by both PIN and BURN ship-gate plans + docs plan — parallel execution would create merge conflicts. Re-evaluate when a phase has 6+ genuinely independent plans with non-overlapping `files_modified`.

- **D-P8-16 · Wave structure: strictly sequential, one plan per wave, all 6 plans autonomous.** `autonomous: true` in every plan's frontmatter. No human-checkpoints. No inter-plan parallelism.

### Claude's Discretion

- Argon2id salt-buffer reuse: `Zeroizing<[u8; 32]>` vs new buffer per call. Planner picks. Both satisfy CLAUDE.md zeroize rule.
- Whether `src/pin.rs` is a new file or an extension to `src/crypto.rs`. Phase 6 set the precedent for new files (`src/preview.rs`, `src/payload/ingest.rs`). Phase 8 likely follows but planner picks.
- Exact wording of the `Error::PinTooWeak` reasons (analogous to Phase 6's `Error::InvalidMaterial { reason }`). Curated short literals; oracle-hygiene enumeration test enforces.
- Whether `LedgerState` enum lives in `src/state.rs` (new) or `src/flow.rs` (existing). Most ledger code is currently in `flow.rs`; planner picks the right extraction boundary.
- Whether the PIN prompt re-tries on wrong PIN, or single-shot fails immediately. PIN-01 doesn't say. Recommendation: single-shot fail; matches v1.0 passphrase prompt behavior; avoids brute-force-via-rapid-retry. Planner confirms.
- Whether to clobber-protect against running `cipherpost send --pin` on a non-TTY context (no PIN source). Recommendation: hard exit 1 with message "`--pin` requires interactive TTY (non-interactive PIN sources deferred to v1.2)".
- Banner separator widths and exact dash counts in compose case (matches Phase 7 conventions).
- Whether the receipt for a burn share carries a different field or marker. Recommendation: NO — receipt is identical shape to non-burn (BURN-04 just says receipt is published); burn-fact is recoverable from the share's `burn_after_read` flag in the Envelope sender already has.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` §PIN encryption mode — PIN-01..10 (inline phase tags)
- `.planning/REQUIREMENTS.md` §Burn-after-read mode — BURN-01..09 (inline phase tags)
- `.planning/REQUIREMENTS.md` §Out of Scope — PIN recovery, cryptographic burn destruction, non-interactive PIN, server/relay all explicitly rejected
- `.planning/REQUIREMENTS.md` §Deferred Requirements (v1.2+) — DEFER-PIN-01/02 (`--pin-file`, `--pin-fd`)
- `.planning/ROADMAP.md` §Phase 8 — goal + success criteria

### Source-of-truth lineage
- `cclink/src/crypto/mod.rs` — `pin_derive_key()` (line 144), `pin_encrypt()` (line 171), `pin_decrypt()` (line 195). **Cipherpost reuses KDF shape; DIVERGES on AEAD path** (D-P8-01).
- `cclink/src/commands/pickup.rs` — burn handling (line 252). **Cipherpost rejects DHT-revoke; burn is local-state-only** (D-P8-01, BURN-08).
- `cclink/src/cli.rs` + `cclink/src/commands/publish.rs` — `--burn` flag pattern at sender side (line 197). Cipherpost mirrors flag UX; diverges on receiver-side handling.

### Phase 6/7 locked-in patterns (DO NOT re-derive)
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` §C Acceptance banner layout — inline subblock pattern, banner header conventions; Phase 8 extends with `[BURN]` marker placement (D-P8-08)
- `.planning/phases/07-typed-material-pgpkey-sshkey/07-CONTEXT.md` §B PGP secret-key warning placement (D-P7-07) — Phase 8 banner stacks `[BURN]` marker WITH `[WARNING: SECRET key]` per D-P8-08
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` §B Error-oracle hygiene (D-P6-08) — Phase 8 extends `EXPECTED_REASONS` for PIN error paths and the enumeration test for HKDF info `cipherpost/v1/pin` (D-P8-02)
- `.planning/phases/06-typed-material-x509cert/06-04-PLAN.md` (ship-gate template) — Phase 8 plans 02, 04 mirror this template (fixture → JCS byte-identity → ingest negative matrix → golden-string banner → oracle-hygiene → leak-scan → SPEC update)

### Domain pitfalls (load-bearing)
- `.planning/research/PITFALLS.md` #23 — PIN-as-distinguishable-oracle; mitigation enforced by D-P8-02 (HKDF info enumeration test extension) and oracle-hygiene Display equality
- `.planning/research/PITFALLS.md` #24 — PIN entropy floor; PIN-02 + planner-side anti-pattern validation
- `.planning/research/PITFALLS.md` #25 — burn-is-local-state-only; THREAT-MODEL.md additions per D-P8-13 (Plan 06)
- `.planning/research/PITFALLS.md` #26 — **OUTDATED**; superseded by D-P8-12 emit-before-mark for burn. Plan 04 must record the resolution.
- `.planning/research/PITFALLS.md` #36 — per-variant size checks before JCS encode; Phase 8 inherits naturally (no new variants this phase)
- `.planning/research/SUMMARY.md` §Open Questions — cclink survey CLOSED at this phase (D-P8-01); pkarr bootstrap question still open for Phase 9

### Project conventions (CLAUDE.md load-bearing)
- `CLAUDE.md` §Load-bearing lock-ins — `chacha20poly1305 only via age` (load-bearing for D-P8-06 nesting choice); HKDF info `cipherpost/v1/<context>` (load-bearing for D-P8-02); identity path `~/.cipherpost/` mode 0600 (load-bearing for ledger writes); error-oracle hygiene (load-bearing for D-P8-12 Display equality across credential failures); `serial_test = "3"` + `#[serial]` for env-mutating tests
- `CLAUDE.md` §Architectural lineage — fork-and-diverge from cclink (D-P8-01 makes the divergence explicit and recordable)
- `.planning/PROJECT.md` §Constraints — 64 KB plaintext cap; no relay/operator; ciphertext-only-on-wire (load-bearing for D-P8-04 Envelope-not-OuterRecord placement)
- `.planning/PROJECT.md` §Key Decisions — burn+receipt = Option A (receipt IS published per BURN-04)

### Spec sections to edit in Phase 8
- `SPEC.md` §3.X PIN crypto stack (NEW) — Argon2id params, HKDF namespace, salt encoding, nested-age structure, wire blob layout, UX order, error-oracle constraint, 8-char floor + anti-pattern validation (PIN-09)
- `SPEC.md` §3.X Burn semantics (NEW) — local-state-only, ledger inversion (emit-before-mark), DHT-ciphertext-survives-TTL, receipt-still-published
- `SPEC.md` §5.1 CLI — extend `Send` with `--pin` (TTY-only) and `--burn`; document `--pin <value>` rejection at parse + runtime; add cross-reference to deferred non-interactive PIN
- `SPEC.md` §5.2 Acceptance banner — `[BURN — you will only see this once]` placement (top, before Purpose); PIN prompt order (after outer-verify, before age-decrypt, BEFORE typed-z32)
- `SPEC.md` §6 Exit-code taxonomy — exit 4 covers wrong-PIN (same Display as wrong-identity per PIN-07); exit 7 covers `share already consumed` (BURN-02)
- `SPEC.md` §Pitfall #22 — wire-budget continues; pin+burn+typed-material composite size measurement deferred to Phase 9 (DHT-07)
- `THREAT-MODEL.md` §X.Y "PIN mode" (NEW per PIN-10)
- `THREAT-MODEL.md` §X.Y "Burn mode" (NEW per BURN-08)
- `CLAUDE.md` §Load-bearing lock-ins — add HKDF info `cipherpost/v1/pin`; add ledger `state` field invariant; add emit-before-mark contract (D-P8-12)

### Existing code — primary edit sites (paths as of HEAD after Phase 7 close)
- `src/pin.rs` — NEW (or extension to `src/crypto.rs`; planner picks). `pin_derive_key`, `pin_encrypt_inner`, `pin_decrypt_inner`, `validate_pin` (8-char + anti-pattern). HKDF info `cipherpost/v1/pin` literal.
- `src/record.rs` — `OuterRecord` + `OuterRecordSignable`: add `pin_required: bool` field with `#[serde(default, skip_serializing_if = "is_false")]`. JCS fixture regen for outer record signable variant.
- `src/payload/mod.rs` — `Envelope`: add `burn_after_read: bool` field with `#[serde(default, skip_serializing_if = "is_false")]`. JCS fixture regen for envelope-burn variant.
- `src/flow.rs` — `run_send`: pin-wrap + burn-flag-set branch points; `run_receive`: early ledger pre-check (D-P8-09), PIN prompt step, outer-then-inner age-decrypt (D-P8-06), banner [BURN] marker (D-P8-08), emit-before-mark ordering (D-P8-12). `check_already_consumed()` rename + `LedgerState` enum (D-P8-10).
- `src/cli.rs` — `Send` struct: add `pin: bool` (`--pin`, TTY-only) and `burn: bool` (`--burn`); reject argv-inline `--pin <value>` at clap parse + runtime per existing passphrase rejection pattern.
- `src/main.rs` — Send/Receive dispatch: thread `pin` and `burn` flags to `run_send` / `run_receive`.
- `src/error.rs` — `Error::PinTooWeak { reason: String }` (Display generic per oracle-hygiene); `Error::ShareAlreadyConsumed` → exit 7 mapping.
- `src/lib.rs` — pub-export `pin` module if new file.
- NEW: `tests/fixtures/outer_record_pin_required_signable.bin` (Plan 02)
- NEW: `tests/fixtures/envelope_burn_signable.bin` (Plan 04)
- NEW: `tests/pin_roundtrip.rs` — PIN-08 matrix (a)/(b)/(c) under MockTransport
- NEW: `tests/burn_roundtrip.rs` — BURN-09 (two consecutive receives: exit 0 then exit 7; receipt-count = 1)
- NEW: `tests/pin_burn_compose.rs` — pin×burn×each typed-material variant; wrong-PIN-on-burn doesn't-mark-burned; typed-z32-declined-on-burn doesn't-mark-burned
- NEW: `tests/pin_error_oracle.rs` — wrong-PIN Display vs wrong-identity-passphrase Display vs sig-failure Displays — all identical strings
- `tests/state_ledger.rs` — extend with `state` field default-deserialization test (v1.0 rows still parse as Accepted)

### Dependency additions
- **NONE.** Phase 8 uses already-present `argon2 = "0.5"`, `hkdf` (transitive via age?), `age` (already pulled). Verify at Plan 01 time via `cargo tree | grep -E "^argon2|^hkdf|^age"`. If `hkdf` is not directly available, add `hkdf = "0.12"` in Plan 01 (matches cclink's). Per SUMMARY.md "Phases 5, 8, 9: zero new crates."

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets (Phase 1-7 shipped)
- `src/flow.rs::accepted_dir() / ledger_path() / append_ledger_entry()` — v1.0 ledger plumbing. Phase 8 extends `append_ledger_entry()` to write the new `state` field; reuses the path conventions verbatim.
- `src/flow.rs::check_already_accepted()` — renames to `check_already_consumed()` with new return type `LedgerState` enum (D-P8-10). Existing callers updated.
- `age::Encryptor::with_recipients` — used in v1.0 for outer-encrypt-to-receiver-identity. Phase 8 reuses verbatim for both layers in nested-age (D-P8-06).
- `age::Decryptor` — used in v1.0 receive flow. Phase 8 calls TWICE per receive when pin_required (outer with identity, inner with pin_recipient).
- `argon2 = "0.5"` already pulled (per SUMMARY.md research; verify at Plan 01).
- `hkdf` — needs verification at Plan 01 whether direct dep or transitive via age.
- v1.0's `Error::SignatureOuter`, `SignatureInner`, `SignatureCanonicalMismatch` — Phase 8 EXTENDS the oracle-hygiene Display equality with wrong-PIN variants. Existing test `signature_failure_variants_share_display` is the template.
- v1.0's typed-z32 acceptance prompt path — Phase 8 prepends `[BURN]` marker BEFORE this prompt's banner emission. Prompter trait extension from Phase 6/7 already supports the `Option<&str>` preview-subblock parameter.
- v1.0's `share_ref` derivation — `sha256(ciphertext || created_at_be).truncate(16)` — Phase 8 reuses unchanged for the early ledger pre-check (D-P8-09).
- v1.0's `serial_test = "3"` + `#[serial]` convention for env-mutating tests — Phase 8 marks PIN tests `#[serial]` because they may set `CIPHERPOST_HOME`.

### Established Patterns (Phase 6-7)
- Per-variant ship-gate plan template: foundation → preview/UX → wiring → ship-gate (fixtures + tests + SPEC update + dep-tree guard). Phase 8's plans 01+02 (PIN) and 03+04 (BURN) compress to 2-plan pairs because each feature is more cohesive than the typed-material variants were.
- Manual `Debug` redaction on byte-holding structs (no `#[derive(Debug)]`) — extends to PIN salt buffer, derived key buffer, nested age ciphertext intermediate.
- `EXPECTED_REASONS` constant-table oracle-hygiene matrix — Phase 8 adds PIN error path reasons to the table; the enumeration test exhaustively asserts no Display leaks.
- JCS fixture discipline: committed bytes at `tests/fixtures/<context>_signable.bin`; property test asserts byte-for-byte determinism across regen.
- `cargo tree` dep-tree guards — Phase 8 has zero new crates but Plan 01 still asserts `argon2` + `age` versions remain pinned and `chacha20poly1305` does NOT appear as a direct dep (only transitive via age).
- `#[serial]` on env-mutating tests — Phase 8 inherits.

### Integration Points
- `src/flow.rs::run_send` step ordering: Phase 8 inserts a pin-wrap step BEFORE the existing outer age-encrypt; sets `OuterRecord.pin_required` and prepends salt to blob bytestream.
- `src/flow.rs::run_receive` step ordering: Phase 8 inserts (a) early ledger pre-check after share_ref derive, (b) PIN prompt after outer-verify, (c) inner age-decrypt after outer age-decrypt when pin_required, (d) `[BURN]` marker injection at banner emission, (e) emit-before-mark ordering for ledger write.
- `src/cli.rs::Send` and `src/cli.rs::Receive` (or wherever burn-flag-not-needed-on-receive — receiver discovers burn from envelope, not flag): `--pin` and `--burn` flags on send; receive auto-detects pin_required + burn_after_read from the share metadata. NO new receive flags.
- `src/error.rs` exit-code taxonomy unchanged: exit 4 absorbs wrong-PIN (matches wrong-identity-passphrase); exit 7 absorbs `share already consumed`.
- `src/record.rs::OuterRecord` and `src/payload/mod.rs::Envelope` — additive fields; v1.0 byte-identity preserved via skip_serializing_if.
- THREAT-MODEL.md and SPEC.md — additive sections; no edits to v1.0 prose beyond cross-references.
- NO change to PKARR publish path, transport, identity-keypair generation, or HKDF contexts other than the new `cipherpost/v1/pin` literal.

### Anti-patterns to avoid (carried from earlier phases + this discussion)
- Do NOT call `chacha20poly1305` directly. PIN crypto wraps the derived key into an age `Identity` and uses `age::Encryptor::with_recipients`. CLAUDE.md load-bearing.
- Do NOT add a distinct `Error::PinIncorrect` variant with its own Display. Wrong PIN must surface with the SAME user-facing message and exit code as wrong identity passphrase. PIN-07 + oracle-hygiene enumeration test enforces.
- Do NOT mutate the DHT slot on burn. Burn is local-state-only. Cipherpost diverges from cclink on this point. BURN-08 + THREAT-MODEL.md.
- Do NOT publish a receipt for a burn share that failed inner-verify or wrong-PIN. Tamper-zero invariant: receipt comes ONLY after full verify + acceptance + emit. BURN-04 says receipt IS published, but only after success.
- Do NOT log PIN bytes anywhere — not stderr, not Debug, not panic messages. PIN-10 + leak-scan test extension.
- Do NOT prompt for PIN before outer-verify. Tamper-zero invariant: outer-verify is the gate; failures here must produce exit 3 with no PIN-prompt side effect.
- Do NOT mark `burned` BEFORE emit. Crash between mark-and-emit loses user's data. D-P8-12 inverts v1.0's mark-then-emit ordering specifically for burn.
- Do NOT assume `--pin-file` or `--pin-fd` exist. PIN-01 defers to v1.2; SUMMARY.md draft listing them is OUTDATED.
- Do NOT promote `burn_after_read` to OuterRecord. DHT observers must not see burn-marked shares. CLAUDE.md principle 3.
- Do NOT reuse the v1.0 `accepted` mark-then-emit ordering for burn. The two state types have OPPOSITE atomicity contracts (D-P8-12).
- Do NOT skip the cclink-divergence write-up in Plan 01 SUMMARY. The fork-and-diverge lineage is THE reason this phase exists in this shape (D-P8-01).

</code_context>

<specifics>
## Specific Ideas

- **Banner mockup (worst-case compose: pin + burn + pgp-secret-key):**
  ```
  === CIPHERPOST ACCEPTANCE ===============================
  [BURN — you will only see this once]
  Purpose:     "signing key handoff for alice@example"
  Sender:      ed25519:SHA256:…
               yx8a3…iq8jo
  Share ref:   f4e5d6c7…
  Type:        pgp_key
  Size:        419 bytes
  [WARNING: SECRET key — unlocks cryptographic operations]

  --- OpenPGP ---------------------------------------------
  Fingerprint: 4AEE18F83AFDEB23A89D1F25E81CAB3E6C9A2F4B
  Primary UID: Alice Example <alice@example.com>
  Key:         Ed25519
  Subkeys:     2 (Ed25519, ECDH-X25519)
  Created:     2024-03-15 10:22 UTC
  TTL:         23h remaining (expires 2026-04-26 13:11 UTC / 2026-04-26 09:11 EDT local)
  =========================================================
  To accept, paste the sender's z32 pubkey and press Enter:
  ```

- **PIN prompt (sender-side, send time):**
  ```
  $ cipherpost send --pin --share <z32> < secret.bin
  Enter PIN (8+ chars, no all-same, no sequential): ********
  Confirm PIN: ********
  ⚠ --burn is local-state-only; ciphertext remains on DHT until TTL (24h
    by default). This prevents YOUR second decryption, not a second machine's.
  Sent. Share ref: f4e5d6c7…
  ```
  (the `⚠` warning only when `--burn` is also set; PIN confirm prompt is double-entry per cipherpost passphrase-confirm convention.)

- **PIN prompt (receiver-side, receive time, BEFORE typed-z32 banner):**
  ```
  $ cipherpost receive --share-ref f4e5d6c7…
  This share is PIN-protected. Enter PIN: ********

  === CIPHERPOST ACCEPTANCE ===============================
  [BURN — you will only see this once]
  ...
  ```
  (PIN prompt is rendered to stderr above the banner, so stdout-piping doesn't see it.)

- **Wire format examples:**

  Non-pin, non-burn share (v1.0 byte-identity):
  ```json
  {
    "blob": "<base64(age_encrypt_to_identity(envelope_json))>",
    "created_at": 1745784000,
    "purpose": "...",
    "share_ref": "f4e5d6c7..."
  }
  ```

  Pin share (no burn):
  ```json
  {
    "blob": "<base64(salt[32] || age_encrypt_to_identity(age_encrypt_to_pin(envelope_json)))>",
    "created_at": 1745784000,
    "pin_required": true,
    "purpose": "...",
    "share_ref": "f4e5d6c7..."
  }
  ```
  (Note: `pin_required` field is JCS-alphabetically between `created_at` and `purpose`, automatic via JCS.)

  Burn share (no pin), Envelope after age-decrypt:
  ```json
  {
    "burn_after_read": true,
    "created_at": 1745784000,
    "material": {...},
    "protocol_version": 1,
    "purpose": "...",
    "ttl_seconds": 86400
  }
  ```

- **Ledger row examples (`accepted.jsonl`):**
  ```jsonl
  {"share_ref":"f4e5d6c7","accepted_at":"2026-04-25T13:11:42Z","purpose":"..."}
  {"share_ref":"a1b2c3d4","accepted_at":"2026-04-25T14:22:18Z","state":"burned","purpose":"signing key handoff"}
  ```
  (v1.0 row missing `state` field; deserialize via serde default to Accepted. v1.1 burn row carries explicit `state: burned`.)

- **HKDF info enumeration test extension:** existing test walks every HKDF call-site and asserts non-empty + `cipherpost/v1/<context>` prefix. Phase 8 Plan 01 adds `cipherpost/v1/pin` to the expected literals. Mirrors the v1.0 baseline pattern.

- **Error-oracle Display equality test extension:** existing `signature_failure_variants_share_display` test asserts `format!("{}", err)` is identical across `Error::SignatureOuter`, `SignatureInner`, `SignatureCanonicalMismatch`. Phase 8 Plan 02 adds `Error::PinIncorrect` (or whatever the variant is named — could be folded into existing PassphraseIncorrect path) to the equivalence class. Wrong PIN, wrong identity passphrase, sig failures — all identical Display, exit 4 (or 3 for sig-specific).

- **Compose test fixtures:** for each typed-material variant (generic-secret, x509-cert, pgp-key, ssh-key), write a pin+burn+variant fixture under `tests/fixtures/` and assert byte-for-byte JCS determinism. Mirrors Phase 6/7 fixture discipline; per-variant ledger entries in `tests/pin_burn_compose.rs` walk through full receive-flow and assert state transitions.

- **Plan 06 (docs) THREAT-MODEL.md insertion points:** `§X.Y "PIN mode"` after existing v1.0 sections on `Tamper-zero invariant` (parallel to existing per-property sections); `§X.Y "Burn mode"` immediately after PIN section. Both sections include: (1) what the property is, (2) what attacker capabilities it covers, (3) what attacker capabilities it does NOT cover, (4) test references in `tests/`.

</specifics>

<deferred>
## Deferred Ideas

- **Non-interactive PIN sources (`--pin-file`, `--pin-fd`, `CIPHERPOST_PIN`)** — DEFER-PIN-01/02 in REQUIREMENTS.md. v1.2+. Rationale: v1.1 keeps PIN as intentionally human-in-the-loop second factor; automated-script receive of PIN-required share is anti-pattern for the threat model.
- **DHT-side burn (publish empty packet over slot, cclink-style)** — explicit BURN-08 rejection. Cipherpost burn is local-state-only by design. Not a deferral; a contract.
- **Cryptographic burn destruction** — out-of-scope per REQUIREMENTS Out of Scope. Public DHT ciphertext cannot be force-deleted.
- **PIN recovery** — out-of-scope. Wrong PIN is indistinguishable from wrong key; lost PIN means lost share. Documented contract.
- **Multi-machine burn coordination** — multi-machine race documented as caveat in THREAT-MODEL.md (BURN-08); not solved. Future milestone if anyone asks.
- **PIN retry counter / lockout** — single-shot fail (Claude's discretion default). Brute-force resistance comes from Argon2id cost (64 MB, 3 iter), not retry limits. If demand for lockout surfaces, separate phase.
- **Wire-budget escape hatch for pin+burn+typed-material composites** — Phase 9 (DHT-07) measures the worst-case (pin+burn+pgp ~2KB); if it exceeds OuterRecord budget, fix happens in v1.2 wire-budget delivery-mechanism milestone. Phase 8 just MUST surface clean `WireBudgetExceeded` errors per Phase 6/7 pattern.
- **`--pin` on identity generate** — out-of-scope; identity has its own passphrase contract; PIN is share-level, not identity-level.
- **`--pin` rotation / change-PIN-on-existing-share** — impossible without re-sending; share is immutable on DHT once published. Document as natural contract.
- **PIN strength meter / live feedback** — out-of-scope UX polish. v1.1 ships the validation rules (PIN-02); UX feedback can come later if useful.
- **Burn confirmation prompt** — `[BURN — you will only see this once]` banner marker is the warning. Adding an "Are you sure?" prompt before z32 typed-acceptance would be redundant friction. Consider only if user reports of accidental burns surface.
- **Burn sentinel TTL / cleanup** — burned ledger entries accumulate forever. Cleanup tooling deferred until disk usage matters.
- **Different state-ledger format (e.g., SQLite, structured DB)** — append-only JSONL is the v1.0 contract; preserved here. State migration to a structured DB is a v2.0 concern at earliest.
- **Dedicated `cipherpost burn <share-ref>` command (mark burned without emit)** — out-of-scope. Burn is a receive-mode property, not a separate command. If users want to "discard without reading", they currently can `receive > /dev/null` then the ledger is marked burned anyway.
- **Send-time `--pin <value>` argv-inline** — argv-inline rejected at parse and runtime, mirroring v1.0's passphrase contract (CLAUDE.md "argv-inline is rejected"). Consistent with PIN-01 TTY-only constraint.

</deferred>

---

*Phase: 08-pin-and-burn-encryption-modes*
*Context gathered: 2026-04-25*
*cclink survey closed at this phase (D-P8-01).*
