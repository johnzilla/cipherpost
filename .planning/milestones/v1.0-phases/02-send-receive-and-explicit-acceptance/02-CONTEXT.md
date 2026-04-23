# Phase 2: Send, receive, and explicit acceptance - Context

**Gathered:** 2026-04-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver the user-visible core round trip. A sender can hand off a generic-secret payload to themselves (`cipherpost send --self`) or to a named recipient (`cipherpost send --share <pubkey>`). A recipient can retrieve, verify both signatures before decryption, enforce TTL on the inner signed timestamp, see a full-fingerprint acceptance screen with the sender-attested purpose, and — only on explicit typed confirmation — receive the decrypted material on stdout or `-o <path>`. CLI ergonomics (`-` stdin/stdout, exit-code taxonomy, `cipherpost version`, passphrase hygiene) land alongside the first user-visible commands so the skeleton cannot calcify a different answer in Phase 3.

Signed receipt publication (RCPT-*) and the resolve-merge-republish transport extension (TRANS-03) are Phase 3. Phase 2 acceptance updates the local state ledger only; the receipt DHT publish is deferred.

**Requirements owned:** PAYL-01..05, SEND-01..05, RECV-01..06, CLI-01..05 (21 reqs).

</domain>

<decisions>
## Implementation Decisions

### Payload size model
- **D-PS-01:** Two-layer enforcement. **Plaintext cap = 64 KB** (PAYL-03 / PROJECT.md wording honored). Reject plaintext > 64 KB before any crypto with `payload exceeds 64 KB limit: actual=N, cap=65536`. **Wire-budget cap = PKARR/BEP44 ~1000 bytes encoded SignedPacket** (SEND-05). When the encrypted packet exceeds the wire budget, fail at publish time with a DISTINCT error: `share too large for PKARR packet: encoded=N bytes, budget=~1000 bytes (plaintext was K bytes)`. Two separate error paths, two separate `Error` variants (extend from Phase 1's `PayloadTooLarge`).
- **D-PS-02:** `cipherpost send` rejects over-budget packets — no warn-and-publish, no silent chunking. Error text names both actual size and budget. Skeleton does not ship multi-packet chunking; v1.1+ may add `--chunk` as a future flag (tracked as a deferred idea, not mentioned in Phase 2 error strings).
- **D-PS-03:** Phase 2 size-cap integration test per ROADMAP SC4: feed a 65537-byte plaintext to `cipherpost send`, assert rejection with an error whose text contains both `65537` and `65536` (the cap). Pure client-side check, pre-encrypt. A separate assertion (Phase 1 already has `signed_packet_budget.rs` for a representative payload; extend with a Phase 2 case) covers the wire-budget path.

### Share URI format
- **D-URI-01:** URI format = `cipherpost://<sender-z32>/<share_ref_hex>`. Example: `cipherpost://yhigci4xwmadibrmj8wzmf45f3i8xg8mht9abnprq3r5cfxihj8y/0123456789abcdef0123456789abcdef`. Length ≈ 99 chars. Single copy-paste token. Scheme marker `cipherpost://` signals protocol; z32 is the sender's PKARR pubkey used to resolve; share_ref_hex is the 32-char hex of the 128-bit share_ref (already locked in Phase 1).
- **D-URI-02:** On `receive`, if the URI's `share_ref_hex` mismatches the resolved `OuterRecord.share_ref`, abort with a distinct error — add `Error::ShareRefMismatch` variant, exit code `1` (falls into the generic-error slot of CLI-02's taxonomy; do NOT reuse exit 3, which is reserved for signature failures, nor exit 5, which is NotFound). Error text: `share_ref in URI does not match resolved record; sender may have republished — re-confirm the URI`.
- **D-URI-03:** `receive` strictly requires the full `cipherpost://` URI. Bare z32 input is rejected with `expected cipherpost:// URI, got bare pubkey; use the URI that \`send\` printed`. No "convenience" fallback — uniform input shape makes the `ShareRefMismatch` defense reliable.

### Payload wire format
- **D-WIRE-01:** Envelope binding is implicit. `OuterRecordSignable` keeps its Phase 1 shape unchanged: `{blob, created_at, protocol_version, pubkey, recipient, share_ref, ttl_seconds}`. No `ciphertext_hash` or `cleartext_hash` fields added at the outer layer. Envelope contents (purpose, material) are authenticated by the composition of (a) outer inner-sig over JCS of `OuterRecordSignable` (which covers `blob`), and (b) age AEAD's Poly1305 tag inside the blob. Phase 3's Receipt hashes are computed by the recipient post-decrypt — sender does not pre-commit. Consistent with CLAUDE.md "ciphertext only on the wire; metadata encrypted too."
- **D-WIRE-02:** `Envelope` struct = `{purpose: String, material: Material, created_at: i64, protocol_version: u16}` (PAYL-01). Serialized as JCS, then age-encrypted to produce the blob. `Envelope.created_at` matches `OuterRecordSignable.created_at` (single timestamp for the share). `Envelope.protocol_version` matches the crate-level `PROTOCOL_VERSION: u16 = 1`.
- **D-WIRE-03:** `Material` enum serde = `#[serde(tag = "type", rename_all = "snake_case")]`. On-wire shape: `{"type": "generic_secret", "bytes": "<base64-std-padded>"}`. Variant names: `generic_secret`, `x509_cert`, `pgp_key`, `ssh_key`. Non-`generic_secret` variants are unit or struct stubs that return `Err(Error::NotImplemented { phase: ... })` on encode or decode, so round-trip of a foreign generic_secret share works but a cert share produced by a future version is rejected cleanly.
- **D-WIRE-04:** `GenericSecret.bytes` wire encoding = base64 standard with padding via `base64::engine::general_purpose::STANDARD`. Matches Phase 1's codec choice for `OuterRecord.signature` and `OuterRecord.blob` — single base64 codec in the codebase. Purpose: consistency; ban `URL_SAFE_NO_PAD` at this layer.
- **D-WIRE-05:** Purpose string: stripped of ASCII control characters (C0 0x00..0x1F and DEL 0x7F; C1 0x80..0x9F) BEFORE JCS canonicalization and signature (PAYL-04). Stripping is a normalization step applied once at `send` time — not at display time — so sender and recipient see identical bytes. Documented as sender-attested in Phase 4's SPEC.md (Pitfall #12).

### Receive flow order (locks the verify-before-decrypt-before-accept invariant)
- **D-RECV-01:** Strict order inside `cipherpost receive`: (1) parse URI and extract `sender_z32`, `url_share_ref`; (2) transport resolve — outer PKARR SignedPacket sig check happens inside `pkarr::ClientBlocking` + `DhtTransport::resolve`; (3) extract `OuterRecord` from TXT, inner Ed25519 sig verify via `record::verify_record` (already in Phase 1); (4) check `url_share_ref == record.share_ref` (D-URI-02); (5) TTL check against inner signed `created_at + ttl_seconds` (RECV-02, exit 2); (6) age-decrypt `blob` into `Zeroizing<Vec<u8>>`; (7) parse decrypted bytes as JCS → `Envelope`; (8) present acceptance screen on stderr (D-ACCEPT-02); (9) user types full sender z32 confirmation (D-ACCEPT-01); (10) write material to stdout or `-o <path>`; (11) append ledger entry + write sentinel file (D-STATE-01). NO payload field (including purpose) is printed to stdout OR stderr before step 8 starts. Step 7 failure (Envelope parse) returns `Error::SignatureCanonicalMismatch` — treated as sig failure, exit 3.
- **D-RECV-02:** RECV-06 idempotent re-receive check happens AT STEP 1 — before any network call. If `~/.cipherpost/state/accepted/<url_share_ref>` sentinel exists, print the prior acceptance row to stderr (`already accepted at <timestamp>; not re-decrypting`) and exit 0 without network I/O. No receipt re-publication (Phase 3 will add receipt publish AFTER the state write; idempotence there is inherent because state check comes first).

### Acceptance UX (RECV-04)
- **D-ACCEPT-01:** Confirmation token = the sender's full 52-char z-base-32 pubkey. User must type or paste it exactly. Comparison is byte-equal to `OuterRecord.pubkey`. Mismatch (including trailing whitespace past a `trim()`) returns `Error::Declined` → exit 7. No default value. No `--yes` flag. No fallback confirmations. Rationale: constant-length token, anti-phishing (can't accept the wrong sender by muscle memory), Pitfall #6 aligned.
- **D-ACCEPT-02:** Acceptance screen layout = bordered box on stderr, labeled rows. Order and framing:
  ```
  === CIPHERPOST ACCEPTANCE ===============================
  Purpose:     "<control-char-stripped purpose>"
  Sender:      ed25519:SHA256:<openssh-fingerprint>
               <sender z32 52 chars>
  Share ref:   <32-char hex>
  Type:        generic_secret
  Size:        <N> bytes
  TTL:         <Xh Ym> remaining (expires <ISO UTC> / <local>)
  =========================================================
  To accept, paste the sender's z32 pubkey and press Enter:
  >
  ```
  Purpose is ALWAYS wrapped in ASCII double quotes with control chars stripped (defense against lookalike / zero-width / newline-injection in purpose). If purpose is empty, render `""` explicitly. OpenSSH fingerprint and z32 are on separate lines so both are visually comparable. No terminal colors by default (ANSI-free output so acceptance screen renders legibly in logs and screenshots).
- **D-ACCEPT-03:** TTY requirement: stderr AND stdin must both be TTYs. If either is not a TTY, `receive` aborts before decrypt with `Error::Config("acceptance requires a TTY; non-interactive receive is deferred")` → exit 1. Consistent with the passphrase TTY-required policy (Phase 1) and V2-OPS-02 which explicitly marks non-interactive batch as v2. Rationale: Pitfall #6 prohibits any default-yes path; if we can't prompt interactively, we refuse.

### Local state ledger (RECV-06)
- **D-STATE-01:** Two files at `~/.cipherpost/state/`:
  - **Ledger:** `~/.cipherpost/state/accepted.jsonl` — append-only, newline-delimited JSON. One line per acceptance:
    ```json
    {"share_ref": "<hex>", "sender": "<z32>", "accepted_at": "<ISO-8601 UTC>", "purpose": "<stripped>", "ciphertext_hash": "<sha256 hex>", "cleartext_hash": "<sha256 hex>"}
    ```
    `ciphertext_hash` = sha256(age blob bytes); `cleartext_hash` = sha256(decrypted envelope JCS bytes). Both hashes captured for Phase 3's Receipt cross-reference. Keys alphabetically ordered (mirrors JCS convention elsewhere in the codebase).
  - **Sentinel:** `~/.cipherpost/state/accepted/<share_ref>` — empty regular file, mode 0600. Existence = "this share_ref accepted." O(1) RECV-06 idempotence check (D-RECV-02).
- **D-STATE-02:** Directory permissions: `~/.cipherpost/state/` created at mode 0700 on first acceptance; `accepted.jsonl` written at mode 0600; sentinel dir `accepted/` at mode 0700; each sentinel file at mode 0600. Matches Phase 1's `~/.cipherpost/` identity-dir discipline.
- **D-STATE-03:** No rotation / GC in skeleton. Unbounded append. Acceptable for the skeleton user (1–100 shares/week per PITFALLS traffic estimate). Rotation deferred (tracked in deferred ideas).
- **D-STATE-04:** `CIPHERPOST_HOME` env var overrides the path (matches Phase 1's identity convention). Integration tests set `CIPHERPOST_HOME=<TempDir>` to avoid polluting `$HOME`.

### Error additions (extends Phase 1's `error.rs`)
- **D-ERR-01:** New variants needed in `Error`:
  - `ShareRefMismatch` — D-URI-02, exit 1, Display: `share_ref in URI does not match resolved record`.
  - `WireBudgetExceeded { encoded: usize, budget: usize, plaintext: usize }` — D-PS-01, exit 1, Display: `share too large for PKARR packet: encoded=N bytes, budget=M bytes (plaintext was K bytes)`.
  - `InvalidShareUri` — D-URI-03 (and malformed URIs generally), exit 1.
- Phase 1 already has `Expired` (exit 2), `Signature*` (exit 3, unified Display D-16), `Declined` (exit 7), `PayloadTooLarge` (exit 1), `NotFound` (exit 5), `Network` (exit 6). No changes to existing variants.

### Claude's Discretion
- **TTL parse format** (`--ttl <duration>`): accept seconds-only OR humanized (`24h`, `2d`, `3600s`) — planner's call; humanized via `humantime` crate or hand-rolled. Default 24h either way.
- **`cipherpost version` output format**: current `main.rs` already prints a 2-line format (`cipherpost X.Y.Z (git-sha)` + `crypto: age, Ed25519, Argon2id, HKDF-SHA256, JCS`). Planner may keep, adjust whitespace, or add a `--json` flag. Content is locked by CLI-04.
- **Stdout-to-TTY detection for decrypted payload**: default to stdout per RECV-05; whether to add a TTY safety check ("refuse to dump secret bytes to terminal unless `-o -` is explicit") is planner's call. Note that `rpassword` does TTY detection already — the same idiom applies.
- **`--dht-timeout` default**: inherits Phase 1's 30-second default (TRANS-04). Whether `receive` adds per-command override or inherits is a CLI-surface detail.
- **URI scheme extension plan**: if a future version needs query/fragment params (e.g., compression hint), how to parse forward-compat — planner may define a simple rejection rule (unknown trailing components → `InvalidShareUri`) or pass-through.
- **Exact `Error::Config` message text** for TTY-required failures and passphrase/TTY composition issues — wording detail.
- **Acceptance-screen TTL remaining formatting** — `23h 57m` vs `23:57:00` vs `23h 57m 12s`. Stderr output, presentation detail.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project-level (all phases)
- `.planning/PROJECT.md` — vision, core value, constraints, Key Decisions table (TTL=24h, JCS, fingerprint format, identity path, HKDF namespace, share_ref=128b, error-oracle hygiene all applicable to Phase 2)
- `.planning/REQUIREMENTS.md` — the 21 REQ-IDs this phase owns (PAYL-01..05, SEND-01..05, RECV-01..06, CLI-01..05) plus v1 acceptance criteria
- `.planning/ROADMAP.md` §"Phase 2" — goal, dependencies, five numbered success criteria (end-to-end round trip, tamper abort, acceptance screen contents, size-cap test, version/help/exit-code/stdin-stdout scan)

### Prior phase context (carry-forward)
- `.planning/phases/01-foundation-scaffold-vendored-primitives-and-transport-seam/01-CONTEXT.md` — Phase 1's 15+ locked decisions (module layout, wire constants, CLI style, error model). Phase 2 extends but does not revise.
- `.planning/phases/01-foundation-scaffold-vendored-primitives-and-transport-seam/01-VERIFICATION.md` — what Phase 1 actually shipped (vs planned), including the `serde_canonical_json 1.0.0` upgrade, `serial_test` addition, `cfg(test)` cross-crate note.
- `.planning/phases/01-foundation-scaffold-vendored-primitives-and-transport-seam/01-HUMAN-UAT.md` — the one pending interactive-TTY UAT item (still applies; Phase 2 will add similar TTY items for acceptance + `receive` passphrase flow).

### Research (read before planning)
- `.planning/research/SUMMARY.md` §"Reconciled Build Order" phases 4–7 — the 10-phase skeleton that this coarse Phase 2 consolidates (payload schema, self-mode round trip, share-mode, acceptance step). Esp. §"Gaps the PRD Missed" (G1–G10 table) — G3 `-`/stdin-stdout, G4 passphrase contract, G5 DHT progress, G6 version, G7 acceptance-screen content, G10 idempotent re-pickup all land in Phase 2.
- `.planning/research/PITFALLS.md` — Pitfalls Phase 2 owns: **#2 dual-sig order** (D-RECV-01 enforces), **#3 canonical JSON** (D-WIRE-02 JCS), **#6 acceptance prompt** (D-ACCEPT-01/02/03), **#9 age-only AEAD** (D-WIRE-02 via age), **#11 PKARR replay** (D-RECV-01 TTL check against inner signed timestamp), **#12 purpose sender-attested** (D-WIRE-05 strip + documented in SPEC.md draft in Phase 4), **#14 passphrase via argv** (inherited from Phase 1's `resolve_passphrase`).
- `.planning/research/ARCHITECTURE.md` §4 — payload/, receipt/, flow/ module designs (note: Phase 1 D-01/D-02 flattened the directory layout to single-file modules; this module layout is the guidance, but all lives in `src/payload.rs`, `src/flow.rs` files, not directories).
- `.planning/research/FEATURES.md` — CLI ergonomics table stakes (T1 errors, T2 fingerprint, T4 `-`, T5 `-o`, T6 TTY passphrase, T8 exit codes, T9 examples, T10 progress-to-stderr, T13 expiration local+UTC, T14 single-pickup retire, T17 accept-step content, T18 sig-fail fatal, T19 `version` crypto list). All of T1..T19 marked "must have" for skeleton land in this phase.
- `.planning/research/STACK.md` — confirms no new deps needed in Phase 2 (all crypto primitives already pinned in Phase 1: age, ed25519-dalek, pkarr, serde_canonical_json, base64, clap, etc.). Phase 2 adds test-only `humantime`/similar at planner discretion.

### External (reference, not dependency)
- `https://github.com/johnzilla/cclink` — prior art for send/receive flow shape. cclink's payload was session strings, not generic secrets — the flow orchestration is analogous but the payload schema is new (per Phase 1's fork-and-diverge Key Decision).

### Not yet written (Phase 4 output)
- `SPEC.md` — will document: share URI format (D-URI-01), Envelope/Material schema (D-WIRE-02/03/04), acceptance-screen content (D-ACCEPT-02), exit-code taxonomy (CLI-02), state-file format (D-STATE-01). Phase 2's decisions are the v1 source-of-truth for these sections; Phase 4 formalizes.

</canonical_refs>

<code_context>
## Existing Code Insights

Phase 1 delivered the full scaffold. Every constant, struct, and trait Phase 2 needs is either in place or placeholder. No greenfield modules — Phase 2 fills in the bodies of `src/payload.rs` (currently `// TODO: phase 2+`) and `src/flow.rs` (currently `// TODO: phase 2+`), and replaces the three `"not implemented yet (phase 2)"` stubs in `src/main.rs::dispatch` for `Send` and `Receive`.

### Reusable Assets (ready for Phase 2 consumption)

- **`src/crypto.rs`** — `ed25519_to_x25519_public`, `ed25519_to_x25519_secret`, `encrypt_key_envelope`, `decrypt_key_envelope`, `hkdf_infos::IDENTITY_KEK` const. Phase 2 adds new constants to `hkdf_infos` (e.g., `SHARE_SENDER`, `SHARE_RECIPIENT`, `INNER_PAYLOAD`) — the HKDF-enumeration test in `tests/hkdf_info_enumeration.rs` enforces central-registration. Phase 2 does NOT add new HKDF call-sites outside `crypto.rs`.
- **`src/identity.rs`** — `Identity`, `generate`, `load`, `show_fingerprints`, `Passphrase`, `resolve_passphrase`, `key_dir`, `key_path`. Phase 2's `send` / `receive` commands call `load()` after `resolve_passphrase()` (same idiom `main.rs::dispatch::IdentityCmd::Show` already uses). Also: `Identity::public_key_bytes()` for x25519 derivation when encrypting to self; `keypair.sign()` for inner sig (already exposed via `record::sign_record` which takes `&pkarr::Keypair`).
- **`src/record.rs`** — `OuterRecord`, `OuterRecordSignable`, `share_ref_from_bytes`, `sign_record`, `verify_record`, `SHARE_REF_BYTES`, `SHARE_REF_HEX_LEN`. Phase 2 uses these as-is. No changes to `OuterRecordSignable` (D-WIRE-01). Phase 2's `flow::send` composes: build Envelope → JCS-serialize → age-encrypt → base64 → compute share_ref → build `OuterRecordSignable` → `sign_record` → assemble `OuterRecord` → `Transport::publish`. Phase 2's `flow::receive` composes the inverse.
- **`src/transport.rs`** — `Transport` trait (`publish`, `resolve`, `publish_receipt`), `DhtTransport`, `MockTransport` (cfg-gated). `resolve` already verifies inner sig inline. `MockTransport` enforces the 1000-byte budget (relevant to D-PS-01's wire-budget check path). Phase 2's size-cap integration test uses `MockTransport`.
- **`src/error.rs`** — single `Error` enum, `exit_code`, `user_message`. Phase 2 adds `ShareRefMismatch`, `WireBudgetExceeded`, `InvalidShareUri` variants per D-ERR-01. Signature-failure unified Display (D-16 from Phase 1) is preserved — none of the new variants are signature failures.
- **`src/cli.rs`** — full clap tree is final. `Send { self_, share, purpose, material_file, ttl }`, `Receive { share, output, dht_timeout }`, `Version` variants all have their argument sets locked in Phase 1. Phase 2 only replaces handler bodies in `main.rs::dispatch` — no clap wiring changes.
- **`src/lib.rs`** — `PROTOCOL_VERSION`, `HKDF_INFO_PREFIX`, `ENVELOPE_MAGIC`, `DHT_LABEL_OUTER`, `DHT_LABEL_RECEIPT_PREFIX`. All wire constants already correct for Phase 2.

### Established Patterns (Phase 2 follows without revisiting)

- `Result<T, cipherpost::Error>` at library boundaries; `anyhow::Result<()>` in `main.rs` with explicit match-to-exit-code dispatcher (`exit_code(ce)`); `user_message(ce)` for stderr (no source-chain walking, D-15).
- Every HKDF call goes through a `hkdf_infos` constant — enforced by `tests/hkdf_info_enumeration.rs`. Phase 2 adds new constants, does not inline info strings.
- Every secret buffer uses `Zeroizing<Vec<u8>>` or `secrecy::SecretBox`. Debug derive forbidden on any key-holding struct (`tests/debug_leak_scan.rs`).
- `#[cfg(any(test, feature = "mock"))]` on test-only code in library modules so integration tests can `use cipherpost::...::MockTransport` under `--features mock`.
- All HKDF info strings, envelope magic, and DHT labels are constants in `lib.rs` — never string-literal'd elsewhere. Phase 2 follows.
- JCS serialization uses `serde_canonical_json::CanonicalFormatter` via `serde_json::Serializer::with_formatter` (pattern established in `record.rs::jcs`). Phase 2 reuses this pattern for Envelope serialization.

### Integration Points

Phase 3 will consume (Phase 2 provides):

- `cipherpost::payload::{Envelope, Material}` — the schema; Phase 3's Receipt references `share_ref`, `purpose`, and stores `ciphertext_hash`/`cleartext_hash` that Phase 2 already computes at acceptance time (D-STATE-01 ledger fields).
- `cipherpost::flow::{run_send, run_receive}` (names TBD by planner) — the orchestration; Phase 3 adds `run_receipts` that reads recipient's PKARR key and walks `_cprcpt-<share_ref>` TXT records.
- `~/.cipherpost/state/accepted.jsonl` ledger — Phase 3 will extend lines with a `receipt_published_at` field after successful DHT publish. Phase 2's ledger schema must permit backwards-compatible field addition.
- `cipherpost::transport::Transport::publish_receipt` — Phase 1 shipped a simple clobber-replace impl sufficient for Phase 2 (Phase 2 does not call `publish_receipt` at all — receipt publishing is Phase 3). Phase 3 upgrades both `DhtTransport` and `MockTransport` to resolve-merge-republish per TRANS-03.
- `Error::Signature*` variants with unified Display — already locked in Phase 1; Phase 2's tamper tests will reuse them.

Phase 4 will consume (Phase 2 provides):

- The locked share URI format (D-URI-01), acceptance-screen content (D-ACCEPT-02), state-file schema (D-STATE-01), and exit-code additions (D-ERR-01) are the v1 spec source-of-truth that `SPEC.md` § URIs / Acceptance / State / Exit codes will quote.

</code_context>

<specifics>
## Specific Ideas

- **User-value lens for acceptance**: the sender-z32 confirmation token is the single strongest defense against the class of attacks PITFALLS #6 catalogs (MFA-fatigue-style prompt bombing with attacker-controlled purpose text). It's deliberately more friction than `accept` — the friction IS the feature. Do not soften in the planner's discretion.
- **Share URI is copy-pasted across trust boundaries** (email, Signal, Slack, in-person). The 99-char length is acceptable because it's a one-time paste. Any shorter encoding (base58, bech32) that saves chars at the cost of introducing a new codec is rejected: the skeleton already has z32 for pubkey display + hex for share_ref display + base64 for signatures — adding a fourth encoding for URIs alone is churn.
- **Two-layer size enforcement** (D-PS-01) is "honest about the bug in PROJECT.md" — 64 KB plaintext was aspirational, the real cap is ~hundreds of bytes after age/base64/packet overhead. Rather than changing PROJECT.md and REQUIREMENTS.md to lower the number and pretending that's what we meant, Phase 2 ships both limits with clearly distinct error paths. Phase 4's `SPEC.md` documents the real wire budget alongside the 64 KB plaintext ceiling.
- **No `--yes` flag. No `--no-confirm`. No batch mode.** (D-ACCEPT-03) The whole point of the acceptance step is that there is no bypass. If the skeleton lands with a bypass path, the threat model is paper. V2-OPS-02 (non-interactive batch) is explicitly deferred to v1.0+, and even then any implementation must preserve the attestation-before-material invariant.

</specifics>

<deferred>
## Deferred Ideas

Ideas raised in discussion or implied by adjacent decisions but outside Phase 2 scope. Preserved so they are not lost and are not re-raised in Phase 3/4 planning:

- **Multi-packet chunking** (`--chunk` or equivalent). Would let large (>wire budget) payloads publish across multiple PKARR packets/labels. Serious design work; raises replay/consistency questions. Track for v1.1+.
- **Compression before encrypt** (zstd / brotli on envelope plaintext). Would stretch effective plaintext range for text-y content (PEM, ASCII). Locks a compression algo that future versions can't change without a protocol bump. Deferred; reconsider after real-use telemetry.
- **State ledger rotation / GC**. `accepted.jsonl` grows unbounded. At 1–100 shares/week (PITFALLS traffic estimate) this is tolerable for years; revisit if a real user hits a pain point. Tools like `jq`/`rg` make even a few-MB ledger manageable.
- **State-store encryption at rest**. Currently `accepted.jsonl` stores purpose + sender in plaintext at mode 0600. Same threat-model exposure as the identity file (local-process-with-same-UID). Could be encrypted to the user's own identity key; deferred to v1.0 (would be a breaking format change; not worth pre-committing).
- **Receipt publishing on acceptance**. Phase 3 work (RCPT-01). Phase 2 deliberately does NOT emit a receipt; the ledger capture of `ciphertext_hash` / `cleartext_hash` at acceptance time is the handoff to Phase 3.
- **`cipherpost list`** (show currently-received shares with their acceptance status). Implied by state ledger existence but not in REQUIREMENTS.md v1. Add to backlog.
- **Stdout-to-TTY safety check for payload material**. Good defense-in-depth; tracked as Claude's Discretion because the planner can decide whether to ship in Phase 2 or leave for a v1.0 ergonomic pass.
- **Sender-side publish-and-retry on DHT failure** (PITFALLS #10). Skeleton currently does one-shot publish; republish-on-timeout is in PITFALLS but in REQUIREMENTS.md only as DHT progress UX (TRANS-05 stderr). Track for v1.0.
- **`cipherpost version --json`**. Machine-readable version output. Useful for CI; not required for skeleton. Planner discretion.
- **Encrypt-then-sign for inner layer** (PITFALLS #2 forward-look). Would allow inner-sig verification BEFORE decrypt, reducing age-parser attack surface. Requires a protocol-version bump; SPEC.md (Phase 4) should discuss as a v2 consideration.

### Reviewed Todos (not folded)

No todos existed to review (`gsd-sdk query todo.match-phase 2` returned 0).

</deferred>

---

*Phase: 02-send-receive-and-explicit-acceptance*
*Context gathered: 2026-04-21*
