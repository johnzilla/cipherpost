# Phase 7: Typed Material — PgpKey + SshKey - Context

**Gathered:** 2026-04-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Apply Phase 6's typed-Material pattern to OpenPGP binary packet streams (`Material::PgpKey { bytes }`) and OpenSSH v1 private-key blobs (`Material::SshKey { bytes }`). User-visible deliverable: `cipherpost send --material pgp-key` ingests a binary OpenPGP packet stream and `cipherpost send --material ssh-key` ingests an OpenSSH v1 key; `receive` renders a variant-specific acceptance subblock (fingerprint, UID/comment, key algorithm), typed-z32 gates acceptance, and emits bytes (with `--armor` on PGP only). Round-trip proven under MockTransport for Ed25519-minimal fixtures that fit under the 1000 B BEP44 ceiling; oversized realistic keys surface a clean `Error::WireBudgetExceeded` (documented as a v1.2 delivery-mechanism gap).

**In scope:**
- Clap `--material pgp-key | ssh-key` values activated on `send` (already declared in `MaterialVariant` enum from Phase 6; swap `NotImplemented { phase: 7 }` for live dispatch)
- `payload::ingest::pgp_key(raw: &[u8]) -> Result<Material, Error>` and `payload::ingest::ssh_key(raw: &[u8]) -> Result<Material, Error>`
- `preview::render_pgp_preview(bytes: &[u8]) -> Result<String, Error>` and `preview::render_ssh_preview(bytes: &[u8]) -> Result<String, Error>`
- `Material::PgpKey { bytes: Vec<u8> }` and `Material::SshKey { bytes: Vec<u8> }` struct-variant upgrades with `as_pgp_key_bytes()` / `as_ssh_key_bytes()` accessors; `plaintext_size()` covers all four variants
- PGP `[WARNING: SECRET key]` banner line for secret-key input
- SSH `[DEPRECATED]` tag on Key line for DSA and RSA<2048 (display-only, never block)
- `--armor` on `receive`: accepted for `x509-cert` (Phase 6) and `pgp-key` (new); rejected for `ssh-key` and `generic-secret`
- JCS fixtures `tests/fixtures/material_pgp_signable.bin` and `tests/fixtures/material_ssh_signable.bin` committed + property tests assert byte-for-byte determinism
- Ed25519-minimal round-trip integration tests for BOTH variants under MockTransport (positive wire-budget success floor)
- Per-variant `<variant>_send_realistic_key_surfaces_wire_budget_exceeded_cleanly` test on a real-world-minimum fixture (Ed25519 primary with minimal UID for PGP; Ed25519 OpenSSH v1 with empty comment for SSH) that exceeds the ceiling
- Leak-scan extension: all four Material variants asserted never-Debug-leak their byte fields
- Error-oracle enumeration: `EXPECTED_REASONS` extended with all PGP and SSH rejection reason literals; negative assertions matrix grows
- Dep-tree guard extension: assert `ring`/`aws-lc` absent; assert `pgp` and `ssh-key` versions pinned
- SPEC.md updates: §3.2 PGP + SSH wire shapes; §5.1 CLI `--material` extended values + `--armor` matrix; §5.2 banner subblock shapes; §6 no new exit codes (reuse `InvalidMaterial` → 1 and `WireBudgetExceeded` → 7)
- `cargo tree | grep ed25519-dalek` pre-flight measurement documented in plan 01 per SSH-10

**Out of scope (noted for deferral):**
- Real-world delivery of oversized keys over DHT — deferred to v1.2 as "wire-budget delivery mechanism" (design the fix with production data on payload sizes users actually hit)
- `--pin` / `--burn` encryption modes — Phase 8
- Real-DHT cross-identity round trip — Phase 9
- PGP key verification (signature checks on UIDs / subkeys) — explicit non-goal; ingest is parse-only
- PGP encryption/signing/decryption operations — not in cipherpost's scope (KMS territory)
- SSH fingerprint algorithms other than SHA-256 (MD5 / SHA-1) — not rendered; they're deprecated and we don't want to surface them
- Multi-primary PGP keyrings — explicit REQUIREMENTS.md non-goal; rejected at ingest
- PGP v3 (RFC 1991) keys — not surveyed; rejection behavior is whatever `pgp` crate produces, gated by error-oracle
- Chunking / two-tier / OOB delivery schemes (candidate strategies B, A, C from discussion) — all deferred to v1.2 milestone

</domain>

<decisions>
## Implementation Decisions

### A. Wire-budget strategy (inherited from Phase 6; locks Phase 7 scope)

- **D-P7-01 · Ship with `WireBudgetExceeded` documented (Option D from discussion).** Phase 7 does NOT introduce chunking, two-tier storage, or OOB delivery. The protocol stays as shipped in Phase 6: oversized payloads surface `Error::WireBudgetExceeded { encoded, budget: 1000, plaintext }` after the `check_wire_budget` step, exit code 7. SPEC.md Pitfall #22 (added in Phase 6) extends to cover PGP and SSH variants. The v1.2 milestone is carved out to design the real delivery-mechanism fix with data on actual user payload sizes. **Rejected:** Option A (two-tier) — violates "no server" unless user brings URL, adds ~2× phase scope. **Rejected:** Option B (chunking) — adds new wire format that all future milestones inherit; chunk-ordering + partial-fetch complexity not worth solving in one phase. **Rejected:** Option C (OOB + hash-commit) — dramatic PRD pivot (cipherpost becomes attestation channel, not delivery).

- **D-P7-02 · Per-variant positive `WireBudgetExceeded` test.** Two new tests: `pgp_send_realistic_key_surfaces_wire_budget_exceeded_cleanly` and `ssh_send_realistic_key_surfaces_wire_budget_exceeded_cleanly`. Each drives a real-world-minimum fixture through `run_send` and asserts the error surfaces as `WireBudgetExceeded` (not panic, not `InvalidMaterial`, no `pgp`/`ssh-key` crate internals in the Display). Mirrors Phase 6's `x509_send_realistic_cert_surfaces_wire_budget_exceeded_cleanly`. **Rejected:** one consolidated parameterized test — couples the three variants, failure-in-one-breaks-others. **Rejected:** additional `#[ignore]`d full round-trip tests — Phase 6 added them; Phase 7 doesn't need the regression coverage since the error-path test fully exercises the send pipeline.

- **D-P7-03 · Ed25519-minimal round-trip MUST pass E2E (explicit success floor).** Plan 01 for each variant must produce a minimal Ed25519 fixture that fits under 1000 B encoded packet. Concretely: for PGP, a transferable public key containing exactly one Ed25519 primary + one self-certification + one minimal UID (≤32 chars) + zero subkeys + zero SCTs. For SSH, an OpenSSH v1 Ed25519 private key with empty comment and no passphrase. Success criteria: `pgp_self_round_trip_recovers_packet_stream` and `ssh_self_round_trip_recovers_canonical_bytes` tests pass end-to-end through MockTransport. Measurement note: if plan-01 measurement shows an Ed25519 OpenSSH v1 floor > 1000 B regardless of comment/kdf/cipher settings, document the ceiling in plan 01 and DOWNGRADE SSH-only round-trip to `#[ignore]` with an honest note — do NOT lower the acceptance criteria silently.

### B. PGP ingest + preview (mirrors Phase 6 X.509 pattern)

- **D-P7-04 · PGP crate: `pgp` (rpgp), parse-only, no default features we don't need.** Add `pgp = { version = "0.x", default-features = false, features = ["alloc"] }` (exact version resolved by the phase researcher via `cargo search` at plan time). Dep tree MUST NOT pull `ring` or `aws-lc` — CI dep-tree guard extends to assert this alongside the existing X.509 guard. **Rejected:** `sequoia-openpgp` — ~180 K LOC; default backend is `nettle` (C bindings); full keyring/signing/encryption surface we don't use. **Rejected:** hand-roll RFC 4880 packet parser — v4-vs-v5 fingerprint hashing differences, UID encoding quirks, and sig-subpacket semantics are too much protocol surface to author in one plan without shipping bugs.

- **D-P7-05 · PGP ASCII-armor rejection: strict prefix check (PGP-01).** After `trim_start()`, if `input.starts_with(b"-----BEGIN PGP")` → return `Error::InvalidMaterial { variant: "pgp_key", reason: "ASCII-armored input rejected — supply binary packet stream" }`. Catches both `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----BEGIN PGP PRIVATE KEY BLOCK-----` without parsing. Mirrors Phase 6's X.509 PEM-sniff inverted. One grep, generic error. **Rejected:** try-parse fall-through — couples error message to crate internals (oracle-hygiene risk); `pgp` may de-armor silently, accepting armor by accident. **Rejected:** accept + de-armor — explicitly violates PGP-01.

- **D-P7-06 · Multi-primary rejection: top-level Public-Key (tag 6) OR Secret-Key (tag 5) count > 1 (PGP-03).** Ingest parses the packet stream, counts top-level tag-5 and tag-6 packets (subkeys are tag-7 and tag-14 — not counted). If count > 1 → return `Error::InvalidMaterial { variant: "pgp_key", reason: "PgpKey must contain exactly one primary key; keyrings are not supported in v1.1 (found N primary keys)" }` with N substituted. **Rejected:** first-primary-wins — silent truncation violates PGP-03 and hides key-drift (sender's keyring ≠ receiver's keyring). **Rejected:** RFC 4880 §11 strict "OpenPGP message" concatenation rejection — stricter than PGP-03 requires; reject error messages get clunky.

- **D-P7-07 · Secret vs public detection and warning placement.** `pgp` crate distinguishes `PublicKey` (tag 6) from `SecretKey` (tag 5) at the top-level packet enum. When the primary is tag-5, `render_pgp_preview` returns a string whose first line is `[WARNING: SECRET key — unlocks cryptographic operations]` followed by a blank line, then the `--- OpenPGP ---` separator and normal fields. High visual weight. Parallel to Phase 6's `[VALID]`/`[EXPIRED]` tag pattern but elevated. **Rejected:** inline tag on Key: line — compact but skim-past risk; doesn't carry the gravity of private-key transfer. **Rejected:** banner-header `!!!` line — breaks Phase 6 banner symmetry; no other variant warning gets this treatment.

- **D-P7-08 · PGP preview fields (per PGP-04): v4 40-hex OR v5 64-hex fingerprint; primary UID (RFC 4514 not applicable — UIDs are free-form UTF-8, truncate at 64 chars with `…`); key algorithm (`Ed25519`, `RSA-4096`, `ECDSA-P256`, etc. via OID lookup — mirror D-P6-14 OID table); subkey count + types (`subkeys: 2 (Ed25519, ECDH-X25519)`); creation time ISO UTC.** Field ordering: Fingerprint → Primary UID → Key (algorithm) → Subkeys → Created. Separator width 57 dashes (matches Phase 6 X.509 subblock). **Rejected:** all subkeys on one line each — unbounded banner height; keyring with 10 subkeys fills the screen.

- **D-P7-09 · `pgp` crate import scope: CONFINED TO `src/payload/ingest.rs` AND `src/preview.rs`.** Identical blast-radius containment as Phase 6's `x509-parser` rule. Dep-tree guard test asserts `pgp` crate not imported anywhere else in `src/`. Prevents accidental "just import pgp::Signature here" drift.

### C. SSH ingest + preview (mirrors Phase 6; tighter crate-feature control)

- **D-P7-10 · SSH crate: `ssh-key` with default features DISABLED, `alloc` only.** Add `ssh-key = { version = "0.6", default-features = false, features = ["alloc"] }` initially. Plan 01 pre-flight: `cargo tree -p ed25519-dalek` — if only `3.0.0-pre.5` is present, feature-disable worked. If `2.x` appears, investigate whether the `ed25519` feature (default-on in `ssh-key`) is the culprit and whether disabling it still allows SHA-256 fingerprint extraction from public-key bytes. **Fallback if feature-disable breaks fingerprint extraction: accept coexistence (both 2.x + 3.0.0-pre.5 in dep tree), document trade-off in plan 01 and SPEC.md.** Do NOT fall back to hand-rolled OpenSSH v1 parsing — adds too much Phase 7 scope and protocol-bug risk.

- **D-P7-11 · Canonical wire blob: re-encode through `ssh-key` (SSH-02).** `ingest::ssh_key(raw)` parses the user's input via `ssh-key::PrivateKey::from_openssh()`, then re-encodes via `PrivateKey::to_bytes_openssh()` with the user's comment preserved verbatim and block-standard padding. The re-encoded bytes go into `Material::SshKey { bytes }`. SHA-256 fingerprint and JCS byte-identity both deterministic across re-sends. Mirrors Phase 6 X.509 "canonical DER from either DER or PEM input" pattern. **Rejected:** strict-match input bytes — two senders of the same key via different `ssh-keygen` versions get different `share_ref`. **Rejected:** parse-then-compare reject-on-mismatch — strictest correctness, worst UX; users have to pre-canonicalize.

- **D-P7-12 · SSH format rejection (SSH-01): any input that does NOT start with `-----BEGIN OPENSSH PRIVATE KEY-----` (after `trim_start()`) → `Error::SshKeyFormatNotSupported` with exit 1.** Explicit rejection cases the error message names: legacy PEM (`-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN DSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`), RFC 4716 (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`), FIDO (`-----BEGIN OPENSSH-FIDO PRIVATE KEY-----`). Error string: `"SSH key format not supported — convert to OpenSSH v1 via \`ssh-keygen -p -m RFC4716\`"` (wait — RFC4716 is what we REJECT; the correct hint is `ssh-keygen -p -o` which is the DEFAULT modern form). Final error string picked at plan time from the `ssh-keygen` help text. New error variant `Error::SshKeyFormatNotSupported` — does NOT collapse into `InvalidMaterial` because the hint-with-conversion-command is variant-specific. Exit code 1.

- **D-P7-13 · `--armor` rejected for SSH (SSH-05).** `cipherpost receive --material ssh-key --armor` returns `Error::Config("--armor not applicable to ssh-key — OpenSSH v1 is self-armored")`. Phase 6 rejection pattern extended (`--armor requires --material x509-cert or pgp-key`). `run_receive` gains a `(variant, armor)` → `Result<(), Error>` validation function called immediately after CLI parse. **Rejected:** silent no-op — flag-does-nothing is a UX surprise. **Rejected:** `--no-armor` toggle emitting raw base64 body — out of scope for v1.1.

- **D-P7-14 · Deprecated algorithm display (SSH-04): `[DEPRECATED]` tag on Key: line for DSA (any size) and RSA<2048; display-only, never block.** On the Key: line inside the subblock: `Key:         ssh-rsa 1024 [DEPRECATED]` or `Key:         ssh-dss [DEPRECATED]`. Parallel to Phase 6's `[EXPIRED]`/`[VALID]` display-don't-block pattern. No additional stderr warning line (unlike PGP SECRET which gets dedicated elevation — SSH deprecated keys are a softer concern; user might be intentionally migrating legacy infra). **Rejected:** additional stderr warning — overweight for the threat. **Rejected:** hard-reject at ingest — contrary to SSH-04.

- **D-P7-15 · SSH preview fields (per SSH-04): key type (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, `ssh-dss`); SHA-256 fingerprint in `SHA256:<base64-unpadded>` form (OpenSSH convention, matches `ssh-keygen -lf`); comment labeled `[sender-attested]` and truncated at 64 chars with `…`; key size in bits (RSA-2048, EC P-256, Ed25519-256, etc.).** Field ordering: Key (type + size + [DEPRECATED] if applicable) → Fingerprint → Comment. Separator width 57 dashes. **Rejected:** `MD5:...` legacy fingerprint — deprecated, should not be surfaced.

- **D-P7-16 · `ssh-key` crate import scope: CONFINED TO `src/payload/ingest.rs` AND `src/preview.rs`.** Same blast-radius containment as `x509-parser` and `pgp`. Dep-tree guard asserts no other `src/` file imports `ssh-key`.

### D. Phase structure + execution posture

- **D-P7-17 · Plan layout: 8 plans in two Phase-6-style sequences (Option A).** Plans 07-01..04 handle PGP (foundation → preview → wiring → ship-gate); 07-05..08 handle SSH (same structure). No shared foundation plan — each variant's foundation is independent (different crate, different struct variant, different error-oracle reason list additions). Clearest lesson-per-plan story; if PGP research surprises us mid-execution, SSH plans aren't blocked. Cost: ~2× Phase 6 duration. **Rejected:** Option B (5 plans, 3 waves with parallelism) — parallelism collapses to sequential today because worktrees are disabled. **Rejected:** Option C (split into phases 7a + 7b) — roadmap renumbering churn; two full GSD cycles instead of one. **Rejected:** Option D (interleaved 6 plans) — couples PGP and SSH in single plans; PGP bug blocks SSH shipping.

- **D-P7-18 · Worktrees stay disabled for Phase 7.** `workflow.use_worktrees = false` unchanged. 8 plans × Phase-6-pace ≈ 2 hours of agent time sequentially — not worth the worktree merge overhead (SPEC.md + Cargo.toml both touched by PGP and SSH ship-gate plans; parallel execution would create merge conflicts). Re-evaluate worktrees when a phase has 6+ genuinely independent plans with non-overlapping `files_modified`.

- **D-P7-19 · Wave structure: strictly sequential, one plan per wave, all 8 plans autonomous.** `autonomous: true` in every plan's frontmatter. No human-checkpoints. No inter-plan parallelism. Phase 7 execution runs `/gsd-execute-phase 7` and goes.

### Claude's Discretion

- Exact `pgp` crate version — resolved via `cargo search pgp` at plan 01 time. Accept whatever is current and MIT/Apache-2.0 licensed without `ring`/`aws-lc` in its transitive deps.
- Exact `ssh-key` crate version — SSH-10 mandates 0.6 or later for modern OpenSSH v1 support, but the specific patch version is picked at plan 01 based on what's current.
- Fixture byte layout: hand-crafted single PGP packet stream via `pgp` crate round-trip; hand-crafted SSH key via `ssh-keygen -t ed25519 -C "" -N ""` invoked once, bytes committed. Reproduction recipes documented in sibling `.txt` files per Phase 6 pattern.
- Error string wording for `Error::SshKeyFormatNotSupported` hint — pick something that references a current `ssh-keygen` flag users can copy-paste. Plan 01 task should include copying `ssh-keygen --help` output for reference.
- Whether `render_pgp_preview` takes the raw bytes and re-parses, or takes a pre-parsed `pgp::composed::PublicOrSecret` struct. Inside-the-function re-parse is simpler and avoids leaking `pgp` crate types up the call stack (Phase 6 picked this; Phase 7 mirrors).
- Preview struct shape: `render_pgp_preview` MAY return `{ warning: Option<String>, subblock: String }` struct instead of a single string, to let the caller decide how to format the SECRET warning. OR the returned string may embed the warning line. Planner picks; both satisfy D-P7-07.
- UID truncation width (~64 chars) — tune to fit 80-col TTY with indentation. Measure at plan time against real-world UIDs from the GnuPG test-data repo.
- Whether oracle-hygiene `EXPECTED_REASONS` const moves to a shared `tests/common.rs` or stays inlined per-test-file. Planner picks; matters for Phase 8+ regression.
- Whether the PGP ship-gate and SSH ship-gate plans each emit a separate SUMMARY.md section updating SPEC.md, or whether a final "phase-7 SPEC consolidation" task lands in plan 08. Planner picks at plan time.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` §Typed Material: OpenPGP keys (PGP) — PGP-01..09 (inline phase tags)
- `.planning/REQUIREMENTS.md` §Typed Material: OpenSSH keys (SSH) — SSH-01..10 (inline phase tags)
- `.planning/REQUIREMENTS.md` §Out of Scope — chain validation, PGP sig verify, cert conversion, multi-primary keyrings, ASCII armor on PGP input all explicitly rejected
- `.planning/ROADMAP.md` §Phase 7 — goal + success criteria

### Phase 6 locked-in patterns (DO NOT re-derive)
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` §A Material dispatch UX — `MaterialVariant` enum, `--material` flag shape, default-generic-secret back-compat (D-P6-01..04)
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` §B PEM normalize boundary + error shape — `payload::ingest` submodule structure, strict prefix sniff pattern, error-oracle hygiene (D-P6-05..08)
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` §C Acceptance banner layout — inline subblock pattern, RFC4514/fingerprint rendering conventions, `[EXPIRED]`/`[VALID]` display-don't-block pattern (D-P6-09..14)
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` §D Typed-Material API shape — per-variant accessors, `plaintext_size()`, `preview::` module structure, ingest return type (D-P6-15..18)
- `.planning/phases/06-typed-material-x509cert/06-SUMMARY.md` files (06-01..04) — what shipped; byte-counts on fixtures; OID lookup table for key algorithms
- `.planning/phases/06-typed-material-x509cert/06-REVIEW.md` WR-01 — PEM trailing-bytes invariant lesson; Phase 7 PGP and SSH ingest must parallel-check for trailing-bytes on any concatenated-input path
- `.planning/phases/06-typed-material-x509cert/06-REVIEW-FIX.md` — the WR-01 fix; Phase 7 ingest MUST enforce trailing-bytes rejection symmetrically

### Domain pitfalls (load-bearing)
- `.planning/research/PITFALLS.md` #7 — no Debug leak on secret-holding structs → applies to BOTH PgpKey and SshKey (extends D-P6-08)
- `.planning/research/PITFALLS.md` #22 — wire-budget-vs-plaintext-cap distinction → D-P7-01 carries this forward; SPEC.md Pitfall #22 section extends to all three typed variants
- `.planning/research/PITFALLS.md` #19 — (PGP-adapted) binary packet stream validity vs ASCII-armor ambiguity; D-P7-05 strict-prefix rejection is the mitigation
- `.planning/research/PITFALLS.md` #36 — per-variant size checks before JCS encode

### Project convention
- `CLAUDE.md` §Load-bearing lock-ins — JCS via `serde_canonical_json`; HKDF info `cipherpost/v1/<context>`; no `#[derive(Debug)]` on secret holders; ed25519-dalek =3.0.0-pre.5 pin (LOAD-BEARING for D-P7-10 SSH crate decision)
- `CLAUDE.md` §Architectural lineage — fork-and-diverge from cclink; no shared `cipherpost-core` crate
- `.planning/PROJECT.md` §Constraints — 64 KB plaintext cap; no chain validation; primitive first, workflows second
- `.planning/PROJECT.md` §Key Decisions — skeleton uses generic-secret payload type; Phase 6 extended to X509Cert; Phase 7 extends to PgpKey + SshKey

### Spec sections to edit in Phase 7
- `SPEC.md` §3.2 Material variants — add PgpKey wire shape (`{"type":"pgp_key","bytes":"<base64-std>"}`) and SshKey wire shape (`{"type":"ssh_key","bytes":"<base64-std>"}`); document "PgpKey.bytes carries binary OpenPGP packet stream" and "SshKey.bytes carries canonical OpenSSH v1 wire blob"
- `SPEC.md` §5.1 CLI — extend `--material` values to `pgp-key` + `ssh-key`; document `--armor` matrix (accepted for x509-cert + pgp-key; rejected for ssh-key + generic-secret)
- `SPEC.md` §5.2 Acceptance banner — add PGP subblock shape and SSH subblock shape alongside the Phase 6 X.509 subblock
- `SPEC.md` §6 Exit-code taxonomy — add `Error::SshKeyFormatNotSupported` → exit 1 row (alongside `InvalidMaterial` → 1 from Phase 6)
- `SPEC.md` §Wire-budget (Pitfall #22) — extend to explicitly name PGP and SSH realistic-key overflow as v1.2 delivery-mechanism scope

### Existing code — primary edit sites (paths as of HEAD after Phase 6 close)
- `src/payload/mod.rs` — `Material` enum: upgrade `PgpKey` + `SshKey` unit variants to struct variants `{ bytes: Vec<u8> }`; extend manual `Debug` redaction
- `src/payload/mod.rs` — `impl Material` — add `as_pgp_key_bytes()` and `as_ssh_key_bytes()` accessors; `plaintext_size()` match arms for PgpKey/SshKey
- `src/payload/ingest.rs` — new `pub fn pgp_key(raw: &[u8]) -> Result<Material, Error>` (plan 07-01); new `pub fn ssh_key(raw: &[u8]) -> Result<Material, Error>` (plan 07-05). Each parallels the existing `x509_cert` function structure (strict-prefix reject → parse → validate → construct Material).
- `src/preview.rs` — new `pub fn render_pgp_preview(bytes: &[u8]) -> Result<String, Error>` (plan 07-02); new `pub fn render_ssh_preview(bytes: &[u8]) -> Result<String, Error>` (plan 07-06).
- `src/cli.rs` — `MaterialVariant` enum: `PgpKey` and `SshKey` variants are already declared (Phase 6 added them with `NotImplemented { phase: 7 }` dispatch); no enum change needed. `--armor` matrix validation extends in `run_receive` (plans 07-03, 07-07).
- `src/main.rs` — Send/Receive dispatch: swap `MaterialVariant::PgpKey | MaterialVariant::SshKey` "NotImplemented" rejection for live routing to `payload::ingest::pgp_key` / `ssh_key` (plans 07-03, 07-07).
- `src/flow.rs` — `run_send` dispatches to new ingest fns; `run_receive` match arms for PgpKey/SshKey preview rendering; `--armor` matrix validation.
- `src/error.rs` — add `Error::SshKeyFormatNotSupported` variant with exit 1 mapping; Display returns generic message naming the format (`"SSH key format not supported — convert to OpenSSH v1"`), no crate internals.
- `src/lib.rs` — no new module exports (both `preview` and `payload::ingest` already public from Phase 6).
- NEW: `tests/fixtures/material_pgp_signable.bin` + `.reproduction.txt` (plan 07-04)
- NEW: `tests/fixtures/material_ssh_signable.bin` + `.reproduction.txt` (plan 07-08)
- NEW: `tests/material_pgp_ingest.rs` — sniff/normalize/strictness (happy packet, armor rejected, multi-primary rejected, malformed packet, wrong variant accessor)
- NEW: `tests/material_ssh_ingest.rs` — format acceptance (OpenSSH v1 only), legacy-PEM/RFC4716/FIDO rejection, canonical re-encode round-trip, deprecated-algo display
- NEW: `tests/pgp_roundtrip.rs` — Ed25519-minimal self-send round-trip + WireBudgetExceeded positive test
- NEW: `tests/ssh_roundtrip.rs` — Ed25519-minimal self-send round-trip + WireBudgetExceeded positive test
- NEW: `tests/pgp_banner_render.rs` + `tests/ssh_banner_render.rs` — golden-string pins on subblock output
- NEW: `tests/pgp_error_oracle.rs` + `tests/ssh_error_oracle.rs` — EXPECTED_REASONS × variants × forbidden-tokens matrix extended
- `tests/debug_leak_scan.rs` — extend Material-variant enumeration: `pgp_key_debug_redacts_bytes` and `ssh_key_debug_redacts_bytes`
- `tests/x509_dep_tree_guard.rs` — either extend to assert `pgp` + `ssh-key` versions, or add new `tests/pgp_dep_tree_guard.rs` + `tests/ssh_dep_tree_guard.rs`. Planner picks.

### Dependency additions (to confirm at plan 01 + plan 05 time)
- `Cargo.toml` — add `pgp = { version = "0.x", default-features = false, features = ["alloc"] }` (exact version from `cargo search` at plan 07-01 time). Confirm via `cargo tree -p pgp` that no `ring`/`aws-lc` pulled.
- `Cargo.toml` — add `ssh-key = { version = "0.6", default-features = false, features = ["alloc"] }` (plan 07-05). Confirm via `cargo tree | grep ed25519-dalek` that only `3.0.0-pre.5` is present (D-P7-10). If `2.x` appears, investigate ed25519 feature and accept coexistence as documented fallback.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets (all Phase 6 shipped)
- `payload::enforce_plaintext_cap(len: usize) -> Result<(), Error>` — per-variant cap check; `plaintext_size()` feeds this directly. PGP/SSH match arms added to `plaintext_size()` in plan 07-01 and 07-05 respectively.
- `payload::ingest::x509_cert` — the pattern template. `pgp_key` and `ssh_key` mirror its structure: (1) strict-prefix rejection of unsupported formats, (2) parse via crate, (3) validate (multi-primary for PGP, canonical re-encode for SSH), (4) return fully-constructed Material variant.
- `preview::render_x509_preview` — the pure-renderer template. `render_pgp_preview` and `render_ssh_preview` mirror: take raw bytes, parse, format into subblock string, never touch stdout/stderr directly.
- `preview::format_unix_as_iso_utc` — promoted to `pub(crate)` in Phase 6; reusable for PGP Created timestamp rendering.
- `Envelope` + `Material` + `base64_std` serde module — all reusable; PgpKey and SshKey gain `{ bytes }` data fields, serde tags already declared.
- `check_wire_budget()` — carries `WireBudgetExceeded` surfacing; unchanged in Phase 7. PGP/SSH oversized inputs trip it naturally.
- `Error::InvalidMaterial { variant, reason }` — reused verbatim for PGP ingest failures; new variant `Error::SshKeyFormatNotSupported` added for SSH because the format-hint error needs a distinct variant (its Display includes a hint the user can act on).
- `TtyPrompter::render_and_confirm` — extends with match arms for PgpKey and SshKey calling the new preview fns. Phase 6 established the Prompter trait extension pattern (preview_subblock: Option<&str> parameter).
- `Material::X509Cert`-shaped manual Debug impl — pattern replicated for PgpKey and SshKey arms.
- `MockTransport` — handles all Phase 7 round-trip tests.

### Established Patterns (all Phase 6)
- `payload/ingest.rs` submodule convention: one pub fn per variant; strict input-format checking first; parse-and-validate second; Material constructor last. `pgp_key` and `ssh_key` slot in next to `x509_cert` and `generic_secret`.
- Manual `Debug` redaction on byte-holding variants; leak-scan test enumerates all Material variants asserting no bytes Debug-leak (Pitfall #7).
- `EXPECTED_REASONS` constant-table oracle-hygiene pattern: reasons × variants × forbidden-tokens matrix. Phase 7 extends both EXPECTED_REASONS (add PGP and SSH reason literals) and the variants list (add PgpKey, SshKey Material variants).
- JCS fixture discipline: committed bytes at `tests/fixtures/material_<variant>_signable.bin`; property test asserts byte-for-byte determinism; regeneration helper `#[ignore]`'d.
- Ship-gate plan template: DER/blob fixture → JCS byte-identity → ingest negative matrix → golden-string banner → oracle-hygiene enumeration → leak-scan extension → dep-tree guard → SPEC.md update. Plans 07-04 and 07-08 each replicate this.
- Dep-tree guard assertion convention: `cargo tree` command parsed for version-pin confirmation; `ring`/`aws-lc` absence assertion remains.
- Wire-budget-aware integration test convention: `#[ignore]` full round-trips that exceed budget (Phase 6 did; Phase 7 does NOT — D-P7-02 prefers positive error-surface tests only), positive `WireBudgetExceeded`-surface test that validates clean error path.

### Integration Points
- `MaterialVariant::{PgpKey, SshKey}` already declared in Phase 6 with `NotImplemented { phase: 7 }` dispatch. Plans 07-03 and 07-07 swap the rejection for live dispatch.
- `Envelope.material` field — PgpKey and SshKey variants slot in with zero Envelope changes (structural change is internal to Material).
- `run_send` step 2 currently dispatches `MaterialVariant::{GenericSecret, X509Cert}` → ingest fn, `{PgpKey, SshKey}` → NotImplemented. Swap for live dispatch.
- `run_receive` step 8 acceptance match: currently handles GenericSecret + X509Cert; add match arms for PgpKey + SshKey calling their preview fns.
- `pem_armor_certificate` helper in `src/flow.rs` is X.509-specific (from Phase 6); PGP `--armor` on receive uses the `pgp` crate's armor serialization, NOT this helper. SSH rejects `--armor` (D-P7-13) so no helper needed.
- No change to Transport, OuterRecord, Receipt, PKARR publish path, or HKDF contexts. Phase 7 is strictly payload-layer.

### Anti-patterns to avoid (from Phase 6 + this discussion)
- Do NOT enable any `pgp` or `ssh-key` crate feature that pulls `ring` or `aws-lc`. Dep-tree guard asserts absence.
- Do NOT let any `pgp` or `ssh-key` internal error chain reach user-facing stderr. Error-oracle hygiene rule; violated = `Error::InvalidMaterial.Display` or `Error::SshKeyFormatNotSupported.Display` leaks crate internals, which error-oracle tests catch.
- Do NOT emit key bytes (fingerprint, UID, comment, subkeys — ANY field) to stderr BEFORE the acceptance prompt returns `Ok(())`. Banner IS the surface. `preview::render_*_preview` returns strings; `Prompter` owns emission.
- Do NOT `#[derive(Debug)]` on the new `Error::SshKeyFormatNotSupported` variant if its fields carry crate internals. String field should be a curated short label, never a wrapped parser error.
- Do NOT normalize by writing to a temp file. Ingest is pure in-memory (bytes → bytes).
- Do NOT skip the WR-01 trailing-bytes invariant: PGP packet streams can be concatenated (an attacker-controlled sender could ship "cert A followed by cert B"), SSH files can have trailing comments after the BEGIN/END markers. Both ingest fns MUST assert the parser consumed the entire input or trailing-bytes-only-whitespace, parallel to the Phase 6 WR-01 fix on X.509 PEM.
- Do NOT attempt to verify PGP signatures, decrypt PGP material, compute SSH challenges, or do any crypto operation on the keys. Parse + fingerprint + display only.
- Do NOT try to support PGP ASCII-armor "in later phases". The rejection is protocol-level — PGP armor headers are non-deterministic across tools and would break JCS byte-identity forever. This is a permanent contract.

</code_context>

<specifics>
## Specific Ideas

- **Banner mockup (PGP secret key):**
  ```
  === CIPHERPOST ACCEPTANCE ===============================
  Purpose:     "key handoff for alice@example"
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
  TTL:         23h remaining (expires 2026-04-25 13:11 UTC / 2026-04-25 09:11 EDT local)
  =========================================================
  To accept, paste the sender's z32 pubkey and press Enter:
  ```

- **Banner mockup (SSH Ed25519):**
  ```
  === CIPHERPOST ACCEPTANCE ===============================
  Purpose:     "server bootstrap key"
  Sender:      ed25519:SHA256:…
               yx8a3…iq8jo
  Share ref:   a7b8c9d0…
  Type:        ssh_key
  Size:        411 bytes
  --- SSH -------------------------------------------------
  Key:         ssh-ed25519 256
  Fingerprint: SHA256:tWtRbCXYZ…abcDEF
  Comment:     [sender-attested] deploy@bastion
  TTL:         23h remaining (expires 2026-04-25 13:11 UTC / 2026-04-25 09:11 EDT local)
  =========================================================
  To accept, paste the sender's z32 pubkey and press Enter:
  ```

- **Banner mockup (SSH legacy RSA):**
  ```
  --- SSH -------------------------------------------------
  Key:         ssh-rsa 1024 [DEPRECATED]
  Fingerprint: SHA256:…
  Comment:     [sender-attested] old-laptop
  ```

- **Subblock separator widths:** PGP = `--- OpenPGP ` + 53 dashes = 65 chars total; SSH = `--- SSH ` + 57 dashes = 65 chars. Matches Phase 6's `--- X.509 ` + 57 dashes = 67. Render test asserts line-width within ±2 chars of Phase 6 banner.

- **Cap-check order (both variants):** (1) read_material → raw bytes; (2) payload::ingest::<variant>(raw)? → Material; (3) payload::enforce_plaintext_cap(material.plaintext_size())?; (4) build Envelope. Ingest runs BEFORE cap: a 1 MB ASCII-armored PGP input would be rejected at ingest for armor BEFORE hitting the cap, rather than hitting the cap with misleading size accounting.

- **Fixtures:**
  - **PGP:** Ed25519 primary + one self-cert + UID `cipherpost-fixture <fixture@cipherpost.test>` (43 chars). No subkeys. Created timestamp fixed (e.g., 2026-01-01T00:00:00Z). Regenerated via `gpg --batch --quick-gen-key` or via the `pgp` crate's key-generation test utils; bytes committed once, reproduction recipe in `tests/fixtures/material_pgp_fixture.reproduction.txt`.
  - **SSH:** `ssh-keygen -t ed25519 -C "" -N "" -f /tmp/cipherpost-fixture`, then committed as `tests/fixtures/material_ssh_fixture.openssh-v1`. Reproduction command in `.txt` sibling. Comment empty, no passphrase — minimizes wire size.

- **Wire-budget measurements to record in plan 07-01 (PGP) and plan 07-05 (SSH):**
  - Minimum Ed25519 PGP transferable public key with minimal UID: target ~400 B DER; measure encoded PKARR packet size; target < 1000 B ceiling.
  - Minimum Ed25519 OpenSSH v1 private key with empty comment: target ~411 B blob; measure encoded PKARR packet size; target < 1000 B ceiling.
  - If measurement shows either floor > 1000 B despite minimalism: document and update D-P7-03 acceptance criteria accordingly (SSH-only round-trip downgraded to `#[ignore]` with honest note).

- **ed25519-dalek pre-flight evidence format (SSH-10 compliance):** Plan 07-05 SUMMARY.md includes a verbatim `cargo tree -p ed25519-dalek` output block. If only `3.0.0-pre.5` present → primary outcome ("no 2.x leak"). If `2.x` and `3.0.0-pre.5` both present → fallback outcome ("coexistence accepted, binary carries two Ed25519 impls, supply-chain doubles for Ed25519"). Both outcomes are valid per SSH-10; what's NOT valid is shipping SSH code without documenting one of them.

- **Dep-tree guard extension:** Augment `tests/x509_dep_tree_guard.rs` (Phase 6) with additional `cargo tree` assertions for `pgp` and `ssh-key` version pins, OR add new `tests/pgp_dep_tree_guard.rs` + `tests/ssh_dep_tree_guard.rs` (Planner picks). Either way, running `cargo test dep_tree` runs all three guards.

- **Test-naming convention:** Mirror Phase 6 — `material_<variant>_ingest.rs`, `<variant>_roundtrip.rs`, `<variant>_banner_render.rs`, `<variant>_error_oracle.rs`. Plan 07-04 and 07-08 each stand up the test suite for their variant.

</specifics>

<deferred>
## Deferred Ideas

- **Real-world delivery of oversized PGP/SSH keys over DHT** — v1.2 milestone. Design the fix (two-tier? chunking? OOB attestation?) with production data on actual payload sizes users hit, rather than guessing which strategy is best in the abstract.
- **PGP ASCII armor on send input** — permanently rejected. Non-deterministic armor headers break JCS byte-identity. Not a deferral; a contract.
- **SSH `--no-armor` flag (emit base64 body or raw OpenSSH v1 binary form)** — out of scope for Phase 7; would be a v1.2+ UX polish if users request it. OpenSSH v1 is ASCII-armored by convention; emitting a non-armored form is not widely useful.
- **PGP v3 (RFC 1991) key support** — ancient and rare; whatever `pgp` crate does with it is what we do. If someone opens an issue we re-evaluate.
- **MD5 / SHA-1 fingerprint rendering** — deprecated OpenSSH fingerprint forms; explicitly not surfaced. User can compute via `ssh-keygen -lE md5` externally.
- **PGP signature verification on UIDs or subkeys** — explicit non-goal; KMS territory, not transport.
- **PGP encryption / decryption on keys** — out of scope; cipherpost is a transport, not a PGP toolkit.
- **SSH FIDO-format keys** (ssh-ed25519-sk, ssh-rsa-sk, etc.) — rejected at ingest (SSH-01). Future support would require an additional Material variant or a sub-type flag.
- **SSH certificate keys** (`<key-type>-cert-v01@openssh.com`) — NOT supported initially. User must hand off the plain key; cert goes OOB. If demand appears, new phase.
- **`cargo tree | grep pgp` supply-chain guard** — pre-flight at plan 07-01; specific vulnerabilities in the `pgp` crate history should be checked against the version we lock. Not a deferral, just a plan-01 task.
- **Multi-key handoff in one cipherpost send** — e.g., "send alice's PGP public key AND alice's SSH public key in one Envelope." Out of scope — explicit single-variant contract per Envelope.
- **Consolidated SPEC.md wire-budget section** — move the per-variant Pitfall #22 notes (Phase 6 X.509, Phase 7 PGP + SSH) into a single unified section when Phase 9 closes. Document trigger: v1.2 milestone kickoff.
- **Key-type explicit rejection list in Error::SshKeyFormatNotSupported message** — instead of generic "format not supported," enumerate the detected legacy-PEM header. Claude's discretion at plan time; may or may not land.
- **Subkey cap for PGP** — a malicious PGP key with 1000 subkeys would blow past the plaintext cap. The plaintext cap (64 KB) handles this naturally. If we want to reject earlier/cheaper, add a per-variant subkey-count cap in ingest. Not required for Phase 7; revisit if performance matters.

</deferred>

---

*Phase: 07-typed-material-pgpkey-sshkey*
*Context gathered: 2026-04-24*
