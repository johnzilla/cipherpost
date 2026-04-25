---
phase: 07-typed-material-pgpkey-sshkey
reviewed: 2026-04-24T00:00:00Z
depth: standard
files_reviewed: 27
files_reviewed_list:
  - Cargo.toml
  - Cargo.lock
  - deny.toml
  - rust-toolchain.toml
  - examples/generate_pgp_fixture.rs
  - SPEC.md
  - src/error.rs
  - src/flow.rs
  - src/main.rs
  - src/payload/ingest.rs
  - src/payload/mod.rs
  - src/preview.rs
  - tests/debug_leak_scan.rs
  - tests/material_pgp_envelope_round_trip.rs
  - tests/material_pgp_ingest.rs
  - tests/material_ssh_envelope_round_trip.rs
  - tests/material_ssh_ingest.rs
  - tests/pgp_banner_render.rs
  - tests/pgp_error_oracle.rs
  - tests/pgp_roundtrip.rs
  - tests/phase2_material_variants_unimplemented.rs
  - tests/ssh_banner_render.rs
  - tests/ssh_error_oracle.rs
  - tests/ssh_roundtrip.rs
  - tests/x509_dep_tree_guard.rs
  - tests/x509_roundtrip.rs
  - tests/fixtures/material_pgp_fixture.reproduction.txt
findings:
  critical: 0
  warning: 2
  info: 4
  total: 6
status: issues_found
---

# Phase 7: Code Review Report

**Reviewed:** 2026-04-24
**Depth:** standard
**Files Reviewed:** 27
**Status:** issues_found

## Summary

Phase 7 (Typed Material — PgpKey + SshKey) implements the eight-plan PGP +
SSH variant rollout cleanly. Load-bearing project invariants were each spot-
checked and found correct:

- **Canonical JSON via `serde_canonical_json`**: all signable / envelope
  paths still funnel through `crypto::jcs_serialize`; new variants gain the
  same JCS-byte-identity property tests (PGP envelope fixture 376 B; SSH
  envelope fixture indirected through canonical re-encode).
- **`chacha20poly1305` only via age**: no new direct call sites in `src/`;
  `deny.toml` ban list still passes.
- **`#[derive(Debug)]` not on secret holders**: `Material::PgpKey` and
  `Material::SshKey` upgraded to struct variants with manual Debug
  redaction (`[REDACTED N bytes]`). `tests/debug_leak_scan.rs` extended.
- **Dual-signature gating**: `run_receive` order unchanged
  (transport.resolve → outer + inner verify → URI/share_ref → TTL → age
  decrypt → JCS parse → variant-aware preview render → typed-z32
  acceptance). Variant-specific preview renderers run AFTER inner-sig
  verify and BEFORE the prompt; no envelope field is surfaced before
  acceptance. Material pre-render parse failures funnel through curated
  `Error::InvalidMaterial` literals shared with ingest, so an oracle
  adversary cannot distinguish "ingest reject" vs "preview reject".
- **No envelope field surfaced before inner-sig verify**: `Material::SshKey`
  + `Material::GenericSecret` `--armor` rejections fire BEFORE
  `as_*_bytes()` is called, matching the cost-on-error pattern. PgpKey +
  X509Cert preview-then-prompt-then-armor sequence is preserved.
- **ed25519-dalek 2.x ↔ 3.0.0-pre.5 coexistence**: `Cargo.lock` confirms
  exactly two versions present (2.2.0 from pgp 0.19.0, 3.0.0-pre.5 from
  pkarr). Two dep-tree guard tests assert the shape and that ssh-key
  introduces no third version.
- **Error-oracle hygiene**: every PGP/SSH ingest + preview parse failure
  surfaces through curated reason literals; rpgp + ssh-key crate internals
  never reach Display (enumerated in `tests/pgp_error_oracle.rs` and
  `tests/ssh_error_oracle.rs` against `FORBIDDEN_DISPLAY_TOKENS`).
- **Crate import scoping**: `pgp::*` confined to `src/payload/ingest.rs` +
  `src/preview.rs` (D-P7-09). `ssh_key::*` confined to the same two
  modules (D-P7-16). `rsa::traits::PublicKeyParts` is the ONLY rsa import
  and is trait-only — no RSA crypto operations anywhere, so the accepted
  RUSTSEC-2023-0071 advisory is genuinely inapplicable.

Issues found are documentation drift in SPEC.md (two stale references to
ssh_key being "reserved" / "unimplemented") plus minor code-quality
items. No security or correctness defects.

## Warnings

### WR-01: SPEC.md §3.2 still claims `ssh_key` returns `NotImplemented{phase:7}`

**File:** `SPEC.md:154-155`
**Issue:** The Material variant table reads:

```
**cipherpost/v1.0 shipped:** `generic_secret` only.
**cipherpost/v1.1 (Phase 6) adds:** `x509_cert { bytes }`.
**cipherpost/v1.1 (Phase 7) adds:** `pgp_key { bytes }`.
**Reserved for Phase 7 Plan 05+:** `ssh_key` (dispatch returns
`Error::NotImplemented { phase: 7 }` at both `main.rs::dispatch` and
`flow::run_send` — exit 1).
```

This is contradicted later in the same document at §3.2 line 254
(`ssh_key wire form (cipherpost/v1.1, Phase 7 Plan 05+)`), at §5.1 line
442 (`ssh-key (Phase 7 Plan 05-08 — LIVE)`), and by the actual code in
`src/main.rs` + `src/flow.rs` which both dispatch `MaterialVariant::SshKey`
live to `payload::ingest::ssh_key` (no `NotImplemented` rejection
anywhere). The "Reserved" framing also mis-states the error: the dispatch
NEVER returned `NotImplemented{phase:7}`; in the pre-Plan-05 state it
returned `NotImplemented{phase:7}` only briefly, and now it ingests
fully.

**Fix:** Replace lines 152-156 with:

```markdown
**cipherpost/v1.0 shipped:** `generic_secret` only.
**cipherpost/v1.1 (Phase 6) adds:** `x509_cert { bytes }`.
**cipherpost/v1.1 (Phase 7) adds:** `pgp_key { bytes }` and `ssh_key { bytes }`.
```

### WR-02: SPEC.md §9 Lineage repeats the stale "reserved for v1.0+" claim

**File:** `SPEC.md:1009-1010`
**Issue:** The Lineage section says:

```
1. **Typed payload schema** — `Envelope` with `Material` enum (`generic_secret` implemented;
   `x509_cert`, `pgp_key`, `ssh_key` reserved for v1.0+).
```

All four variants are now implemented in v1.1 (Phase 6 X.509 + Phase 7
PGP/SSH), so "reserved for v1.0+" is wrong AND the version label drifted
(v1.0 vs v1.1). This is the same documentation-drift class as WR-01.

**Fix:** Update to:

```markdown
1. **Typed payload schema** — `Envelope` with `Material` enum
   (`generic_secret` shipped in v1.0; `x509_cert` added in v1.1 Phase 6;
   `pgp_key` and `ssh_key` added in v1.1 Phase 7).
```

## Info

### IN-01: Duplicate `strip_control_chars` implementation in `src/preview.rs`

**File:** `src/preview.rs:427-429` (private fn) duplicates
`src/payload/mod.rs:196-198` (public fn).

**Issue:** Both functions have identical bodies (`s.chars().filter(|c|
!c.is_control()).collect()`), but the preview-side docstring is also
slightly inaccurate — it says "ASCII control characters (< 0x20 or
0x7F)" while `char::is_control()` covers the full Unicode "Cc" category
(C0 0x00..0x1F, DEL 0x7F, AND C1 0x80..0x9F). Phase 2's
`payload::strip_control_chars` docstring correctly states the wider
range. Two implementations are a low-grade DRY violation with a real
risk of drift if one is later "tightened" inconsistently.

**Fix:** Delete the private `preview::strip_control_chars` and call
`crate::payload::strip_control_chars` from `first_uid_string`. No
behavioral change, eliminates the docstring inconsistency.

### IN-02: Stale MSRV comment in `src/flow.rs`

**File:** `src/flow.rs:1241-1242`
**Issue:** The comment still reads:

```rust
// ---- std::io::IsTerminal: required by TtyPrompter (Rust 1.70+; MSRV 1.85) --
use std::io::IsTerminal;
```

Phase 7 Plan 01 bumped MSRV to 1.88 (`Cargo.toml:8`,
`rust-toolchain.toml:2`) per D-P7-20. The MSRV note is wrong. Not a
behavior bug — `IsTerminal` is still 1.70+ — but the comment will
mislead a future reader inspecting MSRV-minimum facts.

**Fix:** Update to `// MSRV 1.88` or drop the MSRV-specific reference and
keep just the 1.70 stabilization marker.

### IN-03: Redundant CPU work — `pgp_armor` re-parses bytes already parsed by preview

**File:** `src/preview.rs:530-554` + `src/flow.rs:571`
**Issue:** When `--armor` is requested for a PgpKey share, the receive
path parses the binary packet stream THREE times:

1. `render_pgp_preview` parses (via `pgp_primary_is_secret` +
   `extract_public_metadata` / `extract_secret_metadata`).
2. `pgp_armor` re-runs `pgp_primary_is_secret` (parses every
   top-level packet again).
3. `pgp_armor` then re-parses the full key via
   `SignedPublicKey::from_bytes` or `SignedSecretKey::from_bytes`.

Performance is out of v1 scope per the review charter, so this is INFO-
only. It is flagged because (a) the comment in `pgp_armor` (lines
533-537) acknowledges the deterministic-dispatch rationale but does not
note the re-parse cost, and (b) a small refactor — threading
`is_secret` and a parsed `SignedPublicKey/SignedSecretKey` from
preview into the armor step — would avoid the duplication while keeping
the same security guarantees. Not required, but worth a note.

**Fix:** Defer to v1.2 if at all; document in the Phase 7 retro that
the trade-off was accepted in exchange for keeping preview and armor
helpers decoupled.

### IN-04: `.planning/phases/07-typed-material-pgpkey-sshkey/07-CONTEXT.md` says `WireBudgetExceeded` exit 7; code maps to exit 1

**File:** `.planning/phases/07-typed-material-pgpkey-sshkey/07-CONTEXT.md:25,46`
(planning artifact, not source — out of normal review scope, but flagging
for traceability)

**Issue:** Phase 7 CONTEXT decisions D-P7-01 say "exit code 7" for
`Error::WireBudgetExceeded`, and the in-scope-list at line 25 says
"reuse … `WireBudgetExceeded` → 7". The actual mapping in
`src/error.rs:122` is exit 1 (alongside `ShareRefMismatch` and
`InvalidShareUri`), which is what `SPEC.md:704` documents. CONTEXT was
written before research / cross-check; the code and SPEC agree, but the
CONTEXT is misleading for any future reader auditing exit-code lineage.

**Fix:** Per CLAUDE.md "Planning docs convention" the per-phase
VERIFICATION.md is authoritative for implementation status, not CONTEXT,
so this can be left as-is. If desired, a note on the phase RETRO that
"D-P7-01 + scope-list mention exit 7 for WireBudgetExceeded — actual is
exit 1 per `error.rs::exit_code`; documentation drifted from the
shipped error taxonomy" preserves the trail.

---

_Reviewed: 2026-04-24_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
