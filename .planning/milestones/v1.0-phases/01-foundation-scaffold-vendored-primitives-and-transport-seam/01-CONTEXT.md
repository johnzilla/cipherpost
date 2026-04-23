# Phase 1: Foundation — scaffold, vendored primitives, and transport seam - Context

**Gathered:** 2026-04-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver a single buildable `cipherpost` crate whose crypto/identity/transport/record layers (ported from cclink as prior art — not a live dependency) already have every wire-format and signed-payload lock-in correct: RFC 8785 canonical JSON (JCS), versioned HKDF info namespace, Argon2id params persisted in the identity file header, zeroized secrets with no `Debug` leakage, a `Transport` trait that admits both `DhtTransport` and `MockTransport`, and an `OuterRecord` schema reserving a 128-bit `share_ref` slot. The binary builds and `cipherpost identity generate` + `cipherpost identity show` work end-to-end; `send`/`receive`/`receipts` exist as clap subcommands that currently print "not implemented yet (phase N)" and exit 1.

Clarification captured during discussion: cclink is **prior art**, not an ongoing dependency. Copy what's useful, rename, diverge. No VENDORED.md manifest, no git subtree, no SHA pinning for future bug-sync — once Phase 1 ships, the cipherpost tree stands alone. The "fork-and-diverge" language in PROJECT.md Key Decisions means *cipherpost was built drawing on cclink as reference*, not *cipherpost maintains a vendor relationship with cclink*.

</domain>

<decisions>
## Implementation Decisions

### Module layout
- **D-01**: `src/` uses a flat layout — single-file modules at the crate root, not directories with `mod.rs`. Phase 1 creates `src/{crypto.rs, identity.rs, transport.rs, record.rs, cli.rs, error.rs, lib.rs, main.rs}`. Split a module into a directory only when it genuinely grows too big; don't pre-split.
- **D-02**: Phase 1 creates `src/payload.rs`, `src/receipt.rs`, `src/flow.rs` as **empty placeholder files** with a single `// TODO: phase 2+` comment and an empty `mod` block. Reason: signals the full shape of the skeleton on day one; Phase 2/3 PRs add bodies to existing files rather than introducing new files.
- **D-03**: `MockTransport` lives in `src/transport.rs` (behind `#[cfg(any(test, feature = "mock"))]`) rather than in `tests/`, so integration tests in `tests/` can `use cipherpost::transport::MockTransport` via the library re-export.

### Wire-format / on-disk constants (locked now; any change post-Phase-1 is a protocol bump)
- **D-04**: Envelope magic bytes = `CIPHPOSK` (ASCII, 8 bytes).
- **D-05**: Outer record DHT label = `_cipherpost`.
- **D-06**: Receipt DHT label = `_cprcpt-<share_ref>` where `<share_ref>` is the 32-char hex form of the 128-bit share_ref.
- **D-07**: Protocol version = `1` (u16). Written into every signed `OuterRecordSignable` and `Envelope`.
- **D-08**: HKDF info namespace = `cipherpost/v1/<context>` where `<context>` is context-specific (e.g., `cipherpost/v1/identity-kek`, `cipherpost/v1/share-sender`). Every HKDF call-site is enumerated by test.

### CLI surface
- **D-09**: Single crate with both `[[bin]]` and `[lib]` targets in one `Cargo.toml`. No workspace. Binary at `src/main.rs`, library at `src/lib.rs`; the binary imports from the library. Workspace split deferred until a second consumer exists (per PROJECT.md Key Decision).
- **D-10**: Command style is **hybrid**:
  - Flat verbs: `cipherpost send`, `cipherpost receive`, `cipherpost receipts`, `cipherpost version`
  - Subcommands under `identity`: `cipherpost identity generate`, `cipherpost identity show`
- **D-11**: Phase 1 ships the **full clap command tree**. `identity generate` and `identity show` work end-to-end. `send`, `receive`, `receipts` exist as typed clap subcommands whose handlers print `not implemented yet (phase N)` to stderr and exit `1`. Phase 2 and Phase 3 replace the handler bodies; no new clap wiring needed in later phases.
- **D-12**: `cipherpost` invoked with no args prints the default clap `--help` output (full command tree with descriptions). `--help` and every subcommand `--help` include at least one worked example (`EXAMPLES` section) — this is locked by CLI-03.
- **D-13**: `cipherpost version` is implemented in Phase 1 (not stubbed). It prints crate version, embedded git commit hash (via `build.rs` or `env!` on a `VERGEN_GIT_SHA`-style var — planner's call), and a one-line list of crypto primitives (`age`, `Ed25519`, `Argon2id`, `HKDF-SHA256`, `JCS`).

### Error type
- **D-14**: Library exposes a single `pub enum Error` deriving `thiserror::Error`. One variant per failure class with a `#[source]` chain preserved for all underlying errors (`age::DecryptError`, `pkarr::Error`, `io::Error`, `argon2::Error`, etc.).
- **D-15**: **Source chains are never Displayed in user-facing output.** Binary (`src/main.rs`) matches on the top-level variant to pick exit code + sanitized message; never walks the `source()` chain into stderr. A test scans bad-input stderr output for any substring matching `age::`, `pkarr::`, or `Os {` as proof of non-leakage. Source chains remain reachable for `RUST_LOG=debug` logging and test assertions.
- **D-16**: **All signature-verification failures produce the identical user-facing message.** Outer PKARR signature failure, inner Ed25519 signature failure, canonical-JSON re-serialization mismatch, and tampered-field detection all emit one message (recommended: `signature verification failed`) on stderr and exit `3`. The internal variants may be distinct (for tests and logs); the binary-visible message is one string. Prevents distinguishing-oracle attacks against the verifier.
- **D-17**: Error-crate choice: **`thiserror` in `src/lib.rs`**, **`anyhow` in `src/main.rs`**. Both already in the locked stack (`anyhow 1`, `thiserror 2`); no new deps. Library code returns `Result<T, cipherpost::Error>`; binary uses `anyhow::Result<()>` + `.context(...)` for ergonomic propagation at the top level, with an explicit match-to-exit-code dispatcher before exit.

### Claude's Discretion
Downstream research/planning agents have latitude on:
- Whether to scaffold `cargo-fuzz` targets in Phase 1 or defer to a later phase (skeleton lock-in doesn't require fuzz harnesses; REQUIREMENTS.md doesn't explicitly require them in Phase 1). Either is fine.
- Whether to generate the git-commit-hash build-time var via `vergen`, `built`, `env!` on a `cargo:rustc-env=` in `build.rs`, or similar. Implementation detail.
- Property-test framework for CRYPTO-04's JCS determinism assertion: `proptest` is already in the research-recommended stack, but planner may choose quickcheck or hand-rolled if there's a reason.
- Whether Argon2id PHC string in the identity file header uses the standard `$argon2id$v=19$m=...$t=...$p=...$salt$hash` form or a cipherpost-specific parser that embeds the same fields. Standard PHC form is the default expectation.
- Exact shape of the acceptance-stub `not implemented yet` message — as long as exit `1` and stderr output are consistent.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project-level (all phases)
- `.planning/PROJECT.md` — vision, core value, constraints, key decisions (including the locked crypto/stack decisions this phase inherits)
- `.planning/REQUIREMENTS.md` — the 20 REQ-IDs this phase owns (SCAF-01..05, CRYPTO-01..06, IDENT-01..05, TRANS-01/02/04/05) plus their acceptance criteria
- `.planning/ROADMAP.md` §"Phase 1" — goal statement and five success criteria

### Research (read before planning)
- `.planning/research/SUMMARY.md` — reconciled 10-phase build order; identifies which skeleton-lock-in pitfalls Phase 1 owns
- `.planning/research/STACK.md` — exact crate pins (pkarr 5.0.3, `ed25519-dalek =3.0.0-pre.5`, age 0.11, argon2 0.5, hkdf 0.12, sha2 0.10, zeroize 1, clap 4.5, anyhow 1, thiserror 2, base64 0.22, bech32 0.9, dirs 5, dialoguer 0.12, serde + serde_json, serde_canonical_json) and the rationale for pinning exactly to cclink v1.3.0's set
- `.planning/research/ARCHITECTURE.md` — module layout proposal (consumed here, refined to the flat layout in D-01/D-02), data flow per flow, vendored-vs-new boundary, `Transport` trait design
- `.planning/research/PITFALLS.md` — the 15 skeleton-lock-in pitfalls with prevention tests; Phase 1 owns #1 (Ed25519→X25519), #4 (HKDF versioning), #7 (no Debug on secrets), #8 (Argon2 params in header), #9 (age-only, no direct chacha20poly1305), #13 (cargo-audit/deny in CI), #15 (0600 perms)
- `.planning/research/FEATURES.md` — CLI-ergonomics table stakes referenced by CLI-01..05

### External (prior art, not a dependency)
- `https://github.com/johnzilla/cclink` — prior implementation the author built; copy/clone/rename what's useful for the crypto/identity/transport/record layers. **Not a long-term link:** cipherpost is its own project; cclink is reference-only.

### Not yet written (will be produced in Phase 4)
- `SPEC.md` — final lock for payload schema, canonical JSON rules, signature format, DHT labels, exit codes, passphrase contract. Phase 1's decisions above are the SPEC's v1 source-of-truth for constants and error shape.

</canonical_refs>

<code_context>
## Existing Code Insights

This is a greenfield Rust project. Only `cipherpost-prd.md`, `CLAUDE.md`, `README.md` exist in the working tree prior to Phase 1. No `src/`, no `Cargo.toml`, no tests.

### Reusable Assets
None yet in this repo. Code patterns will be lifted from `johnzilla/cclink` as reference:
- Ed25519 ↔ X25519 conversion (cclink's crypto module)
- Argon2id + HKDF-SHA256 KEK derivation
- PKARR SignedPacket publish/resolve via `pkarr::ClientBlocking`
- Dual-signature (outer PKARR + inner Ed25519 over canonical JSON) pattern
- Canonical JSON via declaration-order struct fields — **replaced in cipherpost with `serde_canonical_json` (JCS / RFC 8785)** per Key Decision

### Established Patterns
None in this repo. Establishing now (Phase 1 is the reference implementation for every later phase):
- `Result<T, cipherpost::Error>` at library boundaries
- `anyhow::Result<()>` in `main.rs` with explicit match-to-exit-code dispatcher
- `Zeroizing<Vec<u8>>` / `secrecy::SecretBox<T>` for every key-holding value
- `#[cfg(any(test, feature = "mock"))]` to gate `MockTransport`
- All HKDF calls use domain-separated info strings prefixed `cipherpost/v1/`

### Integration Points
Phase 2 consumes:
- `cipherpost::crypto::{ed25519_to_x25519, kdf_kek_from_passphrase, hkdf_expand, ...}`
- `cipherpost::identity::{Identity, load, generate}` (plus the identity-file PHC header format)
- `cipherpost::record::{OuterRecord, OuterRecordSignable, share_ref_from_bytes}` (the signable-struct shape; Phase 2 adds the `Envelope` that gets serialized into `OuterRecord.ciphertext`)
- `cipherpost::transport::{Transport, DhtTransport, MockTransport}` (trait + both impls; Phase 2 uses the send/receive methods)
- `cipherpost::Error` (with Phase-2-relevant variants like `Expired`, `SignatureInvalid`, `DecryptFailed`, `NotFound` already defined)

Phase 3 additionally consumes:
- `Transport::publish_receipt` signature (defined here with a placeholder impl that calls `self.publish(packet)` — real resolve-merge-republish body lands in Phase 3)

</code_context>

<specifics>
## Specific Ideas

- The author built `cclink` (https://github.com/johnzilla/cclink), which solved the same protocol problem for Claude session IDs. Cipherpost generalizes the payload and flow. Copy whatever's useful; no long-term link.
- "Flat until it hurts" — author-stated module layout preference. Keep `src/` flat; split to directories only when a single-file module genuinely grows too large.
- Sig-failure unification message: author's preferred strictness is "all sig failures look the same on stderr" — aligns with PITFALLS #16 error-oracle hygiene even though it's framed there as a v1.0 concern.
- `identity show` must print both fingerprints (OpenSSH-style + z-base-32) — locked via IDENT-05 and PROJECT.md Key Decisions. Not a Phase 1 gray area; called out here because it's the user-facing output of the only complete command Phase 1 ships.

</specifics>

<deferred>
## Deferred Ideas

Nothing raised in discussion that belonged outside Phase 1 scope. Topics explicitly flagged as *not* Phase 1 during discussion (and already tracked elsewhere):

- **`cargo-fuzz` scaffold and targets** — PITFALLS recommended for skeleton, but REQUIREMENTS.md doesn't lock it in Phase 1. Leave to planner's discretion (Claude's Discretion above); if not Phase 1, add as Phase 2 or Phase 4 task.
- **Property tests for JCS determinism beyond CRYPTO-04's fixture check** — CRYPTO-04 requires a property test for `serde_canonical_json` determinism. Broader property coverage of `OuterRecord` round-tripping belongs in Phase 2 where `Envelope` is actually serialized.
- **Cross-platform CI matrix** — PITFALLS #18 explicitly v1.0, not skeleton. Phase 1 CI targets linux/x86_64 only.
- **MSRV pin** — PITFALLS #17 explicitly v1.0, not skeleton.
- **`cargo-vet` and sigstore/cosign release signing** — v1.0 release engineering, per PITFALLS #13 "skeleton = cargo-audit + cargo-deny; v1.0 = + vet + sigstore".
- **Workspace split into `cipherpost-core` + `cipherpost-cli`** — deferred until a second consumer exists (PROJECT.md Key Decision).
- **pkarr 5 → 6 upgrade** — post-skeleton (Out of Scope in REQUIREMENTS.md).

### Reviewed Todos (not folded)
No todos existed to review (`gsd-sdk query todo.match-phase 1` returned 0).

</deferred>

---

*Phase: 01-foundation-scaffold-vendored-primitives-and-transport-seam*
*Context gathered: 2026-04-20*
