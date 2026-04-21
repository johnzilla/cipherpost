# Phase 1: Foundation — scaffold, vendored primitives, and transport seam - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-20
**Phase:** 01-foundation-scaffold-vendored-primitives-and-transport-seam
**Areas discussed:** Vendoring strategy (aborted — not a real gray area per user), Module layout + naming, CLI surface in Phase 1, Error type design

---

## Area selection (initial multiSelect)

| Option | Description | Selected |
|--------|-------------|----------|
| Vendoring strategy | Verbatim-copy-then-cleanup vs clean-room-rename-at-copy-time vs git-subtree | ✓ |
| Module layout + naming | Mirror ARCHITECTURE.md exactly vs cclink-names-then-rename | ✓ |
| CLI surface in Phase 1 | Library + identity only vs full tree with stubs vs library-only | ✓ |
| Error type design | thiserror enum vs anyhow vs two-tier opaque | ✓ |

**User's choice:** All four areas selected for discussion.

---

## Vendoring strategy

**Outcome:** Aborted as a gray area. User clarified: cclink is **prior art**, not a live vendor relationship. "Copy/clone as needed, change names, whatever, don't care. Focus on the delta." Questions about provenance tracking, SHA pinning, VENDORED.md manifests, and two-commit verbatim-then-rename PRs were reframing a non-problem — once the skeleton ships, cipherpost stands alone.

Area dropped; moved to Module layout.

**Questions NOT answered** (obsoleted by the framing correction):
- Copy mode (two-commit vs one-commit vs subtree)
- Provenance marking (header comment vs manifest vs both)
- Vendor scope (minimum vs minimum+util+error vs everything)
- cclink pin (v1.3.0 tag vs latest main vs specific SHA)

---

## Module layout + naming

### Layout

| Option | Description | Selected |
|--------|-------------|----------|
| ARCHITECTURE.md 7-module split | crypto/transport/record/identity/payload/receipt/flow directories | |
| Flat until it hurts | src/{crypto.rs, identity.rs, transport.rs, record.rs, cli.rs, error.rs, lib.rs} single-file modules | ✓ |
| You decide | Pick whichever reads well | |

**User's choice:** Flat until it hurts.
**Notes:** Single-file modules at src/ root. Split to directories only when a module genuinely grows too big.

### Boundary (stubs for Phase 2+)

| Option | Description | Selected |
|--------|-------------|----------|
| Create stubs now (empty mod.rs + placeholder comment) | src/payload.rs, src/receipt.rs, src/flow.rs exist with TODO marker | ✓ |
| Create when needed | Phase 1 only creates files it touches | |

**User's choice:** Create stubs now.
**Notes:** Under the flat layout, this means creating `src/payload.rs`, `src/receipt.rs`, `src/flow.rs` as placeholder files with a `// TODO: phase 2+` comment.

### Rename set

| Option | Description | Selected |
|--------|-------------|----------|
| Lock the obvious set | CIPHPOSK / _cipherpost / _cprcpt-<share_ref> / protocol v1 | ✓ |
| Different names I'll specify | User names final spellings | |
| Defer to Phase 4 SPEC.md draft | Phase 1 uses placeholder names | |

**User's choice:** Lock the obvious set.

---

## CLI surface in Phase 1

### P1 cmds (which commands work vs stub)

| Option | Description | Selected |
|--------|-------------|----------|
| Just identity generate + show | No stubs for send/receive/receipts | |
| Identity + stub send/receive/receipts | Full clap command tree with stubs exiting 1 | ✓ |
| Identity + version only | No send/receive/receipts stubs at all | |

**User's choice:** Identity + stub send/receive/receipts.

### Command style

| Option | Description | Selected |
|--------|-------------|----------|
| Subcommands (cargo/gh/kubectl style) | `cipherpost <noun> <verb>` everywhere | |
| Flat verbs (age/ssh/gpg style) | `cipherpost send`, `cipherpost identity`, single level | |
| Hybrid | Flat verbs for send/receive/receipts/version + subcommands under identity | ✓ |

**User's choice:** Hybrid.

### Binary + library layout

| Option | Description | Selected |
|--------|-------------|----------|
| Single crate: bin + lib | One Cargo.toml with both targets | ✓ |
| Separate crates in workspace | cipherpost-lib + cipherpost-cli | |
| Library only in Phase 1 | No binary target until Phase 2 | |

**User's choice:** Single crate: bin + lib.

### Bare invoke (`cipherpost` with no args)

| Option | Description | Selected |
|--------|-------------|----------|
| Clap-default help | Full --help output | ✓ |
| Short usage + pointer to --help | Two-line minimal | |
| You decide | Whichever reads best | |

**User's choice:** Clap-default help.

---

## Error type design

### Err shape

| Option | Description | Selected |
|--------|-------------|----------|
| Single thiserror enum | One pub enum Error with variant per failure class | ✓ |
| Two-tier (internal + public ProtocolError) | Compile-time error-oracle hygiene | |
| anyhow everywhere + ExitCode trait | Simpler; hygiene becomes review discipline | |

**User's choice:** Single thiserror enum.

### Source chain

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — but never Display in user output | Preserved for RUST_LOG=debug; test enforces non-leakage | ✓ |
| No — strip at the boundary | Public variants flat | |
| Yes, and also show in --verbose | Opt-in detail on -v | |

**User's choice:** Yes — but never Display in user output.

### Error oracle (sig-failure distinguishability)

| Option | Description | Selected |
|--------|-------------|----------|
| All sig failures identical | One message for outer+inner+canonical-JSON+tampered-field | ✓ |
| Distinguish outer vs inner | Two messages | |
| Distinguish each failure class | Best debug ergonomics; worst oracle posture | |

**User's choice:** All sig failures identical.

### Crate deps

| Option | Description | Selected |
|--------|-------------|----------|
| thiserror only (in lib) | No anyhow | |
| thiserror + anyhow | thiserror in lib, anyhow in bin | ✓ |
| Neither — hand-rolled | Smallest deps, most boilerplate | |

**User's choice:** thiserror + anyhow.

---

## Final gate (explore more or move to context)

| Option | Description | Selected |
|--------|-------------|----------|
| I'm ready for context | Write 01-CONTEXT.md now | ✓ |
| One more area: testing depth | proptest + cargo-fuzz scaffold now or defer | |
| Different area I'll name | Free-text | |

**User's choice:** I'm ready for context.

---

## Claude's Discretion

Explicitly granted to downstream agents (CONTEXT.md §Claude's Discretion):
- Whether to scaffold `cargo-fuzz` in Phase 1 or defer
- Git-commit-hash build-time mechanism (`vergen`/`built`/`build.rs` env)
- Property-test framework (`proptest` recommended but not locked)
- Argon2id PHC string format (standard PHC parser vs cipherpost-specific)
- Exact shape of the "not implemented yet" stub message

## Deferred Ideas

Topics surfaced or implicitly flagged as non-Phase-1 during discussion:
- cargo-fuzz targets, cross-platform CI matrix, MSRV pin, cargo-vet, sigstore/cosign, workspace split, pkarr 5→6 upgrade — all explicitly v1.0 or post-skeleton per REQUIREMENTS.md Out of Scope and PITFALLS.md.
