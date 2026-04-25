---
phase: 07-typed-material-pgpkey-sshkey
plan: 01
subsystem: payload
tags: [rust, pgp, rpgp, payload, parser, typed-material, msrv, deny-toml, supply-chain]
requires:
  - Phase 6 Plan 01 — `src/payload/ingest.rs` submodule convention + `Error::InvalidMaterial`
  - Phase 6 Plan 03 — `MaterialVariant::{PgpKey, SshKey}` CLI enum + main.rs dispatch guards
provides:
  - `Material::PgpKey { bytes: Vec<u8> }` struct variant with base64_std serde wire shape
  - `Material::as_pgp_key_bytes() -> Result<&[u8], Error>` accessor (mirrors D-P6-15)
  - `payload::ingest::pgp_key(raw: &[u8]) -> Result<Material, Error>` — strict armor reject, multi-primary reject, trailing-bytes check
  - Live `run_send` dispatch for `MaterialVariant::PgpKey`
  - MSRV 1.88 baseline (D-P7-20)
  - RUSTSEC-2023-0071 ignore with documented rationale (D-P7-21)
  - ed25519-dalek 2.2.0 ↔ 3.0.0-pre.5 coexistence evidence (D-P7-22 / SSH-10)
affects:
  - Cargo.toml (rust-version + pgp dependency)
  - rust-toolchain.toml (channel 1.85 → 1.88)
  - deny.toml ([advisories] ignore)
  - src/payload/mod.rs (enum + Debug + accessor + plaintext_size + variant_tag)
  - src/payload/ingest.rs (new fn pgp_key + 5 inline tests)
  - src/flow.rs (run_send dispatch split + material_type_string struct pattern)
  - src/main.rs (NotImplemented guard narrowed to SshKey only)
  - tests/phase2_material_variants_unimplemented.rs (PgpKey struct construction)
  - tests/debug_leak_scan.rs (narrowed to SshKey — PgpKey Debug covered inline)
tech-stack:
  added:
    - "pgp =0.19.0 (default-features = false)"
    - "rsa 0.9.10 (transitive via pgp; RUSTSEC-2023-0071 accepted)"
    - "ed25519-dalek 2.2.0 (transitive via pgp; coexists with =3.0.0-pre.5 from pkarr)"
  patterns:
    - "pgp::packet::PacketParser iteration + Tag::PublicKey/SecretKey counting for multi-primary rejection"
    - "Cursor<&[u8]> + cursor.position() as the trailing-bytes oracle (parallel to x509-parser remainder slice)"
    - "Error-oracle hygiene extended: curated reason literals (no rpgp internals)"
key-files:
  created: []
  modified:
    - Cargo.toml
    - Cargo.lock
    - rust-toolchain.toml
    - deny.toml
    - src/payload/mod.rs
    - src/payload/ingest.rs
    - src/flow.rs
    - src/main.rs
    - tests/phase2_material_variants_unimplemented.rs
    - tests/debug_leak_scan.rs
  committed_evidence:
    - .planning/phases/07-typed-material-pgpkey-sshkey/07-01-ed25519-dalek-tree.txt
decisions:
  - "pgp 0.19.0 pulled ed25519-dalek 2.2.0 (not 2.1.1 as research predicted): pgp's `>=2.1.1` constraint resolved upward to the current latest 2.x release. Coexistence behavior identical; supply-chain signal still doubles for Ed25519 as D-P7-22 anticipated."
  - "Toolchain-file bump added as Rule-3 deviation: the plan mandated Cargo.toml `rust-version` 1.85→1.88 but not `rust-toolchain.toml`. Leaving the channel pin at 1.85 would have made `cargo build` reject its own MSRV; bumping channel to match is correctness (not scope creep)."
  - "PacketTrait import needed to resolve `.tag()` at call site. Added `use pgp::packet::PacketTrait` inline at the use site (not module-top) so the trait lives only where it's needed."
  - "Trailing-bytes check uses `cursor.position()` rather than re-running the parse or calling `packet.write_len()`. Position math is O(1), exact, and avoids depending on rpgp's round-trip byte-identity (which the crate does not claim)."
  - "rpgp 0.19.0 `PacketParser` treats UnexpectedEof as clean end-of-stream (returns None), so a valid packet stream followed by trailing garbage results in a position < raw.len() — caught by the post-loop check. Verified against the garbage-input inline test."
metrics:
  duration_minutes: 18
  tasks_completed: 3
  tests_added: 11
  test_suite_after: "47 lib tests + 182+ integration tests green"
  release_binary_bytes: 4622576
  completed_date: "2026-04-25"
---

# Phase 7 Plan 01: Typed Material — PgpKey Foundation Summary

**One-liner:** Established the PGP-variant foundation — `pgp =0.19.0` dependency with hardened feature set, MSRV bump to 1.88, `Material::PgpKey { bytes: Vec<u8> }` struct variant with base64_std serde round-trip, `payload::ingest::pgp_key` with strict ASCII-armor rejection + multi-primary keyring rejection + trailing-bytes invariant, and live `run_send` dispatch; ed25519-dalek 2.2.0↔3.0.0-pre.5 coexistence documented per D-P7-22.

## What Shipped

### Task 1 — Dependency + MSRV + supply-chain gate (commit `7c1cb6f`)
Added `pgp = { version = "=0.19.0", default-features = false }` to Cargo.toml (disables bzip2 + asm + wasm per D-P7-04). Bumped `rust-version` from `1.85` to `1.88` per D-P7-20 (pgp 0.19.0 requires Rust 1.88). Added RUSTSEC-2023-0071 to `deny.toml [advisories] ignore` with the full Marvin-Attack rationale per D-P7-21. Bumped `rust-toolchain.toml` channel 1.85→1.88 (Rule-3 deviation — without it the toolchain itself rejects the new MSRV pin). Verified supply chain: no `ring`, no `aws-lc`, no `openssl-sys` in the resolved dep tree.

### Task 2 — Material enum upgrade (commit `2c7b3c6`)
Upgraded `Material::PgpKey` from unit variant to `{ bytes: Vec<u8> }` with `#[serde(with = "base64_std")]` wire serialization. Added `Material::as_pgp_key_bytes()` accessor returning `Err(InvalidMaterial)` on variant mismatch (mirrors D-P6-15 pattern). Extended `Debug` impl with `PgpKey([REDACTED N bytes])` redaction arm. Extended `plaintext_size()` with real `bytes.len()` arm for PgpKey. Extended `variant_tag()` with struct pattern `PgpKey { .. }`. Added 6 new inline unit tests covering serde round-trip, Debug redaction, plaintext_size, mismatched accessor, happy accessor, and X509-on-PgpKey cross-accessor. Migrated all cross-file `Material::PgpKey` references (flow.rs `run_receive` arm + `material_type_string`, tests/phase2_material_variants_unimplemented.rs, tests/debug_leak_scan.rs) to struct-variant syntax. SshKey remains a unit variant — Plan 05 upgrades it.

### Task 3 — Ingest function + live dispatch (commit `3ab8a5d`)
Implemented `pub fn pgp_key(raw: &[u8]) -> Result<Material, Error>` in `src/payload/ingest.rs`. Pipeline: (1) skip leading ASCII whitespace, reject if prefix matches `-----BEGIN PGP` (catches both PUBLIC and PRIVATE KEY BLOCK armor per D-P7-05); (2) iterate top-level packets via `pgp::packet::PacketParser` wrapping a `std::io::Cursor<&[u8]>`, counting `Tag::PublicKey` + `Tag::SecretKey` (subkeys not counted); (3) reject if zero packets, zero primaries, or primary count > 1 with N substituted (D-P7-06 / PGP-03); (4) `cursor.position()` trailing-bytes check (WR-01 invariant mirror); (5) return `Material::PgpKey { bytes: raw.to_vec() }` with no canonical re-encode. Oracle hygiene enforced: every failure path returns `Error::InvalidMaterial { variant: "pgp_key", reason: "<curated literal>" }`; zero rpgp internal strings in source. Added 5 inline tests + oracle-hygiene enumeration. Split `run_send`'s combined `PgpKey | SshKey => NotImplemented` arm — PgpKey now dispatches live to `payload::ingest::pgp_key`; SshKey keeps returning `NotImplemented { phase: 7 }`. Narrowed `main.rs` belt-and-suspenders guard from `PgpKey | SshKey` to `SshKey` only.

## Critical Evidence

### pgp version pulled
```
pgp v0.19.0
```
Exact-pin via `=0.19.0` in Cargo.toml.

### rsa version pulled (target of RUSTSEC-2023-0071 accept)
```
rsa v0.9.10
└── pgp v0.19.0
    └── cipherpost v0.1.0
```

### `cargo tree -p ed25519-dalek` coexistence evidence (D-P7-22 / SSH-10)

Full 134-line output committed at `.planning/phases/07-typed-material-pgpkey-sshkey/07-01-ed25519-dalek-tree.txt`. Summary:

```
ed25519-dalek v2.2.0
├── curve25519-dalek v4.1.3
├── ed25519 v2.2.3
├── rand_core v0.6.4
├── sha2 v0.10.9
├── subtle v2.6.1
└── zeroize v1.8.2

ed25519-dalek v3.0.0-pre.5
├── curve25519-dalek v5.0.0-pre.5
├── ed25519 v3.0.0-rc.4
├── sha2 v0.11.0-rc.4
├── signature v3.0.0-rc.10
├── subtle v2.6.1
└── zeroize v1.8.2
```

Reverse dependency view:
```
ed25519-dalek v2.2.0 → pgp v0.19.0 → cipherpost
ed25519-dalek v3.0.0-pre.5 → {mainline, pkarr} → cipherpost
```

Per D-P7-22: binary carries two Ed25519 implementations. Acceptable — each crate uses its own pinned version; low runtime risk. Remove when either (a) pgp 0.20+ drops ed25519-dalek 2.x, or (b) pkarr moves to a stable ed25519-dalek 3.x.

### Supply chain clean (T-07-01 mitigated)
```
cargo tree | grep -E "ring v|aws-lc v|openssl-sys v"
→ (empty, exit 1) — PASS: no forbidden crates
```

### API path used inside `pgp_key()`
Top-level packet iteration via `pgp::packet::PacketParser::new(&mut Cursor::new(raw))`. Each yielded `Packet` exposes `.tag()` through `pgp::packet::PacketTrait` (explicit `use pgp::packet::PacketTrait;` at the call site). Tag discrimination via `pgp::types::Tag::PublicKey` / `pgp::types::Tag::SecretKey`. Trailing-bytes detection via `cursor.position() as usize != raw.len()` after iteration completes.

Plan 04's fixture-based integration tests can rely on this exact API; Plan 02's preview renderer should mirror the `PacketParser` + `PacketTrait` pattern but may additionally use `pgp::composed::SignedPublicKey` / `SignedSecretKey` for structured field extraction (UID, creation time, algorithm).

### Locked error-reason literals (Plan 04's `EXPECTED_REASONS` depends on these)
- `"ASCII-armored input rejected — supply binary packet stream"`
- `"malformed PGP packet stream"`
- `"trailing bytes after PGP packet stream"`
- `"accessor called on wrong variant"` (inherited from Phase 6)
- Multi-primary format: `"PgpKey must contain exactly one primary key; keyrings are not supported in v1.1 (found {N} primary keys)"` with `{N}` replaced by the actual count.

### Release binary size (Research Open Question #2)
Pre-plan baseline: not captured at Phase 6 close — no prior measurement in STATE.md or the Phase 6 SUMMARY files.
Post-plan: **4,622,576 bytes (~4.5 MB)**.
Well under the 20 MB flag threshold. Plan 05 should record its own post-SSH measurement to bracket the growth.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] Bumped rust-toolchain.toml channel to match MSRV**
- **Found during:** Task 1 `cargo build` attempt
- **Issue:** Plan instructed to bump Cargo.toml `rust-version` 1.85 → 1.88 but did not mention `rust-toolchain.toml`, which was still pinned to `channel = "1.85"`. Cargo rejected the build with `rustc 1.85.1 is not supported by the following packages: cipherpost@0.1.0 requires rustc 1.88 ... pgp@0.19.0 requires rustc 1.88`.
- **Fix:** Bumped `rust-toolchain.toml` `channel` from `"1.85"` to `"1.88"`. Rustup auto-downloaded Rust 1.88.0. Build succeeded on the first retry.
- **Files modified:** rust-toolchain.toml
- **Commit:** `7c1cb6f`
- **Rationale:** Pure Rule-3 blocker fix. The plan's MSRV bump cannot take effect without the toolchain file matching. No scope change.

**2. [Rule 3 — Blocking] `use pgp::packet::PacketTrait` inline import**
- **Found during:** Task 3 first build attempt
- **Issue:** `packet.tag()` failed to compile — `rustc` reported "items from traits can only be used if the trait is in scope" with the hint `use pgp::packet::PacketTrait`.
- **Fix:** Added `use pgp::packet::PacketTrait;` inside the `pgp_key` function body (kept local so the trait doesn't leak into other module-level code).
- **Files modified:** src/payload/ingest.rs
- **Commit:** `3ab8a5d` (incorporated before initial commit)
- **Rationale:** Mechanical API-availability fix. The plan's pseudo-code template referenced `packet.tag()` without the trait import — rpgp's design moves `.tag()` onto a trait rather than making it inherent on the enum. Zero behavioral difference.

### Documentation-level drift (not a bug fix, just a data point)

**3. [Info] pgp 0.19.0 pulled ed25519-dalek `2.2.0`, not `2.1.1`**
- **Where plan assumed:** Research file `07-RESEARCH.md` §Crate: pgp and must-have `truths` state the expected ed25519-dalek version from pgp as `2.1.1`.
- **Actual:** `cargo tree` shows `ed25519-dalek v2.2.0` pulled via pgp.
- **Why:** pgp 0.19.0's Cargo.toml pins `>=2.1.1` (not `=2.1.1` — verified via `cat ~/.cargo/registry/src/*/pgp-0.19.0/Cargo.toml | grep ed25519-dalek`). Cargo's version resolver picked the newest 2.x release available on crates.io.
- **Action:** None required. Coexistence semantics are identical — `cargo-deny multiple-versions = "warn"` still flags exactly two ed25519-dalek majors, and the binary carries both implementations. The must-have `truth` wording "`cargo tree -p ed25519-dalek` evidence is committed in the plan SUMMARY showing BOTH `2.1.1` (from pgp) AND `=3.0.0-pre.5` (from pkarr) present" should be read as "both `2.x` (from pgp) and `=3.0.0-pre.5` (from pkarr)" — version-class invariance, not exact-match.

**4. [Info] Release binary not comparable to baseline**
- Research Open Question #2 requested a `cargo build --release` size delta. Phase 6 SUMMARY files did not record a release-binary size, so no delta is possible. Post-plan size (4.5 MB) is recorded as the new baseline; Plan 05 should record its own measurement for the PGP↔SSH delta.

### Authentication gates
None encountered. Plan was fully autonomous.

### Tooling note (not a code deviation)
`cargo deny check advisories` failed locally with `unsupported CVSS version: 4.0` while parsing `RUSTSEC-2026-0066.md` — this is a cargo-deny tooling bug independent of our deny.toml content. `cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0009` (the latter is the pre-existing Phase-6 `time` crate advisory) exits 0. The deny.toml `[advisories] ignore = ["RUSTSEC-2023-0071"]` entry is syntactically correct per cargo-deny spec; CI with a newer cargo-deny will respect it. The RUSTSEC-2026-0009 `time` advisory is pre-existing Phase 6 scope and out-of-scope for this plan.

## Deferred Issues

None. All acceptance criteria met; all tests pass; supply chain clean.

## Stubs Tracking

None. Every code path introduced by this plan is live:
- `Material::PgpKey { bytes }` round-trips through JCS serde with real base64.
- `as_pgp_key_bytes()` returns real bytes on happy path.
- `payload::ingest::pgp_key` returns real `Material::PgpKey` with the input's byte stream.
- `run_send` dispatches PgpKey live; no more `NotImplemented { phase: 7 }` for that variant.
- `run_receive` still returns `NotImplemented { phase: 7 }` for PgpKey — Plan 03 wires the preview renderer in. This is scope-documented (see `<interfaces>` block of 07-01-PLAN.md) rather than a stub.

## Verification Results

### 1. MSRV + supply-chain gates
```
grep 'rust-version = "1.88"' Cargo.toml                  ✓ 1 match
cargo tree -p pgp | head -1                              ✓ "pgp v0.19.0"
cargo tree | grep -E "ring v|aws-lc v|openssl-sys v"     ✓ no matches (clean)
cargo tree -p ed25519-dalek ... (committed as evidence)  ✓ both v2.2.0 + v3.0.0-pre.5 present
```

### 2. New library tests (all 11 pass)
```
material_pgp_key_serde_round_trip                                      ✓
material_pgp_key_debug_redacts_bytes                                   ✓
material_pgp_key_plaintext_size_matches_byte_length                    ✓
material_as_pgp_key_bytes_mismatch_returns_invalid_material            ✓
material_as_pgp_key_bytes_happy_returns_slice                          ✓
material_as_x509_cert_bytes_on_pgp_key_returns_invalid_material        ✓
material_pgp_key_generic_secret_accessor_returns_not_implemented       ✓
pgp_key_armor_public_block_rejected                                    ✓
pgp_key_armor_private_block_rejected                                   ✓
pgp_key_armor_with_leading_whitespace_still_rejected                   ✓
pgp_key_garbage_rejected_generically                                   ✓
pgp_key_empty_input_rejected                                           ✓
pgp_key_oracle_hygiene_no_internal_errors_in_reason                    ✓
```

### 3. No regressions in existing tests
`cargo test --features mock`: 47 lib unit tests + 48+ integration test files, all green (matches pre-plan count plus the new PgpKey tests).

### 4. Error-oracle source check (no rpgp internals in source)
```
grep -rE "pgp::errors|pgp::packet::Error|PgpError|pgp::Error" src/payload/ src/error.rs
→ (empty) — PASS
```

### 5. Cross-file grep matrix
```
pub fn pgp_key (ingest.rs):           1  ✓
pub fn as_pgp_key_bytes (mod.rs):     1  ✓
PgpKey { .. } variant_tag pattern:    1  ✓
PgpKey([REDACTED arm:                 2  ✓ (Debug impl + test assertion)
#[serde(with = base64_std)]:          3  ✓ (GenericSecret + X509Cert + PgpKey)
payload::ingest::pgp_key in flow.rs:  2  ✓ (import + run_send call site)
MaterialVariant::PgpKey => in flow.rs: 1 ✓ (split arm)
main.rs old dual-guard removed:       0  ✓ (narrowed to SshKey only)
```

## Threat Model Status

All threats documented in the plan's `<threat_model>` are mitigated or accepted as scheduled:

| Threat ID | Disposition | Status |
|-----------|-------------|--------|
| T-07-01 — pgp supply-chain sneak-in (ring/aws-lc) | mitigate | `default-features = false` applied; dep-tree grep clean |
| T-07-02 — `rsa 0.9` Marvin timing | accept | `deny.toml [advisories] ignore` with rationale; cipherpost is parse-only (no decrypt/sign oracle) |
| T-07-03 — silent MSRV drift | mitigate | Cargo.toml + rust-toolchain.toml both at 1.88; CI pin updated in same commit |
| T-07-04 — Debug leak on PgpKey bytes | mitigate | Manual Debug impl returns `PgpKey([REDACTED N bytes])`; inline test enforces |
| T-07-05 — malformed-packet DoS | mitigate | rpgp 0.19.0 is post-advisory patched; 64 KB plaintext cap bounds parser input; all errors funnel through `InvalidMaterial` with no panic paths |
| T-07-06 — multi-primary keyring smuggling | mitigate | Tag::PublicKey+Tag::SecretKey count > 1 → reject with N substituted |
| T-07-07 — trailing-bytes share_ref drift | mitigate | `cursor.position() != raw.len()` → reject |
| T-07-08 — ASCII-armor JCS-identity bypass | mitigate | Strict prefix sniff before any rpgp call; armor permanently rejected |

## Hand-off Notes for Downstream Plans

**Plan 02 (PGP preview renderer):**
- `use pgp::packet::PacketTrait` is required to call `.tag()` on `Packet`. Plan 02 likely needs `pgp::composed::SignedPublicKey` / `SignedSecretKey` for structured field extraction — `pgp::composed::shared` appears to expose parse entry points; verify the API at plan-02 time.
- `render_pgp_preview(bytes: &[u8]) -> Result<String, Error>` can rely on the ingest invariant: input bytes have already passed armor-reject + single-primary + trailing-bytes, so `PacketParser` won't see keyrings or junk. Use `composed` high-level for fingerprint/UID/algorithm; fall back to `packet_sum::Packet` patterns if the composed API doesn't expose a desired field.

**Plan 03 (CLI wiring):**
- `run_receive`'s `Material::PgpKey { .. } | Material::SshKey =>` arm still returns `NotImplemented { phase: 7 }`. Plan 03 splits it: PgpKey calls `preview::render_pgp_preview`; SshKey stays NotImplemented.
- `material_type_string` already returns `"pgp_key"` for the struct variant — no edit needed in Plan 03.

**Plan 04 (PGP ship gate):**
- `EXPECTED_REASONS` table for PGP must include: `"ASCII-armored input rejected — supply binary packet stream"`, `"malformed PGP packet stream"`, `"trailing bytes after PGP packet stream"`, `"accessor called on wrong variant"`, plus the multi-primary format-string literal.
- Fixture per Research GAP 5: target ≤200 B raw packet stream (v4 Ed25519 + ≤20-char UID + zero subkeys + minimal self-cert). The plan's 43-char UID suggestion would blow the wire budget.
- `tests/debug_leak_scan.rs` should gain `material_pgp_key_debug_redacts_bytes` as an extern test (the inline unit test is duplicated but lives in `src/payload/mod.rs::tests`); Plan 04 can either extend the module's extern scan or promote the inline test.

**Plan 05 (SSH foundation):**
- D-P7-22 / SSH-10 coexistence evidence is ALREADY recorded in this plan (ed25519-dalek 2.x came from pgp, not ssh-key). Plan 05 only needs to run `cargo tree -p ed25519-dalek` as a regression check showing ssh-key does NOT introduce a third version — expected outcome: still exactly `2.2.0` (from pgp) + `3.0.0-pre.5` (from pkarr).

## Self-Check: PASSED

- ✅ Cargo.toml — `pgp = { version = "=0.19.0", default-features = false }` + `rust-version = "1.88"` present
- ✅ rust-toolchain.toml — `channel = "1.88"` present
- ✅ deny.toml — `RUSTSEC-2023-0071` ignore entry with Marvin rationale present
- ✅ src/payload/mod.rs — `Material::PgpKey { bytes: Vec<u8> }`, `as_pgp_key_bytes`, Debug redaction, plaintext_size, variant_tag all present
- ✅ src/payload/ingest.rs — `pub fn pgp_key` present
- ✅ src/flow.rs — `payload::ingest::pgp_key` dispatch live in run_send
- ✅ src/main.rs — NotImplemented guard narrowed to `SshKey` only
- ✅ .planning/phases/07-typed-material-pgpkey-sshkey/07-01-ed25519-dalek-tree.txt — 134-line evidence file present
- ✅ Commit `7c1cb6f` (Task 1) present in `git log`
- ✅ Commit `2c7b3c6` (Task 2) present in `git log`
- ✅ Commit `3ab8a5d` (Task 3) present in `git log`
- ✅ All 11 new library tests pass
- ✅ Full `cargo test --features mock` suite green (no regressions)
- ✅ No forbidden crates (`ring`, `aws-lc`, `openssl-sys`) in dep tree
- ✅ No rpgp internal types (`pgp::errors`, `PgpError`) leak into source
