---
phase: 07-typed-material-pgpkey-sshkey
verified: 2026-04-25T12:30:00Z
status: passed
score: 5/5 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 4/5
  initial_verification: false
  gaps_closed:
    - "SPEC.md §3.2 documents ssh_key as still LIVE in Phase 7 (not 'reserved' or returning NotImplemented{phase:7})"
  gaps_remaining: []
  regressions: []
gaps:
  - truth: "SPEC.md §3.2 documents ssh_key as still LIVE in Phase 7 (not 'reserved' or returning NotImplemented{phase:7})"
    status: resolved
    reason: "Resolved in commit f4750a5 (2026-04-25) via verbatim application of 07-REVIEW.md WR-01 + WR-02 fixes. SPEC.md §3.2 (line 154) now reads 'cipherpost/v1.1 (Phase 7) adds: pgp_key { bytes } and ssh_key { bytes }.' with no stale 'Reserved for Phase 7 Plan 05+' or 'NotImplemented{phase:7}' clauses. SPEC.md §9 Lineage (lines 1007-1008) now reads 'Envelope with Material enum (generic_secret shipped in v1.0; x509_cert added in v1.1 Phase 6; pgp_key and ssh_key added in v1.1 Phase 7).' with no stale 'reserved for v1.0+' phrasing. Regression grep confirms zero remaining occurrences of the stale patterns; full test suite (253 pass / 0 fail / 14 ignored) green; lychee --offline SPEC.md clean per commit message."
    artifacts:
      - path: SPEC.md
        issue: "RESOLVED — see commit f4750a5 (8 lines changed: -5 / +3)"
    missing: []
---

# Phase 7: Typed Material — PgpKey + SshKey Verification Report

**Phase Goal:** Users can securely hand off OpenPGP keys and OpenSSH private keys with full metadata visible on the acceptance screen; both variants apply the Phase 6 pattern.

**Verified:** 2026-04-25
**Status:** passed (re-verification after gap closure)
**Re-verification:** Yes — second pass after commit f4750a5 closed the WR-01/WR-02 SPEC doc-drift gap

## Re-verification Summary

The initial verification on 2026-04-24 returned `gaps_found` with **score 4/5** because of one Warning-class SPEC.md doc-drift gap (WR-01 lines 154-155 stale "Reserved for Phase 7 Plan 05+" claim about ssh_key + WR-02 line 1010 stale "reserved for v1.0+" claim about all three typed variants). All five ROADMAP success criteria were code-verified; the gap was purely documentation-narrative drift that contradicted shipped code.

**Closure evidence (commit f4750a5, 2026-04-25):**

```
SPEC.md §3.2 line 154 now reads:
  cipherpost/v1.1 (Phase 7) adds: pgp_key { bytes } and ssh_key { bytes }.

SPEC.md §9 Lineage lines 1007-1008 now read:
  Typed payload schema — Envelope with Material enum (generic_secret shipped in v1.0;
  x509_cert added in v1.1 Phase 6; pgp_key and ssh_key added in v1.1 Phase 7).
```

The fixes match the verbatim wording proposed in 07-REVIEW.md WR-01 + WR-02 and the `missing:` clauses of the prior VERIFICATION.md. The diff is exactly 8 lines (5 deletions, 3 additions) — pure text edits to the two stale narrative blocks; no code changes, no other SPEC sections modified.

**Regression checks performed during re-verification:**

| Check | Command | Result |
|-------|---------|--------|
| Stale phrases removed | `grep -nE "Reserved for Phase\|reserved for v1\.0\|NotImplemented \{ phase: 7" SPEC.md` | 0 matches (exit 1) |
| Stale `v1.0+` callouts removed | `grep -nE "v1\.0\+\|NotImplemented\{phase:7" SPEC.md` | 0 matches (exit 1) |
| Full test suite still green | `cargo test --features mock` | 253 passed / 0 failed / 14 ignored |
| `ssh_key` references coherent in SPEC | `grep -nE "ssh_key\|ssh-key" SPEC.md` | All remaining references are factually correct (LIVE Phase 7 Plan 05-08, wire shape, error oracle, dep-tree guard test names) |

**No regressions introduced.** Test count and ignored-test set are identical to the initial verification's snapshot. All other code-level evidence from the initial pass remains valid (artifacts unchanged, key links unchanged, data-flow unchanged).

## Goal Achievement

Phase 7 ships eight plans (01-08) across two parallel waves (PGP plans 01-04 + SSH plans 05-08) implementing both `Material::PgpKey` and `Material::SshKey` end-to-end. The code-level implementation is complete and ship-quality: all four variants live in `run_send` + `run_receive`, both renderers emit the documented banner subblocks, supply-chain invariants hold, and the full test suite (253 passing tests + 14 documented `#[ignore]`'d wire-budget tests) is green. The single gap from the initial verification — SPEC.md doc-drift on ssh_key status — is now resolved in commit f4750a5.

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | User can `cipherpost send --material pgp-key` with a binary OpenPGP packet stream and receive it; ASCII-armored input is rejected (non-deterministic headers); multi-primary keyrings are rejected with exit 1 naming the count; secret keys display `[WARNING: SECRET key]` on the acceptance screen but are not blocked | ✓ VERIFIED | `src/payload/ingest.rs:132-264 pub fn pgp_key` rejects armor (line 152: `"ASCII-armored input rejected — supply binary packet stream"`), rejects multi-primary with N substituted (`"PgpKey must contain exactly one primary key; keyrings are not supported in v1.1 (found {N} primary keys)"`), enforces trailing-bytes invariant. `src/preview.rs:284-528 render_pgp_preview` emits `[WARNING: SECRET key — unlocks cryptographic operations]` first-line for tag-5 primaries (line 311). All 11 `tests/material_pgp_ingest.rs` tests pass; `tests/pgp_banner_render.rs` (7 tests) pin the SECRET-warning placement. (Re-verified: regression spot-check confirmed.) |
| 2 | User can `cipherpost send --material ssh-key` with an OpenSSH v1 format key; legacy PEM, RFC 4716, and FIDO-format keys are rejected at ingest; the acceptance screen shows key type, SHA-256 fingerprint (OpenSSH-style), and comment labeled as sender-attested | ✓ VERIFIED | `src/payload/ingest.rs:269+ pub fn ssh_key` strict-rejects non-OpenSSH-v1 input via prefix sniff (`Error::SshKeyFormatNotSupported`); 5 format-rejection tests in `tests/material_ssh_ingest.rs` (rsa/dsa/ec/rfc4716/fido). `src/preview.rs:683+ render_ssh_preview` emits Key + SHA-256 fingerprint (`SHA256:<base64-unpadded>`) + `[sender-attested]`-labeled comment per Plan 06; 7 `tests/ssh_banner_render.rs` golden-string tests pass. (Re-verified: regression spot-check confirmed.) |
| 3 | JCS fixtures `tests/fixtures/material_pgp_signable.bin` and `tests/fixtures/material_ssh_signable.bin` are committed and asserted byte-for-byte identical on every CI run | ✓ VERIFIED | `tests/fixtures/material_pgp_signable.bin` (376 B) committed; `tests/material_pgp_envelope_round_trip.rs::material_pgp_envelope_fixture_bytes_match` byte-identity test passes. `tests/fixtures/material_ssh_signable.bin` (620 B) committed; `tests/material_ssh_envelope_round_trip.rs` (3 active tests) all pass. (Re-verified: still green.) |
| 4 | `cargo tree | grep ed25519-dalek` pre-flight result is documented in Phase 7 plan 01 — either "no 2.x leak" or explicit coexistence acceptance recorded before any `ssh-key` code ships | ✓ VERIFIED | `.planning/phases/07-typed-material-pgpkey-sshkey/07-01-ed25519-dalek-tree.txt` (134-line evidence) + `07-05-ed25519-dalek-tree.txt` (regression check) commit explicit coexistence acceptance. Two versions present: `ed25519-dalek v2.2.0` (from pgp 0.19.0, transitive) + `ed25519-dalek v3.0.0-pre.5` (from pkarr direct). `tests/x509_dep_tree_guard.rs` (7 tests, 2 added in Plan 04 + 2 in Plan 08) runtime-enforces this shape — including a dedicated `dep_tree_ssh_key_does_not_pull_ed25519_dalek_2_x_independently` test catching SSH-induced regressions. SSH-10 satisfied. |
| 5 | Malformed PGP packets and malformed SSH bytes at receive time each return exit 1 with a generic message that does not leak crate internals | ✓ VERIFIED | `tests/pgp_error_oracle.rs` (3 tests) + `tests/ssh_error_oracle.rs` (5 tests) enumerate every InvalidMaterial reason × variant × forbidden-token combination (15 PGP forbidden tokens + 6 SSH-specific forbidden tokens); all assert Display contains zero crate internals. `Error::InvalidMaterial { variant: "pgp_key" \| "ssh_key", reason: "malformed PGP packet stream" \| "malformed OpenSSH v1 blob" }` is the curated reason; `exit_code` returns 1. `Error::SshKeyFormatNotSupported` (Plan 05 / D-P7-12 distinct variant for the SSH-format-conversion remediation hint) also maps to exit 1. |

**Score:** 5/5 truths verified. The gap from the initial pass is now resolved.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `Cargo.toml` | pgp =0.19.0 + ssh-key 0.6.7 + MSRV 1.88 + RUSTSEC ignore | ✓ VERIFIED | line 8: `rust-version = "1.88"`; line 65: `pgp = { version = "=0.19.0", default-features = false }`; line 83: `ssh-key = { version = "0.6.7", default-features = false, features = ["alloc"] }`. `deny.toml` carries the RUSTSEC-2023-0071 ignore with full Marvin-Attack rationale (Plan 01). |
| `src/payload/mod.rs` | `Material::PgpKey { bytes: Vec<u8> }` + `Material::SshKey { bytes: Vec<u8> }` struct variants + accessors + Debug redaction + plaintext_size + variant_tag | ✓ VERIFIED | All four Material variants are struct-form with `bytes: Vec<u8>`; manual Debug emits `<Variant>([REDACTED N bytes])`; `as_pgp_key_bytes` and `as_ssh_key_bytes` accessors mirror `as_x509_cert_bytes`; `plaintext_size` returns `bytes.len()` for all four arms (no zero placeholders); `variant_tag` returns the snake_case wire tag. |
| `src/payload/ingest.rs` | `pub fn pgp_key` + `pub fn ssh_key` with strict format-rejection, multi-primary check (PGP), trailing-bytes guards | ✓ VERIFIED | `pgp_key` at line 132 (sniff → packet iteration → multi-primary count → trailing-bytes via per-packet serialized-length sum, hardened in Plan 04 against rpgp's silent-0xFF cursor advance); `ssh_key` at line 269 (sniff → trailing-bytes pre-slice → from_openssh → to_openssh canonical re-encode). All error paths funnel through curated reason literals (oracle hygiene). |
| `src/preview.rs` | `render_pgp_preview` + `render_ssh_preview` + `pgp_armor` + `is_deprecated_ssh_algorithm` | ✓ VERIFIED | `render_pgp_preview` at line 284 (5 fields + SECRET warning + UpperHex 40/64-hex fingerprint); `pgp_armor` at line 530 (rpgp `to_armored_bytes` delegation); `render_ssh_preview` at line 683 (4 fields + `[DEPRECATED]` tag + `SHA256:<base64-unpadded>` fingerprint + `[sender-attested]` comment label). Constants pinned: `PGP_SEPARATOR_DASH_COUNT=53`, `SSH_SEPARATOR_DASH_COUNT=57`. D-P7-09 + D-P7-16 scope invariants intact (rpgp + ssh-key imports confined to ingest.rs + preview.rs). |
| `src/flow.rs` | `run_send` + `run_receive` arms LIVE for both PgpKey and SshKey + `--armor` matrix | ✓ VERIFIED | `run_send` lines 248 + 251: live dispatch to `payload::ingest::pgp_key` and `payload::ingest::ssh_key`. `run_receive` lines 504 + 516: live arms calling `as_*_bytes` + `render_*_preview` + threading subblock via `Option<&str>` to Prompter. `--armor` matrix: x509-cert + pgp-key accepted; generic-secret rejected with `"--armor requires --material x509-cert or pgp-key"` (line 494); ssh-key rejected with `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"` (line 533). No `NotImplemented{phase:7}` remains anywhere in flow.rs. |
| `src/error.rs` | `Error::SshKeyFormatNotSupported` variant with copy-pasteable ssh-keygen hint | ✓ VERIFIED | line 88: `SshKeyFormatNotSupported` variant defined; Display: `"SSH key format not supported — convert to OpenSSH v1 via \`ssh-keygen -p -o -f <path>\`"`; `exit_code` line 124: maps to exit 1 (D-P7-12). |
| `src/main.rs` | NotImplemented guards removed | ✓ VERIFIED | No `MaterialVariant::PgpKey \| MaterialVariant::SshKey` guard remains; `MaterialVariant` reference dropped from `use` line; only doc-comment mention at line 124. |
| `tests/fixtures/material_pgp_*` | PGP fixtures (public + secret + realistic + JCS envelope) | ✓ VERIFIED | 4 fixtures committed: `material_pgp_fixture.pgp` (202 B rpgp Ed25519 public), `material_pgp_secret_fixture.pgp` (239 B), `material_pgp_fixture_realistic.pgp` (935 B gpg RSA-3072 for WireBudgetExceeded test), `material_pgp_signable.bin` (376 B JCS envelope). Reproduction note documents recipes + SHA-256s. |
| `tests/fixtures/material_ssh_*` | SSH fixtures (Ed25519 + RSA-1024 + JCS envelope) | ✓ VERIFIED | 3 fixtures committed: `material_ssh_fixture.openssh-v1` (387 B Ed25519 from Plan 05), `material_ssh_fixture_rsa1024.openssh-v1` (1020 B for [DEPRECATED] test from Plan 08), `material_ssh_signable.bin` (620 B JCS envelope). DSA fixture intentionally skipped per D-P7-10 supply-chain hygiene; DSA-deprecation logic covered by Plan 06's predicate unit test. |
| Test files (10 new + 2 extended) | `tests/material_pgp_*` × 2, `tests/pgp_*` × 3, `tests/material_ssh_*` × 2, `tests/ssh_*` × 3, `tests/x509_dep_tree_guard.rs` extended, `tests/debug_leak_scan.rs` extended | ✓ VERIFIED | All 10 new files present + 2 extensions; full suites green: material_pgp_ingest=10/10, material_ssh_ingest=13/13, pgp_banner_render=7/7, ssh_banner_render=7/7, pgp_error_oracle=3/3, ssh_error_oracle=5/5, pgp_roundtrip=3 active + 2 ignored, ssh_roundtrip=4 active + 1 ignored, material_pgp_envelope_round_trip=3 active + 1 ignored regenerator, material_ssh_envelope_round_trip=3 active + 1 ignored regenerator, x509_dep_tree_guard=7/7 (was 3, +2 PGP + 2 SSH), debug_leak_scan=6/6. |
| `SPEC.md` | §3.2 PgpKey + SshKey wire shapes, §5.1 CLI matrix, §5.2 banner subblocks, §6 exit codes, §Pitfall #22 consolidated wire-budget matrix | ✓ VERIFIED | All updates landed: §3.2 PGP, §3.2 SSH at line 252+, §5.1 CLI matrix, §5.2 banner subblocks, §6 SshKeyFormatNotSupported row, §Pitfall #22 consolidated matrix. The previously-stale lines 154-155 and 1010 are FIXED in commit f4750a5: §3.2 line 154 now correctly reads `cipherpost/v1.1 (Phase 7) adds: pgp_key { bytes } and ssh_key { bytes }.`; §9 Lineage lines 1007-1008 now correctly read `Envelope with Material enum (generic_secret shipped in v1.0; x509_cert added in v1.1 Phase 6; pgp_key and ssh_key added in v1.1 Phase 7).`. Regression grep for `"Reserved for Phase\|reserved for v1\.0\|NotImplemented \{ phase: 7"` returns 0 matches. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `src/flow.rs::run_send` | `payload::ingest::pgp_key` | direct call (line 248) | ✓ WIRED | Live PGP dispatch; replaces Phase 6 NotImplemented arm. |
| `src/flow.rs::run_send` | `payload::ingest::ssh_key` | direct call (line 251) | ✓ WIRED | Live SSH dispatch; final variant; main.rs guard removed. |
| `src/flow.rs::run_receive` | `preview::render_pgp_preview` | call at line 513, threads via Option<&str> to Prompter | ✓ WIRED | PgpKey arm calls `as_pgp_key_bytes` + `render_pgp_preview` + emits subblock. |
| `src/flow.rs::run_receive` | `preview::render_ssh_preview` | call at line 537, threads via Option<&str> to Prompter | ✓ WIRED | SshKey arm calls `as_ssh_key_bytes` + `render_ssh_preview` after armor reject. |
| `src/flow.rs::run_receive` | `preview::pgp_armor` | call at line 571 in armor-output match | ✓ WIRED | PgpKey + armor=true delegates to rpgp's to_armored_bytes; X509Cert uses pem_armor_certificate (Phase 6). |
| `src/flow.rs::run_receive` | `Error::Config` SSH armor reject | line 533 raise site | ✓ WIRED | "--armor not applicable to ssh-key — OpenSSH v1 is self-armored" raised BEFORE preview parse (cost-on-error + pre-emit hygiene). |
| `payload::ingest::pgp_key` | `pgp::packet::PacketParser` + `pgp::ser::Serialize::to_writer` | direct rpgp calls | ✓ WIRED | Top-level packet iteration counts tag-5 + tag-6; trailing-bytes via per-packet serialized-length sum (hardened in Plan 04 vs rpgp 0.19.0's silent-0xFF cursor advance quirk). |
| `payload::ingest::ssh_key` | `ssh_key::PrivateKey::from_openssh` + `to_openssh(LineEnding::LF)` | direct ssh-key calls | ✓ WIRED | Strict prefix sniff → trailing-bytes pre-slice → parse → canonical re-encode (D-P7-11). Empirical byte-determinism guard test PASS. |
| `src/preview.rs::render_pgp_preview` | `pgp::composed::SignedPublicKey/SignedSecretKey + Fingerprint UpperHex + PublicKeyParts (rsa)` | direct rpgp + rsa trait calls | ✓ WIRED | Two parallel extraction paths (public/secret) with accurate subkey count for SECRET keys; algorithm dispatch covers 11 algos + numeric fallback; `[WARNING: SECRET key]` first-line for tag-5 primaries. |
| `src/preview.rs::render_ssh_preview` | `ssh_key::PrivateKey + PublicKey + Fingerprint(HashAlg::Sha256)` | direct ssh-key calls | ✓ WIRED | SHA-256-only fingerprint policy (no MD5 / SHA-1 paths); `[DEPRECATED]` tag for DSA + RSA<2048 via `is_deprecated_ssh_algorithm` predicate; `[sender-attested]` label on Comment line. |
| `src/error.rs::SshKeyFormatNotSupported` | `exit_code` arm | line 124 explicit arm → 1 | ✓ WIRED | Distinct variant from InvalidMaterial; embeds copy-pasteable `ssh-keygen -p -o -f <path>` hint per D-P7-12; same exit class (1) as content errors. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `src/preview.rs::render_pgp_preview` returned String | `out: String` (subblock) | `extract_public_metadata`/`extract_secret_metadata` → real rpgp parse of `Material::PgpKey.bytes` (which `run_receive` populates from the decrypted envelope) | ✓ Yes — banner subblock is produced from real fingerprint/UID/algorithm/subkey/created data extracted via rpgp from the sender's actual key bytes | ✓ FLOWING |
| `src/preview.rs::render_ssh_preview` returned String | `out: String` (subblock) | `SshPrivateKey::from_openssh` parse of `Material::SshKey.bytes` (which `run_receive` populates from the decrypted envelope, which holds the canonical re-encoded bytes from Plan 05's ingest) | ✓ Yes — banner subblock includes real algorithm/bits/SHA-256 fingerprint/comment from the sender's actual key | ✓ FLOWING |
| `payload::ingest::pgp_key` returned `Material::PgpKey { bytes }` | `bytes: Vec<u8>` | `raw.to_vec()` — input bytes verbatim (D-P7-11 PGP variant: bytes-verbatim, no canonical re-encode) | ✓ Yes — JCS envelope carries the actual binary packet stream | ✓ FLOWING |
| `payload::ingest::ssh_key` returned `Material::SshKey { bytes }` | `bytes: Vec<u8>` | `parsed.to_openssh(LineEnding::LF).as_bytes().to_vec()` — canonical re-encoded UTF-8 PEM | ✓ Yes — empirical byte-determinism guard test confirms the canonical-re-encode strategy is sound | ✓ FLOWING |
| `src/flow.rs::run_receive` PgpKey/SshKey output_bytes | `Vec<u8>` | `material_bytes` slice from `Material::*Key.bytes` (raw default path) OR `pgp_armor(material_bytes)?` for armor=true on PgpKey | ✓ Yes — sender's actual bytes flow to stdout/stdin via `write_output(&output_bytes)` | ✓ FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Code compiles cleanly | `cargo build --all-targets` | exit 0 | ✓ PASS |
| Full test suite passes | `cargo test --features mock` | 253 passed / 0 failed / 14 ignored — IDENTICAL to initial verification snapshot | ✓ PASS (no regression) |
| SPEC.md stale-phrase regression check | `grep -nE "Reserved for Phase\|reserved for v1\.0\|NotImplemented \{ phase: 7" SPEC.md` | exit 1 (0 matches) | ✓ PASS |
| SPEC.md `v1.0+` callout regression check | `grep -nE "v1\.0\+\|NotImplemented\{phase:7" SPEC.md` | exit 1 (0 matches) | ✓ PASS |
| §3.2 fix landed verbatim | `sed -n '152,154p' SPEC.md` | Lines 152-154 match the WR-01 proposed fix exactly | ✓ PASS |
| §9 Lineage fix landed verbatim | `sed -n '1007,1008p' SPEC.md` | Lines 1007-1008 match the WR-02 proposed fix exactly | ✓ PASS |
| Supply chain — no forbidden crates | `cargo tree \| grep -E "ring v\|aws-lc v\|openssl-sys v"` | exit 1 (no matches) | ✓ PASS |
| ed25519-dalek coexistence shape | `cargo tree \| grep "ed25519-dalek v"` | shows v2.2.0 (from pgp) + v3.0.0-pre.5 (from pkarr); no third version | ✓ PASS |
| D-P7-09 + D-P7-16 import scope | `grep -rE "^use pgp\|pgp::\|^use ssh_key\|ssh_key::" src/ \| grep -v "src/preview.rs\|src/payload/ingest.rs"` | empty (0 matches) | ✓ PASS |

In re-verification mode the failed must-have got the deepest scrutiny; passing must-haves received quick regression sanity checks (full test suite, supply-chain, import-scope) — all unchanged from the initial pass.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| PGP-01 | 07-01, 07-04 | ASCII-armor rejected at ingest | ✓ SATISFIED | `payload::ingest::pgp_key` strict prefix sniff; tests/material_pgp_ingest.rs: 3 armor-reject tests (PUBLIC/PRIVATE/SIGNATURE block headers all rejected) |
| PGP-02 | 07-01, 07-04 | Wire format `{"type":"pgp_key","bytes":"<base64-std>"}` | ✓ SATISFIED | `Material::PgpKey { #[serde(with = "base64_std")] bytes: Vec<u8> }`; tests/material_pgp_envelope_round_trip.rs byte-identity asserts JCS shape |
| PGP-03 | 07-01, 07-03, 07-04 | Multi-primary keyring rejected with N count | ✓ SATISFIED | `payload::ingest::pgp_key` counts top-level Tag::PublicKey + Tag::SecretKey; rejects with substituted N; tests/material_pgp_ingest.rs::pgp_key_multi_primary_rejected + tests/pgp_roundtrip.rs::pgp_multi_primary_send_rejected_at_ingest |
| PGP-04 | 07-02, 07-04 | Acceptance banner shows fingerprint + UID + algo + subkeys + Created; SECRET warning for tag-5 | ✓ SATISFIED | `preview::render_pgp_preview` 5-field subblock + first-line SECRET warning; tests/pgp_banner_render.rs (7 golden-string tests) |
| PGP-05 | 07-03, 07-04 | --armor emits ASCII-armored output via rpgp | ✓ SATISFIED | `preview::pgp_armor` delegates to rpgp's to_armored_bytes (auto-selects PUBLIC/PRIVATE BLOCK header); src/preview.rs::tests::pgp_armor_* unit tests; tests/pgp_roundtrip.rs::armor_on_pgp_share_emits_ascii_armor (#[ignore]'d for wire-budget; armor path covered by unit tests) |
| PGP-06 | 07-01, 07-04 | Plaintext cap (64 KB) for PgpKey | ✓ SATISFIED | `Material::plaintext_size()` for PgpKey returns `bytes.len()`; Phase 6 cap machinery sees real PGP byte counts; tests/pgp_roundtrip.rs::pgp_send_realistic_key_surfaces_wire_budget_exceeded_cleanly active |
| PGP-07 | 07-04 | JCS fixture committed at tests/fixtures/material_pgp_signable.bin | ✓ SATISFIED | 376 B fixture committed; tests/material_pgp_envelope_round_trip.rs byte-identity test passes |
| PGP-08 | 07-01, 07-02, 07-04 | Malformed PGP returns exit 1; generic Display (no crate internals) | ✓ SATISFIED | tests/pgp_error_oracle.rs (3 tests) enumerates 6 reasons × 4 variants × 15 forbidden tokens; oracle hygiene verified |
| PGP-09 | 07-04 | Round-trip integration test | ⚠️ DEFERRED — acceptable per D-P7-03 honest-messaging discipline | tests/pgp_roundtrip.rs::pgp_self_round_trip_recovers_packet_stream is `#[ignore]`'d due to measured wire-budget overflow (1236 B encoded for 202 B fixture vs 1000 B budget); D-P7-03 amendment carved this fallback for SSH and Plan 04 extended it to PGP; SPEC.md §Pitfall #22 consolidated matrix documents the deferral with measured numbers; v1.2 two-tier storage milestone re-enables. NOT a real gap because the deferral is documented infrastructure-level reality, not implementation absence. |
| SSH-01 | 07-05, 07-08 | OpenSSH v1 only; legacy PEM/RFC4716/FIDO → SshKeyFormatNotSupported exit 1 | ✓ SATISFIED | `payload::ingest::ssh_key` strict prefix sniff; 5 format-rejection tests in tests/material_ssh_ingest.rs (rsa/dsa/ec/rfc4716/fido all return SshKeyFormatNotSupported); Error::SshKeyFormatNotSupported exit 1 verified |
| SSH-02 | 07-05, 07-08 | Wire format + canonical wire blob | ✓ SATISFIED | `Material::SshKey { bytes }` with `to_openssh(LineEnding::LF)` canonical re-encode (D-P7-11); tests/material_ssh_ingest.rs::ssh_key_canonical_re_encode_round_trip pins the invariant; empirical byte-determinism PASS |
| SSH-03 | 07-05 | send --material ssh-key reads OpenSSH v1 bytes | ✓ SATISFIED | `run_send` MaterialVariant::SshKey arm dispatches live to `payload::ingest::ssh_key` (Plan 05) |
| SSH-04 | 07-06, 07-08 | Banner shows key type + SHA-256 fingerprint + sender-attested comment + DSA/RSA<2048 [DEPRECATED] | ✓ SATISFIED | `preview::render_ssh_preview` 4-line subblock; SHA256:<base64-unpadded> fingerprint via ssh-key's HashAlg::Sha256; `[sender-attested]` label on Comment; `is_deprecated_ssh_algorithm` predicate flags DSA + RSA<2048; tests/ssh_banner_render.rs RSA-1024 [DEPRECATED] test passes; DSA case covered by Plan 06's predicate unit test (DSA fixture skipped per D-P7-10 supply-chain hygiene — see Plan 08 Decisions) |
| SSH-05 | 07-07, 07-08 | --armor rejected for ssh-key (self-armored) | ✓ SATISFIED | `run_receive` SshKey arm rejects with "--armor not applicable to ssh-key — OpenSSH v1 is self-armored" BEFORE preview parse; tests/ssh_roundtrip.rs::armor_on_ssh_share_rejected_with_self_armored_error pins the literal via source-grep regression guard |
| SSH-06 | 07-05, 07-08 | Plaintext cap for SSH | ✓ SATISFIED | `Material::plaintext_size()` for SshKey returns `bytes.len()`; tests/ssh_roundtrip.rs::ssh_send_realistic_key_surfaces_wire_budget_exceeded_cleanly active (measured 1589 B encoded vs 1000 B budget) |
| SSH-07 | 07-08 | JCS fixture at tests/fixtures/material_ssh_signable.bin | ✓ SATISFIED | 620 B fixture committed (Plan 08); tests/material_ssh_envelope_round_trip.rs byte-identity test passes |
| SSH-08 | 07-05, 07-06, 07-08 | Malformed SSH returns exit 1; generic Display | ✓ SATISFIED | tests/ssh_error_oracle.rs (5 tests) enumerates SSH reasons × variants × forbidden tokens; SshKeyFormatNotSupported display omits ssh-key crate internals |
| SSH-09 | 07-08 | Round-trip integration test | ⚠️ DEFERRED — acceptable per D-P7-03 | tests/ssh_roundtrip.rs::ssh_self_round_trip_recovers_canonical_bytes is `#[ignore]`'d FROM DAY 1 with EXACT D-P7-03 note text (measured 1589 B encoded vs 1000 B budget); SPEC.md §Pitfall #22 documents; v1.2 two-tier storage re-enables. Same documented deferral pattern as PGP-09. |
| SSH-10 | 07-01, 07-04, 07-05, 07-08 | cargo tree pre-flight ed25519-dalek check | ✓ SATISFIED | Two evidence files committed (07-01 + 07-05 ed25519-dalek-tree.txt); two dep-tree guard tests in tests/x509_dep_tree_guard.rs runtime-enforce; ssh-key 0.6.7 with default-features=false, features=["alloc"] adds NO third version (verified across both Plan 01 baseline + Plan 05 regression check) |

**All 19 requirement IDs accounted for.** PGP-09 + SSH-09 are explicitly `#[ignore]`'d round-trip tests per D-P7-03 honest-messaging discipline (the deferral is documented in SPEC.md §Pitfall #22 with measured wire-budget overflow numbers); positive WireBudgetExceeded tests are ACTIVE for both variants and prove the error-surface is clean. Per D-P7-03 the round-trip ignore is the correct shipping posture, not a true gap.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| ~~SPEC.md~~ | ~~154-155~~ | ~~Stale doc claim: "Reserved for Phase 7 Plan 05+: ssh_key (dispatch returns Error::NotImplemented{phase:7})"~~ | ~~⚠️ Warning~~ | ✓ FIXED in commit f4750a5 |
| ~~SPEC.md~~ | ~~1010~~ | ~~Stale doc claim: "x509_cert, pgp_key, ssh_key reserved for v1.0+"~~ | ~~⚠️ Warning~~ | ✓ FIXED in commit f4750a5 |
| src/preview.rs | 427-429 | Duplicate `strip_control_chars` private fn (also at src/payload/mod.rs:196-198) | ℹ️ Info | DRY violation flagged in 07-REVIEW IN-01; low-grade — both impls have identical bodies, real risk of drift if one is later "tightened" inconsistently. Not a goal-blocker; cleanup deferred. |
| src/flow.rs | 1241-1242 | Stale MSRV comment "Rust 1.70+; MSRV 1.85" — should be 1.88 (Phase 7 Plan 01 bump) | ℹ️ Info | Flagged in 07-REVIEW IN-02; comment-only drift; no behavioral impact. Not a goal-blocker; cleanup deferred. |
| src/preview.rs | 530-554 + src/flow.rs | `pgp_armor` re-parses bytes already parsed by preview (3× parse cost on --armor + PgpKey path) | ℹ️ Info | Flagged in 07-REVIEW IN-03; performance optimization deferred to v1.2 (review charter explicitly defers performance work for v1) |

The two ⚠️ Warnings (SPEC.md doc-drift) are now resolved. The three ℹ️ Info items are nice-to-have cleanup that does not block goal achievement and was explicitly deferred per the review's own categorization. They do not change the verdict.

### Human Verification Required

None. All success criteria are programmatically verifiable — the implementation is verified by the comprehensive test suite + dep-tree guards + golden-string banner tests + error-oracle enumeration. The doc-drift fix is a pure text edit verifiable by regression grep + lychee. No visual/UX/external-service items require human spot-check beyond what the test suite already covers.

### Gaps Summary

**No remaining gaps.** Phase 7 goal is fully achieved.

The single gap from the initial verification — SPEC.md doc-drift on ssh_key status (WR-01 + WR-02) — was closed by commit f4750a5 ("docs(07): fix SPEC.md ssh_key + lineage drift") on 2026-04-25. The fixes match the verbatim wording proposed in 07-REVIEW.md and the `missing:` clauses of the prior VERIFICATION.md. Regression checks confirm:

- Zero remaining occurrences of `Reserved for Phase`, `reserved for v1.0`, or `NotImplemented { phase: 7` in SPEC.md
- Zero remaining occurrences of `v1.0+` callouts referencing typed variants
- Full test suite still green (253 passed / 0 failed / 14 ignored — identical to initial snapshot)
- Lychee --offline SPEC.md still clean (per commit message: "0 errors / 11 OK / 1 excluded")
- No regressions in any other code-level evidence (artifacts, key links, data-flow, supply-chain, import-scope all unchanged)

All 5 ROADMAP success criteria are implementation-verified. All 19 PGP+SSH requirement IDs are accounted for. The supply-chain invariants (D-P7-09 PGP scope, D-P7-16 SSH scope, ed25519-dalek coexistence shape) hold. The wire-budget round-trip `#[ignore]`'s for PGP-09 + SSH-09 remain documented per D-P7-03 with measured numbers in SPEC.md §Pitfall #22 — the correct shipping posture per the explicit honest-messaging discipline, not a hidden defect.

**Phase 7 is ready to proceed.** SPEC.md narrative is now consistent with shipped code; CLAUDE.md "Planning docs convention" drift hazard is closed for this phase.

---

_Verified: 2026-04-25 (re-verification after commit f4750a5)_
_Verifier: Claude (gsd-verifier)_
