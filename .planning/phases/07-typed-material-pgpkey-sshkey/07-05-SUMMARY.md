---
phase: 07-typed-material-pgpkey-sshkey
plan: 05
subsystem: typed-material-ssh-foundation
tags: [rust, ssh, ssh-key, payload, parser, typed-material, ed25519-coexistence-regression, oracle-hygiene]
requires:
  - Phase 6 — `Material::X509Cert { bytes }` + `payload::ingest::x509_cert` (struct-variant + accessor pattern, oracle-hygiene `InvalidMaterial` shape)
  - Phase 7 Plan 01 — `Material::PgpKey { bytes }` + `payload::ingest::pgp_key` (sibling pattern that this plan mirrors for SSH); Plan 01's `MaterialVariant::SshKey` narrowed-guard in main.rs (deleted by this plan)
  - Phase 7 Plan 04 — `tests/x509_dep_tree_guard.rs::dep_tree_ed25519_dalek_coexistence_shape` (runtime regression check this plan must NOT trip)
provides:
  - `Material::SshKey { bytes: Vec<u8> }` — final variant upgraded from unit to struct (Phase 7 closes the typed-material schema)
  - `Material::as_ssh_key_bytes() -> Result<&[u8], Error>` — mirrors `as_pgp_key_bytes` / `as_x509_cert_bytes`, returns `InvalidMaterial { variant, reason: "accessor called on wrong variant" }` on mismatch
  - `Material::plaintext_size()` extended — final `SshKey { bytes } => bytes.len()` arm (no more 0-placeholder for unit variants)
  - `Error::SshKeyFormatNotSupported` — new variant (NOT a reuse of `InvalidMaterial`); D-P7-12 user-facing message embeds copy-pasteable `ssh-keygen -p -o -f <path>` hint; exit code 1
  - `pub fn payload::ingest::ssh_key(raw: &[u8]) -> Result<Material, Error>` — strict OpenSSH-v1 sniff, trailing-bytes-before-parse pre-slice (tolerates whitespace, rejects garbage), `ssh-key::PrivateKey::from_openssh` parse + `to_openssh(LineEnding::LF)` canonical re-encode, stores re-encoded UTF-8 bytes
  - `src/flow.rs::run_send` `MaterialVariant::SshKey` arm — LIVE dispatch to `payload::ingest::ssh_key` (final variant; all 4 arms now real)
  - `tests/fixtures/material_ssh_fixture.openssh-v1` — 387 B Ed25519 OpenSSH v1 private-key fixture for byte-determinism + round-trip tests; sibling `.reproduction.txt` notes recipe + SHA-256
  - `Cargo.toml` — `ssh-key = { version = "0.6.7", default-features = false, features = ["alloc"] }` (verified-clean shape per D-P7-10; ed25519 feature NOT enabled)
  - `.planning/phases/07-typed-material-pgpkey-sshkey/07-05-ed25519-dalek-tree.txt` — SSH-10 regression evidence; verbatim `cargo tree -p ed25519-dalek@2.2.0` + `@3.0.0-pre.5` outputs, demonstrating ssh-key adds no third version
  - `tests/debug_leak_scan.rs::material_ssh_key_debug_redacts_bytes` — fourth and final Material-variant byte-leak guard
affects:
  - Cargo.toml (+11 lines: ssh-key dep + comment block)
  - Cargo.lock (transitive deps for ssh-key 0.6.7)
  - src/error.rs (+15 lines: SshKeyFormatNotSupported variant + exit_code arm)
  - src/payload/mod.rs (Material::SshKey unit → struct; Debug arm extended; plaintext_size arm extended; variant_tag struct pattern; new as_ssh_key_bytes accessor; 6 new inline tests)
  - src/payload/ingest.rs (+88 lines: pub fn ssh_key + 13 new ssh_tests inline)
  - src/flow.rs (run_send SshKey arm live dispatch; material_type_string + run_receive SshKey arm switched to struct pattern)
  - src/main.rs (-7 lines: MaterialVariant::SshKey rejection guard removed; unused MaterialVariant import dropped)
  - tests/phase2_material_variants_unimplemented.rs (ssh_key cross-accessor test re-shaped; legacy unit-variant serialize test deleted)
  - tests/debug_leak_scan.rs (material_ssh_unit_variant_debug_no_bytes → material_ssh_key_debug_redacts_bytes)
tech-stack:
  added:
    - "ssh-key 0.6.7 (OpenSSH v1 private-key parsing + canonical re-encode + SHA-256 fingerprint; default-features=false, features=[\"alloc\"]; D-P7-10 verified-clean)"
  patterns:
    - "Trailing-bytes check FIRST, then parse: ssh-key 0.6.7 strict-rejects ANY post-END-marker bytes (even whitespace from text-editor saves), so we slice raw to BEGIN..=END region BEFORE handing to from_openssh — preserves user-friendly diagnostics (specific 'trailing bytes' reason for non-whitespace; tolerates harmless newlines)"
    - "Distinct Error variant per remediation class: D-P7-12 SshKeyFormatNotSupported is NOT a reuse of InvalidMaterial because the user-facing message embeds an SSH-specific ssh-keygen conversion hint that would be wrong for non-SSH content errors"
    - "Empirical byte-determinism guard test as research-GAP closure: research GAP 4 was 'ssh-key from_openssh + to_openssh round-trip determinism not documented'; ssh_key_canonical_re_encode_is_byte_deterministic test resolves it positively for ssh-key 0.6.7"
    - "Dep-tree regression evidence pattern (mirrors Plan 01): commit `cargo tree -p ed25519-dalek` output to a sibling .txt file; CI's tests/x509_dep_tree_guard.rs runtime-enforces; the .txt is the human-readable diff target"
key-files:
  created:
    - tests/fixtures/material_ssh_fixture.openssh-v1
    - tests/fixtures/material_ssh_fixture.reproduction.txt
    - .planning/phases/07-typed-material-pgpkey-sshkey/07-05-ed25519-dalek-tree.txt
    - .planning/phases/07-typed-material-pgpkey-sshkey/07-05-SUMMARY.md
  modified:
    - Cargo.toml
    - Cargo.lock
    - src/error.rs
    - src/payload/mod.rs
    - src/payload/ingest.rs
    - src/flow.rs
    - src/main.rs
    - tests/phase2_material_variants_unimplemented.rs
    - tests/debug_leak_scan.rs
decisions:
  - "Trailing-bytes check moved BEFORE parse (Rule-1 fix during Task 3): initial implementation followed the plan literally (parse then check post-END bytes), but ssh-key 0.6.7's from_openssh strict-rejects ANY trailing bytes — even harmless newlines from text-editor saves — and reports them as 'malformed'. Restructured to slice raw to BEGIN..=END first, then hand the slice to from_openssh. Result: whitespace-trailer test passes; non-whitespace garbage still produces specific 'trailing bytes after OpenSSH v1 blob' diagnostic."
  - "SSH fixture committed by Plan 05 (not deferred to Plan 08): the empirical byte-determinism guard test in src/payload/ingest.rs::ssh_tests requires a real OpenSSH v1 fixture at compile time. Committed `tests/fixtures/material_ssh_fixture.openssh-v1` (387 B Ed25519, generated via `ssh-keygen -t ed25519 -C \"\" -N \"\"`) as part of Plan 05. Plan 08's full integration tests can reference the same file."
  - "ssh-key 0.6.7 PrivateKey::from_openssh API takes `impl AsRef<[u8]>` directly: research raised the question whether the API expected &str or &[u8]. Source inspection at /home/john/.cargo/registry/src/.../ssh-key-0.6.7/src/private.rs:232 confirmed `pub fn from_openssh(pem: impl AsRef<[u8]>)`. We pass &[u8] directly — no UTF-8 conversion needed (PEM is ASCII; ssh-key handles both internally)."
  - "to_openssh(LineEnding::LF) returns Zeroizing<String>: confirmed at /home/john/.cargo/registry/src/.../ssh-key-0.6.7/src/private.rs:255. We call `encoded.as_bytes().to_vec()` to store the canonical UTF-8 bytes in `Material::SshKey.bytes`. Zeroizing wrapper drops on scope exit, so the intermediate plaintext is wiped — the only persistent copy is the encrypted age envelope downstream."
  - "Did NOT remove `MaterialVariant::SshKey` from src/main.rs's `Send` command struct field: the field type is still `MaterialVariant` (passed to run_send for dispatch). Only the unused `use cipherpost::cli::MaterialVariant` import was removed (Rust unused-import warning would otherwise break CI's clippy -D warnings)."
  - "Did NOT touch unrelated formatting drift in src/preview.rs / tests/pgp_banner_render.rs / tests/x509_dep_tree_guard.rs / src/payload/ingest.rs PGP block: cargo fmt drifted these files (pre-existing condition unrelated to this plan's edits). Per scope-boundary rules, reverted to keep the diff minimal."
metrics:
  duration_minutes: 24
  tasks_completed: 3
  tests_added: 19
  tests_total_after: "13 inline ssh_tests (in src/payload/ingest.rs) + 6 inline payload::tests SshKey tests (in src/payload/mod.rs) + 1 swapped tests/debug_leak_scan.rs test + 1 reshaped tests/phase2_material_variants_unimplemented.rs test"
  test_suite_after: "cargo test --features mock — full suite green; 53 test crates pass / 0 fail / 0 errors"
  fixture_bytes_committed:
    ssh: 387
  binary_size:
    release_mb: "5.1 MB (pre-Plan-05 baseline 4.5 MB; +600 KB; well under the 2 MB flag threshold)"
  completed_date: "2026-04-25"
---

# Phase 7 Plan 05: Typed Material — SshKey Foundation Summary

**One-liner:** Landed the SSH-variant foundation — added `ssh-key = "0.6.7"` (alloc-only, ed25519-dalek-leak-free), upgraded `Material::SshKey` from unit to struct variant with `bytes: Vec<u8>`, added `as_ssh_key_bytes` accessor + Debug redaction, introduced new `Error::SshKeyFormatNotSupported` variant (NOT a reuse of `InvalidMaterial`) with `ssh-keygen -p -o -f <path>` user hint, implemented `payload::ingest::ssh_key` with strict OpenSSH-v1 sniff + canonical re-encode via `to_openssh(LineEnding::LF)` + trailing-bytes-before-parse pre-slice (Rule-1 restructure to handle ssh-key 0.6.7's strict trailer rejection), swapped `run_send`'s SshKey arm to live dispatch, removed the final main.rs belt-and-suspenders guard, validated D-P7-11 canonical-re-encode strategy via empirical byte-determinism guard test (PASS on ssh-key 0.6.7), captured SSH-10 regression evidence showing ed25519-dalek dep tree UNCHANGED from Plan 01 (still 2.2.0 + 3.0.0-pre.5; no third version from ssh-key).

## What Shipped

### Task 1 — ssh-key 0.6.7 dependency + dep-tree regression evidence (commit `5f1aa69`)

Added `ssh-key = { version = "0.6.7", default-features = false, features = ["alloc"] }` to `Cargo.toml` with a 7-line comment block explaining D-P7-10's verified-clean shape (sha2 unconditional, ed25519 feature gated only for ed25519-dalek interop TryFrom impls — not parse path).

Captured `cargo tree -p ed25519-dalek@2.2.0` + `cargo tree -p ed25519-dalek@3.0.0-pre.5` + `cargo tree -d` filtered output to `.planning/phases/07-typed-material-pgpkey-sshkey/07-05-ed25519-dalek-tree.txt` (142 lines, 4 KB). The two ed25519-dalek versions are byte-identical to Plan 01's evidence file: **v2.2.0 (from pgp transitive)** + **v3.0.0-pre.5 (from pkarr direct)** — ssh-key 0.6.7 with `default-features = false, features = ["alloc"]` adds NO third version. T-07-34 (silent ed25519-dalek 2.x leak from ssh-key) mitigated.

`cargo tree | grep -E "ring v|aws-lc v|openssl-sys v"` exits 1 (no matches) — supply chain remains clean. `tests/x509_dep_tree_guard.rs::dep_tree_ed25519_dalek_coexistence_shape` (added in Plan 04) still passes after this plan — runtime enforcement aligned with documented evidence.

`cargo build --release` produces a 5.1 MB binary (vs 4.5 MB Plan 01 baseline = +600 KB). Open Question #2 monitor: well under the 2 MB flag threshold; ssh-key adds modest size overhead (sha2 + base64 encoding + zeroize transitive).

### Task 2 — Material::SshKey struct upgrade + accessor + Debug redaction (commit `0358e23`)

`src/payload/mod.rs`:

- `Material::SshKey` upgraded from unit variant to `SshKey { #[serde(with = "base64_std")] bytes: Vec<u8> }` — matches GenericSecret / X509Cert / PgpKey shape; serde wire form `{"type":"ssh_key","bytes":"<base64>"}`.
- Manual Debug arm: `Material::SshKey { bytes } => write!(f, "SshKey([REDACTED {} bytes])", bytes.len())` — Pitfall #7 / T-07-35 mitigation; SSH private keys NEVER hex-leak via `format!("{:?}", m)`.
- New accessor `pub fn as_ssh_key_bytes(&self) -> Result<&[u8], Error>` mirroring `as_pgp_key_bytes`; cross-variant calls return `InvalidMaterial { variant: <wire-tag>, reason: "accessor called on wrong variant" }`.
- `plaintext_size` arm extended: `Material::SshKey { bytes } => bytes.len()`. The function is now exhaustive over four real arms with no unit-variant zero-placeholder.
- `variant_tag` arm switched to `Material::SshKey { .. } => "ssh_key"` (struct pattern).
- 6 new inline tests in `payload::tests`: serde round-trip, Debug redaction with hex-window assertion, plaintext_size, accessor happy-path, accessor cross-variant mismatch, accessor on PgpKey returns `InvalidMaterial`.
- Phase-2-style placeholder test `material_non_generic_variants_return_not_implemented_on_bytes_access` (which iterated `[Material::SshKey]` after Plan 01 narrowed the loop) replaced with `material_all_variants_have_dedicated_accessors` — asserts all four variants hit their native accessors.

`src/flow.rs`: `material_type_string` and the `run_receive` `Material::SshKey` arm pattern updated to `{ .. }` struct form. The `run_receive` arm STILL returns `Error::NotImplemented { phase: 7 }` — Plan 07 swaps it live alongside `preview::render_ssh_preview`.

`tests/phase2_material_variants_unimplemented.rs`:
- `ssh_key_bytes_access_returns_not_implemented_phase_2` → `ssh_key_generic_secret_accessor_returns_not_implemented_phase_2` (cross-accessor wildcard arm test, parallel to PgpKey + X509Cert).
- `non_generic_variants_serialize_their_type_tag` (which serialized `Material::SshKey` as bare-tag JSON) deleted entirely — no unit variants remain, the assertion no longer applies. Per-variant `*_serde_round_trip` tests in `payload::tests` already cover the serialize behavior in struct form.

`tests/debug_leak_scan.rs`: `material_ssh_unit_variant_debug_no_bytes` (which asserted `format!("{:?}", Material::SshKey) == "SshKey"` while SshKey was unit) replaced with `material_ssh_key_debug_redacts_bytes` — asserts both `REDACTED` substring presence AND no `cdef0123456789ab` hex-window leak. All four Material variants now have dedicated leak-scan tests.

`cargo test --lib payload::tests` → 26 pass / 0 fail (6 new SshKey tests included). `cargo test --test debug_leak_scan` → 6 pass / 0 fail. `cargo test --test phase2_material_variants_unimplemented` → 3 pass / 0 fail.

### Task 3 — Error::SshKeyFormatNotSupported + payload::ingest::ssh_key + dispatch live + main.rs guard removed (commit `4837166`)

**`src/error.rs`** — new `Error::SshKeyFormatNotSupported` variant (D-P7-12) inserted after `InvalidMaterial`. Display literal: `"SSH key format not supported — convert to OpenSSH v1 via \`ssh-keygen -p -o -f <path>\`"`. Distinct from `InvalidMaterial` because:

1. The remediation hint (`ssh-keygen -p -o -f <path>`) is SSH-specific; embedding it in `InvalidMaterial`'s shared message would be wrong for non-SSH content errors.
2. The variant has zero fields (no `variant` / `reason` discriminator) — eliminates an info-disclosure oracle ("your input looked like RSA-PEM" would tell an attacker which format they probed).

`exit_code` extended with explicit arm `Error::SshKeyFormatNotSupported => 1` — same content-error class as `InvalidMaterial`, distinct from signature-failure exit 3.

**`src/payload/ingest.rs`** — new `pub fn ssh_key(raw: &[u8]) -> Result<Material, Error>`. Pipeline:

1. **Format sniff (D-P7-12):** trim leading ASCII whitespace; if input does NOT start with `-----BEGIN OPENSSH PRIVATE KEY-----`, return `Error::SshKeyFormatNotSupported`. Catches legacy PEM (RSA/DSA/EC), RFC 4716 SSH2, OpenSSH-FIDO, garbage, empty input — all in one strict-prefix check.
2. **Trailing-bytes check FIRST, then parse (Rule-1 deviation — see Deviations section):** locate the first `-----END OPENSSH PRIVATE KEY-----` marker. If post-marker bytes are non-whitespace, return `Error::InvalidMaterial { variant: "ssh_key", reason: "trailing bytes after OpenSSH v1 blob" }` (T-07-39 share_ref-drift mitigation). Otherwise slice raw to `[..=end_of_marker]` and pass that to ssh-key.
3. **Parse:** `ssh_key::PrivateKey::from_openssh(parse_input)`. Failure → `Error::InvalidMaterial { variant: "ssh_key", reason: "malformed OpenSSH v1 blob" }`. NEVER wraps the ssh-key crate error chain (oracle hygiene; D-P7-12 mirror of D-P7-09).
4. **Canonical re-encode (D-P7-11):** `parsed.to_openssh(ssh_key::LineEnding::LF)` returns `Zeroizing<String>`. Store `encoded.as_bytes().to_vec()` in `Material::SshKey { bytes }`. The Zeroizing wrapper drops on scope exit — the only persistent copy is the encrypted age envelope produced downstream by `run_send`.

**13 inline `ssh_tests`:**
- `ssh_key_legacy_pem_rsa_rejected` / `_dsa_rejected` / `_ec_rejected` — all three legacy-PEM headers → `SshKeyFormatNotSupported`
- `ssh_key_rfc4716_rejected` — `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----` → `SshKeyFormatNotSupported`
- `ssh_key_fido_rejected` — `-----BEGIN OPENSSH-FIDO PRIVATE KEY-----` → `SshKeyFormatNotSupported`
- `ssh_key_garbage_rejected_as_format_not_supported` — non-key byte soup → `SshKeyFormatNotSupported`
- `ssh_key_empty_input_rejected_as_format_not_supported` — `b""` → `SshKeyFormatNotSupported`
- `ssh_key_format_not_supported_display_omits_internals` — Display contains `ssh-keygen -p -o`; does NOT contain `ssh-key::`, `ssh_encoding`, `ssh_cipher`, or `PemError`
- `ssh_key_malformed_openssh_v1_body_returns_invalid_material` — header IS OpenSSH-v1, body garbage → `InvalidMaterial { reason: "malformed OpenSSH v1 blob" }` (NOT `SshKeyFormatNotSupported` — different remediation class)
- `ssh_key_fixture_round_trips_into_material` — happy path with the committed fixture; returned `Material::SshKey { bytes }` reparses cleanly via `from_openssh`; stored bytes contain BEGIN+END markers
- **`ssh_key_canonical_re_encode_is_byte_deterministic`** — research GAP 4 closure; PASS on ssh-key 0.6.7, validating D-P7-11
- `ssh_key_trailing_garbage_after_end_marker_rejected` — `fixture + b"GARBAGE_TRAILER"` → `InvalidMaterial { reason: "trailing bytes after OpenSSH v1 blob" }` (T-07-39)
- `ssh_key_trailing_whitespace_after_end_marker_accepted` — `fixture + b"\n\n  \t\n"` → `Ok(...)` (whitespace tolerance)

**`src/flow.rs::run_send`** — `MaterialVariant::SshKey` arm now dispatches to `payload::ingest::ssh_key(&plaintext_bytes)?`. All four MaterialVariant arms are now LIVE.

**`src/main.rs`** — the Plan-01-narrowed belt-and-suspenders guard `if matches!(material, MaterialVariant::SshKey) { return Err(NotImplemented{phase:7}.into()); }` REMOVED entirely. Dispatch is now uniform across all four variants. Unused `use cipherpost::cli::MaterialVariant` import dropped (would otherwise trip `clippy -D warnings`).

**`tests/fixtures/material_ssh_fixture.openssh-v1`** (387 B) — Ed25519 OpenSSH v1 private key, generated via `ssh-keygen -t ed25519 -C "" -N "" -f /tmp/cipherpost_ssh_fixture_key`. Sibling `material_ssh_fixture.reproduction.txt` documents recipe, SHA-256 (`3cb6b44426bd6c004348a65d8c42b694e7256df6bbd3d361528c59025acf1e46`), and public-key reference. Used by the inline byte-determinism guard test + the fixture round-trip test; Plan 08 will reference the same file for full integration coverage.

`cargo test --features mock` full suite → 53 test crates pass / 0 fail / 0 errors. `cargo build --all-targets` clean.

## ed25519-dalek Coexistence Evidence (D-P7-22 / SSH-10)

Verbatim `cargo tree -p ed25519-dalek@2.2.0` + `cargo tree -p ed25519-dalek@3.0.0-pre.5` after Plan 05's changes (file: `.planning/phases/07-typed-material-pgpkey-sshkey/07-05-ed25519-dalek-tree.txt`):

```
=== cargo tree -p 'ed25519-dalek@2.2.0' (from pgp 0.19.0) ===
ed25519-dalek v2.2.0
├── curve25519-dalek v4.1.3
├── ed25519 v2.2.3
├── rand_core v0.6.4
├── sha2 v0.10.9
├── subtle v2.6.1
└── zeroize v1.8.2

=== cargo tree -p 'ed25519-dalek@3.0.0-pre.5' (from pkarr 5.0.4) ===
ed25519-dalek v3.0.0-pre.5
├── curve25519-dalek v5.0.0-pre.5
├── ed25519 v3.0.0-rc.4
├── sha2 v0.11.0-rc.4
├── signature v3.0.0-rc.10
├── subtle v2.6.1
└── zeroize v1.8.2
```

(Full transitive trees in the .txt evidence file.)

**Result:** Two distinct ed25519-dalek versions, both unchanged from Plan 01. ssh-key 0.6.7 with `default-features = false, features = ["alloc"]` adds NO third version. `tests/x509_dep_tree_guard.rs::dep_tree_ed25519_dalek_coexistence_shape` runtime-enforces this; the .txt is the human-readable diff target.

## Byte-Determinism Test Outcome (research GAP 4 closure)

**PASS — D-P7-11 canonical-re-encode strategy is VALID for ssh-key 0.6.7.**

Test: `src/payload/ingest.rs::ssh_tests::ssh_key_canonical_re_encode_is_byte_deterministic`
- `parsed1 = PrivateKey::from_openssh(FIXTURE_OPENSSH).unwrap()` (387 B Ed25519 fixture)
- `bytes1 = parsed1.to_openssh(LineEnding::LF).unwrap()` → `Zeroizing<String>`
- `parsed2 = PrivateKey::from_openssh(bytes1.as_str()).unwrap()`
- `bytes2 = parsed2.to_openssh(LineEnding::LF).unwrap()`
- `assert_eq!(bytes1.as_str(), bytes2.as_str())` → PASS

The strategy "store re-encoded canonical bytes" is sound — `share_ref` is deterministic across re-sends of the same OpenSSH-v1 input. No fallback path needed. Plan 08's full integration tests can rely on this guarantee.

## ssh-key 0.6.7 API Notes (for downstream Plan 06 + 08)

- `PrivateKey::from_openssh(impl AsRef<[u8]>) -> Result<Self>` — accepts `&[u8]` directly. We pass `parse_input: &[u8]` (no UTF-8 conversion needed; PEM is ASCII).
- `PrivateKey::to_openssh(LineEnding::LF) -> Result<Zeroizing<String>>` — returns a string wrapper. We extract bytes via `.as_bytes().to_vec()` and let the Zeroizing wrapper drop on scope exit.
- `ssh_key::LineEnding::LF` is in the `ssh_key` crate root namespace (re-exported from `encoding`).
- `from_openssh` is STRICT about post-END-marker bytes — even harmless newlines from text-editor saves are rejected. Mitigation: slice input to `[..=end_of_marker]` BEFORE calling `from_openssh`. Plan 06 (preview) MUST do the same trimming if it parses the stored canonical bytes — though our stored bytes are already trimmed (no trailing whitespace from `to_openssh` output), so Plan 06 can pass `Material::SshKey { bytes }` directly.

## Binary Size Delta (Open Question #2)

| Build               | Size  |
|---------------------|-------|
| Plan 01 baseline    | 4.5 MB |
| **Plan 05 release** | **5.1 MB** |
| Delta               | **+600 KB** |

Well under the 2 MB flag threshold. ssh-key's overhead is moderate (sha2 + base64 + zeroize transitive); no `ed25519-dalek`-style large-feature pull because `default-features = false, features = ["alloc"]` strips ECDSA, std, rand_core.

## SSH Fixture Decision (for Plan 08 hand-off)

**Plan 05 commits the fixture.** `tests/fixtures/material_ssh_fixture.openssh-v1` (387 B Ed25519 OpenSSH v1) lands in this commit (Task 3). The byte-determinism guard test in `src/payload/ingest.rs::ssh_tests` `include_bytes!`s the file at compile time.

Plan 08 should:
- Reference `tests/fixtures/material_ssh_fixture.openssh-v1` directly (no need to author a new fixture).
- Reference `tests/fixtures/material_ssh_fixture.reproduction.txt` for SHA-256 + recipe.
- Add `[[test]]` stanzas in Cargo.toml for any new ssh integration tests it ships (analogous to Plan 04's `material_pgp_ingest`, `pgp_roundtrip`, etc.).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Trailing-bytes check moved BEFORE parse (Task 3)**

- **Found during:** Task 3, on first `cargo test --lib payload::ingest::ssh_tests` run.
- **Issue:** Initial implementation followed the plan exactly: `from_openssh(raw)` first, then check post-END-marker bytes for whitespace. Two tests failed: `ssh_key_trailing_garbage_after_end_marker_rejected` (got "malformed OpenSSH v1 blob" instead of "trailing bytes after OpenSSH v1 blob") AND `ssh_key_trailing_whitespace_after_end_marker_accepted` (also failed with "malformed OpenSSH v1 blob"). Root cause: ssh-key 0.6.7's `from_openssh` is STRICT — it rejects ANY post-END-marker bytes, even harmless newlines from text-editor saves. The plan's approach was unreachable for the trailing-bytes branch (ssh-key always wins).
- **Fix:** Restructured the function — locate END marker first, slice raw to `[..=end_of_marker]`, then hand the slice to `from_openssh`. The post-marker non-whitespace check fires BEFORE parse, producing specific user-facing diagnostics ("trailing bytes after OpenSSH v1 blob") that match the test expectations. Whitespace trailers are silently consumed by the slice trim. Both tests now pass.
- **Files modified:** `src/payload/ingest.rs` (Step 2 reordered; docstring updated to reflect new pipeline order).
- **Commit:** `4837166`.

**2. [Rule 3 - Blocker] Removed unused `MaterialVariant` import in src/main.rs (Task 3)**

- **Found during:** Task 3 Step E, immediately after deleting the `matches!(material, MaterialVariant::SshKey)` guard.
- **Issue:** `cargo build --all-targets` warned `unused import: MaterialVariant` because the guard was the only remaining use of the imported name. CI runs `cargo clippy -- -D warnings`, which would reject the warning as an error.
- **Fix:** Removed `MaterialVariant` from the `use cipherpost::cli::{Cli, Command, IdentityCmd, MaterialVariant};` import line.
- **Files modified:** `src/main.rs` (line 6).
- **Commit:** `4837166`.

### Out-of-scope discoveries (NOT fixed; logged below)

**Pre-existing fmt drift in unrelated files** — `cargo fmt` (which I ran on my edited files for clippy compliance) ALSO reformatted `src/preview.rs`, `tests/pgp_banner_render.rs`, `tests/x509_dep_tree_guard.rs`, and the PGP test block in `src/payload/ingest.rs`. These files have pre-existing fmt drift unrelated to Plan 05's edits. Per scope-boundary rules in the executor protocol, I reverted those changes (`git checkout -- <file>`). Future work: a Plan 06+ executor or a dedicated `chore: cargo fmt repo-wide` commit should resolve the drift in one focused change.

## Threats Addressed

| Threat ID | Disposition | Evidence |
|-----------|-------------|----------|
| T-07-33 (ssh-key feature creep) | mitigate | `default-features = false, features = ["alloc"]` only; inline Cargo.toml comment explains the omission of `ed25519` feature |
| T-07-34 (silent ed25519-dalek 2.x leak from ssh-key) | mitigate | `cargo tree -p ed25519-dalek` evidence committed; runtime-enforced by `tests/x509_dep_tree_guard.rs::dep_tree_ed25519_dalek_coexistence_shape` (still PASS) |
| T-07-35 (Debug leak on SSH secret-key bytes) | mitigate | Manual Debug arm `SshKey { bytes } => write!(f, "SshKey([REDACTED {} bytes])", bytes.len())`; `tests/debug_leak_scan.rs::material_ssh_key_debug_redacts_bytes` runtime-enforces hex-window absence |
| T-07-36 (legacy-PEM/RFC4716/FIDO smuggling) | mitigate | Strict prefix sniff; 5 dedicated negative-path tests (rsa/dsa/ec/rfc4716/fido) all return `SshKeyFormatNotSupported` |
| T-07-37 (ssh-key parser DoS) | mitigate | 64 KB plaintext cap from Phase 6; ssh-key 0.6.7 has no published advisories |
| T-07-38 (canonical re-encode regression) | mitigate | Empirical byte-determinism guard test PASS on ssh-key 0.6.7 |
| T-07-39 (trailing-bytes share_ref drift) | mitigate | Pre-parse trailing-bytes check; non-whitespace garbage rejected with specific `InvalidMaterial { reason: "trailing bytes after OpenSSH v1 blob" }` |
| T-07-40 (oracle leak via Display) | mitigate | `Error::SshKeyFormatNotSupported` has zero fields; Display omits rejected format AND ssh-key crate internals; `ssh_key_format_not_supported_display_omits_internals` test enumerates 4 forbidden tokens |
| T-07-41 (ssh-key import scope creep) | mitigate | `grep -rE "^use ssh_key\|ssh_key::" src/` confined to `src/payload/ingest.rs` (Plan 06 will add `src/preview.rs`; D-P7-16 invariant) |

## Verification

```bash
# Build clean
cargo build --all-targets                          → exit 0
cargo build --release                              → 5.1 MB

# All new tests pass
cargo test --lib payload::tests                    → 26 pass / 0 fail
cargo test --lib payload::ingest::ssh_tests        → 13 pass / 0 fail
cargo test --test debug_leak_scan                  → 6 pass / 0 fail
cargo test --test phase2_material_variants_unimplemented → 3 pass / 0 fail

# No regressions
cargo test --features mock                         → 53 test crates pass / 0 fail / 0 errors

# Dep tree clean
cargo tree -p ed25519-dalek@2.2.0                  → present (from pgp)
cargo tree -p ed25519-dalek@3.0.0-pre.5            → present (from pkarr)
# (no third version; verified via diff vs Plan 01 evidence)
cargo tree | grep -E "ring v|aws-lc v|openssl-sys v" → no matches

# Oracle hygiene
grep -rE "ssh_key::Error|ssh_encoding|PemError" src/payload/ src/error.rs
# → only matches inside the test's forbidden-tokens list (expected; not a leak)

# ssh-key import scope (D-P7-16)
grep -rE "^use ssh_key|ssh_key::" src/ | grep -v "src/payload/ingest.rs"
# → empty (Plan 06 will add src/preview.rs)
```

## Open Items for Plan 06+

- **Plan 06 (preview):** wire `preview::render_ssh_preview` against `ssh-key 0.6.7`'s `Fingerprint::compute` (SHA-256). Reuse the fixture committed by Plan 05.
- **Plan 07 (run_receive live arm):** swap `Material::SshKey { .. } =>` arm from `NotImplemented{phase:7}` to live preview-render + variant-typed acceptance.
- **Plan 08 (ship gate):** dep-tree guard test extension (assert `ssh-key v0.6.x` pin via grep on `cargo tree` first line); full integration tests (`tests/material_ssh_ingest.rs`, `tests/ssh_roundtrip.rs`, `tests/ssh_banner_render.rs`, `tests/ssh_error_oracle.rs`) following Plan 04's PGP pattern.

## Self-Check: PASSED

Files created:
- `tests/fixtures/material_ssh_fixture.openssh-v1` — FOUND (387 B)
- `tests/fixtures/material_ssh_fixture.reproduction.txt` — FOUND
- `.planning/phases/07-typed-material-pgpkey-sshkey/07-05-ed25519-dalek-tree.txt` — FOUND (4 KB)
- `.planning/phases/07-typed-material-pgpkey-sshkey/07-05-SUMMARY.md` — FOUND (this file)

Commits:
- `5f1aa69` chore(07-05): add ssh-key 0.6.7 dependency — FOUND
- `0358e23` feat(07-05): upgrade Material::SshKey to struct variant — FOUND
- `4837166` feat(07-05): add Error::SshKeyFormatNotSupported + ingest::ssh_key — FOUND
