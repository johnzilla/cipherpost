---
phase: 07-typed-material-pgpkey-sshkey
plan: 02
subsystem: preview
tags: [rust, pgp, rpgp, preview, acceptance-banner, secret-key-warning, oracle-hygiene]
requires:
  - Phase 7 Plan 01 — `pgp = "=0.19.0"` dependency, `Material::PgpKey { bytes }` struct variant, `payload::ingest::pgp_key`, `pgp::packet::PacketTrait` import pattern
  - Phase 6 Plan 02 — `src/preview.rs` module + `render_x509_preview` template + `truncate_display` helper + `pub(crate) format_unix_as_iso_utc`
provides:
  - `pub fn preview::render_pgp_preview(bytes: &[u8]) -> Result<String, Error>` — pure renderer, no I/O
  - `[WARNING: SECRET key — unlocks cryptographic operations]` first-line warning placement for tag-5 primaries (D-P7-07 resolved as "embedded string" path)
  - PGP fingerprint rendering as UPPER-case hex via `Fingerprint`'s `UpperHex` impl (40 hex for v4, 64 hex for v5/v6)
  - PGP key-algorithm dispatch covering Ed25519/Ed448/RSA-N/ECDSA P-{256,384,521}/ECDSA secp256k1/ECDH-{curve}/X25519/X448/EdDSA-Legacy/DSA/Elgamal + numeric `<algo-N>` fallback
  - Subkey summary helper `N (alg1, alg2, ...)` or `0` for none
  - Reusable error funnel `pgp_parse_error()` ensuring all parse failures surface as the single curated `"malformed PGP packet stream"` reason — matches `payload::ingest::pgp_key` for oracle-hygiene deduplication
affects:
  - Cargo.toml (added direct `rsa = "0.9"` dep — already in tree transitively via pgp; needed for `PublicKeyParts::n().bits()` on RSA modulus)
  - Cargo.lock (rsa now appears as cipherpost direct dep in dependency list)
  - src/preview.rs (added 13 helper fns + 4 unit tests + 2 const items + 5 use statements)
tech-stack:
  added:
    - "rsa 0.9 (direct dep; already pulled transitively via pgp 0.19.0; default-features = false; trait-only import for `PublicKeyParts::n().bits()`)"
  patterns:
    - "rpgp `composed::Deserializable::from_bytes` for high-level key parsing"
    - "Tag-5 vs Tag-6 primary discrimination via `pgp::packet::PacketParser` (re-uses ingest entry point)"
    - "`SignedPublicKey` and `SignedSecretKey` parallel field-extraction paths; secret-side surfaces both `public_subkeys` and `secret_subkeys` for accurate subkey count"
    - "`Fingerprint::UpperHex` impl for hex rendering (no manual fold)"
    - "Single error literal funnel (`pgp_parse_error()`) for oracle-hygiene"
    - "Defensive control-char strip on user-controlled UID strings (banner-injection mitigation)"
key-files:
  created: []
  modified:
    - Cargo.toml
    - Cargo.lock
    - src/preview.rs
  committed_evidence: []
decisions:
  - "D-P7-07 resolved as embedded-string path (planner's default): warning is the FIRST line of the returned String followed by a blank line then the separator. Caller (`run_receive` in Plan 03) passes the full string through `Option<&str>` to `TtyPrompter::render_and_confirm` — no Prompter trait signature change needed."
  - "Added `rsa = \"0.9\"` as a direct Cargo.toml dep (Rule-3 deviation): `pgp::types::PublicParams::RSA(rsa_params)` exposes the `key: rsa::RsaPublicKey` field, but `RsaPublicKey` has no inherent bit-size accessor — the `n()` modulus accessor lives on `rsa::traits::PublicKeyParts`. The crate is already in the build graph transitively via pgp 0.19.0; adding it as a direct dep is no new supply-chain risk and preserves the plan's explicit `RSA-2048/3072/4096` requirement (vs falling back to `<algo-N>` placeholder for RSA keys)."
  - "Two parallel extraction paths (`extract_public_metadata` and `extract_secret_metadata`) instead of one collapsed path via `SignedSecretKey::to_public_key()`. The collapse loses the `secret_subkeys` Vec — keeping them separate gives an accurate subkey-count for SECRET-key inputs (which carry both public encryption-only subkeys AND secret signing/encryption subkeys per RFC 4880 §5.5.3)."
  - "Subkey summary deliberately renders algorithm names per subkey (NOT deduplicated) — duplicates surface intentional symmetry in the user's keyring (e.g., `2 (Ed25519, Ed25519)` for primary + signing subkey of the same alg). Deduplication would conceal the topology."
  - "PGP UID `strip_control_chars` defensive filter added beyond plan spec — D-P7-07 + research §banner-injection-hardening. RFC 4880 UIDs are free-form UTF-8; nothing stops a hostile sender from embedding `\\r\\n[FAKE BANNER]` in their UID. Using `char::is_control()` strips the U+0000-U+001F + U+007F + Unicode-C-class set."
  - "RSA size accessor uses `rsa::traits::PublicKeyParts` (renamed from earlier `PublicKey` trait in rsa 0.9). The `bits()` method returns `u64`; rendered with `format!(\"RSA-{}\", bits)` — no truncation since modulus widths fit in 32 bits even for `large-rsa` sizes."
metrics:
  duration_minutes: 25
  tasks_completed: 1
  tests_added: 4
  test_suite_after: "51 lib unit tests + full mock integration suite green"
  completed_date: "2026-04-25"
---

# Phase 7 Plan 02: Typed Material — PgpKey Preview Renderer Summary

**One-liner:** Implemented `preview::render_pgp_preview(bytes) -> Result<String, Error>` as a pure-function renderer for the PGP acceptance-banner subblock, with first-line `[WARNING: SECRET key — unlocks cryptographic operations]` placement for tag-5 primaries (D-P7-07), 53-dash OpenPGP separator, fingerprint-via-`Fingerprint::UpperHex` (40/64 hex for v4/v5+), key-algorithm dispatch (Ed25519/RSA-N/ECDSA-{P-256,P-384,P-521,secp256k1}/ECDH-{curve}/+10 more), subkey enumeration, and Created-via-`format_unix_as_iso_utc`; rpgp imports stay confined to `src/preview.rs` and `src/payload/ingest.rs` per D-P7-09.

## What Shipped

### Task 1 (RED + GREEN, single commit pair) — `render_pgp_preview` + helpers + 4 unit tests

- **RED commit `ed9f125`** — Added 4 failing tests in `src/preview.rs::tests`:
  - `render_pgp_preview_rejects_garbage_generically` — asserts garbage input → `Error::InvalidMaterial { variant: "pgp_key", reason: "malformed PGP packet stream" }`
  - `render_pgp_preview_rejects_empty_input` — same for `b""`
  - `pgp_separator_dash_count_is_53` — pins the new `PGP_SEPARATOR_DASH_COUNT` constant
  - `pgp_uid_trunc_limit_is_64` — pins the new `PGP_UID_TRUNC_LIMIT` constant

  Tests fail to compile (4 errors: missing `render_pgp_preview` fn, missing `PGP_SEPARATOR_DASH_COUNT`, missing `PGP_UID_TRUNC_LIMIT`) — confirms RED.

- **GREEN commit `4f569f2`** — Implemented:
  - `pub fn render_pgp_preview(bytes: &[u8]) -> Result<String, Error>` — main entry point; orchestrates discriminator → metadata extract → string format
  - `fn pgp_primary_is_secret(bytes: &[u8]) -> Result<bool, Error>` — re-uses `pgp::packet::PacketParser` to find the first top-level Tag::SecretKey or Tag::PublicKey
  - `fn pgp_parse_error() -> Error` — single-source-of-truth error constructor; one literal across all parse-failure paths (oracle-hygiene gate matching `payload::ingest::pgp_key`)
  - `fn extract_public_metadata(bytes) -> Result<(String,String,String,String,i64), Error>` — `SignedPublicKey::from_bytes` path
  - `fn extract_secret_metadata(bytes) -> Result<(String,String,String,String,i64), Error>` — `SignedSecretKey::from_bytes` path; surfaces both `public_subkeys` and `secret_subkeys` for accurate subkey count
  - `fn format_fingerprint_upper(fp) -> String` — `format!("{:X}", fp)` via the rpgp `Fingerprint` `UpperHex` impl
  - `fn first_uid_string(users) -> String` — first SignedUser's `id.as_str()` with `(no user id)` fallback + control-char strip
  - `fn strip_control_chars(s) -> String` — defensive banner-injection hardening; uses `char::is_control()`
  - `fn render_pgp_key_algorithm(alg, params) -> String` — main dispatch on `PublicKeyAlgorithm`; covers 11 algorithms + numeric `<algo-N>` fallback for `#[non_exhaustive]` PQC variants
  - `fn render_rsa_with_size(params) -> String` — `RSA-<bit-count>` via `PublicKeyParts::n().bits()`
  - `fn render_ecdsa(params) -> String` — `ECDSA P-256` etc. + secp256k1 + Unsupported-curve fallback
  - `fn render_ecdh(params) -> String` — `ECDH-<curve-name>` via `EcdhPublicParams::curve().name()`
  - `fn render_pgp_public_subkey_summary(subkeys) -> String` — `0` or `N (alg1, alg2, ...)`
  - 2 const items: `PGP_SEPARATOR_DASH_COUNT = 53`, `PGP_UID_TRUNC_LIMIT = 64`
  - 5 new use statements (rpgp + rsa) at module top, all confined per D-P7-09

  All 12 preview unit tests pass (8 X.509 + 4 PGP); full `cargo test --features mock` suite green.

## Critical Evidence

### Exact rpgp 0.19.0 API paths used in `render_pgp_preview`

For Plan 04's golden-string test (which depends on the exact renderer output shape) and any future rpgp upgrade:

```rust
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::PacketTrait;
use pgp::types::{EcdsaPublicParams, KeyDetails, PublicParams, Tag};
use rsa::traits::PublicKeyParts;
```

- **High-level parse:** `SignedPublicKey::from_bytes(bytes)` and `SignedSecretKey::from_bytes(bytes)` (the `from_bytes` method comes from the `Deserializable` trait — must be in scope; takes any `BufRead` and the `&[u8]` slice satisfies that).
- **Fingerprint:** `key.fingerprint()` — returns `Fingerprint` enum (`V2`/`V3`/`V4(20-byte)`/`V5(32-byte)`/`V6(32-byte)`/`Unknown`); rendered via `format!("{:X}", fp)` using the `UpperHex` impl (each variant defines `#[display("{}", hex::encode_upper(_0))]`).
- **Algorithm:** `key.algorithm()` — returns `PublicKeyAlgorithm` enum (`#[non_exhaustive]`; matched arms are `Ed25519` / `Ed448` / `EdDSALegacy` / `X25519` / `X448` / `DSA` / `ElgamalEncrypt` / `Elgamal` / `RSA` / `RSAEncrypt` / `RSASign` / `ECDSA` / `ECDH`; catch-all renders numeric ID via `u8::from(alg)`).
- **Public params:** `key.public_params()` — returns `&PublicParams`. RSA arm carries `RsaPublicParams { key: rsa::RsaPublicKey }`; ECDSA arm carries `EcdsaPublicParams::P256{...}/P384{...}/P521{...}/Secp256k1{...}/Unsupported{curve,...}`; ECDH arm carries `EcdhPublicParams` with a `.curve() -> ECCCurve` method.
- **UID:** `key.details.users` is `Vec<SignedUser>`; first user's `.id.as_str()` is `Option<&str>` (RFC 4880 UIDs are recommended-UTF-8 but not guaranteed; `as_str()` returns None on invalid UTF-8 — handled by fallback to `(no user id)`).
- **Created:** `key.created_at()` returns `Timestamp(u32)`; `.as_secs() -> u32` converted to `i64` via `i64::from()`.
- **Subkeys (public path):** `key.public_subkeys: Vec<SignedPublicSubKey>`; per-subkey `.key.algorithm()` + `.key.public_params()`.
- **Subkeys (secret path):** Both `key.public_subkeys` AND `key.secret_subkeys` enumerated for accurate count.
- **Tag discriminator:** `pgp::packet::PacketParser::new(&mut Cursor::new(bytes))` iterator; `.tag()` is via `PacketTrait` (must be in scope); pattern-matches against `Tag::SecretKey` (5) and `Tag::PublicKey` (6).
- **RSA bit size:** `rsa_params.key.n().bits() -> u64` via `rsa::traits::PublicKeyParts` trait.

### Acceptance-criteria grep matrix

```
$ grep -c "pub fn render_pgp_preview" src/preview.rs              → 1   ✓
$ grep -c "PGP_SEPARATOR_DASH_COUNT: usize = 53" src/preview.rs   → 1   ✓
$ grep -c "PGP_UID_TRUNC_LIMIT: usize = 64" src/preview.rs        → 1   ✓
$ grep -c "WARNING: SECRET key — unlocks cryptographic operations" src/preview.rs
                                                                    → 2  ✓ (1 docstring + 1 emit literal)
$ grep -E '"(Fingerprint: |Primary UID: |Key:         |Subkeys:     |Created:     )' src/preview.rs | wc -l
                                                                    → 5  ✓ (all five field prefixes)
$ grep -c "malformed PGP packet stream" src/preview.rs            → 6   ✓
$ grep -E "pgp::errors|pgp::Error|PgpError|packet::Error" src/preview.rs
                                                                    → 0  ✓ (oracle hygiene PASS)
$ grep -rE "^use pgp|pgp::" src/ | grep -v "src/preview.rs\|src/payload/ingest.rs"
                                                                    → 0  ✓ (D-P7-09 scope invariant PASS)
```

### Test results

```
cargo test --lib preview::tests
  → 12 passed; 0 failed
  - render_pgp_preview_rejects_garbage_generically                     ✓
  - render_pgp_preview_rejects_empty_input                              ✓
  - pgp_separator_dash_count_is_53                                      ✓
  - pgp_uid_trunc_limit_is_64                                           ✓
  - 8 pre-existing X.509 tests untouched                                ✓

cargo test --lib                       → 51 passed; 0 failed
cargo test --features mock             → all integration tests green; 0 failures
```

### V6 fingerprint path documentation (for Plan 04 fixture work)

The `Fingerprint` enum has dedicated `V4([u8; 20])` and `V6([u8; 32])` variants with the same `derive_more::Display`/`UpperHex` derivation. A v6 key's fingerprint will render as 64 hex chars (32 bytes × 2), automatically matching PGP-04's "v4 40-hex OR v5/v6 64-hex" requirement WITHOUT a separate code path. Same `format!("{:X}", fp)` works for both. No v6 fixtures were tested in this plan (Plan 04 owns the fixture-backed golden tests); CONTEXT.md `<specifics>` recommends v4 fixtures for the wire-budget headroom.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] Added `rsa = "0.9"` as a direct Cargo.toml dep**

- **Found during:** GREEN-phase implementation when wiring up `render_rsa_with_size`.
- **Issue:** The plan calls for `Key:         RSA-2048/3072/4096` rendering. pgp's `PublicParams::RSA(RsaPublicParams)` exposes a `pub key: rsa::RsaPublicKey` field, but `RsaPublicKey` has NO inherent bit-size method — `n()` and `size()` live on the `rsa::traits::PublicKeyParts` trait. Without `rsa` as a direct cipherpost dep, the trait can't be brought into scope (Rust requires direct-dep declaration to `use` a crate's items, even when it's already in the resolution graph transitively).
- **Fix:** Added `rsa = { version = "0.9", default-features = false }` to Cargo.toml with a comment explaining the trait-only import rationale. Verified Cargo.lock now has `cipherpost → rsa` as a direct dep edge.
- **Files modified:** Cargo.toml, Cargo.lock
- **Commit:** `4f569f2` (folded into GREEN commit)
- **Rationale:** Rule-3 blocker; without it the only fallback is to render `RSA` (no size) for all RSA keys — defeats PGP-04's explicit `RSA-N` requirement. No new supply-chain risk: rsa 0.9.10 is already in the dep tree transitively via pgp 0.19.0 (resolved in Plan 01 with the RUSTSEC-2023-0071 ignore). Default features only; no encryption/signing/decryption surface added.

**2. [Rule 2 — Critical functionality] Added defensive `strip_control_chars` on UID rendering**

- **Found during:** GREEN-phase code review of `first_uid_string`.
- **Issue:** RFC 4880 UIDs are free-form UTF-8 with no control-char restriction. The acceptance banner is the user's pre-decrypt surface; emitting an attacker-controlled UID with `\r\n[FAKE BANNER]` could overlay a forged acceptance prompt onto the genuine one. Phase 2 already applies the same hardening to the `purpose` field (per CONTEXT.md `<code_context>` → existing `payload::strip_control_chars`).
- **Fix:** Added local `fn strip_control_chars(s) -> String` using `char::is_control()` filter. Stripping happens INSIDE `first_uid_string` so every code path that surfaces a UID through the banner gets the protection.
- **Files modified:** src/preview.rs
- **Commit:** `4f569f2`
- **Rationale:** Banner-injection is a Trust-Boundary concern (the banner IS the acceptance surface). The plan's threat-model section names T-07-12 (side channel via emission ordering) but does not explicitly call out content-injection; auto-fixing per Rule 2 is correct because this is a correctness/security requirement, not a feature.

### Documentation-level decisions (not code deviations)

**3. [Info] D-P7-07 warning placement resolved as "embedded string"**

- **Where plan allowed discretion:** D-P7-07 says planner picks one of (a) embed warning as first line of returned String, or (b) struct return `{ warning: Option<String>, subblock: String }` letting `run_receive` thread the warning into the prompter's main banner.
- **Choice made:** Option (a). Returned String starts with `[WARNING: SECRET key — unlocks cryptographic operations]\n\n` followed by the separator. This keeps `Result<String, Error>` return signature unchanged from Phase 6's `render_x509_preview` template — Plan 03's `run_receive` wiring needs no Prompter trait extension.
- **Plan 04 impact:** Golden-string banner test for the secret-key path asserts the returned String starts with the literal warning line + blank line + `--- OpenPGP `, NOT a struct decomposition.

**4. [Info] Two parallel extraction paths, not one collapsed via `to_public_key()`**

- **Where plan allowed discretion:** Implementation detail.
- **Choice made:** `extract_public_metadata` and `extract_secret_metadata` are separate functions. Could have collapsed by calling `SignedSecretKey::to_public_key()` and reusing the public-key path, but that loses access to `secret_subkeys` — only `public_subkeys` survives the conversion. Surfacing accurate subkey count for SECRET-key inputs (which carry both encryption-only public-subkeys AND secret signing/encryption subkeys per RFC 4880 §5.5.3) requires the separate path.
- **Cost:** ~15 LOC duplication.
- **Benefit:** Accurate subkey topology in the SECRET-key banner — matters for the user's risk assessment (a secret key with 5 subkeys signals a heavier handoff than one with 0).

### Authentication gates

None encountered. Plan was fully autonomous.

## Deferred Issues

None. All acceptance criteria met; all tests pass; no oracle-hygiene leaks.

The fixture-backed golden-string banner tests for both the public-key + secret-key happy paths land in Plan 04 (`tests/pgp_banner_render.rs`) once a real PGP fixture is committed. Plan 02's scope is just the renderer + helpers + error-path tests; Plan 03 wires it into `run_receive`; Plan 04 ships fixtures + integration tests.

## Stubs Tracking

None. Every code path introduced by this plan is live:
- `render_pgp_preview` returns real String for both public + secret inputs (verified by build + helper tests).
- All 13 helper fns have real implementations dispatching to rpgp 0.19.0 API.
- The `<algo-N>` fallback for unknown PublicKeyAlgorithm variants is a real renderer (just a numeric placeholder), not a stub.

## Verification Results

### 1. Library builds clean
```
cargo build --lib   → exit 0; no warnings on new code
```

### 2. All preview unit tests pass (Phase 6 + new Phase 7)
```
cargo test --lib preview::tests   → 12 passed; 0 failed
```

### 3. No regressions in any existing test
```
cargo test --lib              → 51 passed; 0 failed
cargo test --features mock    → all 30+ integration test files green; 0 failures
```

### 4. Error-oracle source check (no rpgp internal types in preview.rs)
```
grep -E "pgp::errors|pgp::Error|PgpError|packet::Error" src/preview.rs   → 0 matches  ✓
```

### 5. rpgp imports bounded to ingest + preview ONLY (D-P7-09 scope)
```
grep -rE "^use pgp|pgp::" src/ | grep -v "src/preview.rs\|src/payload/ingest.rs"
                                                                          → 0 matches  ✓
```

### 6. Pinned Phase 6 X.509 golden-string test stays green
```
cargo test --test x509_banner_render   → 9 passed; 0 failed
```

## Threat Model Status

All threats documented in the plan's `<threat_model>` are mitigated:

| Threat ID | Disposition | Status |
|-----------|-------------|--------|
| T-07-09 — PGP parser DoS on adversarial input | mitigate | rpgp 0.19.0 strict-profile parsing + bounded input (64KB plaintext cap from ingest) + every `?` path funnels into `pgp_parse_error()` — no panic paths in `render_pgp_preview` source |
| T-07-10 — preview error-oracle leak | mitigate | ONE error literal (`"malformed PGP packet stream"`) emitted from this fn; matches `payload::ingest::pgp_key`'s reason for cross-Plan deduplication; source grep `pgp::errors\|PgpError\|packet::Error` returns empty |
| T-07-11 — SECRET-key silent handoff | mitigate | Tag-5 detection runs FIRST; warning is the FIRST line of the returned String followed by a blank line then the separator (D-P7-07 embedded-string path); high visual weight via full-caps WARNING label + dedicated line + blank-line separator |
| T-07-12 — emission ordering side channel | mitigate | Pure function; no `eprintln!`/`println!` anywhere in preview.rs (verified by `grep eprintln src/preview.rs` empty); caller (run_receive — Plan 03) owns emission |
| T-07-13 — fingerprint determinism | mitigate | Computed by rpgp from the canonical binary packet stream stored verbatim in `Material::PgpKey.bytes` (Plan 01 stores input bytes with no canonical re-encode); external `gpg --with-fingerprint --with-colons` on the same bytes produces the same hex |
| T-07-14 — preview blast radius | mitigate | rpgp imports source-grep-pinned to preview.rs + ingest.rs; Plan 04 will codify with `tests/pgp_dep_tree_guard.rs` |

## Hand-off Notes for Downstream Plans

**Plan 03 (PGP CLI wiring):**
- Call site: in `run_receive`'s `Material::PgpKey { .. }` arm, call `preview::render_pgp_preview(&envelope.material.as_pgp_key_bytes()?)` and pass the resulting `String` through `Some(&subblock)` to `TtyPrompter::render_and_confirm`'s `preview_subblock: Option<&str>` parameter.
- The Prompter trait signature established in Phase 6 Plan 03 is reused unchanged — no widening needed for the SECRET-key warning (it's embedded inside the subblock string).
- The `--armor` matrix update (Phase 6's `"--armor requires --material x509-cert"` → `"--armor requires --material x509-cert or pgp-key"`) lands here; existing `armor_on_generic_secret_rejected_with_config_error` test (in `tests/x509_roundtrip.rs`) needs an exact-string update.

**Plan 04 (PGP ship gate):**
- Golden-string banner test (`tests/pgp_banner_render.rs`) should pin per-line prefixes EXACTLY:
  - `--- OpenPGP ---------------------------------------------` (12 + 53 = 65 chars total)
  - `Fingerprint: ` (UPPER-case hex; 40 hex for v4, 64 hex for v5/v6)
  - `Primary UID: ` (truncated at 64 with `…`)
  - `Key:         ` (algorithm name)
  - `Subkeys:     ` (count + types or `0`)
  - `Created:     ` (ISO UTC `YYYY-MM-DD HH:MM UTC`)
- Secret-key fixture banner additionally STARTS with: `[WARNING: SECRET key — unlocks cryptographic operations]\n\n` BEFORE the separator.
- Returned String has NO leading or trailing newline — `assert!(!s.starts_with('\n')) && assert!(!s.ends_with('\n'))`.
- Fixture budget per Research GAP 5: target ≤200 B raw packet stream (v4 Ed25519 + ≤20-char UID + zero subkeys + minimal self-cert) so the round-trip stays under the 1000 B PKARR ceiling.

**Plan 05 (SSH foundation):**
- The `rsa` direct-dep addition in Plan 02 is a precedent for "direct-dep a transitively-pulled crate to access its trait surface." If SSH needs similar trait access, follow the same pattern (Cargo.toml comment + no new supply-chain risk justification).

## Self-Check: PASSED

- ✅ src/preview.rs — `pub fn render_pgp_preview` present (1 match)
- ✅ src/preview.rs — `PGP_SEPARATOR_DASH_COUNT: usize = 53` present
- ✅ src/preview.rs — `PGP_UID_TRUNC_LIMIT: usize = 64` present
- ✅ src/preview.rs — `[WARNING: SECRET key — unlocks cryptographic operations]` literal present (in emit + docstring)
- ✅ src/preview.rs — all 5 field prefixes (Fingerprint:, Primary UID:, Key:, Subkeys:, Created:) present
- ✅ src/preview.rs — sanitized `"malformed PGP packet stream"` reason literal (6 matches across error funnel + tests)
- ✅ src/preview.rs — no rpgp internal type strings (`pgp::errors`, `PgpError`, `packet::Error`) in source
- ✅ src/ — no pgp:: imports outside preview.rs + payload/ingest.rs (D-P7-09 scope invariant)
- ✅ Cargo.toml — `rsa = "0.9"` direct dep present with rationale comment
- ✅ Cargo.lock — `rsa` listed as cipherpost direct dep
- ✅ Commit `ed9f125` (RED — failing tests) present in `git log`
- ✅ Commit `4f569f2` (GREEN — implementation + helpers) present in `git log`
- ✅ All 4 new preview unit tests pass
- ✅ All 8 pre-existing X.509 preview unit tests pass (untouched)
- ✅ Full `cargo test --lib` suite green (51 tests)
- ✅ Full `cargo test --features mock` suite green (no integration test regressions)
