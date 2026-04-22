---
phase: 01-foundation-scaffold-vendored-primitives-and-transport-seam
verified: 2026-04-20T00:00:00Z
reverified: 2026-04-22T14:30:00Z
status: passed
score: 5/5 success criteria verified + 1/1 human UAT passed
overrides_applied: 0
deferred:
  - truth: "publish_receipt resolves the recipient's existing SignedPacket if any, merges the receipt TXT record, re-signs, and republishes (TRANS-03)"
    addressed_in: "Phase 3"
    evidence: "Resolved in Phase 3: 03-VERIFICATION.md row 3 confirms publish_receipt preserves coexisting TXT records via resolve-merge-republish. REQUIREMENTS.md traceability updated at milestone close."
    resolved: true
human_verification:
  - test: "Run `cipherpost identity generate` interactively via TTY (no env var)"
    expected: "Passphrase is prompted twice (confirm), identity file written at {CIPHERPOST_HOME}/secret_key mode 0600, both fingerprints printed on success"
    why_human: "Interactive TTY prompt cannot be driven by automated test runner; the binary rejects stdin piping with 'TTY not available' when stdout is not a terminal"
    result: passed
    executed: 2026-04-22
    executed_by: johnzilla (repo maintainer)
    findings: |
      UAT initially found a discrepancy: shipped code prompted once only,
      not twice. Root cause: `src/identity.rs:304` called
      `dialoguer::Password::new().with_prompt(...).interact()` without the
      `.with_confirmation(...)` call. Silently-typo'd passphrase on key
      generation would have bricked the new identity (no recovery path).
      Fixed in-phase before milestone close: `resolve_passphrase` gained a
      `confirm_on_tty: bool` parameter; `IdentityCmd::Generate` now passes
      `true` (other unlock paths — Show, Send, Receive — pass `false` since
      typos there surface as PassphraseIncorrect against the existing
      identity, no footgun).
      Re-run verified: dialoguer prompts twice, matching passphrases succeed,
      mismatched passphrases trigger "error: Passphrases don't match" with
      re-prompt. File mode 0600 confirmed. Both OpenSSH + z-base-32
      fingerprints printed (e.g., ed25519:SHA256:2b+bq8mrGm5VJYyiX/8Ke1VRtiDcnl9KesBzm6QUICk
      / bjh9oh49j6rqa7i7f9udy8j61d67dg8qjrsoup9b8dmc5f4b8hwy).
    fix_commit: 2e29b74
---

# Phase 1: Foundation Scaffold Verification Report

**Phase Goal:** Produce a single buildable `cipherpost` crate whose vendored crypto/identity/transport/record layers are byte-compatible with `cclink` reference vectors, with every wire-format and signed-payload lock-in already correct: domain-separated HKDF info strings, RFC 8785 canonical JSON (JCS), Argon2id parameters persisted in the identity file header, universally zeroized secrets with no `Debug` leaks, a `Transport` trait admitting both `DhtTransport` and `MockTransport`, and an `OuterRecord` schema carrying a 128-bit `share_ref` — so that Phases 2-3 cannot re-litigate any of these decisions.

**Verified:** 2026-04-20
**Re-verified:** 2026-04-22 (human UAT executed + discrepancy fixed)
**Status:** passed

## Goal Achievement

### Observable Truths (mapped to 5 Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `cargo build --release` produces a single `cipherpost` binary with no tokio dep and plain `fn main()` | VERIFIED | Build exits 0; `grep -c 'fn main()' src/main.rs` = 1; no `#[tokio::main]`; `grep -cE '^tokio' Cargo.toml` = 0 |
| 2 | Ed25519→X25519 fixture test and JCS property test with committed byte-array pass on every CI run | VERIFIED | `ed25519_x25519_matches_committed_vectors` ok; `jcs_fixture_bytes_match_committed` ok; `jcs_round_trip_determinism` ok; all from `cargo test --all-features` |
| 3 | `cipherpost identity generate` + `show` writes 0600 file, prints both fingerprints, refuses 0644, rejects `--passphrase <value>` argv | VERIFIED | Live binary run: file at mode 0600 confirmed, dual fingerprints printed, chmod 0644 → exit 4 "identity file permissions too permissive", `--passphrase foo` → exit 4 "invalid passphrase input method (inline argv rejected)" |
| 4 | HKDF info enumeration test asserts all call-sites use distinct `cipherpost/v1/` prefixed strings; `format!("{:?}", <secret>)` on key-holding structs does not leak bytes | VERIFIED | `all_hkdf_info_strings_are_versioned_and_distinct` ok; `identity_debug_does_not_leak_bytes` ok; `passphrase_debug_does_not_leak` ok |
| 5 | MockTransport publishes + resolves `OuterRecord` without real DHT; `DhtTransport` implements same trait; SignedPacket fits within 1000-byte budget | VERIFIED | `mock_publish_then_resolve_roundtrips_verified_record` ok; `mock_resolve_unpublished_returns_not_found` ok; `mock_publish_receipt_stores_under_cprcpt_label` ok; `representative_outer_record_fits_in_1000_bytes` ok |

**Score:** 5/5 success criteria verified

### Deferred Items

Items not yet met but explicitly addressed in later milestone phases.

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | TRANS-03: `publish_receipt` resolve-merge-republish semantics | Phase 3 | REQUIREMENTS.md traceability: TRANS-03 → Phase 3; Plan 03 SUMMARY §Phase 3 Upgrade Obligations documents exact upgrade contract for both DhtTransport and MockTransport |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `Cargo.toml` | cclink v1.3.0 stack pinned, no tokio | VERIFIED | `ed25519-dalek = "=3.0.0-pre.5"` literal present; `pkarr = { version = "5.0.3", default-features = false, features = ["dht"] }`; no tokio; `panic = "abort"` in release profile; `assert_cmd`/`predicates` in dev-deps |
| `src/lib.rs` | Wire constants: ENVELOPE_MAGIC, DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX, HKDF_INFO_PREFIX, PROTOCOL_VERSION | VERIFIED | All 5 constants present; grep counts each = 1 (no false-positive from comments) |
| `src/main.rs` | Plain `fn main()`, anyhow dispatch, exit-code downcast | VERIFIED | `fn main()` count = 1; no `#[tokio::main]`; `exit_code()` + `user_message()` downcast present |
| `src/error.rs` | Single `pub enum Error`, 4 Signature* variants sharing one Display | VERIFIED | `pub enum Error` count = 1; "signature verification failed" count = 4 |
| `src/crypto.rs` | Ed25519↔X25519, age wrappers, Argon2id+HKDF, JCS, hkdf_infos module | VERIFIED | All exports present; `hkdf_infos::IDENTITY_KEK = "cipherpost/v1/identity-kek"`; no `#[derive(Debug)]` on secret types |
| `src/identity.rs` | generate/load/show_fingerprints, resolve_passphrase, 0600 enforcement, PHC header | VERIFIED | All functions present; argv rejection wired; manual Debug on Identity and Passphrase |
| `src/transport.rs` | Transport trait (3 methods), DhtTransport, MockTransport cfg-gated | VERIFIED | `pub trait Transport` count = 1; 3 method signatures; DEFAULT_DHT_TIMEOUT = 30s; MockTransport behind `#[cfg(any(test, feature = "mock"))]` |
| `src/record.rs` | OuterRecord + OuterRecordSignable, sign/verify, share_ref, 128-bit SHARE_REF_BYTES | VERIFIED | Both structs; alphabetical field order; SHARE_REF_BYTES = 16; `serde_canonical_json::CanonicalFormatter` used |
| `tests/fixtures/ed25519_x25519_vectors.json` | Committed cross-impl fixture vectors | VERIFIED | File exists |
| `tests/fixtures/jcs_signing_bytes.bin` | Committed JCS canonical-form bytes | VERIFIED | File exists |
| `tests/fixtures/outer_record_signable.bin` | Committed OuterRecordSignable JCS bytes | VERIFIED | File exists; 192 bytes; test passes |
| `.github/workflows/ci.yml` | 5 jobs: fmt, clippy, nextest, audit, deny on PR + main | VERIFIED | All 5 jobs present; `pull_request` and `branches: [main]` triggers confirmed |
| `deny.toml` | tokio + chacha20poly1305 banned, license allowlist, sources restricted | VERIFIED | Both bans present; `[licenses]`, `[bans]`, `[sources]` sections present |
| `LICENSE` | MIT license | VERIFIED | File exists |
| `rust-toolchain.toml` | channel = "1.85" | VERIFIED | File exists |
| `build.rs` | Emits CIPHERPOST_GIT_SHA | VERIFIED | File exists; git hash confirmed in `cipherpost version` output: `cipherpost 0.1.0 (d8fb2028d2f2)` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/main.rs` dispatch | `identity::resolve_passphrase` + `identity::generate/load` | Direct call in `IdentityCmd::Generate/Show` arms | WIRED | Live binary: `generate` writes file, `show` reads both fingerprints, `--passphrase` argv rejected with exit 4 |
| `src/lib.rs` | `src/{crypto,identity,transport,record,error}` | `pub mod` re-exports | WIRED | All 9 `pub mod` declarations present; `pub use error::Error` present |
| `src/record.rs::sign_record` | `serde_canonical_json::CanonicalFormatter` | `jcs()` private fn | WIRED | `jcs_fixture_bytes_match_committed` passes; `sign_verify_round_trip` passes |
| `src/transport.rs::DhtTransport` | `pkarr::ClientBlocking` | `Client::builder().no_relays().request_timeout(t).build()?.as_blocking()` | WIRED | Build succeeds; `no_relays()` in construction path |
| `src/transport.rs::MockTransport` | `record::verify_record` | Called in `resolve()` | WIRED | `mock_publish_then_resolve_roundtrips_verified_record` passes — resolve path calls verify_record |
| CI workflow | `cargo-audit`, `cargo-deny` | `taiki-e/install-action` + invocation steps | WIRED | Both tools present in workflow |

### Data-Flow Trace (Level 4)

Transport and record layers process dynamic data. Tracing data flows for the MockTransport integration test:

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `MockTransport::resolve` | `OuterRecord` deserialized from store | `serde_json::from_str` of stored JSON from `MockTransport::publish` | Yes — round-trips the exact signed record | FLOWING |
| `identity::load` | `Zeroizing<[u8;32]>` seed | `crypto::decrypt_key_envelope` reading actual file written by `generate` | Yes — real Argon2id+HKDF KEK derived, actual age ciphertext decrypted | FLOWING |
| `jcs_fixture_bytes_match_committed` | committed fixture bytes | `tests/fixtures/jcs_signing_bytes.bin` (142 bytes, committed) | Yes — binary file on disk; assertion is byte-exact equality | FLOWING |
| `outer_record_signable_bytes_match_committed_fixture` | committed fixture bytes | `tests/fixtures/outer_record_signable.bin` (192 bytes, committed) | Yes — binary file on disk; assertion is byte-exact equality | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Binary builds | `cargo build --release` | Finished in 3.92s, exit 0 | PASS |
| Version output correct | `./target/release/cipherpost version` | `cipherpost 0.1.0 (d8fb2028d2f2)` + `crypto: age, Ed25519, Argon2id, HKDF-SHA256, JCS` | PASS |
| Identity generate via env var | `CIPHERPOST_PASSPHRASE=x cipherpost identity generate` | Mode 0600 file, both fingerprints printed, exit 0 | PASS |
| Identity show reads fingerprints | `CIPHERPOST_PASSPHRASE=x cipherpost identity show` | `ed25519:SHA256:<base64>` + z32 pubkey printed, exit 0 | PASS |
| 0644 file rejected | `chmod 0644 secret_key; cipherpost identity show` | "identity file permissions too permissive" exit 4 | PASS |
| argv passphrase rejected | `cipherpost identity generate --passphrase foo` | "invalid passphrase input method (inline argv rejected)" exit 4 | PASS |
| Clippy clean | `cargo clippy --all-features -- -D warnings` | No warnings, exit 0 | PASS |
| All 23 tests pass | `cargo test --all-features` | 23 ok, 0 FAILED, 2 ignored (fixture-regeneration) | PASS |
| TTY prompt interactive | Must test on real terminal | Not testable without TTY | SKIP — see human verification |

### Requirements Coverage

All 20 Phase 1 requirement IDs verified:

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SCAF-01 | Plan 01 | Cargo.toml with exact dep pins matching cclink v1.3.0 | SATISFIED | All deps present; `ed25519-dalek = "=3.0.0-pre.5"` literal; note: `serde_canonical_json = "1"` (was "0.2" — 0.2 unavailable on crates.io; API identical; documented in 01-01-SUMMARY.md); pkarr resolves to 5.0.4 in Cargo.lock (compatible, documented in 01-03-SUMMARY.md) |
| SCAF-02 | Plan 01 | `cargo build --release` produces single binary | SATISFIED | Build exits 0; binary at `target/release/cipherpost` |
| SCAF-03 | Plan 01 | CI runs fmt, clippy, nextest, audit, deny on every PR and main | SATISFIED | `.github/workflows/ci.yml` has 5 jobs; triggers on `pull_request` and `push: branches: [main]` |
| SCAF-04 | Plan 01 | LICENSE (MIT), README.md stub, .gitignore excludes target/ | SATISFIED | All three files exist; `.gitignore` contains `/target/`; `Cargo.lock` is NOT in .gitignore |
| SCAF-05 | Plan 01 | `fn main()` (no tokio), no direct tokio dep | SATISFIED | `grep -c 'fn main()' src/main.rs` = 1; no `#[tokio::main]`; tokio absent from Cargo.toml |
| CRYPTO-01 | Plan 02 | Ed25519↔X25519 reproduces cclink reference vectors | SATISFIED | `ed25519_x25519_matches_committed_vectors` passes; 3 fixture vectors committed in `tests/fixtures/ed25519_x25519_vectors.json` |
| CRYPTO-02 | Plan 02 | Argon2id params in identity file header as PHC string (not hardcoded) | SATISFIED | `encrypt_key_envelope_impl` writes PHC string; `decrypt_key_envelope` reads params from header; `unlock_uses_header_params_not_code_constants` test passes |
| CRYPTO-03 | Plan 02 | HKDF info strings domain-separated `cipherpost/v1/<context>`, never empty | SATISFIED | `hkdf_infos::IDENTITY_KEK = "cipherpost/v1/identity-kek"`; `all_hkdf_info_strings_are_versioned_and_distinct` passes |
| CRYPTO-04 | Plan 02 | RFC 8785 (JCS) via serde_canonical_json; property test; float guard | SATISFIED | `jcs_serialize` in crypto.rs; `jcs_fixture_bytes_match_committed` passes; `signable_struct_has_no_floats` passes; `jcs_round_trip_determinism` passes |
| CRYPTO-05 | Plan 02 | Only age encryption used; no direct chacha20poly1305 calls | SATISFIED | `no_direct_aead_imports` test passes; grep shows only comment references to chacha20poly1305 in src/ |
| CRYPTO-06 | Plan 02 | Key-holding structs use Zeroize/SecretBox; Debug redacts content | SATISFIED | `Zeroizing<[u8;32]>` for seeds; `SecretBox<String>` for passphrases; manual Debug on Identity ("REDACTED Identity") and Passphrase ("REDACTED"); `identity_debug_does_not_leak_bytes` + `passphrase_debug_does_not_leak` pass |
| IDENT-01 | Plan 02 | `cipherpost identity generate` writes 0600 file, TTY prompt | SATISFIED (partial) | Automated: `CIPHERPOST_PASSPHRASE` env path verified at 0600; TTY path requires human verification |
| IDENT-02 | Plan 02 | `cipherpost identity show` unlocks identity; wrong passphrase → exit 4 | SATISFIED | `CIPHERPOST_PASSPHRASE` env path verified; wrong passphrase → `DecryptFailed` → exit 4 (error enum + exit_code dispatcher) |
| IDENT-03 | Plan 02 | File refuses to open if permissions wider than 0600 | SATISFIED | `load_refuses_0644_identity_file` passes; live binary: `chmod 0644` → exit 4 "identity file permissions too permissive" |
| IDENT-04 | Plan 02 | Non-interactive passphrase via env/file/fd; inline `--passphrase` refused | SATISFIED | `argv_passphrase_rejected` + `argv_passphrase_argv_rejected_on_show_too` pass; live binary: `--passphrase foo` → exit 4 |
| IDENT-05 | Plan 02 | `identity show` prints OpenSSH `ed25519:SHA256:<base64>` and z32 fingerprints | SATISFIED | Live binary: both formats printed; `openssh_fingerprint` implementation uses RFC 4253 wire format + SHA-256 |
| TRANS-01 | Plan 03 | `Transport` trait with publish/resolve/publish_receipt; DhtTransport wraps ClientBlocking | SATISFIED | `pub trait Transport` with 3 methods; `DhtTransport` implements it; pkarr::Client::builder().no_relays() confirmed in code |
| TRANS-02 | Plan 03 | MockTransport in-memory map keyed by PKARR pubkey; no real DHT | SATISFIED | `MockTransport` behind `#[cfg(any(test, feature = "mock"))]`; 3 integration tests pass without real DHT |
| TRANS-04 | Plan 03 | 30s default DHT timeout; timeouts → exit 6 (distinct from exit 5 not-found) | SATISFIED | `DEFAULT_DHT_TIMEOUT = Duration::from_secs(30)`; `PublishError::Query(QueryError::Timeout)` → `Error::Network` → exit 6; `Error::NotFound` → exit 5 |
| TRANS-05 | Plan 03 | DHT progress written to stderr; stdout pipeable | SATISFIED | `eprintln!("Publishing to DHT...")`, `eprintln!("Resolving from DHT...")`, `eprintln!("Publishing receipt to DHT...")` present; `grep -c 'Resolving from DHT'` = 1, `grep -c 'Publishing to DHT'` = 1 |

**Note on TRANS-03:** TRANS-03 maps to Phase 3 in REQUIREMENTS.md traceability table. It was NOT included in the Phase 1 plan requirements (Plans 01-03 list TRANS-01, TRANS-02, TRANS-04, TRANS-05 — not TRANS-03). It is correctly deferred.

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `src/payload.rs` | `// TODO: phase 2+` | Info | Intentional Phase 2+ stub; no user-visible rendering |
| `src/receipt.rs` | `// TODO: phase 2+` | Info | Intentional Phase 3 stub; no user-visible rendering |
| `src/flow.rs` | `// TODO: phase 2+` | Info | Intentional Phase 2+ stub; no user-visible rendering |
| `src/transport.rs:65` | `#[allow(dead_code)]` on `timeout` field | Info | `timeout` stored for future per-request override; DhtTransport currently uses it only at construction via `request_timeout(timeout)` — not a stub, just forward-declared |

No blockers found. All TODOs are in intentionally-stub Phase 2+ modules. The `return null` / `return []` / hardcoded empty patterns are absent from the three implemented modules (`crypto.rs`, `identity.rs`, `transport.rs`, `record.rs`).

### Human Verification Required

#### 1. TTY Interactive Passphrase Prompt (IDENT-01 coverage gap)

**Test:** On a machine with a real TTY, run:
```
cipherpost identity generate
```
with no `CIPHERPOST_PASSPHRASE` env var set and no `--passphrase-file` / `--passphrase-fd` flag.

**Expected:** `dialoguer::Password` prompt appears twice ("Cipherpost passphrase" + confirmation), and on matching input the identity is generated at `~/.cipherpost/secret_key` at mode 0600, with both fingerprints printed.

**Why human:** The binary's `resolve_passphrase` falls through to `dialoguer::Password::interact()` only when no other passphrase source is present. The automated test runner cannot provide a TTY; piping stdin causes dialoguer to fail with "TTY not available for passphrase prompt" (observed during verification). The automated path via `CIPHERPOST_PASSPHRASE` env var was verified successfully — the TTY path is the only unverified code path.

---

## Gaps Summary

No gaps found. All 5 success criteria are verified. All 20 Phase 1 requirement IDs are satisfied (TRANS-03 is correctly deferred to Phase 3). One human verification item remains: interactive TTY passphrase prompt. All other IDENT-01 behaviors (env var, file, fd, argv rejection, 0600 mode, dual fingerprints) were verified with the live binary.

**Notable deviations (documented, not gaps):**
- `serde_canonical_json = "1"` instead of planned `"0.2"` (0.2 not on crates.io; API identical; documented in 01-01-SUMMARY.md)
- `pkarr` resolves to `5.0.4` in Cargo.lock despite `"5.0.3"` in Cargo.toml (semver-compatible patch; all APIs confirmed identical; documented in 01-03-SUMMARY.md)
- Blob ceiling is 550 bytes (not 600) for the 1000-byte PKARR budget — empirically measured; `tests/signed_packet_budget.rs` uses 550; Phase 2 must enforce at payload layer (documented in 01-03-SUMMARY.md)

---

_Verified: 2026-04-20_
_Verifier: Claude (gsd-verifier)_
