---
phase: 01-foundation-scaffold-vendored-primitives-and-transport-seam
plan: "02"
subsystem: crypto-identity
tags: [crypto, identity, ed25519, x25519, argon2id, hkdf, age, jcs, passphrase, security]
dependency_graph:
  requires:
    - Cargo.toml with pinned cclink v1.3.0 stack (Plan 01)
    - src/lib.rs with ENVELOPE_MAGIC, HKDF_INFO_PREFIX constants (Plan 01)
    - src/error.rs with Error enum (Plan 01)
    - src/cli.rs with IdentityCmd tree and passphrase flags (Plan 01)
  provides:
    - src/crypto.rs — Ed25519↔X25519, age encrypt/decrypt, Argon2id+HKDF KEK, CIPHPOSK envelope, JCS serialize
    - src/identity.rs — generate/load/show_fingerprints, Passphrase, resolve_passphrase
    - src/main.rs — IdentityCmd::Generate/Show wired end-to-end
    - tests/fixtures/ed25519_x25519_vectors.json — committed fixture vectors (3)
    - tests/fixtures/jcs_signing_bytes.bin — committed canonical-JSON fixture bytes
    - 9 prevention tests for CRYPTO-01..06 and IDENT-01..05
  affects:
    - Plan 03 (transport.rs, record.rs) extends hkdf_infos with SHARE_SENDER etc.
    - Plan 03 OuterRecordSignable uses jcs_serialize from this plan
    - All future plans use identity::load/generate and crypto::age_encrypt/decrypt
tech_stack:
  added:
    - ed25519-dalek VerifyingKey::to_montgomery() for Edwards→Montgomery conversion
    - SigningKey::to_scalar_bytes() for X25519 private scalar
    - age::Encryptor::with_recipients + age::Decryptor for all AEAD
    - argon2::PasswordHasher::hash_password for PHC string generation
    - argon2::password_hash::PasswordHash for PHC parsing at decrypt time
    - hkdf::Hkdf::<Sha256>::new + expand with domain-separated info strings
    - bech32 0.9 Variant::Bech32 for age identity/recipient encoding
    - serde_canonical_json::CanonicalFormatter for RFC 8785 JCS
    - pkarr::Keypair::random + from_secret_key + public_key().to_z32()
    - sha2::Sha256::digest for OpenSSH fingerprint
    - base64::engine::general_purpose::STANDARD_NO_PAD for fingerprint encoding
    - dialoguer::Password for TTY passphrase prompt
    - secrecy::SecretBox<String> for all passphrase in-memory storage
    - zeroize::Zeroizing<[u8;32]> for all secret key material
  patterns:
    - Manual Debug impls on Identity and Passphrase (no derive on secret-holding types)
    - hkdf_infos module as allowlist of all HKDF info strings (IDENTITY_KEK for Phase 1)
    - PHC string stored in CIPHPOSK envelope header (Pitfall #8 — params not hardcoded)
    - CIPHERPOST_HOME env var override for test isolation
    - encrypt_key_envelope_with_params always public (safe: requires seed + passphrase)
    - secret_key_bytes_for_leak_test always public (safe: requires constructed Identity)
key_files:
  created:
    - src/crypto.rs
    - src/identity.rs
    - tests/crypto_ed25519_x25519_fixture.rs
    - tests/crypto_jcs_determinism.rs
    - tests/crypto_no_floats_in_signable.rs
    - tests/hkdf_info_enumeration.rs
    - tests/chacha20poly1305_direct_usage_ban.rs
    - tests/debug_leak_scan.rs
    - tests/identity_perms_0600.rs
    - tests/identity_phc_header.rs
    - tests/identity_passphrase_argv_rejected.rs
    - tests/fixtures/ed25519_x25519_vectors.json
    - tests/fixtures/jcs_signing_bytes.bin
  modified:
    - src/main.rs (IdentityCmd::Generate/Show bodies replaced with real implementation)
decisions:
  - "encrypt_key_envelope_with_params made always-public (not cfg(test)/cfg(mock)) because integration tests are a separate crate from the library and cfg(test) does not propagate across crate boundaries; the function is safe since callers must supply both seed and passphrase"
  - "secret_key_bytes_for_leak_test made always-public for the same reason; the name communicates intent"
  - "hkdf_info_enumeration.rs filters out the bare HKDF_INFO_PREFIX literal (cipherpost/v1/) by requiring cap.len() > prefix.len() — prevents false positive from lib.rs constant"
  - "str_err() helper uses manual Debug impl (not #[derive(Debug)]) to satisfy acceptance criterion of zero derive(Debug) in src/crypto.rs"
  - "age Encryptor::with_recipients takes Iterator not Vec — uses std::iter::once"
  - "argon2::password_hash::Salt::decode_b64 used (not deprecated b64_decode)"
metrics:
  duration_minutes: 13
  completed_date: "2026-04-20"
  tasks_completed: 2
  tasks_total: 2
  files_created: 13
  files_modified: 1
---

# Phase 01 Plan 02: Crypto Primitives and Identity Layer Summary

**One-liner:** Argon2id+HKDF-SHA256 KEK derivation with PHC-header params, CIPHPOSK envelope encode/decode, Ed25519→X25519 Edwards-Montgomery conversion, age-only AEAD, RFC 8785 JCS canonical JSON, and full identity generate/load/show wired end-to-end with redacted Debug on all secret types.

## What Was Built

### Task 1: src/crypto.rs — Crypto primitives with prevention tests

**Ed25519↔X25519 conversion (CRYPTO-01 / Pitfall #1):**
- `ed25519_to_x25519_public`: `VerifyingKey::from_bytes(ed_pub).to_montgomery().to_bytes()` — Edwards→Montgomery via curve25519-dalek
- `ed25519_to_x25519_secret`: `SigningKey::from_bytes(seed).to_scalar_bytes()` — clamped first 32 bytes of SHA-512(seed)
- Committed fixture: `tests/fixtures/ed25519_x25519_vectors.json` with 3 vectors (seeds `[42;32]`, `[99;32]`, `[0;32]`)
- Test: `crypto_ed25519_x25519_fixture` asserts byte-exact match against fixture

**age encrypt/decrypt (CRYPTO-05 / Pitfall #9):**
- `age_encrypt`: `Encryptor::with_recipients(iter::once(recipient as &dyn Recipient))` → `wrap_output` → `finish`
- `age_decrypt`: `Decryptor::new(ct).decrypt(iter::once(identity as &dyn Identity))`
- `recipient_from_x25519_bytes` / `identity_from_x25519_bytes`: bech32 encode with "age" / "age-secret-key-" HRP
- No `chacha20poly1305` / `aes_gcm` imports anywhere in `src/`

**Argon2id + HKDF-SHA256 KEK (CRYPTO-02 / CRYPTO-03 / Pitfalls #4, #8):**
- `derive_kek`: `Argon2::hash_password_into` → `Hkdf::<Sha256>::new(Some(salt), argon_out).expand(IDENTITY_KEK, okm)`
- HKDF info string: `hkdf_infos::IDENTITY_KEK = "cipherpost/v1/identity-kek"` (Phase 2/3 will extend the module)
- All future Hkdf calls MUST use `hkdf_infos::*` constants (grep test enforces this)

**CIPHPOSK envelope (CRYPTO-02 / Pitfall #8):**
- Layout: `MAGIC(8) || VER(1) || PHC_LEN(2 BE) || PHC_STRING(N) || age_ciphertext`
- PHC string carries Argon2 params (m, t, p, salt) so `decrypt_key_envelope` reads them from the header — not hardcoded
- `encrypt_key_envelope_with_params` exposed for tests that need non-default params

**JCS canonical JSON (CRYPTO-04 / Pitfall #3):**
- `jcs_serialize<T: Serialize>`: `serde_json::Serializer::with_formatter(..., CanonicalFormatter::new())`
- Committed fixture: `tests/fixtures/jcs_signing_bytes.bin` = 142 bytes for the OuterRecordSignable-shaped struct
- `regenerate_jcs_fixture` `#[ignore]` test can regenerate the fixture if needed

**hkdf_infos module:**
- `pub mod hkdf_infos { pub const IDENTITY_KEK: &str = "cipherpost/v1/identity-kek"; }`
- Test `hkdf_info_enumeration` walks `src/` and asserts all strings starting with `"cipherpost/v1/"` + subcontext are non-empty, distinct, and versioned

**Prevention tests (all passing):**
- `crypto_ed25519_x25519_fixture`: byte-exact cross-impl fixture match
- `crypto_jcs_determinism`: fixture bytes match + proptest round-trip
- `crypto_no_floats_in_signable`: serde_json::Value introspection for f64 fields
- `hkdf_info_enumeration`: all HKDF info strings versioned and distinct
- `chacha20poly1305_direct_usage_ban`: grep asserts no direct AEAD imports in src/

### Task 2: src/identity.rs + src/main.rs wiring + identity prevention tests

**Path helpers:**
- `key_dir()`: checks `CIPHERPOST_HOME` env var first, falls back to `~/.cipherpost/`
- `key_path()`: `{key_dir}/secret_key`

**Identity struct:**
- Wraps `pkarr::Keypair`; manual `Debug` impl returns `"[REDACTED Identity]"` (no `#[derive(Debug)]`)
- `public_key_bytes()` → `[u8; 32]`
- `z32_pubkey()` → z-base-32 string via `keypair.public_key().to_z32()`
- `secret_key_bytes_for_leak_test()` — always public, for debug_leak_scan integration test

**generate/load (IDENT-01/02/03):**
- `generate`: `Keypair::random()`, `encrypt_key_envelope`, atomic write to `.tmp` then rename, chmod 0600, `fsync`
- `load`: checks `mode & 0o777 == 0o600`, reads blob, `decrypt_key_envelope`, `Keypair::from_secret_key(seed)`

**show_fingerprints (IDENT-05):**
- OpenSSH: `uint32(len("ssh-ed25519")) || "ssh-ed25519" || uint32(32) || pk_bytes` → SHA-256 → base64-no-pad
- z-base-32: pkarr's `PublicKey::to_z32()`

**Passphrase + resolve_passphrase (IDENT-04 / Pitfall #14):**
- `Passphrase(SecretBox<String>)` with manual Debug → `"Passphrase([REDACTED])"`
- `resolve_passphrase(inline_argv, env_var_name, file, fd)`: rejects argv-inline immediately (exit 4, "inline argv"), then prefers fd > file > env > TTY dialoguer
- File passphrase: requires mode 0600 or 0400

**main.rs wiring:**
- `IdentityCmd::Generate` and `IdentityCmd::Show` arms replaced with real `resolve_passphrase` + `identity::generate/load` calls
- `Command::Version` was already correct from Plan 01 (not modified)

**Prevention tests (all passing):**
- `identity_perms_0600`: `generate` writes 0600; `chmod 0644` → `load` returns `IdentityPermissions`
- `identity_phc_header`: weak params (m=19456, t=2, p=1) in header → `load` succeeds using header params
- `debug_leak_scan`: `format!("{:?}", id)` contains "REDACTED", no 8-byte seed window in hex
- `identity_passphrase_argv_rejected`: `cipherpost identity generate --passphrase foo` → exit 4, "inline argv" in stderr

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocker] cfg(test) does not propagate across crate boundaries for integration tests**
- **Found during:** Task 2, running `identity_phc_header` and `debug_leak_scan`
- **Issue:** `#[cfg(any(test, feature = "mock"))]` on `encrypt_key_envelope_with_params` and `#[cfg(test)]` on `secret_key_bytes_for_leak_test` caused compile errors in integration tests — integration tests compile against the library without `cfg(test)` being active in the library
- **Fix:** Made both functions unconditionally public. `encrypt_key_envelope_with_params` is safe since callers need a `Zeroizing<[u8;32]>` seed + `SecretBox<String>` passphrase. `secret_key_bytes_for_leak_test` is documented as test-only by its name.
- **Files modified:** `src/crypto.rs`, `src/identity.rs`

**2. [Rule 1 - Bug] hkdf_info_enumeration test false-positive on HKDF_INFO_PREFIX constant**
- **Found during:** Task 1, running hkdf_info_enumeration test
- **Issue:** Test collected `"cipherpost/v1/"` (the bare prefix constant from `src/lib.rs`) as an HKDF info string, causing a duplicate assertion failure when combined with `"cipherpost/v1/identity-kek"`
- **Fix:** Added `&& cap.len() > "cipherpost/v1/".len()` guard so bare prefix is excluded; only complete info strings (with a subcontext after the final `/`) are collected
- **Files modified:** `tests/hkdf_info_enumeration.rs`

**3. [Rule 1 - Bug] Clippy: redundant closures `|e| str_err(e)` → `str_err`**
- **Found during:** Final clippy run after Task 2 commit
- **Issue:** 11 instances of `map_err(|e| str_err(e))` flagged as redundant closures
- **Fix:** Replaced all with `map_err(str_err)` via `replace_all = true`
- **Files modified:** `src/crypto.rs`

**4. [Rule 1 - Bug] doc comments containing `#[derive(Debug)]` literal**
- **Found during:** Acceptance criteria grep check after Task 1 and Task 2
- **Issue:** Comments saying `NO #[derive(Debug)]` were matched by `grep -c '#\[derive(Debug)\]'`
- **Fix:** Rephrased comments to `"Debug is NOT derived"` and `"never derived in this file"`
- **Files modified:** `src/crypto.rs`, `src/identity.rs`

**5. [Rule 3 - Blocker] age Encryptor::with_recipients takes Iterator not Vec**
- **Found during:** Task 1, first build of crypto.rs
- **Issue:** `vec![Box::new(recipient.clone())]` is not an Iterator; API requires `impl Iterator<Item = &'a dyn Recipient>`
- **Fix:** Changed to `std::iter::once(recipient as &dyn age::Recipient)`
- **Files modified:** `src/crypto.rs`

**6. [Rule 1 - Bug] argon2 Salt::b64_decode deprecated**
- **Found during:** Task 1 build warnings
- **Issue:** `b64_decode` is deprecated; replacement is `decode_b64`
- **Fix:** Changed to `decode_b64`
- **Files modified:** `src/crypto.rs`

## Known Stubs

The following modules remain empty stubs from Plan 01 (unchanged by this plan):

| File | Reason | Filled by |
|------|--------|-----------|
| `src/transport.rs` | Phase 1 scaffold only | Plan 03 |
| `src/record.rs` | Phase 1 scaffold only | Plan 03 |
| `src/payload.rs` | Phase 2+ per D-02 | Plan 02+ |
| `src/receipt.rs` | Phase 3 per D-02 | Plan 03+ |
| `src/flow.rs` | Phase 2+ per D-02 | Plan 02+ |

## Threat Flags

None — no new network endpoints or auth paths beyond what the threat register (T-01-02-01 through T-01-02-12) covers. All mitigations listed in the plan's `<threat_model>` are implemented:
- T-01-02-01: Manual Debug impls with REDACTED + `tests/debug_leak_scan.rs`
- T-01-02-02: argv-inline rejection + `tests/identity_passphrase_argv_rejected.rs`
- T-01-02-03: 0600 enforcement + `tests/identity_perms_0600.rs`
- T-01-02-04: PHC header params + `tests/identity_phc_header.rs`
- T-01-02-05: hkdf_infos allowlist + `tests/hkdf_info_enumeration.rs`
- T-01-02-06: JCS fixture + `tests/crypto_jcs_determinism.rs`
- T-01-02-07: float guard + `tests/crypto_no_floats_in_signable.rs`
- T-01-02-08: deny.toml ban + `tests/chacha20poly1305_direct_usage_ban.rs`

## Self-Check

### Created files exist:

- src/crypto.rs: FOUND
- src/identity.rs: FOUND
- src/main.rs (modified): FOUND
- tests/crypto_ed25519_x25519_fixture.rs: FOUND
- tests/crypto_jcs_determinism.rs: FOUND
- tests/crypto_no_floats_in_signable.rs: FOUND
- tests/hkdf_info_enumeration.rs: FOUND
- tests/chacha20poly1305_direct_usage_ban.rs: FOUND
- tests/debug_leak_scan.rs: FOUND
- tests/identity_perms_0600.rs: FOUND
- tests/identity_phc_header.rs: FOUND
- tests/identity_passphrase_argv_rejected.rs: FOUND
- tests/fixtures/ed25519_x25519_vectors.json: FOUND
- tests/fixtures/jcs_signing_bytes.bin: FOUND

### Commits exist:

- bc4042f: feat(01-02): implement src/crypto.rs — FOUND
- 3f7eab4: feat(01-02): implement src/identity.rs — FOUND

## Self-Check: PASSED
