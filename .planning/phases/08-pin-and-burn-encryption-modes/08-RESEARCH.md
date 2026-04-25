# Phase 8: --pin and --burn encryption modes — Research

**Researched:** 2026-04-25
**Domain:** PIN-as-second-factor cryptography (cclink fork-and-diverge) + burn-after-read state-ledger inversion
**Confidence:** HIGH (every focus area resolved against shipped code; no `[ASSUMED]` claims for code APIs)

## User Constraints (from CONTEXT.md)

### Locked Decisions

D-P8-01 cclink survey closed; KDF shape forked, AEAD diverged to age nesting, burn diverged to local-state-only. Full divergence write-up lands in Plan 01 SUMMARY.md.

D-P8-02 HKDF info string locked: `cipherpost/v1/pin` (not `cipherpost/v1/pin_wrap`).

D-P8-03 `OuterRecord.pin_required: bool` outer-signed, pre-decrypt readable, `#[serde(default, skip_serializing_if = "is_false")]`.

D-P8-04 `Envelope.burn_after_read: bool` inner-signed, post-decrypt, `#[serde(default, skip_serializing_if = "is_false")]`.

D-P8-05 PIN salt encoding: when `pin_required=true`, `blob = base64(salt[32] || outer_age_ct)`; when `false`, exactly v1.0 shape `blob = base64(outer_age_ct)`.

D-P8-06 Nested age (NOT multi-recipient). Sender flow: inner age-encrypt to PIN-derived `Identity`, outer age-encrypt to receiver-identity `Recipient`. Both passphrase AND PIN required to decrypt.

D-P8-07 Receive flow ordering: 16-step sequence — outer-verify before any PIN prompt; early ledger pre-check after share_ref derive; PIN prompt after outer-verify, before age-decrypt; PIN BEFORE typed-z32 acceptance.

D-P8-08 `[BURN — you will only see this once]` marker at TOP of acceptance banner, before Purpose line.

D-P8-09 Ledger pre-check at earliest possible point (after share_ref derived, before any decrypt).

D-P8-10 Ledger row gains `state: "accepted"|"burned"` field. v1.0 rows missing the field deserialize to `accepted` via serde default. `check_already_consumed()` (renamed from `check_already_accepted`) returns `LedgerState` enum {None, Accepted{accepted_at}, Burned{burned_at}}.

D-P8-11 Burn ledger write order: ledger row FIRST, then sentinel touched. Inverts v1.0 ordering only for the burn case.

D-P8-12 Emit-before-mark for burn (BURN-03 lock). PITFALLS #26 is OUTDATED — Plan 04 must record the resolution.

D-P8-13 Six plans: PIN core / PIN ship-gate / BURN core / BURN ship-gate / Compose / Docs.

D-P8-14 PIN-first sequencing.

D-P8-15 Worktrees disabled.

D-P8-16 Strictly sequential, all autonomous.

### Claude's Discretion

Argon2id salt-buffer reuse strategy; whether `src/pin.rs` is new or extends `src/crypto.rs`; exact `Error::PinTooWeak.reason` literals; whether `LedgerState` enum lives in `src/state.rs` or `src/flow.rs`; PIN single-shot vs retry; non-TTY hard-rejection wording; banner separator widths; receipt-on-burn marker (recommend NO).

### Deferred Ideas (OUT OF SCOPE)

`--pin-file`, `--pin-fd`, `CIPHERPOST_PIN` env (DEFER-PIN-01/02). DHT-side burn (BURN-08 contract). Cryptographic burn destruction. PIN recovery. Multi-machine burn coordination. PIN retry counter / lockout. Wire-budget escape hatch for pin+burn+typed-material composites (Phase 9 measures; v1.2 fixes if needed). `--pin` on identity generate. PIN rotation / change-PIN. PIN strength meter / live feedback. Burn confirmation prompt. Burn sentinel TTL / cleanup. SQLite ledger format. Dedicated `cipherpost burn <share-ref>` command. Argv-inline `--pin <value>` (rejected at parse + runtime).

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PIN-01 | TTY-only PIN at send (deferred non-interactive sources) | `identity::resolve_passphrase` shape mirrored without fd/file/env paths; existing `dialoguer::Password` with `with_confirmation` (src/identity.rs:323-328) reusable verbatim |
| PIN-02 | 8-char min + anti-pattern validation | Direct fork of cclink `validate_pin` (cclink/src/commands/publish.rs:19-67); blocklist + sequential + all-same algorithms reusable |
| PIN-03 | Argon2id → HKDF-SHA256 (`cipherpost/v1/pin`) → X25519 scalar → age Identity → Encryptor::with_recipients | All four crates already pulled (verified via `cargo tree`); `crypto::identity_from_x25519_bytes()` (src/crypto.rs:129) already accepts a 32-byte scalar |
| PIN-04 | `OuterRecord` + `OuterRecordSignable` add `pin_required: bool` | Both structs in src/record.rs:27-50; identical `From<&OuterRecord>` projection symmetry (line 52-64) needs the new field |
| PIN-05 | Salt embedded in blob: `base64(salt || ciphertext)` when pin_required | Decode happens in src/flow.rs:469-471 — base64 STANDARD; insertion is a single `if pin_required { split_at(32) }` branch |
| PIN-06 | PIN prompt BEFORE typed-z32 banner | TtyPrompter in src/flow.rs:1101-1239; PIN prompt is upstream of `prompter.render_and_confirm` call at flow.rs:543 |
| PIN-07 | Wrong-PIN Display = wrong-passphrase Display = sig-fail Display | Existing D-16 unified-Display invariant in src/error.rs:27-37; wrong-PIN folds into existing `Error::DecryptFailed` (already exit 4) — no new variant needed for the oracle |
| PIN-08 | (a)/(b)/(c) round-trip matrix under MockTransport | `tests/phase2_self_round_trip.rs` is the closest template; new `tests/pin_roundtrip.rs` mirrors with `AutoConfirmPrompter` |
| PIN-09 | SPEC.md PIN crypto stack | SPEC.md §3.X insertion point: between §3.2 Material and §3.3 OuterRecord; or as §3.6 after §3.5 DHT Label Stability |
| PIN-10 | THREAT-MODEL.md "PIN mode" | Insertion at §6 (after Passphrase-MITM); next adversary-property section before §7 Receipt-Replay |
| BURN-01 | `Envelope.burn_after_read: bool` inner-signed | src/payload/mod.rs:31-36 Envelope struct; alphabetic JCS placement: `burn_after_read` lands FIRST (before `created_at`) |
| BURN-02 | First receive succeeds; second returns exit 7 | `check_already_consumed()` → `Burned` arm raises `Error::Declined` (already exit 7) — no new exit code |
| BURN-03 | Emit-before-mark | Inverts the v1.0 src/flow.rs:583-591 ordering: write_output BEFORE create_sentinel + append_ledger_entry, only when burn_after_read |
| BURN-04 | Receipt always published on successful burn | src/flow.rs:612-662 `publish_outcome` closure — no change; burn-fact is recoverable from Envelope sender holds |
| BURN-05 | Send-time stderr warning when --burn | New helper near src/main.rs send dispatch; `eprintln!` immediately after CLI parse confirms `--burn` set |
| BURN-06 | Banner `[BURN — you will only see this once]` marker | TtyPrompter::render_and_confirm signature extends with one `Option<&str>` marker param; emitted at line 1196 (between header and Purpose) |
| BURN-07 | --pin and --burn compose orthogonally | Both flags → both fields set; outer carries pin_required, inner carries burn_after_read; nesting is identical to PIN-only path |
| BURN-08 | THREAT-MODEL.md "Burn mode" — local-state-only | Insertion at §6 or §7; describes DHT-survives-TTL caveat, multi-machine race |
| BURN-09 | Two consecutive receives → exit 0 then exit 7; receipt count = 1 | New tests/burn_roundtrip.rs; reuses MockTransport; asserts ledger state transitions |

## Summary

Phase 8 layers two orthogonal share-level features (PIN second-factor encryption, single-consume burn) onto the v1.0 walking skeleton without a protocol_version bump. Both are additive: `OuterRecord.pin_required` and `Envelope.burn_after_read` are `#[serde(default, skip_serializing_if = "is_false")]`, preserving v1.0 byte-identity for non-pin / non-burn shares. Crypto is **fork-and-diverge from cclink**: cclink's `pin_derive_key()` shape (Argon2id 64MB×3iter → HKDF-SHA256 → 32-byte scalar) is reused verbatim with the namespace adapted from `cclink-pin-v1` → `cipherpost/v1/pin`; the AEAD path diverges from cclink's direct `chacha20poly1305` calls to nested age (CLAUDE.md `chacha20poly1305 only via age` invariant). Burn diverges from cclink's DHT-revoke-on-pickup (`client.revoke()` at cclink/src/commands/pickup.rs:253) to local-state-only (BURN-08); cipherpost rejects DHT mutation entirely.

Three claims in CONTEXT.md need correction during planning: (1) `pin_required` lands alphabetically between `created_at` and **`protocol_version`** (not `purpose` — `purpose` is on Envelope, not OuterRecord); (2) `hkdf` is already a direct dep at version 0.12.4 (no Cargo.toml change needed); (3) wrong-PIN Display equality can fold into the existing `Error::DecryptFailed` path — no new `Error::PinIncorrect` variant required.

**Primary recommendation:** Plan 01 ships `src/pin.rs` (new file, parallels Phase 6's `src/preview.rs` precedent) with `pin_derive_key`, `pin_encrypt_inner`, `pin_decrypt_inner`, `validate_pin` — all four are direct ports from cclink with the AEAD step replaced by `crate::crypto::age_encrypt(plaintext, &Identity::to_public())`. Plan 02 extends the existing `tests/hkdf_info_enumeration.rs` (literal-grep test; one new constant in `crypto::hkdf_infos`) and the existing D-16 Display-equality assertion pattern (asserted today by `tests/phase3_receipt_sign_verify.rs::assert_unified_d16_display` and `src/record.rs:224`).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| PIN entropy validation | CLI / clap layer | `src/pin.rs::validate_pin` | Reject before crypto ever runs; CLI returns exit 1 with generic Display |
| PIN prompt (TTY) | `src/identity.rs`-style helper (PIN variant) | `dialoguer::Password::with_confirmation` | Mirror existing passphrase prompt; argv-inline rejected at parse + runtime |
| Argon2id + HKDF + X25519 derivation | `src/pin.rs::pin_derive_key` | `crate::crypto::hkdf_infos::PIN` constant | Single source of truth for the KDF shape; HKDF info enumeration test is the gate |
| Nested age (inner pin, outer identity) | `src/flow.rs::run_send` orchestrates | `crate::crypto::age_encrypt` (existing) | Two sequential `age_encrypt` calls; no new age API needed |
| OuterRecord.pin_required (outer-signed metadata) | `src/record.rs` | JCS via serde_canonical_json | Pre-decrypt readable; receiver dispatches on this before age-decrypt |
| Envelope.burn_after_read (inner-signed metadata) | `src/payload/mod.rs` | JCS via serde_canonical_json | Post-decrypt; DHT observers do NOT see this field (CLAUDE.md ciphertext-only-on-wire) |
| Salt embedding in blob | `src/flow.rs::run_send` (prepend) + `src/flow.rs::run_receive` (split) | `base64::Engine::STANDARD` | Salt is OUTSIDE both age layers; readable before any decryption |
| Ledger schema migration | `src/flow.rs::LedgerEntry` (new optional state field) | `serde::default` for v1.0 row compat | Append-only JSONL; v1.0 rows still parse |
| `check_already_consumed()` + `LedgerState` enum | `src/flow.rs` (rename) OR new `src/state.rs` | scan-once pattern | Two existing callers (flow.rs:433, main.rs:237); rename + variant-match |
| Banner `[BURN]` marker emission | `src/flow.rs::TtyPrompter` | additional `Option<&str>` parameter on `Prompter` trait | Symmetric extension of Phase 6's preview_subblock parameter |
| Send-time `--burn` stderr warning | `src/main.rs` send dispatch | `eprintln!` on stderr | Pre-encrypt; surface caveat before user commits to send |
| THREAT-MODEL.md / SPEC.md / CLAUDE.md sections | Plan 06 (docs) | Cross-referenced from Plans 01-05 | Documentation consolidation phase |

## Standard Stack

### Core (verified against `Cargo.toml` HEAD + `cargo tree`)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `argon2` | `0.5` (resolves 0.5.3) | PIN → 32-byte key | [VERIFIED: Cargo.toml:31] already pulled, password-hash crate's reference Argon2id impl |
| `hkdf` | `0.12` (resolves 0.12.4) | Argon2 output → X25519 scalar with domain separation | [VERIFIED: Cargo.toml:32] already a direct dep — supersedes CONTEXT.md "transitive via age" hedge |
| `age` | `0.11` (resolves 0.11.2) | AEAD via X25519 recipient (no direct chacha calls) | [VERIFIED: Cargo.toml:30] CLAUDE.md `chacha20poly1305 only via age` invariant requires this |
| `sha2` | `0.10` | HKDF-SHA256 backend | [VERIFIED: Cargo.toml:33] |
| `bech32` | `0.9` | X25519 scalar → "age-secret-key-..." identity string | [VERIFIED: Cargo.toml:38] used by existing `crypto::identity_from_x25519_bytes` |
| `zeroize` | `1` (with `zeroize_derive`) | Drop-zeroes on PIN, salt, derived-key buffers | [VERIFIED: Cargo.toml:34] |
| `serial_test` | `3` | `#[serial]` on env-mutating PIN/BURN tests | [VERIFIED: dev-deps; CLAUDE.md load-bearing] |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `serde_canonical_json` | `1` (resolves 1.0.0) | JCS for new optional fields | All Envelope + OuterRecord serialization |
| `dialoguer` | `0.12` | TTY PIN prompt with `with_confirmation` | Mirror existing `identity::resolve_passphrase` priority-5 path |
| `secrecy` | `0.10` | `SecretBox<String>` for PIN value | Same as passphrase contract |
| `base64` | `0.22` | Encode `salt || ciphertext` blob | Existing `base64::engine::general_purpose::STANDARD` |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| age multi-recipient `[identity, pin]` | rejected by D-P8-06 | age semantics give EITHER, not BOTH; violates PIN-10 second-factor |
| Direct `chacha20poly1305` | rejected by CLAUDE.md | Load-bearing lock-in; would force PR-level reject |
| Separate `pin_salt: Option<[u8;32]>` field on OuterRecord | rejected by D-P8-05 | Cleaner shape but diverges from PIN-05 wording; requires REQ amendment |
| `Error::PinIncorrect` variant | rejected by D-P8-12 / Pitfall #23 | Distinguishable oracle attack class; fold into existing `DecryptFailed` instead |
| New `cipherpost burn <share-ref>` command | rejected (out-of-scope) | Burn is a receive-mode property, not a separate command |

**No new Cargo.toml dependencies.** Every focus-area need maps to an already-present crate at the version pinned today. Plan 01's evidence file should be `08-01-pin-deps-tree.txt` containing the output of:
```bash
cargo tree | grep -E "^(cipherpost|├── |└── )(age|argon2|hkdf|sha2|chacha20)"
```
This parallels Phase 7's `07-01-ed25519-dalek-tree.txt`.

## API surface findings (verified against shipped source)

### age 0.11.2 — `x25519::Identity` from a 32-byte scalar

`age::x25519::Identity` (age-0.11.2/src/x25519.rs:36) wraps `x25519_dalek::StaticSecret`. The public constructor is `FromStr::from_str(&str)` (line 38-55) that parses a bech32-encoded `"age-secret-key-..."` string. There is **no** public `from_bytes` constructor. The bech32-encode-then-parse pattern is the only path.

**Cipherpost already does this** at `src/crypto.rs:129` as `identity_from_x25519_bytes(bytes: &[u8; 32]) -> Result<x25519::Identity, Error>`. Plan 01 calls this verbatim with the PIN-derived 32-byte scalar — no new function needed.

```rust
// src/crypto.rs:129-133 (existing — Plan 01 reuses)
pub fn identity_from_x25519_bytes(bytes: &[u8; 32]) -> Result<x25519::Identity, Error> {
    let encoded =
        bech32::encode("age-secret-key-", bytes.to_base32(), Variant::Bech32).map_err(str_err)?;
    x25519::Identity::from_str(&encoded.to_uppercase()).map_err(str_err)
}
```

### age 0.11.2 — `Encryptor::with_recipients` and nested-age overhead

`Encryptor::with_recipients` (age-0.11.2/src/protocol.rs:73) takes `impl Iterator<Item = &'a dyn Recipient>`. **Cipherpost already wraps this** at `src/crypto.rs:139` as `age_encrypt(plaintext: &[u8], recipient: &x25519::Recipient) -> Result<Vec<u8>, Error>`. Plan 01 calls `age_encrypt` TWICE for nested encryption when `pin_required=true`:

```rust
// Pseudocode for Plan 01
let pin_recipient = pin_identity.to_public();              // age::Identity → age::Recipient
let inner_ct = crate::crypto::age_encrypt(envelope_jcs_bytes, &pin_recipient)?;
let outer_ct = crate::crypto::age_encrypt(&inner_ct, &receiver_recipient)?;
let blob = base64::engine::general_purpose::STANDARD.encode(salt.iter().chain(&outer_ct).collect::<Vec<_>>());
```

**Per-layer overhead estimate ([VERIFIED: age 0.11.2 protocol.rs:115-118 + grep `grease_the_joint`]):** each age v1 layer adds:
- `age-encryption.org/v1\n` header (22 bytes)
- 1 X25519 recipient stanza: `-> X25519 <epk-base64>\n<ENCRYPTED_FILE_KEY base64>\n` ≈ 80 bytes
- `--- <hmac-base64>\n` (≈ 50 bytes)
- 16-byte payload nonce
- ChaCha20-Poly1305 16-byte tag per 64KB chunk
- **`grease_the_joint`** random stanza: 0..=265 bytes (already captured by `WIRE_BUDGET_RETRY_ATTEMPTS = 20` in src/flow.rs:58)

**Predicted nested-age overhead:** ~165 bytes per layer + grease variance. Two layers ≈ 330 bytes overhead vs one layer ≈ 165 bytes. For a 64-byte PIN message → outer ≈ 240 bytes; inner-then-outer ≈ 410 bytes. Worst-case pin+burn+pgp-secret-key (a 419-byte typed material per CONTEXT.md banner mockup): inner ≈ 590 bytes; outer ≈ 770 bytes; +32 salt + base64(4/3 ratio) → ~1080 bytes encoded SignedPacket. **Likely to brush against the 1000-byte BEP44 budget**; Plan 01 should call out that the existing `WIRE_BUDGET_RETRY_ATTEMPTS=20` retry covers grease variance but cannot recover from a structural overflow. DHT-07 in Phase 9 makes this measurable; v1.2 is the wire-budget escape hatch. [CITED: src/flow.rs:39-58, age-0.11.2/src/protocol.rs lines 73-125]

### hkdf 0.12.4 — directly available

[VERIFIED: cargo tree output] `hkdf v0.12.4` is at `Cargo.toml:32` as a direct dep AND transitive via `argon2` and `age`. `src/crypto.rs:24` already does `use hkdf::Hkdf;`. **No Cargo.toml change required for Phase 8.** This supersedes the CONTEXT.md hedge "verify whether transitive via age" — the dep is shipped and directly used by `crypto::derive_kek` (src/crypto.rs:204).

The `Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut okm)` API is the same shape cclink uses (cclink/src/crypto/mod.rs:157-160). One-line API translation:

```rust
// cclink (src/crypto/mod.rs:159):  hkdf.expand(b"cclink-pin-v1", okm.as_mut())?;
// cipherpost Plan 01:              hk.expand(hkdf_infos::PIN.as_bytes(), &mut okm[..])?;
```

### argon2 0.5.3 — params already pinned to PIN-09 values

[VERIFIED: src/crypto.rs:175-177] `default_argon2_params()` returns `Params::new(65536, 3, 1, Some(32))` — exactly the values cclink uses for `pin_derive_key` (cclink/src/crypto/mod.rs:146). Plan 01 can either reuse the existing helper OR define a local `pin_argon2_params()` with the same numbers. Recommend defining a local helper for documentation clarity; the values are also cclink's PIN-specific contract, NOT the identity-KEK contract (those are read from the PHC header per Pitfall #8 — DIFFERENT lifecycle).

## Existing test patterns to extend

### HKDF info enumeration test

[VERIFIED: tests/hkdf_info_enumeration.rs:1-73] The test walks `src/` for any string literal starting with `cipherpost/v1/` and asserts (a) all are non-empty, (b) all are distinct, (c) all start with the prefix. **Source-grep based — no AST**. Plan 01 extension is mechanical: add one constant to `src/crypto.rs::hkdf_infos` module:

```rust
// src/crypto.rs::hkdf_infos (Plan 01 addition):
pub const PIN: &str = "cipherpost/v1/pin";
```

Then call it in src/pin.rs:
```rust
hk.expand(crate::crypto::hkdf_infos::PIN.as_bytes(), &mut okm[..])?;
```

The enumeration test will automatically discover the new literal in `crypto.rs` and verify uniqueness against `IDENTITY_KEK`, `SHARE_SENDER`, `SHARE_RECIPIENT`, `INNER_PAYLOAD` (the existing four). No test code change needed.

### Error-oracle Display equality

The intended test name `signature_failure_variants_share_display` from CONTEXT.md does not exist as a single named test in tests/. The D-16 invariant is enforced in **three distributed places**:

1. `src/error.rs:27-37` — `#[error("signature verification failed")]` literal on all four `Signature*` variants — the compile-time guarantee.
2. `src/record.rs:224` — `assert_eq!(format!("{}", err), "signature verification failed");` (inline unit test).
3. `tests/phase3_receipt_sign_verify.rs:64-71` — `assert_unified_d16_display(err)` helper, called from three tampered-field tests.
4. `tests/phase2_tamper_aborts_before_decrypt.rs:83-85` — `assert_eq!(msg, "signature verification failed");`.

**Plan 02's task:** extend this discipline for wrong-PIN. The recommended approach (per Pitfall #23 + D-P8-12) is to **fold wrong-PIN into the existing `Error::DecryptFailed` path** — `crypto::age_decrypt` (src/crypto.rs:153-164) already maps every age decryption failure (including wrong recipient = wrong PIN at the inner layer) to `Error::DecryptFailed`. No new variant. The test verifies:
- `Error::DecryptFailed` Display is `"wrong passphrase or identity decryption failed"` (src/error.rs:24).
- Wrong-PIN, wrong-passphrase, AND wrong-identity-key paths all return `DecryptFailed` and produce identical Display.
- Exit code is 4 in all three cases (src/error.rs:118).

A new file `tests/pin_error_oracle.rs` walks: (a) build a pin-share, attempt receive with wrong PIN; (b) build any share, attempt receive with wrong identity passphrase; (c) build any share with tampered ciphertext; assert all three produce identical user-facing Display.

**Note on CONTEXT.md ambiguity:** The wording "wrong PIN at later age-decrypt fails with exit 4 + identical Display to wrong-identity (PIN-07)" is consistent with this approach. PIN-07 in REQUIREMENTS.md says wrong-PIN shares Display with wrong-identity-key (exit 4) AND with sig-failures (exit 3) — these are TWO different exit codes; PIN-07's intent is "the user-facing message is identical" not "the exit code is identical". Plan 02 must verify this reading is correct; if PIN-07 strictly demands a single exit code across all failure paths, the implementation must remap. Recommend: reading PIN-07 as "Display is identical even though exit codes differ".

### JCS fixture regen pattern

[VERIFIED: tests/outer_record_canonical_form.rs:11-44] Fixtures are committed bytes; the test asserts byte-for-byte equality against the committed file. Regeneration is via the **same test file** with `#[ignore]`-gated `regenerate_fixture` function (line 38-44). Run: `cargo test -- --ignored regenerate_fixture` and commit the resulting `.bin`.

**Plan 02 needs:** new test `tests/outer_record_pin_required_signable.rs` that mirrors `outer_record_canonical_form.rs` exactly, but with `OuterRecordSignable { pin_required: true, ... }` and writes to `tests/fixtures/outer_record_pin_required_signable.bin`. Estimated fixture size: ~218 bytes (192-byte v1.0 fixture + ~22 bytes for `,"pin_required":true`).

**Plan 04 needs:** new test `tests/envelope_burn_signable.rs` mirroring the same pattern, fixture `tests/fixtures/envelope_burn_signable.bin`. Existing `tests/fixtures/envelope_jcs_generic_secret.bin` (file present per `ls` of fixtures dir) is a peer template.

### JCS field-ordering for new optional fields ([VERIFIED: serde_canonical_json 1.0.0 = RFC 8785 alphabetic])

`serde_canonical_json::CanonicalFormatter` sorts JSON object keys lexicographically per RFC 8785 §3.2.3 — this is the JCS definition, not a configurable option. Two new fields:

**OuterRecord existing field order (alphabetic):** `blob`, `created_at`, `protocol_version`, `pubkey`, `recipient`, `share_ref`, `signature`, `ttl_seconds`. Inserting `pin_required`:
- `b`-l-o-b ... `c`-r-e-a-t-e-d ... `p`-i-n_r ... `p`-r-o-t ...
- `pi` < `pr` (since `i`=0x69, `r`=0x72), so **`pin_required` lands between `created_at` and `protocol_version`**.

**Correction to CONTEXT.md:** The CONTEXT.md wire-format example lists `pin_required` between `created_at` and `purpose`. But `purpose` is on **Envelope**, not OuterRecord. The example is wrong about which struct it shows. Plan 01 must verify the Plan 02 fixture writes `pin_required` between `created_at` and `protocol_version`. The full alphabetic OuterRecordSignable order with the new field is:
```
blob, created_at, pin_required, protocol_version, pubkey, recipient, share_ref, ttl_seconds
```

**Envelope existing field order (alphabetic):** `created_at`, `material`, `protocol_version`, `purpose`. Inserting `burn_after_read`:
- `b` < `c`, so **`burn_after_read` lands FIRST**. Full Envelope-with-burn order:
```
burn_after_read, created_at, material, protocol_version, purpose
```

Both correct alphabetic placements match the CONTEXT.md wire-format examples for the Envelope, and correct the CONTEXT.md ambiguity for the OuterRecord example. Plan 01/02 fixture regen will surface the correct order automatically — the JCS formatter does the sort.

## Existing code anchors (file:line for each integration point)

### Plan 01 (PIN core) anchors

| What | Location | Note |
|------|----------|------|
| New module `src/pin.rs` (or extension to `src/crypto.rs`) | NEW | Planner picks file boundary; `src/preview.rs` is the new-file precedent |
| HKDF info constant | `src/crypto.rs:41-60` (`hkdf_infos` module) | Add `pub const PIN: &str = "cipherpost/v1/pin";` |
| Argon2id params | `src/crypto.rs:175-177` (`default_argon2_params`) | Reuse OR define local `pin_argon2_params()` with same values; recommend local helper for clarity |
| age Identity construction | `src/crypto.rs:129-133` (`identity_from_x25519_bytes`) | Existing — reuse verbatim |
| age recipient construction | `src/crypto.rs:120-123` (`recipient_from_x25519_bytes`) | OR call `age::x25519::Identity::to_public()` (age-0.11.2/src/x25519.rs:83-85) |
| age encrypt | `src/crypto.rs:139-148` (`age_encrypt`) | Reuse verbatim; called twice for nested case |
| OuterRecord struct | `src/record.rs:27-36` | Add `#[serde(default, skip_serializing_if = "is_false")] pub pin_required: bool` |
| OuterRecordSignable struct | `src/record.rs:42-50` | Mirror addition; `From<&OuterRecord>` (line 52-64) needs the new field threaded |
| `is_false` helper | NEW (or inline) | `fn is_false(b: &bool) -> bool { !*b }` — convention; see x509-parser etc. for examples |
| dep-tree evidence file | NEW: `08-01-pin-deps-tree.txt` | At repo root or `.planning/phases/08-.../`; parallels Phase 7 |

### Plan 02 (PIN ship-gate) anchors

| What | Location | Note |
|------|----------|------|
| `--pin` flag on Send | `src/cli.rs:61-101` (Send subcommand) | Add `#[arg(long)] pub pin: bool` after `material_stdin: Option<String>` line 100 |
| Argv-inline `--pin <value>` rejection | `src/cli.rs` | Mirror `passphrase: Option<String>` `hide = true` pattern (line 95-96) — but only if PIN is going to admit non-interactive sources later. PIN-01 says NO non-interactive PIN, so a single `bool` flag is sufficient and simpler |
| PIN prompt helper | NEW: `src/pin.rs::prompt_pin(confirm: bool)` | Mirror `identity::resolve_passphrase` priority-5 path (src/identity.rs:323-332); use `dialoguer::Password::with_confirmation` when `confirm=true` |
| PIN validation | `src/pin.rs::validate_pin` | Direct fork of cclink/src/commands/publish.rs:19-67. Recommend: same blocklist + same algo. Display should be GENERIC ("PIN does not meet entropy requirements") for oracle hygiene; specific reason can be on stderr but not in the Error::Display path |
| Wire-budget evidence | `tests/x509_dep_tree_guard.rs` | Pattern template for the new dep-tree assertion test |
| JCS fixture | NEW: `tests/fixtures/outer_record_pin_required_signable.bin` | ~218 bytes; fixture-regen pattern from `tests/outer_record_canonical_form.rs:38-44` |
| PIN round-trip test | NEW: `tests/pin_roundtrip.rs` | Template: `tests/phase2_self_round_trip.rs`; uses `AutoConfirmPrompter`, MockTransport |
| PIN error-oracle test | NEW: `tests/pin_error_oracle.rs` | Asserts `Error::DecryptFailed` Display identity for wrong-pin / wrong-passphrase / tampered-ciphertext |
| SPEC.md PIN crypto section | `SPEC.md:147-322` (between §3.2 Material and §3.3 OuterRecord) | OR new §3.6 after §3.5 DHT Label Stability (line 392+); planner picks |

### Plan 03 (BURN core) anchors

| What | Location | Note |
|------|----------|------|
| Envelope struct | `src/payload/mod.rs:31-36` | Add `#[serde(default, skip_serializing_if = "is_false")] pub burn_after_read: bool` |
| `--burn` flag on Send | `src/cli.rs:61-101` | Add `#[arg(long)] pub burn: bool` |
| Send-time stderr warning | `src/main.rs:199` (just before `run_send` call) | Inline `eprintln!` when `burn==true`; literal text from BURN-05 |
| `LedgerEntry` struct | `src/flow.rs:883-893` | Add `#[serde(default, skip_serializing_if = "is_default")] pub state: LedgerState` (or `Option<String>` for simpler default-elision) |
| `LedgerState` enum | NEW (in `src/flow.rs` or new `src/state.rs`) | `enum LedgerState { None, Accepted{accepted_at: String}, Burned{burned_at: String} }`; planner picks file |
| `check_already_consumed()` | `src/flow.rs:128-150` (rename from `check_already_accepted`) | Return type changes to `LedgerState`; existing 2 callers update |
| Caller 1 | `src/flow.rs:433` (run_receive) | Pattern-match the new enum |
| Caller 2 | `src/main.rs:237` (CLI dispatch idempotency check) | Same |
| Migrate v1.0 row deserialization | `src/flow.rs::LedgerEntry`-paired Deserialize | Add a peer struct `LedgerRow { ..., #[serde(default)] state: Option<String>, ... }` with `state.unwrap_or("accepted")` mapping; existing rows pre-Phase-8 have no `state` field and parse cleanly |

### Plan 04 (BURN ship-gate) anchors

| What | Location | Note |
|------|----------|------|
| Banner `[BURN]` marker | `src/flow.rs:1196` (before `Purpose:` line) | Render `eprintln!("[BURN — you will only see this once]")` when marker passed |
| `Prompter` trait extension | `src/flow.rs:83-97` | Add `marker: Option<&str>` param; OR use `&[&str]` for forward extension |
| TtyPrompter implementation | `src/flow.rs:1165-1239` | Insert marker-emit between `eprintln!("=== CIPHERPOST ACCEPTANCE")` (line 1196) and Purpose line (1197) |
| run_receive call site | `src/flow.rs:543-553` | Thread `marker` parameter; `Some("[BURN — you will only see this once]")` when `envelope.burn_after_read=true`, else `None` |
| Test prompters | `src/flow.rs:1041-1078` (`AutoConfirmPrompter`, `DeclinePrompter`) | Update method signatures; ignore the new param |
| Receive flow burn integration | `src/flow.rs:583-591` | Insert ordering: write_output BEFORE create_sentinel + append_ledger_entry, only when `envelope.burn_after_read==true` |
| JCS fixture | NEW: `tests/fixtures/envelope_burn_signable.bin` | ~140 bytes; mirror `envelope_jcs_generic_secret.bin` |
| BURN round-trip test | NEW: `tests/burn_roundtrip.rs` | Two-receive sequence; assert exit 0 then exit 7; receipt count = 1 |
| PITFALLS.md #26 supersession note | `.planning/research/PITFALLS.md:395-449` | Append a "**SUPERSEDED 2026-04-XX (D-P8-12)**" header at the top of #26; don't delete the original text |

### Plan 05 (compose tests) anchors

| What | Location | Note |
|------|----------|------|
| Compose matrix | NEW: `tests/pin_burn_compose.rs` | Each typed-material variant × {pin alone, burn alone, pin+burn}; ~12 cases |
| Wrong-PIN-on-burn test | within compose file | Asserts no `state: burned` ledger row written; share remains re-receivable |
| Typed-z32-declined-on-burn test | within compose file | Asserts no `state: burned` ledger row, no receipt published |
| Receipt-published-on-burn assertion | within compose file | Counts MockTransport receipt calls; expects 1 |

### Plan 06 (docs) anchors

| What | Location | Note |
|------|----------|------|
| SPEC.md §3.X PIN crypto | `SPEC.md` between §3.2 Material (line 147) and §3.3 OuterRecord (line 323) — recommend §3.5.5 OR §3.6 | Argon2id params; HKDF namespace; salt encoding; nested-age structure; UX order; oracle constraint; entropy floor |
| SPEC.md §3.X Burn semantics | `SPEC.md` after the PIN section | Local-state-only; ledger inversion; DHT-survives-TTL; receipt-still-published |
| SPEC.md §5.1 Send extension | `SPEC.md:435-509` | Document `--pin` (TTY-only) and `--burn` flags; cross-ref deferred non-interactive PIN |
| SPEC.md §5.2 Receive banner | `SPEC.md:510-675` | `[BURN — you will only see this once]` placement; PIN prompt order |
| SPEC.md §6 Exit codes | `SPEC.md:693-723` | Exit 4 for wrong PIN (same Display as wrong-identity per PIN-07); exit 7 for `share already consumed` (BURN-02) |
| THREAT-MODEL.md §X "PIN mode" | `THREAT-MODEL.md` after §6 Passphrase-MITM (line 304) — recommend §6.5 OR §7 (renumber existing) | Second-factor semantics; offline brute-force bound (Argon2id 64MB×3 + entropy floor); intentional indistinguishability; no PIN logging |
| THREAT-MODEL.md §X "Burn mode" | `THREAT-MODEL.md` after PIN section | Local-state-only; DHT-ciphertext-survives-TTL; multi-machine race documented; burn ≠ cryptographic destruction |
| CLAUDE.md §Load-bearing additions | `CLAUDE.md` "## Load-bearing lock-ins" section (existing bullet list) | Add three new bullets: HKDF info `cipherpost/v1/pin`; ledger `state` field invariant; emit-before-mark contract for burn |

### CLAUDE.md exact insertion targets (verified bullets)

The existing CLAUDE.md `## Load-bearing lock-ins` section has 12 bullets. Plan 06 adds three; recommended placement (preserving section cadence):

- After "HKDF info strings = `cipherpost/v1/<context>`. Never empty, never `None`. ..." — append a sub-clause: "Phase 8 adds `cipherpost/v1/pin` to the enumeration; the `signature_failure_variants_share_display` discipline extends to wrong-PIN failures."
- After the "ed25519-dalek =3.0.0-pre.5 exact pin" bullet — add a new bullet: "`accepted.jsonl` rows carry an optional `state: \"accepted\"|\"burned\"` field; v1.0 rows missing the field deserialize via serde default to `accepted`. Burn rows write `state: \"burned\"`. (D-P8-10)"
- After the "Error-oracle hygiene" bullet — add: "Burn write order is **emit-before-mark** (D-P8-12), inverting v1.0's accepted-then-emit ordering. Crash between emit and ledger-write leaves share re-receivable — safer failure mode. v1.0 `accepted` flow is unchanged."

## JCS field-ordering verification

Already verified above. Summary:
- **`pin_required`** lands alphabetically **between `created_at` and `protocol_version`** in OuterRecord(Signable). (CONTEXT.md says "between `created_at` and `purpose`" — this is wrong; `purpose` is on Envelope, not OuterRecord.)
- **`burn_after_read`** lands alphabetically **first** in Envelope (before `created_at`).

Both consistent with `serde_canonical_json::CanonicalFormatter` RFC 8785 §3.2.3 lexicographic key ordering. `skip_serializing_if = "is_false"` ensures byte-identity with v1.0 fixtures when the new fields are `false`.

## Ledger schema migration shape

[VERIFIED: src/flow.rs:883-893] Current `LedgerEntry` struct (compile-time):
```rust
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_published_at: Option<&'a str>,
    sender: &'a str,
    share_ref: &'a str,
}
```

[VERIFIED: src/flow.rs:128-150] Current `check_already_accepted` returns `Option<String>` (just the `accepted_at` ISO string).

**Plan 03 schema change:**
```rust
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_published_at: Option<&'a str>,
    sender: &'a str,
    share_ref: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,  // None | Some("accepted") | Some("burned")
}
```

Rationale for `Option<&str>` (NOT a typed enum field on `LedgerEntry` itself): JSONL rows are append-only and read by both this code and external tooling; JSON's open-set extensibility favors a string. The TYPED `LedgerState` enum is a runtime-side abstraction in `check_already_consumed`'s return type — NOT the wire shape.

`check_already_consumed` rename:
```rust
pub enum LedgerState {
    None,
    Accepted { accepted_at: String },
    Burned { burned_at: String },
}
pub fn check_already_consumed(share_ref_hex: &str) -> LedgerState { ... }
```

[VERIFIED: src/flow.rs:433 + src/main.rs:237] **Two callers** of the existing function:
1. `src/flow.rs:433` — `run_receive` step 1 idempotency short-circuit. Pattern-match: `Accepted` → existing "already accepted" path; `Burned` → return `Error::Declined` (which already maps to exit 7); `None` → continue to step 2.
2. `src/main.rs:237` — CLI dispatch idempotency check (visible to user before TTY prompt). Same enum-match.

Both callers update sequentially in Plan 03; cargo build verifies.

## TtyPrompter banner extension shape

[VERIFIED: src/flow.rs:83-97] Current `Prompter` trait signature:
```rust
pub trait Prompter {
    fn render_and_confirm(
        &self,
        purpose: &str,
        sender_openssh_fp: &str,
        sender_z32: &str,
        share_ref_hex: &str,
        material_type: &str,
        size_bytes: usize,
        preview_subblock: Option<&str>,
        ttl_remaining_seconds: u64,
        expires_unix_seconds: i64,
    ) -> Result<(), Error>;
}
```

**Plan 04 minimal extension** — add ONE parameter:
```rust
banner_marker: Option<&str>,  // e.g., Some("[BURN — you will only see this once]")
```

Rationale for `Option<&str>` over `&[&str]`:
- Phase 6's `preview_subblock` already established the `Option<&str>` precedent
- Burn is the only marker today; `&[&str]` premature-generalizes
- If a future phase needs multiple markers (e.g., `[BURN]` + a different banner badge), upgrade to `&[&str]` then. YAGNI.

The banner emission point is `src/flow.rs:1196`:
```rust
eprintln!("=== CIPHERPOST ACCEPTANCE ===============================");
// INSERTION POINT — Plan 04 adds:
if let Some(marker) = banner_marker {
    eprintln!("{}", marker);
}
eprintln!("Purpose:     \"{}\"", safe_purpose);
```

The two test prompters (`AutoConfirmPrompter`, `DeclinePrompter` at src/flow.rs:1041-1078) gain `_banner_marker: Option<&str>` and ignore it. The `tty_prompter_rejects_non_tty_env` test (src/flow.rs:1305-1345) needs one new parameter (`None`) at the call site.

## PIN validation algorithm

Direct fork of cclink/src/commands/publish.rs:19-67. Algorithm (cipherpost/Plan 02 port):

```rust
// src/pin.rs::validate_pin
pub fn validate_pin(pin: &str) -> Result<(), Error> {
    let len = pin.len();
    if len < 8 {
        return Err(Error::Config("PIN does not meet entropy requirements".into()));
    }
    let first = pin.chars().next().unwrap();
    if pin.chars().all(|c| c == first) {
        return Err(Error::Config("PIN does not meet entropy requirements".into()));
    }
    let chars: Vec<char> = pin.chars().collect();
    let asc = chars.windows(2).all(|w| (w[1] as i32) - (w[0] as i32) == 1);
    let desc = chars.windows(2).all(|w| (w[0] as i32) - (w[1] as i32) == 1);
    if asc || desc {
        return Err(Error::Config("PIN does not meet entropy requirements".into()));
    }
    const COMMON: &[&str] = &["password", "qwerty", "letmein", "12345678", "87654321", "qwertyui", "asdfghjk"];
    if COMMON.contains(&pin.to_lowercase().as_str()) {
        return Err(Error::Config("PIN does not meet entropy requirements".into()));
    }
    Ok(())
}
```

**Display contract:** GENERIC literal `"PIN does not meet entropy requirements"` for ALL four rejection reasons. The specific reason (length / all-same / sequential / blocklist) can be:
- Logged separately to stderr at a different verbosity level (NOT recommended — leak risk via terminal-recording / shell-redirect)
- OR carried in a private internal field consumed only by tests (recommended pattern below)

Recommended: use `Error::Config(String)` with the literal generic string, but introduce a parallel test-only function `validate_pin_with_reason(pin: &str) -> Result<(), &'static str>` returning a non-generic reason that tests assert against without touching production user-output. The Phase 6 `Error::InvalidMaterial { variant, reason }` pattern is precedent — though there `reason` IS user-facing; for PIN it should NOT be. Phase 8 should adopt a NEW pattern: production Display is generic; test assertions go through a `#[cfg(test)]` reason-returning helper.

**Why generic Display matters (Pitfall #23 / Pitfall #24):** A specific "PIN too short" message tells a brute-forcer exactly what dimension to vary. Generic "does not meet entropy requirements" preserves the entropy floor as opaque.

## Wire-budget overhead prediction

[VERIFIED: src/flow.rs:39-58 + age 0.11.2 internals]

| Layer composition | Predicted overhead vs plaintext | Notes |
|-------------------|--------------------------------|-------|
| Single age (v1.0 default) | ~165 bytes header + per-chunk MAC | Existing measurement; budget headroom in DHT-07 |
| Nested age (Phase 8 PIN) | ~330 bytes (2× header) + 2× grease variance | Adds ~165 bytes per layer |
| + `burn_after_read: true` field | ~22 bytes JCS overhead | One bool key in alphabetic Envelope position |
| + `pin_required: true` field | ~21 bytes JCS overhead | One bool key in OuterRecord |
| + 32-byte salt prefix | 32 bytes raw + 4/3 base64 expansion ≈ 43 bytes | Outside both age layers |
| **Worst-case pin+burn+pgp-secret-key compose** | ~1080 bytes encoded SignedPacket | Brushes 1000-byte BEP44 budget |

**Plan 01 must surface clean `Error::WireBudgetExceeded` errors** when overflow occurs. The existing retry-grease loop (src/flow.rs:303-352) handles grease variance. Plan 01 documents the predicted overhead in SUMMARY; Phase 9 (DHT-07) measures empirically. The actual overflow handling already works — the 20-attempt retry surfaces a final WireBudgetExceeded with last-seen `encoded` size for user diagnostics.

**Recommendation:** Plan 01 adds an integration test `tests/pin_burn_wire_budget_smoke.rs` that constructs a worst-case 419-byte pgp_key payload + pin + burn and asserts the result is **either** Ok(uri) **or** `Error::WireBudgetExceeded` (not a panic / Transport error). This codifies the Phase 6/7 wire-budget deferral pattern (`#[ignore]`-gated round-trip if encoded size is too tight).

## CLAUDE.md / SPEC.md / THREAT-MODEL.md insertion points (concrete anchors)

### SPEC.md

Section structure: §3 Wire Format → §3.1 Envelope → §3.2 Material → §3.3 OuterRecord → §3.4 Receipt → §3.5 DHT Label Stability → §4 Share URI → §5 Flows → §5.1 Send → §5.2 Receive → §5.3 Receipts → §6 Exit Codes → §7 Passphrase Contract → §8 Test Vectors → §9 Lineage.

Plan 06 inserts **two new subsections within §3** (recommend §3.6 PIN Crypto Stack and §3.7 Burn Semantics — preserving the §3.X numbering convention) and extends §5.1 / §5.2 / §6 / §8 (test vectors) inline. The §3.6 PIN section parallels §3.2 Material in shape (params table, wire form example, normalization rules); §3.7 Burn parallels §3.5 DHT Label Stability (one-paragraph rationale + invariants list).

### THREAT-MODEL.md

Section structure: §1 Trust Model → §2 Identity Compromise → §3 DHT Adversaries → §4 Sender-Purpose → §5 Acceptance-UX → §6 Passphrase-MITM → §7 Receipt-Replay/Race → §8 Out of Scope → §9 Lineage.

Plan 06 inserts §6.5 "PIN mode (second-factor share encryption)" between §6 Passphrase-MITM and §7 Receipt-Replay (no renumber needed), and §6.6 "Burn mode (local-state-only single-consume)" immediately after. **Alternative:** insert as §7 "PIN mode" + §8 "Burn mode" with a renumber of existing §7 → §9 and §8 → §10. The §6.X variant is less disruptive.

Each new section follows the existing per-property template visible in §3.1 Sybil through §3.3 Replay: (1) what the property is, (2) attacker capabilities it covers, (3) attacker capabilities it does NOT cover, (4) test references in `tests/`.

### CLAUDE.md

The existing § "Load-bearing lock-ins" bullet list has 12 entries (counted via grep `^- ` between the section headers). Plan 06 adds three new bullets at appropriate positions — SEE the "CLAUDE.md exact insertion targets" subsection above under Plan 06 anchors.

## Open risks for the planner

1. **PIN-07 exit-code reading.** PIN-07 says "wrong PIN returns exit 4 with the same Display as wrong identity passphrase" — but `Error::DecryptFailed` (exit 4) and the four `Signature*` variants (exit 3) have DIFFERENT Display strings today. Plan 02 must verify that PIN-07 means "Display matches wrong-passphrase Display" (exit 4 unified — feasible) NOT "Display matches all four credential-failure paths" (would require collapsing exit 3 and exit 4 into one — taxonomy break). **Recommendation:** Plan 02 reads PIN-07 narrowly — wrong-PIN folds into `Error::DecryptFailed` (exit 4). Wrong-PIN does NOT collide with `Error::Signature*` (exit 3). The user-facing oracle hygiene comes from the fact that an attacker observing exit code already cannot tell wrong-PIN from wrong-passphrase (both exit 4), and cannot tell either from sig-failure (exit 3 — but sig-failure would have to follow wire tampering, which is a different attacker capability).

2. **`pin_required` JCS placement (CONTEXT.md correction).** CONTEXT.md says `pin_required` lands "between `created_at` and `purpose`". `purpose` is on Envelope, not OuterRecord. The actual alphabetic placement on OuterRecord is between `created_at` and `protocol_version`. Plan 01 must verify the JCS fixture writes the correct order; the formatter does this automatically, but the Plan SUMMARY should call out the correction so reviewers don't assume the CONTEXT.md example is canonical.

3. **PITFALLS #26 supersession authority.** D-P8-12 says PITFALLS #26 is OUTDATED. Plan 04 must update the file. Recommendation: **prepend** a "**SUPERSEDED 2026-04-XX (D-P8-12)**" header at the top of the #26 section block, do NOT delete the original analysis (which is still valuable as the rejected alternative). This preserves the historical reasoning for future readers.

4. **Receipt-on-burn implementation gotcha.** BURN-04 says receipt IS published. The existing `run_receive` step 13 (src/flow.rs:612-662) is wrapped in a closure that **always** publishes (no burn-conditional). Plan 04's burn integration MUST NOT add a `if !envelope.burn_after_read { publish_receipt(...) }` guard. The receipt always flows. Test: `tests/burn_roundtrip.rs::receipt_count_is_1_after_burn`.

5. **Wire-budget pin+burn+pgp risk.** Per overhead prediction above, the worst-case compose may exceed the 1000-byte BEP44 budget. Phase 8 surfaces clean `WireBudgetExceeded`; Phase 9 measures; v1.2 escape-hatches. Plan 01 must NOT silently truncate or split — it just must produce a clean error. Test the failure mode in Plan 02 (positive WireBudgetExceeded test), ignore-gate the success-mode round-trip if the budget is too tight.

6. **Argv-inline `--pin <value>` rejection scope.** PIN-01 defers `--pin-file` / `--pin-fd` / `CIPHERPOST_PIN`. So `--pin` is just a `bool` flag; there is no `--pin <value>` form to reject at runtime — the flag has no value. CONTEXT.md notes a recommendation to "reject argv-inline `--pin <value>` at clap parse + runtime per existing passphrase rejection pattern" — but the only argv-inline path possible is `--pin=<some-string>`, which clap-bool can be configured to reject by NOT defining the value. Plan 02 should use `#[arg(long)] pub pin: bool` (no `value_name`, no `Option<String>`) — clap rejects `--pin=foo` automatically with a parse error.

7. **`is_false` helper convention.** Cipherpost has no current `is_false(&bool) -> bool` helper. Plan 01 adds one — recommended location: `src/lib.rs` (crate-public `pub(crate)`) or inline in each module that uses `skip_serializing_if`. Convention: `fn is_false(b: &bool) -> bool { !*b }`. Match what serde-with crate does, or hand-roll (no new dep).

8. **Wave-0 test infra status.** Phase 8 inherits the existing test infra (cargo + nextest + serial_test 3 + #[serial] convention). No Wave 0 gaps. Skip the formal Validation Architecture block — `nyquist_validation` defaults to disabled per `.planning/config.json` reading; the per-plan acceptance criteria are sufficient.

## Project Constraints (from CLAUDE.md)

| Directive | Phase 8 compliance |
|-----------|-------------------|
| `chacha20poly1305 only via age` | D-P8-06 nested-age choice satisfies; Plan 01 dep-tree evidence file confirms no direct dep |
| HKDF info `cipherpost/v1/<context>` | D-P8-02 `cipherpost/v1/pin`; Plan 01 extends `crypto::hkdf_infos` |
| Argon2id params in identity file PHC string (NOT hardcoded) | PIN's Argon2id params are intentionally hardcoded — they are a **share-level** contract, not an identity-level. PHC-header rule applies only to identity unlock (CCIPHPOSK envelope). Document the distinction in SPEC.md §3.6. |
| No `#[derive(Debug)]` on key-holding structs | Plan 01: PIN-derived 32-byte key buffer must not derive Debug; salt buffer must not either. Mirror existing `secrecy::SecretBox` pattern. |
| Dual-signature ordering (outer before age-decrypt; inner before any envelope field surfaces) | D-P8-07 step 2 outer-verify; PIN prompt is AFTER outer-verify; envelope fields surface only after inner-verify (step 9). All preserved. |
| Identity path `~/.cipherpost/`, mode 0600 | Ledger writes to `state_dir()` (existing). State file mode 0600 (existing src/flow.rs:867-880). |
| Default TTL 24h | Unchanged. |
| `pkarr::ClientBlocking` (no tokio) | Unchanged — Phase 8 doesn't touch transport. |
| `ed25519-dalek =3.0.0-pre.5` | Unchanged. |
| Error-oracle hygiene (Display equality across credential failures) | D-P8-12 wrong-PIN folds into `Error::DecryptFailed`; existing D-16 unified Display extends naturally. |
| `share_ref = sha256(ciphertext || created_at_be).truncate(16)` | Unchanged — pre-decrypt early ledger pre-check (D-P8-09) uses this verbatim. |
| Argv-inline rejection | `--pin` is a bool flag — no inline value to reject. (See Open Risk #6.) |
| `serial_test = "3"` + `#[serial]` for env-mutating tests | All new PIN tests that may touch `CIPHERPOST_HOME` carry `#[serial]`. |

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Argon2id PIN derivation | Custom HMAC-or-PBKDF2 chain | `argon2 = "0.5"` (already pulled) — `Argon2::new(Algorithm::Argon2id, V0x13, params)` | NIST 800-63B-aligned; cclink already validated; constant-time |
| HKDF with domain separation | Custom HMAC chain | `hkdf = "0.12"` (already pulled) — `Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut okm)` | RFC 5869 |
| AEAD layer | Direct `chacha20poly1305` | `age::Encryptor::with_recipients` | CLAUDE.md load-bearing |
| TTY PIN prompt | Direct termios + read | `dialoguer::Password` | Already pulled (0.12); existing src/identity.rs:323-332 template |
| PIN validation rules | Custom regex / per-rule loops | Direct fork of cclink `validate_pin` | Already debugged; tested in cclink tests |
| Secure memory clearing | Manual zero loops | `zeroize::Zeroizing` / `secrecy::SecretBox` | Already pulled; CLAUDE.md compliant |
| JSONL append + state field migration | Custom file format | Existing src/flow.rs LedgerEntry + serde default | One-field additive change preserves v1.0 row parsing |
| JCS canonicalization | Sort keys manually | `serde_canonical_json::CanonicalFormatter` | RFC 8785 reference; already pulled |
| z-base-32 ↔ Ed25519 ↔ X25519 conversion | Hand-rolled curve math | `pkarr::PublicKey` + `crypto::ed25519_to_x25519_*` | Existing src/crypto.rs:75-89; cclink-fixture-pinned |

**Key insight:** Phase 8 is mostly orchestration. The math, the AEAD, the parsing, the PIN-rules — every primitive is either already in cipherpost or already in cclink and reuseable as a direct fork. Plans focus on **wiring**, not on **inventing**.

## Common Pitfalls

### Pitfall: Dropping the `[ASSUMED]` discipline on PITFALLS #26 supersession

**What goes wrong:** Plan 04 deletes the original PITFALLS #26 prose and replaces it with the new D-P8-12 emit-before-mark rule. Future readers lose the reasoning for why mark-then-emit was originally chosen.

**Prevention:** Prepend a "**SUPERSEDED 2026-04-XX by D-P8-12**" header at the top of #26's existing section. Keep the original analysis intact below the header. Add a new section #26b "Burn ordering: emit-before-mark (resolution)" with the D-P8-12 rationale.

### Pitfall: Wrong-PIN distinguishability via Argon2 timing

**What goes wrong:** A short wrong PIN reaches the Argon2 step quickly; a wrong PIN of length 8 takes the full Argon2 cost. An observer measuring receive latency could distinguish "PIN was the wrong length" from "PIN was the wrong content".

**Prevention:** PIN length validation runs BEFORE Argon2 (during input). Once a PIN passes validation, the Argon2 cost is identical regardless of correctness. The remaining Argon2 → HKDF → age-decrypt path is constant-time per the underlying primitives. Plan 02 documents this in SPEC.md §3.6 ("Length validation is pre-Argon2; post-validation timing is constant").

### Pitfall: Salt placement leaks burn-mode marker via blob length

**What goes wrong:** Pin-shares are 32 bytes longer than non-pin-shares (the salt prefix). DHT observers can guess "this share is pin-protected" by measuring the blob size. This is INTENTIONAL — `pin_required` is on OuterRecord (outer-signed, pre-decrypt readable) per D-P8-03 — observers already see the bool flag. No additional leak via length.

**Prevention:** None needed. The bool flag IS the signal. Plan 04 does NOT need to pad-mask non-pin shares.

### Pitfall: `LedgerState::Burned` deserialization on v1.1+ rows reverts to Accepted on missing field

**What goes wrong:** A v1.0 row with no `state` field correctly deserializes to `LedgerState::Accepted`. But a v1.1 burn row with `state: "burned"` written then later mangled (file truncation, partial-write recovery) could lose the field and silently re-classify as accepted, allowing a re-receive of a burned share.

**Prevention:** `append_ledger_entry` writes `state: "burned"` atomically (write-all-then-fsync). Plan 03's test asserts that a partial write fails the deserialization (returns the previous row's state). Audit recommendation: `serde::Deserialize` for the row struct uses `#[serde(deny_unknown_fields)]` so a corrupted line is rejected outright rather than silently defaulting.

### Pitfall: PIN prompt re-render on every receive in MockTransport tests

**What goes wrong:** Tests that drive PIN-protected shares need to inject a PIN. The existing `AutoConfirmPrompter` doesn't return a PIN — it just confirms. Plan 02 must add a `PinSource` injection point distinct from the `Prompter` trait (or extend the trait).

**Prevention:** Add a dedicated `PinPrompter` trait at Phase 8 design time:
```rust
pub trait PinPrompter {
    fn prompt_pin(&self) -> Result<SecretBox<String>, Error>;
}
```
With a `TtyPinPrompter` (production) and `FixedPinPrompter(SecretBox<String>)` (test). The receive flow takes both `&dyn Prompter` and `&dyn PinPrompter`. Tests inject `FixedPinPrompter::new("validpin1")`.

## Code Examples

### Plan 01 — `pin_derive_key` (direct cclink fork with namespace adapt)

```rust
// src/pin.rs (NEW FILE — Plan 01)
use crate::crypto::hkdf_infos;
use crate::error::Error;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// PIN-specific Argon2id parameters (matches cclink's pin_derive_key shape).
/// Distinct from the identity-KEK params (which are read from the PHC header).
fn pin_argon2_params() -> Params {
    Params::new(65536, 3, 1, Some(32)).expect("static PIN argon2 params are always valid")
}

/// Derive a 32-byte X25519 scalar from a PIN and a 32-byte salt.
///
/// Matches cclink's pin_derive_key shape (Argon2id 64MB×3iter → HKDF-SHA256 →
/// 32 bytes) with the namespace adapted from `cclink-pin-v1` to
/// `cipherpost/v1/pin` per cipherpost's domain-separation convention
/// (CLAUDE.md load-bearing).
pub fn pin_derive_key(pin: &str, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, pin_argon2_params());
    let mut argon_out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pin.as_bytes(), salt, argon_out.as_mut())
        .map_err(|e| Error::Crypto(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))))?;

    let hk = Hkdf::<Sha256>::new(None, &*argon_out);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(hkdf_infos::PIN.as_bytes(), &mut okm[..])
        .map_err(|e| Error::Crypto(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))))?;
    Ok(okm)
}
```

Source: cclink/src/crypto/mod.rs:144-163 with adaption noted inline.

### Plan 01 — Inner-then-outer nested age

```rust
// src/flow.rs::run_send (Plan 01 modification — pseudo-code excerpt)
let envelope_jcs_bytes = envelope.to_jcs_bytes()?;

let outer_recipient = /* existing X25519 recipient derivation */;

let (final_ciphertext, salt_prefix): (Vec<u8>, Option<[u8; 32]>) = if pin_required {
    let pin = pin_prompter.prompt_pin()?;
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let pin_key = crate::pin::pin_derive_key(pin.expose_secret(), &salt)?;
    let pin_identity = crate::crypto::identity_from_x25519_bytes(&pin_key)?;
    let pin_recipient = pin_identity.to_public();
    let inner_ct = crate::crypto::age_encrypt(&envelope_jcs_bytes, &pin_recipient)?;
    let outer_ct = crate::crypto::age_encrypt(&inner_ct, &outer_recipient)?;
    (outer_ct, Some(salt))
} else {
    let outer_ct = crate::crypto::age_encrypt(&envelope_jcs_bytes, &outer_recipient)?;
    (outer_ct, None)
};

use base64::Engine;
let blob = if let Some(salt) = salt_prefix {
    let mut bytes = Vec::with_capacity(32 + final_ciphertext.len());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&final_ciphertext);
    base64::engine::general_purpose::STANDARD.encode(&bytes)
} else {
    base64::engine::general_purpose::STANDARD.encode(&final_ciphertext)
};
```

### Plan 03 — `LedgerState` enum + `check_already_consumed` rename

```rust
// src/flow.rs (or new src/state.rs — planner picks)

/// State of a `share_ref` in the local ledger.
///
/// `None` — no record; receive is fresh.
/// `Accepted` — already accepted via v1.0 idempotent flow OR Phase 8 non-burn flow;
///              re-receive is a no-op success.
/// `Burned` — already accepted via Phase 8 burn flow; re-receive returns exit 7.
#[derive(Debug, PartialEq, Eq)]
pub enum LedgerState {
    None,
    Accepted { accepted_at: String },
    Burned { burned_at: String },
}

/// Renamed from `check_already_accepted`. Returns the full ledger state for the
/// given `share_ref_hex`. Callers branch on the variant.
pub fn check_already_consumed(share_ref_hex: &str) -> LedgerState {
    if !sentinel_path(share_ref_hex).exists() {
        return LedgerState::None;
    }
    if let Ok(data) = fs::read_to_string(ledger_path()) {
        for line in data.lines() {
            if !line.contains(share_ref_hex) {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v.get("share_ref").and_then(|s| s.as_str()) == Some(share_ref_hex) {
                    let ts = v.get("accepted_at").and_then(|s| s.as_str()).unwrap_or("<unknown>").to_string();
                    let state = v.get("state").and_then(|s| s.as_str()).unwrap_or("accepted");
                    return match state {
                        "burned" => LedgerState::Burned { burned_at: ts },
                        _ => LedgerState::Accepted { accepted_at: ts },
                    };
                }
            }
        }
    }
    // Sentinel present but no matching line — treat as Accepted (consistent with v1.0 fallback)
    LedgerState::Accepted { accepted_at: "<unknown; sentinel exists but ledger missing>".to_string() }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| cclink direct `chacha20poly1305` for PIN AEAD | cipherpost nested age | 2026-04-25 (D-P8-01) | CLAUDE.md compliance; one less direct crypto-crate dep |
| cclink HKDF info `cclink-pin-v1` | cipherpost `cipherpost/v1/pin` | 2026-04-25 (D-P8-02) | Domain separation convention enforced by enumeration test |
| cclink burn = DHT empty-packet revoke | cipherpost burn = local-state-only | 2026-04-25 (D-P8-01, BURN-08) | Honest threat model; no false promise of cryptographic destruction |
| cclink `validate_pin` returns `Result<(), String>` | cipherpost returns `Error::Config(generic_literal)` | 2026-04-25 (Plan 02) | Oracle hygiene — generic Display, no specific reason in user-facing path |
| v1.0 `check_already_accepted` returns `Option<String>` | Phase 8 `check_already_consumed` returns `LedgerState` | 2026-04-25 (D-P8-10) | Three-state semantics for burn discrimination |
| v1.0 mark-then-emit for `accepted` | Phase 8 emit-then-mark for `burned`; mark-then-emit unchanged for `accepted` | 2026-04-25 (D-P8-12) | Two flows have OPPOSITE atomicity contracts because semantics differ |
| PITFALLS #26 mark-then-emit for burn | Superseded by D-P8-12 emit-then-mark | 2026-04-25 (D-P8-12) | Plan 04 records resolution; original analysis preserved as alternative |

**Deprecated/outdated:**
- `.planning/research/SUMMARY.md` listing of `CIPHERPOST_PIN` env var and `--pin-file` — superseded by REQUIREMENTS PIN-01 (TTY-only); listed in CONTEXT.md "Out of scope"
- `.planning/research/SUMMARY.md` HKDF info `cipherpost/v1/pin_wrap` — superseded by D-P8-02 `cipherpost/v1/pin`
- PITFALLS #26 — superseded by D-P8-12

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Per-layer age v1 overhead ≈ 165 bytes | Wire-budget overhead prediction | Numeric estimate; Phase 9 measures empirically. If significantly higher, Plan 01's wire-budget smoke test still surfaces the WireBudgetExceeded cleanly — no plan change needed, just expectation-setting. |
| A2 | PIN-07 Display-identity is exit-4-only (NOT collapsing exits 3 and 4) | Open Risks #1 | If PIN-07 demands ALL credential failures share Display AND exit, Plan 02 needs a taxonomy redesign. Recommend confirming reading with `/gsd-discuss-phase` before Plan 02 starts. |
| A3 | THREAT-MODEL.md insertion as §6.5/§6.6 (no renumber) | THREAT-MODEL.md insertion points | If reviewers prefer renumber-all-after, Plan 06's diff is larger but content is identical. |

**All other claims are [VERIFIED] against shipped code or [CITED] from `Cargo.toml`, `cargo tree`, source comments, or RFCs.**

## Open Questions

1. **Should `LedgerState::Accepted` and `LedgerState::Burned` carry the same field name (`at: String`) or different names (`accepted_at` vs `burned_at`)?**
   - What we know: the wire-format ledger-row JSON uses `accepted_at` for the timestamp; the new `state` field is a separate string column.
   - What's unclear: when constructing `LedgerState::Burned { burned_at: ts }` in Rust, should the timestamp field name match the wire field (always `accepted_at`) or differ semantically (`burned_at`)?
   - Recommendation: Use `accepted_at` in both variants — matches the wire field; simpler. If the test suite ever wants to assert the burn timestamp specifically, it does so through the variant match, not the field name.

2. **Is there an `is_false` helper to add at crate scope, or inline per-module?**
   - Convention: `serde-with` provides one; cipherpost doesn't pull `serde-with`. Hand-roll.
   - Recommendation: Inline `pub(crate) fn is_false(b: &bool) -> bool { !*b }` in `src/lib.rs` or each module. Single source of truth recommended (lib.rs).

3. **Should the cclink-divergence write-up live as a separate `.md` file or inline in Plan 01 SUMMARY?**
   - Per D-P8-01, "Plan 01 SUMMARY.md MUST contain this divergence write-up". Recommend: inline in Plan 01's `SUMMARY.md`. Don't fragment into a separate file unless the write-up exceeds ~300 lines.

## Sources

### Primary (HIGH confidence)
- `Cargo.toml` (cipherpost) — verified all crate versions and direct-dep status
- `cargo tree` output — verified `chacha20poly1305 v0.10.1` is transitive via age, NOT a direct dep
- `src/crypto.rs:1-386` — JCS, age, Argon2, HKDF integration
- `src/flow.rs:1-1346` — run_send, run_receive, ledger, TtyPrompter, Prompter trait
- `src/record.rs:1-227` — OuterRecord + OuterRecordSignable + JCS sign/verify
- `src/payload/mod.rs:1-635` — Envelope + Material + JCS round-trip
- `src/cli.rs:1-204` — clap surface; existing `--passphrase` rejection pattern
- `src/error.rs:1-135` — D-16 unified Display; exit code taxonomy
- `src/identity.rs:259-333` — `resolve_passphrase` template (PIN prompt mirror)
- `cclink/src/crypto/mod.rs:144-204` — `pin_derive_key`, `pin_encrypt`, `pin_decrypt`
- `cclink/src/commands/publish.rs:19-67` — `validate_pin` algorithm
- `cclink/src/commands/pickup.rs:249-260` — burn = DHT-revoke (which cipherpost rejects per BURN-08)
- `tests/hkdf_info_enumeration.rs:1-73` — enumeration test for new HKDF info constant
- `tests/outer_record_canonical_form.rs:1-52` — JCS fixture regen pattern
- `tests/phase3_receipt_sign_verify.rs:64-105` — D-16 Display equality assertion template
- `~/.cargo/registry/src/.../age-0.11.2/src/x25519.rs:36-86` — `age::x25519::Identity` API
- `~/.cargo/registry/src/.../age-0.11.2/src/protocol.rs:60-125` — `Encryptor::with_recipients` shape

### Secondary (MEDIUM confidence)
- SPEC.md §3 anchors — section structure verified via grep
- THREAT-MODEL.md anchors — section structure verified via grep
- CLAUDE.md "## Load-bearing lock-ins" bullet count — verified via grep

### Tertiary (LOW confidence)
- Per-layer age v1 overhead prediction (~165 bytes) — derived from header construction in protocol.rs but NOT measured empirically; Phase 9 DHT-07 makes this measurable

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every crate verified against Cargo.toml + cargo tree
- API surface: HIGH — age 0.11.2 source read directly; cipherpost's existing wrappers cover all needs
- Architecture: HIGH — D-P8-01..16 are comprehensive; research found no architectural surprises
- Existing code anchors: HIGH — every file:line cross-checked
- JCS field-ordering: HIGH — `serde_canonical_json` is RFC 8785 (lexicographic, deterministic)
- Wire-budget overhead: MEDIUM — derivation-based prediction; Phase 9 measures empirically
- PIN-07 exit-code reading: MEDIUM — Open Risk #1 calls for confirmation

**Research date:** 2026-04-25
**Valid until:** 2026-05-25 (30 days; stable v1.0 codebase + v1.1 phases 5-7 shipped)

## RESEARCH COMPLETE
