# Architecture Research — Cipherpost v1.1 Integration Points

**Domain:** Self-sovereign cryptographic-material handoff (Rust CLI)
**Researched:** 2026-04-23
**Scope:** v1.1 feature integration into the existing walking-skeleton architecture
**Confidence:** HIGH — based on direct inspection of `src/` (payload.rs, flow.rs, cli.rs,
  main.rs, transport.rs, error.rs) and all `.planning/` context documents.

---

## Existing Architecture (Reference Baseline)

The v1.0 walking skeleton ships as a single flat-module Rust crate:

```
src/
  cli.rs         — clap derive tree; subcommand structs; passphrase field declarations
  crypto.rs      — Ed25519↔X25519 derivation; age_encrypt/decrypt; jcs_serialize; HKDF helpers
  error.rs       — thiserror Error enum; exit_code(); user_message()
  flow.rs        — run_send, run_receive, run_receipts; Prompter trait; TtyPrompter; state ledger
  identity.rs    — load/generate/resolve_passphrase; key_dir(); signing_seed()
  lib.rs         — pub mod re-exports; PROTOCOL_VERSION; DHT_LABEL_OUTER; DHT_LABEL_RECEIPT_PREFIX
  main.rs        — fn dispatch(); clap parse → flow calls; passphrase wiring
  payload.rs     — Envelope; Material enum; base64_std serde module; strip_control_chars
  receipt.rs     — Receipt; ReceiptSignable; sign_receipt; verify_receipt; nonce_hex
  record.rs      — OuterRecord; OuterRecordSignable; sign_record; verify_record; share_ref_from_bytes
  transport.rs   — Transport trait; DhtTransport; MockTransport (cfg-gated)
```

Key invariants that every v1.1 change must respect:

- JCS via `serde_canonical_json 1.0.0` — no raw serde_json byte serialization on signable structs
- HKDF info strings: `cipherpost/v1/<context>` — never empty, never None; enumeration test enforces
- `ed25519-dalek =3.0.0-pre.5` exact pin — pkarr 5.0.4 depends on `^3.0.0-pre.1`; no stable 3.x
- No `#[derive(Debug)]` on secret-holding structs; manual redacting Debug implementations
- All sig-verify variants share identical user-facing Display (error-oracle hygiene, exit 3)
- Dual-signature ordering: outer PKARR verify FIRST, then age-decrypt, then inner Ed25519 verify
- Receipt published only after full verification + typed-z32 acceptance (tamper-zero invariant)
- `chacha20poly1305` reachable only via `age`; no direct calls
- No async runtime at the cipherpost layer; `pkarr::ClientBlocking` throughout
- `serial_test = "3"` + `#[serial]` on any test mutating `CIPHERPOST_HOME` or other process env

---

## 1. Typed Material Integration (Phases 6 and 7)

### 1.1 What the Acceptance Banner Shows (and When)

The acceptance screen is rendered at `flow.rs:run_receive` step 8 — AFTER age-decrypt (step 6)
and Envelope parse (step 7), but BEFORE any payload field reaches stdout/stderr. The fields
surfaced in the banner come from two sources:

- From `OuterRecord` (outer-verified, pre-decrypt): `record.pubkey` (sender z32), `record.share_ref`,
  `record.created_at`, `record.ttl_seconds`. These are available from step 3 onward.
- From `Envelope` (inner-verified, post-decrypt): `envelope.purpose`, `envelope.material`.
  `material_type_string(&envelope.material)` and `material_bytes.len()` appear in the banner.

This means the material-type label and size on the acceptance screen are always post-decrypt.
There is no outer metadata field that leaks the payload type before decrypt — the DHT sees only
the encrypted blob. This is correct behavior; do not add a plaintext `material_type` field to
`OuterRecord` or `OuterRecordSignable`.

### 1.2 Wire Representation for New Variants

`Material` is a `#[serde(tag = "type", rename_all = "snake_case")]` enum. The existing
`GenericSecret` wire shape is:

```json
{"type": "generic_secret", "bytes": "<base64-STANDARD-padded>"}
```

The `bytes` field uses the `base64_std` serde-with module defined in `payload.rs` (standard
padding, not URL-safe no-pad). New variants should follow this same shape for consistency with
the JCS field-ordering invariant:

```json
{"bytes": "<base64-STANDARD-padded>", "type": "x509_cert"}
{"bytes": "<base64-STANDARD-padded>", "type": "pgp_key"}
{"bytes": "<base64-STANDARD-padded>", "type": "ssh_key"}
```

JCS sorts fields alphabetically, so `"bytes"` precedes `"type"` in all four variants. This
ordering is already correct for `GenericSecret` and is inherited automatically by the serde
tag enum.

Concrete variant shapes:

```rust
// in src/payload.rs — modify Material enum in place

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Material {
    GenericSecret {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,
    },
    X509Cert {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,   // raw DER bytes (not PEM) — consistent with GenericSecret
    },
    PgpKey {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,   // binary OpenPGP packet (single transferable key, not armored)
    },
    SshKey {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,   // OpenSSH private key format bytes (the file content)
    },
}
```

**Why raw bytes (not parsed/pre-validated)?** Keeping all variants as `{ bytes: Vec<u8> }`
is the correct choice because:

1. Consistency with `GenericSecret` — the protocol transports an opaque byte payload; parsing
   is a receiver-side concern, not a wire-format concern.
2. JCS stability — a struct with a single `bytes` field has a trivially stable canonical form.
   Adding parsed fields (e.g., `subject: String` for X.509) would require those to be in the
   signable too, creating both a larger JCS byte string and a new fixture to pin.
3. 64 KB plaintext cap still applies — enforced in `run_send` via `enforce_plaintext_cap` before
   `Material` is constructed. No per-variant cap change needed.

**What bytes go in each variant:**

- `X509Cert.bytes`: DER-encoded X.509 certificate. If the sender has PEM, they decode before
  sending. The `size_bytes` shown on the acceptance banner is the DER length.
- `PgpKey.bytes`: Binary OpenPGP transferable key packet (single key, not a keyring). RFC 4880
  binary format. Armored ASCII representation is the sender's concern pre-send.
- `SshKey.bytes`: The raw content of an OpenSSH private key file (the PEM-like `-----BEGIN
  OPENSSH PRIVATE KEY-----` format including headers and trailing newline). This is what
  `~/.ssh/id_ed25519` contains — send it as-is.

### 1.3 Accessor Methods

Replace the current `as_generic_secret_bytes` with per-variant accessors. The current
`NotImplemented { phase: 2 }` error code is no longer appropriate once variants are live.
Add a generic `as_bytes()` accessor that works across all variants:

```rust
// New in src/payload.rs

impl Material {
    /// Return the raw bytes for any variant. Used post-accept in run_receive.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Material::GenericSecret { bytes }
            | Material::X509Cert { bytes }
            | Material::PgpKey { bytes }
            | Material::SshKey { bytes } => bytes.as_slice(),
        }
    }

    /// Retain for backwards compatibility with existing run_receive call site.
    /// Delegates to as_bytes() for GenericSecret; all other variants are now real.
    pub fn as_generic_secret_bytes(&self) -> Result<&[u8], Error> {
        Ok(self.as_bytes())
    }
}
```

The `flow.rs:run_receive` step 8 currently calls `envelope.material.as_generic_secret_bytes()?`.
That call site can remain unchanged if `as_generic_secret_bytes` is updated to delegate to
`as_bytes()` — no change required in `flow.rs` for basic typed-material receive.

### 1.4 Debug Redaction

The manual `Debug` impl in `payload.rs` must be extended to redact bytes for all variants:

```rust
impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Material::GenericSecret { bytes } =>
                write!(f, "GenericSecret([REDACTED {} bytes])", bytes.len()),
            Material::X509Cert { bytes } =>
                write!(f, "X509Cert([REDACTED {} bytes])", bytes.len()),
            Material::PgpKey { bytes } =>
                write!(f, "PgpKey([REDACTED {} bytes])", bytes.len()),
            Material::SshKey { bytes } =>
                write!(f, "SshKey([REDACTED {} bytes])", bytes.len()),
        }
    }
}
```

The leak-scan test `tests/debug_leak_scan.rs` enumerates keyed structs; it must be extended
to cover all four variants.

### 1.5 Error Handling for Malformed Material

When the sender sends `X509Cert` bytes that are malformed DER, the receiver should NOT
validate at receive time — the protocol transports bytes, not parsed objects. Any validation
is an application-layer concern on top of the decrypted bytes. Do not add a new error variant
for malformed cert/key data.

The only new error scenario is if a sender using a future protocol extension sends an unknown
variant name (e.g., `"type": "hardware_token"`) to a v1.1 receiver. `serde` with
`deny_unknown_fields` would reject it; without that attribute, it falls through to
`SignatureCanonicalMismatch` because `Envelope::from_jcs_bytes` will fail to parse. This is
the correct behavior — unknown variants are treated as a signature-class error (exit 3).

### 1.6 JCS Fixture Requirements

Each new variant needs a committed JCS fixture for byte-level determinism enforcement.
Follow the existing pattern: one `.bin` fixture per signable struct containing the canonical
bytes for a test-vector `Envelope`. The existing `tests/fixtures/outer_record_signable.bin`
and `tests/fixtures/receipt_signable.bin` are the model.

New fixtures needed (one per new Material variant):

```
tests/fixtures/envelope_x509cert.bin   — JCS bytes of Envelope { material: X509Cert { bytes: [0xde, 0xad, 0xbe, 0xef] }, ... }
tests/fixtures/envelope_pgpkey.bin
tests/fixtures/envelope_sshkey.bin
```

A property test (extend the existing `envelope_jcs_round_trip_is_byte_identical` test) should
assert byte-for-byte identity for each variant.

### 1.7 Protocol Version Impact

Adding fields to existing variants = protocol break. Adding new variant names = wire-additive
(old receivers see an unknown tag and reject — correct behavior). Because the new variants
(`X509Cert`, `PgpKey`, `SshKey`) are already reserved in the serde enum definition (they
serialize as `{"type":"x509_cert"}` with no fields currently), adding a `bytes` field to them
IS a breaking change to the wire format for senders/receivers running different versions.

Resolution: `protocol_version` stays at `1`. The SPEC.md note "Reserved variants will produce
`Error::NotImplemented`" is updated to define the field shape. Old receivers (v1.0) that
receive a typed envelope will fail at `Envelope::from_jcs_bytes` (deserialization error →
`SignatureCanonicalMismatch`, exit 3). This is acceptable behavior and documented in SPEC.md.
A true protocol bump is only needed when changing existing signed-field semantics.

### 1.8 Build Order: Phase 6 Before 7

Phase 6 (`X509Cert`) establishes the pattern:

1. Add `{ bytes: Vec<u8> }` to `X509Cert` variant in `payload.rs`
2. Update `Debug` impl and `as_bytes()` accessor
3. Add `material_file` type hint for X.509 in `cli.rs` (optional — the CLI is bytes-in, bytes-out)
4. Update `material_type_string` in `flow.rs` to return descriptive strings
5. Commit new JCS fixture
6. Extend property tests

Phase 7 (`PgpKey` + `SshKey`) repeats the same steps for two variants. The work is mechanical
once the X.509 pattern is established. Phase 7 does not depend on Phase 6 being complete to
start — but starting Phase 7 before Phase 6 is fully tested wastes effort if the fixture
approach needs adjustment. Recommended: complete Phase 6 end-to-end (including fixture commit
and test pass) before starting Phase 7.

**Phase 8 (`--pin`/`--burn`) does NOT require typed materials.** It can be layered on
`GenericSecret` alone. Phase ordering: 5 → 6 → 7 → 8 is natural, but 5 → 8 is also valid
if pin/burn is higher priority than typed payloads.

---

## 2. `--pin` and `--burn` Flags (Phase 8)

### 2.1 Where These Modes Come From

cclink's `src/crypto/mod.rs` has `pin_*` functions (referenced in the v1.0 ARCHITECTURE.md).
cclink uses PIN as a second factor: the sender derives a PIN-keyed encryption layer on top of
the age ciphertext, and the receiver must supply the PIN to unwrap it. The HKDF info strings
in cclink use `cclink-pin-v1`; cipherpost has already claimed the domain-separated namespace
`cipherpost/v1/<context>` for all HKDF calls. The fork-and-diverge approach applies: copy the
pin KDF logic from cclink, substitute the HKDF info string prefix.

`--burn` is a state-ledger / protocol-semantic feature, not a crypto primitive. It has no
cclink equivalent — it is a cipherpost-specific addition.

### 2.2 `--pin` Flow Design

**Where the PIN goes:** The PIN is a second recipient factor layered on top of age encryption.
It is NOT a post-decrypt gate (that would not improve security — the material would already be
in RAM). Instead:

1. **Sender side (`run_send`):** After age-encrypts the JCS Envelope bytes, the sender
   applies a PIN-keyed symmetric wrap using HKDF-derived key from the PIN:
   ```
   pin_key = HKDF(salt=random_16_bytes, ikm=pin_bytes, info="cipherpost/v1/pin_wrap", len=32)
   pin_ciphertext = XChaCha20Poly1305(key=pin_key, plaintext=age_ciphertext, nonce=random_24_bytes)
   blob = base64(salt || nonce || pin_ciphertext)
   ```
   The `OuterRecord.blob` then contains the PIN-wrapped ciphertext rather than the raw age
   ciphertext. `pin_required: true` must be signaled to the receiver.

2. **Receiver side (`run_receive`):** Before age-decrypt (step 6), the receiver detects
   `pin_required = true`, prompts for the PIN (via `Prompter` trait — add a
   `prompt_for_pin()` method or a separate `PinPrompter` trait), unwraps the outer layer,
   then proceeds to age-decrypt the inner ciphertext.

3. **`Envelope` or `OuterRecord`?** The `pin_required` signal must appear in `OuterRecord`
   (outer-signed, pre-decrypt readable) so the receiver knows to prompt for a PIN BEFORE
   attempting age-decrypt. Putting it only in `Envelope` (inner, post-decrypt) would create
   a circular dependency: the receiver needs to decrypt to learn the PIN is required, but needs
   the PIN to decrypt. Therefore: add `pin_required: bool` to both `OuterRecord` and
   `OuterRecordSignable`. Default `false` (serde `default`).

4. **Protocol version impact:** Adding a new field with `#[serde(default)]` to
   `OuterRecordSignable` is additive for deserialization (old senders omit the field, old
   receivers deserialize it as `false`). However, because `OuterRecordSignable` is the
   signed struct, any new field changes the JCS bytes — a v1.1 sender with `pin_required:
   false` produces different JCS bytes than a v1.0 sender (which omitted the field). This
   is a wire-format-breaking change. Resolution: bump `protocol_version` to 2 when shipping
   `--pin` support, or add `pin_required` as a field only when `true` via
   `#[serde(skip_serializing_if = "is_false")]`. The skip-if-false approach preserves
   byte-identity with v1.0 for non-pin shares. This is the recommended approach.

5. **`pin_salt` and `pin_nonce`:** The PIN KDF salt and AEAD nonce used for the pin-wrap layer
   must be stored so the receiver can unwrap. Options:
   - Store in `OuterRecord` as `pin_salt: Option<String>` and `pin_nonce: Option<String>` (with
     `skip_serializing_if = "Option::is_none"`).
   - Prepend salt+nonce to the blob (self-contained).
   
   Self-contained blob is simpler (no new `OuterRecord` fields for salt/nonce) and avoids
   expanding the wire budget. Recommended: `blob = base64(16-byte-salt || 24-byte-nonce ||
   pin_ciphertext)` when `pin_required = true`. The receiver strips the prefix before passing
   to the pin_unwrap function.

6. **Non-interactive PIN:** The PIN is a second factor on top of the passphrase. It follows
   the same contract as the passphrase: argv-inline rejected; env var `CIPHERPOST_PIN` or
   `--pin-file <path>` or `--pin-fd <fd>` or TTY prompt. This is consistent with the
   passphrase contract in SPEC.md §7. The `resolve_passphrase` function in `identity.rs`
   can be reused with a different env var name and confirmation behavior.

### 2.3 `--burn` Flow Design

**What burn means:** A share marked `burn_after_read = true` is consumed on first successful
acceptance. The sender trusts the recipient will not re-receive (and the receipt proves they
received it once). The mechanism is ledger + wire-flag based, not cryptographic deletion
(DHT data cannot be actively deleted).

**Wire representation:** Add `burn_after_read: bool` to `Envelope` (inner-signed, post-decrypt).
This is correct because:
- The burn semantic is about the recipient's local behavior after decrypt, not something the
  transport layer needs to know.
- Putting it in `Envelope` (not `OuterRecord`) means DHT observers cannot see that a share is
  burn-marked — consistent with "ciphertext only on the wire."
- The `#[serde(skip_serializing_if = "is_false")]` pattern keeps JCS bytes identical to v1.0
  for non-burn shares.

**Receiver behavior change:** In `run_receive`, after step 12 (sentinel + ledger write), if
`envelope.burn_after_read == true`:
- Mark the sentinel file with a `burned` attribute (or write a separate `burned/<share_ref>`
  file in the state dir).
- The state-ledger entry gets `burned_at: Some(iso)`.
- On a second `cipherpost receive` invocation for the same `share_ref`, the sentinel check
  (step 1) would normally short-circuit with "already accepted." For burned shares, the
  message should instead say "already accepted and burned."
- No cryptographic erasure of the DHT record is possible (DHT is append-only with TTL); the
  burn semantic is purely client-side.

**Interaction with state ledger:** The `check_already_accepted` function returns
`Some(accepted_at_string)` for previously seen share_refs. For burn-marked shares, the sentinel
exists and the check still short-circuits. No change to the idempotency mechanism is needed;
the `burned_at` field in the ledger is informational.

**Does `--burn` require typed payloads?** No. It can ship on `GenericSecret` alone. The
Envelope field `burn_after_read` is independent of `material`. Recommended: ship Phase 8
against `GenericSecret` (or all implemented variants at that point), not dependent on Phase 6/7.

### 2.4 Files Modified for `--pin` and `--burn`

- **new: `src/pin.rs`** — PIN KDF functions: `pin_wrap(plaintext, pin_bytes) -> (salt, nonce, ciphertext)`
  and `pin_unwrap(blob_prefix, pin_bytes) -> Result<Vec<u8>>`. HKDF info: `cipherpost/v1/pin_wrap`.
  This isolates the PIN crypto from the age crypto layer in `crypto.rs`.

- **modified: `src/payload.rs`** — Add `burn_after_read: bool` field to `Envelope` with
  `#[serde(default, skip_serializing_if = "std::ops::Not::not")]`.

- **modified: `src/record.rs`** — Add `pin_required: bool` to both `OuterRecord` and
  `OuterRecordSignable` with `#[serde(default, skip_serializing_if = "std::ops::Not::not")]`.

- **modified: `src/flow.rs`** — `run_send`: branch on `--pin` flag to call `pin.rs` functions
  and set `pin_required = true` in the record. `run_receive`: detect `record.pin_required`,
  prompt for PIN via Prompter, call `pin_unwrap` before age-decrypt. Add `burn_after_read`
  check in step 12.

- **modified: `src/cli.rs`** — Add `pin_file: Option<PathBuf>`, `pin_fd: Option<i32>`,
  `burn: bool` to `Send` subcommand struct. Add `pin_file: Option<PathBuf>`, `pin_fd:
  Option<i32>` to `Receive` subcommand struct.

- **modified: `src/main.rs`** — Thread `pin_file`, `pin_fd`, `burn` through dispatch for
  `Send` and `Receive`.

- **modified: `src/flow.rs` (Prompter trait)** — Add `prompt_for_pin` method to `Prompter`
  trait, or create a separate `PinPrompter` trait. `TtyPrompter` implements both.

---

## 3. Non-Interactive Passphrase UX (Phase 5)

### 3.1 Current State

`identity.rs` already has `resolve_passphrase(inline: Option<&str>, env_var: Option<&str>,
file: Option<&Path>, fd: Option<i32>, confirm_on_tty: bool) -> Result<Zeroizing<String>>`.

`identity generate` and `identity show` in `main.rs` already pass all four sources through.

`send` and `receive` in `main.rs` today call:
```rust
cipherpost::identity::resolve_passphrase(None, Some("CIPHERPOST_PASSPHRASE"), None, None, false)
```

The `cli.rs` `Send` and `Receive` subcommand structs have no `passphrase_file` or
`passphrase_fd` fields.

### 3.2 Changes Required

**Modified: `src/cli.rs`** — Add to both `Send` and `Receive` subcommand structs:
```rust
#[arg(long, value_name = "PATH")]
passphrase_file: Option<std::path::PathBuf>,
#[arg(long, value_name = "N")]
passphrase_fd: Option<i32>,
/// REJECTED — see identity generate --help
#[arg(long, value_name = "VALUE", hide = true)]
passphrase: Option<String>,
```

**Modified: `src/main.rs`** — In `Command::Send` and `Command::Receive` dispatch branches,
destructure the new fields and thread through `resolve_passphrase`:
```rust
// Was:
let pw = cipherpost::identity::resolve_passphrase(None, Some("CIPHERPOST_PASSPHRASE"), None, None, false)?;
// Becomes:
let pw = cipherpost::identity::resolve_passphrase(
    passphrase.as_deref(),
    Some("CIPHERPOST_PASSPHRASE"),
    passphrase_file.as_deref(),
    passphrase_fd,
    false,
)?;
```

**No changes to `flow.rs`** — `run_send` and `run_receive` receive an already-unlocked
`Identity`; passphrase resolution happens before `flow.rs` is entered.

**No changes to `identity.rs`** — `resolve_passphrase` already supports all four sources.

### 3.3 Precedence Order

The existing `resolve_passphrase` function implements the SPEC §7.1 priority: argv-inline
(rejected with `PassphraseInvalidInput`) > env var > file > fd > TTY prompt. This precedence
is already tested for `identity generate/show`; the same tests cover `send`/`receive` once
the wiring is in place.

### 3.4 Test Serialization

Any test that drives `send` or `receive` via `CIPHERPOST_PASSPHRASE` env already uses
`#[serial]`. No new `serial_test` requirements — the file/fd paths don't mutate global
process state the way env var tests do.

### 3.5 Architectural Assessment

This is purely mechanical plumbing. There is no architectural question here — the seam
(`resolve_passphrase`) was designed for this from the start. The only risk is forgetting to
add the `passphrase` (hidden, rejected) field to `Send`/`Receive`, which would allow argv
inline to silently succeed in those subcommands even though `identity generate/show` reject it.
The hidden-field + runtime-rejection pattern must be replicated exactly.

---

## 4. Real-DHT Test Harness (Phase 9)

### 4.1 Test Architecture Recommendation

**Recommended structure:** `tests/real_dht_e2e.rs` behind the `real-dht` feature flag:

```toml
# Cargo.toml
[features]
mock = []        # existing
real-dht = []    # new — gates tests/real_dht_e2e.rs
```

Do NOT use a separate workspace test crate — the single-crate structure is locked and there
is no second consumer to justify a workspace split. Do NOT use `std::process::Command` binary
spawning — it requires a built binary in `target/` and is fragile in CI. Use the library API
(`run_send`, `run_receive`) with `DhtTransport` directly.

```rust
// tests/real_dht_e2e.rs

#![cfg(feature = "real-dht")]

#[test]
#[ignore]  // run explicitly: cargo test --features real-dht -- real_dht --ignored
fn real_dht_cross_identity_round_trip() {
    // Two random keypairs (not fixed-seed — we're testing the live DHT)
    let sender_kp = pkarr::Keypair::random();
    let recipient_kp = pkarr::Keypair::random();
    // ...
    let transport = cipherpost::transport::DhtTransport::with_default_timeout().unwrap();
    // run_send → run_receive → verify receipt
}
```

`#[ignore]` is correct here: it prevents the test from running in `cargo test --features
real-dht` by default (requires `-- --ignored` flag). This matches the pattern used for
`tests/spec_test_vectors.rs` (already `#[ignore]`).

### 4.2 Propagation Latency Assertions

The Mainline DHT has a p50 lookup latency of ~1 minute with a long tail. The test MUST:
- Retry resolve with a backoff loop rather than a fixed sleep.
- Set a maximum retry duration (e.g., 120 seconds) before failing.
- Log progress to stderr (not panic on partial progress) — use `eprintln!` for diagnostics.
- Fail the test if the share is not resolvable within the timeout. Do not downgrade to a
  warning — a timed-out real-DHT test is a real failure, not a flake to ignore.

The backoff can reuse `DhtTransport::with_default_timeout()` (30 seconds per request) with
multiple attempts. The test should not hard-code `thread::sleep(Duration::from_secs(60))` —
that is fragile and wastes CI time on fast DHT resolution.

### 4.3 Concurrent-Racer PKARR `cas` Test

The `publish_receipt` uses resolve-merge-republish with `cas` (compare-and-swap). The
concurrent-racer test validates that two concurrent receipt publications on the same recipient
key do not corrupt each other.

**Where it lives:** The concurrent-racer test does NOT require a real DHT. It can be a
`MockTransport` test that spawns two threads, each calling `transport.publish_receipt()` for
different `share_ref_hex` values on the same keypair, and asserts that after both complete,
both receipts are resolvable.

```rust
// tests/concurrent_receipt_racer.rs — NO feature flag needed; uses MockTransport
// Already gated by `#[cfg(feature = "mock")]` via MockTransport dependency

#[test]
#[cfg(feature = "mock")]
fn concurrent_receipt_publish_both_survive() {
    use std::sync::Arc;
    let transport = Arc::new(cipherpost::transport::MockTransport::new());
    let kp = pkarr::Keypair::random();
    let t1 = { let t = Arc::clone(&transport); let k = kp.clone(); /* publish receipt A */ };
    let t2 = { let t = Arc::clone(&transport); let k = kp.clone(); /* publish receipt B */ };
    t1.join().unwrap(); t2.join().unwrap();
    let receipts = transport.resolve_all_cprcpt(&kp.public_key().to_z32()).unwrap();
    assert_eq!(receipts.len(), 2);
}
```

This test does NOT belong in `tests/real_dht_e2e.rs`. Keep the concurrent-racer test in a
separate file that runs under `cargo test --features mock` in CI, not gated behind `real-dht`.

**Summary:** Two separate files, two separate concerns:
- `tests/concurrent_receipt_racer.rs` — `#[cfg(feature = "mock")]`, runs in CI
- `tests/real_dht_e2e.rs` — `#[cfg(feature = "real-dht")]` + `#[ignore]`, manual only

---

## 5. Traceability-Drift Elimination (Phase 5)

### 5.1 The Problem

REQUIREMENTS.md has two sources of truth: body checkboxes (the actual requirements text with
`- [ ]` / `- [x]`) and a traceability table (rows of `| REQ-ID | Description | Status |
Phase |`). In v1.0 these drifted to 29 out-of-sync rows. The table rows retained "Pending"
while the body checkboxes were checked.

### 5.2 Recommended Option: Drop the Table, Body Checkboxes Are Canonical

Option A (drop the table) is the correct choice for a solo-builder GSD workflow.

Rationale:
- The body checkboxes are what the developer updates during execution. The table is a
  secondary artifact that requires a manual sync step which is reliably skipped under
  time pressure.
- Phase `VERIFICATION.md` files already own the cross-reference role: each VERIFICATION.md
  maps acceptance criteria to test names and confirmed-pass status. The table in
  REQUIREMENTS.md is redundant with that.
- Option B (generate from checkboxes at commit time) adds CI complexity (a script that parses
  REQUIREMENTS.md, extracts checkboxes, rebuilds the table, and fails if the table is stale).
  That script would need to understand the GSD checkbox format and the table format — fragile.
- Option C (template/macro) requires a custom preprocessing step that is more complex to set
  up than the value it adds.

**Concrete change:** In REQUIREMENTS.md for v1.1, omit the traceability table section
entirely. Add a comment at the top: `<!-- Traceability: body checkboxes are canonical.
Phase verification reports at .planning/milestones/v1.1-*/VERIFICATION.md. -->` The
roadmapper and plan-phase agent should not attempt to maintain a parallel table.

This is compatible with the GSD `.planning/` workflow: `ROADMAP.md` maps requirements to
phases via the REQ-ID references in the phase description text, not via a separate table.
`VERIFICATION.md` files are the per-phase audit trail.

---

## 6. DHT Label Audit (Phase 5)

### 6.1 Current Labels

```
_cipherpost              — outgoing share (OuterRecord JSON TXT under sender's PKARR key)
_cprcpt-<share_ref_hex>  — receipt (Receipt JSON TXT under recipient's PKARR key)
```

### 6.2 Audit Findings

The current labels are adequate and should be kept without change. Rationale:

**`_cipherpost`:**
- Clearly branded, no ambiguity about what DNS namespace owns it.
- Alternative `_cpshare` is shorter but loses the branding clarity. The label appears only
  in code (`DHT_LABEL_OUTER` constant in `lib.rs`) and in SPEC.md — it is not user-facing.
- Changing it requires updating `lib.rs`, `transport.rs`, `SPEC.md`, any documentation that
  references the label, AND invalidates all existing shares on the DHT (old receivers resolve
  under `_cipherpost`; new publishers writing `_cpshare` would be invisible to old receivers).
  This is a hard protocol break requiring a version bump.

**`_cprcpt-<share_ref_hex>`:**
- The prefix is short, branded, and structurally distinct from `_cipherpost`.
- The label encodes the `share_ref_hex` as a suffix, which is the correct design (allows
  `resolve_all_cprcpt` to enumerate by prefix scan).
- Alternative `_cprec-` saves two characters with no other benefit.
- Same protocol-break concern as above.

**Recommendation:** Keep `_cipherpost` and `_cprcpt-<share_ref_hex>` unchanged. Document in
SPEC.md that these are stable wire identifiers that will not change in v1.x. The label audit
deliverable for Phase 5 is this written confirmation that no change is warranted, not an
actual label change.

---

## 7. Integration Points by File (Roadmapper Reference)

| Phase | File | Status | Change |
|-------|------|--------|--------|
| 5 | `src/cli.rs` | modified | Add `passphrase_file`, `passphrase_fd`, hidden `passphrase` to `Send` and `Receive` |
| 5 | `src/main.rs` | modified | Thread new passphrase fields through `resolve_passphrase` calls in Send/Receive dispatch |
| 5 | `SPEC.md` | modified | Bless `serde_canonical_json 1.0.0`, `pkarr 5.0.4`, 550 B budget; confirm DHT labels stable |
| 5 | `.planning/REQUIREMENTS.md` | new | Author fresh v1.1 requirements without traceability table |
| 6 | `src/payload.rs` | modified | Add `{ bytes: Vec<u8> }` field to `X509Cert` variant; update `Debug`, `as_bytes()` |
| 6 | `src/flow.rs` | modified | Update `material_type_string` for X.509 banner label |
| 6 | `tests/fixtures/envelope_x509cert.bin` | new | JCS fixture for X.509 envelope |
| 6 | `tests/` (extend existing) | modified | Property test covering X509Cert round-trip determinism |
| 7 | `src/payload.rs` | modified | Add `{ bytes: Vec<u8> }` to `PgpKey` and `SshKey`; extend `Debug` |
| 7 | `tests/fixtures/envelope_pgpkey.bin` | new | JCS fixture |
| 7 | `tests/fixtures/envelope_sshkey.bin` | new | JCS fixture |
| 8 | `src/pin.rs` | new | `pin_wrap`, `pin_unwrap`; HKDF info `cipherpost/v1/pin_wrap` |
| 8 | `src/payload.rs` | modified | Add `burn_after_read: bool` to `Envelope` (skip_serializing_if false) |
| 8 | `src/record.rs` | modified | Add `pin_required: bool` to `OuterRecord` + `OuterRecordSignable` (skip_serializing_if false) |
| 8 | `src/flow.rs` | modified | `run_send`: pin-wrap branch; `run_receive`: pin-unwrap before age-decrypt; burn-after-read in step 12 |
| 8 | `src/cli.rs` | modified | Add `pin_file`, `pin_fd`, `burn` to `Send`; `pin_file`, `pin_fd` to `Receive` |
| 8 | `src/main.rs` | modified | Thread pin/burn flags through dispatch |
| 9 | `tests/real_dht_e2e.rs` | new | `#[cfg(feature = "real-dht")]` + `#[ignore]`; cross-identity round trip |
| 9 | `tests/concurrent_receipt_racer.rs` | new | `#[cfg(feature = "mock")]`; concurrent publish_receipt race |
| 9 | `Cargo.toml` | modified | Add `real-dht = []` feature |

---

## 8. Recommended Build Order

```
Phase 5 (automation E2E)
  └── Mechanical — no new modules. Unblocks scripted CI recipes.
      Dependency: none (independent of Phases 6-9)

Phase 6 (X509Cert)
  └── Establishes typed-material pattern.
      Dependency: Phase 5 (clean baseline before pattern work)

Phase 7 (PgpKey + SshKey)
  └── Applies Phase 6 pattern twice.
      Dependency: Phase 6 pattern established and fixtures committed

Phase 8 (--pin and --burn)
  └── New src/pin.rs; Envelope + OuterRecord field additions.
      Dependency: Can layer on GenericSecret alone — does NOT require Phases 6 or 7.
      Can run concurrently with Phases 6+7 if multiple builders; otherwise after Phase 7.

Phase 9 (Real-DHT + racer test)
  └── concurrent_receipt_racer.rs: depends only on MockTransport (available now)
      real_dht_e2e.rs: depends on a working binary — any phase can precede it
      Recommended: run Phase 9 last as a release-gate after all v1.1 features ship
```

**Parallelism note for solo builder:** The concurrent-racer test (`tests/concurrent_receipt_racer.rs`)
can be written in Phase 5 or any other phase since it uses only existing MockTransport
infrastructure. There is no reason to defer it to Phase 9 except for organizational
convenience. The Phase 9 entry gate is the `real_dht_e2e.rs` test, which requires a
functionally complete binary.

---

## 9. Load-Bearing Lock-In Checklist (Per v1.1 Change)

Every change in v1.1 must pass this checklist before merge:

| Lock-In | Phase 5 | Phase 6 | Phase 7 | Phase 8 | Phase 9 |
|---------|---------|---------|---------|---------|---------|
| JCS via serde_canonical_json, not raw serde_json | n/a | new fixtures commit | new fixtures commit | new Envelope + OuterRecord fields use skip_serializing_if | n/a |
| HKDF info strings `cipherpost/v1/<context>` | n/a | n/a | n/a | pin_wrap info string added to enumeration test | n/a |
| No `#[derive(Debug)]` on secret holders | n/a | extend Debug for new variants | extend Debug | PinKey holder uses manual Debug | n/a |
| Error-oracle: all sig variants share identical Display | n/a | verify NotImplemented not in error surface | same | new error variants (if any) must not distinguish sig paths | n/a |
| `chacha20poly1305` only via `age` | n/a | n/a | n/a | pin_wrap uses XChaCha20Poly1305 — must go through `age` primitives or the `chacha20poly1305` crate? Clarify before Phase 8 starts. | n/a |
| No argv-inline passphrase | passphrase hidden field added to Send/Receive | n/a | n/a | pin has same contract; hidden pin field in Send/Receive | n/a |
| serial_test on env-mutating tests | new env tests (passphrase_file tests may use temp files, not env) | n/a | n/a | CIPHERPOST_PIN env var tests need `#[serial]` | n/a |
| Outer sig before decrypt before inner sig | n/a | n/a | n/a | pin-unwrap AFTER outer sig verify, BEFORE age-decrypt (insert at step 6 in run_receive) | n/a |
| No async runtime at cipherpost layer | n/a | n/a | n/a | n/a | real_dht_e2e uses DhtTransport (blocking) |

**Phase 8 open question flagged:** The `chacha20poly1305` usage in `pin_wrap` must go through
`age` primitives if possible, or explicitly justify a direct crate call in the code comments.
The existing constraint is "no direct `chacha20poly1305` calls anywhere in `src/`." If the
PIN wrap layer uses age's streaming interface with a synthetic age stanza, the constraint is
satisfied. If it requires direct AEAD calls, the constraint must be revisited and the CLAUDE.md
updated with the rationale before implementation.

---

## Sources

- Direct source inspection: `src/payload.rs`, `src/flow.rs`, `src/cli.rs`, `src/main.rs`,
  `src/transport.rs`, `src/error.rs` (all read 2026-04-23)
- `.planning/PROJECT.md` — v1.1 scope, constraints, key decisions
- `.planning/MILESTONES.md` — v1.0 shipped state and deferred items
- `CLAUDE.md` — load-bearing lock-in list
- `SPEC.md` §3–§5 — wire format, send/receive flow steps, passphrase contract
- `.planning/research/ARCHITECTURE.md` (v1.0) — cclink lineage and original module design
- Confidence: HIGH — all claims grounded in inspected source files, not inference
