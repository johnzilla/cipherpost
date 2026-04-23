# Phase 2: Send, receive, and explicit acceptance - Pattern Map

**Mapped:** 2026-04-21
**Files analyzed:** 6 regions (2 module-body replacements + 4 significant additions/extensions) + 8 new integration tests
**Analogs found:** 14 / 14

Phase 2 creates zero new modules. It fills in the bodies of two existing placeholder files (`src/payload.rs`, `src/flow.rs`), replaces two stub match-arms in `src/main.rs::dispatch`, extends two constant/enum modules in place (`src/crypto.rs::hkdf_infos`, `src/error.rs`), and adds eight integration tests in `tests/`. No new directories. Flat-module convention (Phase 1 D-01 / D-02) preserved.

## File Classification

| New / Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---------------------|------|-----------|----------------|---------------|
| `src/payload.rs` (body replacement: Envelope + Material + encode/decode + strip_purpose + enforce_size_cap) | model / schema | transform (serde round-trip) | `src/record.rs` | exact — same JCS-signable-struct pattern |
| `src/flow.rs::run_send` (new function) | service / orchestrator | pipeline (plaintext → Envelope → JCS → age → OuterRecord → publish) | `src/identity.rs::generate` + `src/transport.rs::DhtTransport::publish` | role-match (orchestration + pipeline) |
| `src/flow.rs::run_receive` (new function) | service / orchestrator | pipeline (URI → resolve → verify → TTL → decrypt → Envelope → accept → write → ledger) | `src/transport.rs::DhtTransport::resolve` + `src/identity.rs::resolve_passphrase` | role-match |
| `src/flow.rs::parse_share_uri` / `format_share_uri` (new URI parsing — may fold into payload.rs or stay in flow.rs) | utility | transform (string → (z32, hex)) | `src/record.rs::verify_record` step 1 (`pkarr::PublicKey::try_from(&str)`) | partial — only the z32 parse step is analogous |
| `src/flow.rs` state-ledger helpers (`write_sentinel`, `append_ledger`, `state_dir`) | utility / file-I/O | file-write | `src/identity.rs::generate` (atomic write, mode 0600, CIPHERPOST_HOME env resolution) | exact |
| `src/crypto.rs::hkdf_infos` — add `SHARE_SENDER`, `SHARE_RECIPIENT`, `INNER_PAYLOAD` | config / constants | N/A | `src/crypto.rs::hkdf_infos::IDENTITY_KEK` | exact — same module, same pattern |
| `src/error.rs` — add `ShareRefMismatch`, `WireBudgetExceeded { encoded, budget, plaintext }`, `InvalidShareUri` variants + `exit_code` arms | config / errors | N/A | `src/error.rs::Error::PayloadTooLarge` + `exit_code` match | exact |
| `src/main.rs::dispatch::Send {..}` and `Receive {..}` arms (stub replacement) | controller | request-response (CLI → flow) | `src/main.rs::dispatch::IdentityCmd::Show` | exact — same passphrase-resolve-then-call idiom |
| `tests/phase2_self_round_trip.rs` | test | integration | `tests/mock_transport_roundtrip.rs` | exact |
| `tests/phase2_share_round_trip.rs` | test | integration | `tests/mock_transport_roundtrip.rs` | exact |
| `tests/phase2_tamper_aborts_before_decrypt.rs` | test | integration (negative) | `tests/mock_transport_roundtrip.rs` + `src/record.rs::tests::tampered_blob_fails_verify` | exact |
| `tests/phase2_expired_share.rs` | test | integration (negative) | `tests/mock_transport_roundtrip.rs` | role-match |
| `tests/phase2_size_cap.rs` | test | integration (negative) | `tests/signed_packet_budget.rs` | exact |
| `tests/phase2_envelope_round_trip.rs` + `tests/fixtures/envelope_jcs_generic_secret.bin` | test | fixture | `tests/outer_record_canonical_form.rs` + `tests/fixtures/outer_record_signable.bin` | exact — same regenerate_fixture idiom |
| `tests/phase2_acceptance_screen.rs` / `tests/phase2_declined.rs` / `tests/phase2_idempotent_re_receive.rs` | test | integration with CLI subprocess | `tests/identity_passphrase_argv_rejected.rs` (assert_cmd) + `tests/identity_phc_header.rs` (serial + TempDir) | role-match (combo) |
| `tests/phase2_stderr_no_secrets.rs` | test | fuzz / stderr scan | `tests/debug_leak_scan.rs` + `tests/hkdf_info_enumeration.rs` (src walker) | role-match |
| `tests/phase2_cli_help_examples.rs` | test | integration (CLI help scrape) | `tests/identity_passphrase_argv_rejected.rs` (assert_cmd) | role-match |

---

## Pattern Assignments

### 1. `src/payload.rs` body — Envelope struct + Material enum + encode/decode + strip/size-cap helpers

**Analog:** `src/record.rs` (entire file)

This is the closest existing analog in the codebase — same role (JCS-signed/encoded wire struct), same data flow (serde round-trip with canonical-JSON determinism guarantee), same module style (flat file at `src/` root).

**Derive set + alphabetical-field-order pattern** (`src/record.rs:26-36`):
```rust
/// Signed form — what goes in a DNS TXT record under label `_cipherpost`.
/// Fields are in alphabetical order (belt-and-suspenders for JCS stability).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OuterRecord {
    pub blob: String,
    pub created_at: i64,
    pub protocol_version: u16,
    pub pubkey: String,
    pub recipient: Option<String>,
    pub share_ref: String,
    pub signature: String,
    pub ttl_seconds: u64,
}
```

Apply verbatim to the `Envelope` struct (D-WIRE-02): fields `{created_at, material, protocol_version, purpose}` in alphabetical declaration order, same derive set (including `Debug` — **note:** `Envelope` holds `Material::GenericSecret { bytes }` which IS secret material; the planner MUST verify this does not violate the `debug_leak_scan.rs` invariant — either gate `Debug` behind a manual impl that redacts `material`, or rely on the fact that an `Envelope` is never held in a type whose Debug escapes user-facing output. The safer choice is a manual `Debug` impl that prints `Envelope { purpose, protocol_version, created_at, material: [REDACTED <type>] }`. See `src/identity.rs:56-61` for the manual-Debug-on-secret-holder template.)

**JCS-serialize helper pattern** (`src/record.rs:84-91` and `src/crypto.rs:367-374`):
```rust
/// Serialize any Serialize value to canonical JSON per RFC 8785 (JCS).
fn jcs(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value
        .serialize(&mut ser)
        .map_err(|e| Error::Config(format!("jcs: {}", e)))?;
    Ok(buf)
}
```

**Reuse opportunity:** `src/crypto.rs::jcs_serialize` is already public. Call it directly from `payload::encode_envelope` — do NOT duplicate the helper a third time. `record.rs` has its own local `jcs` for module-independence reasons (see its doc comment); Phase 2 has no such constraint and can depend on `crypto::jcs_serialize`.

**Material enum with serde tag (no direct Phase-1 analog for enums)** — D-WIRE-03 shape:
```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Material {
    GenericSecret {
        #[serde(with = "base64_std_codec")]
        bytes: Vec<u8>,
    },
    X509Cert,
    PgpKey,
    SshKey,
}
```

**Base64 codec pattern** (`src/record.rs:15, 103, 123`):
```rust
use base64::Engine;
// encode
base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
// decode
base64::engine::general_purpose::STANDARD.decode(&record.signature)
    .map_err(|_| Error::SignatureInner)?;
```

Apply to `GenericSecret.bytes` serde via a `base64_std_codec` module with `serialize`/`deserialize` fns. D-WIRE-04 bans `URL_SAFE_NO_PAD`. There is no existing serde-with helper for base64 in the codebase — Phase 2 is creating the first one. Keep it inline in `payload.rs`.

**NotImplemented variant for non-`generic_secret` variants** (`src/error.rs:57-58`):
```rust
#[error("not implemented yet (phase {phase})")]
NotImplemented { phase: u8 },
```

Each non-implemented Material variant's encode/decode paths return `Err(Error::NotImplemented { phase: 11 })` (or pick a sentinel; D-WIRE-03 just says "stub"). This variant already exists in `error.rs:57` — no Error.rs change needed for this.

**Size-cap enforcement pattern** — closest analog is `src/transport.rs::MockTransport::publish` lines 242-247:
```rust
if rdata.len() > 1000 {
    return Err(Error::Config(format!(
        "MockTransport: record too large for PKARR packet: {} > 1000 bytes",
        rdata.len()
    )));
}
```

Apply the same "compare length, return structured error" pattern to `enforce_plaintext_cap` — but use the dedicated `Error::PayloadTooLarge { actual, limit }` (Phase 1 error.rs:52), NOT `Error::Config`:
```rust
const PLAINTEXT_CAP: usize = 65536;
pub fn enforce_plaintext_cap(len: usize) -> Result<(), Error> {
    if len > PLAINTEXT_CAP {
        return Err(Error::PayloadTooLarge { actual: len, limit: PLAINTEXT_CAP });
    }
    Ok(())
}
```

**Note:** D-PS-03 requires the error string to contain both `65537` and `65536`. The current `Error::PayloadTooLarge`'s Display is just `"payload exceeds 64 KB limit"` (no numbers). Planner must either (a) augment the Display to include `actual` and `limit` (breaking the test that asserts `"payload exceeds 64 KB limit"` verbatim — check for this in Phase 1 tests first; a Grep shows no such test), or (b) add a new message format. Simplest: change the `#[error("...")]` to `#[error("payload exceeds 64 KB limit: actual={actual}, cap={limit}")]`.

**Purpose-strip helper** — pure std, no Phase-1 analog. Inline in payload.rs:
```rust
pub fn strip_control_chars(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())  // covers C0 + DEL; C1 via is_control in Unicode
        .collect()
}
```
Watch: `char::is_control()` covers C0, DEL, and C1 per Unicode `Cc` category. D-WIRE-05 specifies exactly this range. Verify with a unit test that `\u{007F}` and `\u{0080}` and `\u{001F}` all strip.

**Delta from record.rs:**
- `Envelope` is encrypted (age'd) before going on the wire; `OuterRecord` is cleartext on the wire. So `Envelope` does NOT need its own signature field — D-WIRE-01 makes the outer inner-sig cover the blob (which is age(jcs(Envelope))).
- `Material` enum introduces a new pattern (serde-tag); `record.rs` has no enums.
- Size-cap helpers and purpose-strip are new functional utilities with no cognate in record.rs.

**Reuse opportunity (direct function calls):**
- `crypto::jcs_serialize(&envelope)` — don't re-implement
- `Error::PayloadTooLarge`, `Error::NotImplemented`, `Error::Config` — existing variants
- `base64::engine::general_purpose::STANDARD` — the crate-standard codec (D-WIRE-04)

---

### 2. `src/flow.rs::run_send` — send orchestration

**Analog:** `src/identity.rs::generate` (lines 96-134) for the orchestration style + `src/transport.rs::DhtTransport::publish` (lines 88-107) for the age-build-and-sign shape.

**Orchestration style from `identity::generate`** (lines 96-134):
```rust
pub fn generate(pw: &SecretBox<String>) -> Result<Identity, Error> {
    let dir = key_dir();
    fs::create_dir_all(&dir).map_err(Error::Io)?;
    let mut dir_perms = fs::metadata(&dir).map_err(Error::Io)?.permissions();
    dir_perms.set_mode(0o700);
    fs::set_permissions(&dir, dir_perms).map_err(Error::Io)?;

    let keypair = pkarr::Keypair::random();
    let seed = Zeroizing::new(keypair.secret_key());

    let blob = crypto::encrypt_key_envelope(&seed, pw)?;
    // ... atomic write ...
    Ok(Identity { keypair })
}
```

Pattern to copy: linear `?`-chained sequence of primitive calls, each returning `Result<T, Error>`; `Zeroizing` wrapper on sensitive intermediates; `fs::set_permissions` with explicit mode after creation.

**age-encrypt call site from crypto.rs:130-140** (this IS the direct function run_send calls):
```rust
pub fn age_encrypt(plaintext: &[u8], recipient: &x25519::Recipient) -> Result<Vec<u8>, Error> {
    let encryptor = age::Encryptor::with_recipients(
        std::iter::once(recipient as &dyn age::Recipient),
    )
    .map_err(str_err)?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).map_err(str_err)?;
    writer.write_all(plaintext).map_err(Error::Io)?;
    writer.finish().map_err(str_err)?;
    Ok(out)
}
```

**Reuse — do NOT duplicate:** call `crypto::age_encrypt(&jcs_bytes, &recipient)` directly.

**Recipient derivation for share mode** — new composition, but each primitive exists:
```rust
// Parse z32 pubkey → VerifyingKey bytes
let pk = pkarr::PublicKey::try_from(recipient_z32)
    .map_err(|_| Error::Config("invalid recipient pubkey".into()))?;
let ed_bytes: [u8; 32] = pk.as_bytes().clone();
// Pattern from src/record.rs:117-119 (different purpose, same call)

// Ed25519 → X25519 conversion — src/crypto.rs:64-69
let x25519_bytes = cipherpost::crypto::ed25519_to_x25519_public(&ed_bytes)?;

// Bytes → age Recipient — src/crypto.rs:110-114
let recipient = cipherpost::crypto::recipient_from_x25519_bytes(&x25519_bytes)?;
```

For **self** mode: use `identity.public_key_bytes()` (src/identity.rs:65-67) as `ed_bytes` — no recipient to parse.

**Sign + assemble OuterRecord pattern** — `tests/mock_transport_roundtrip.rs:11-35` is the textbook example:
```rust
let share_ref = share_ref_from_bytes(blob.as_bytes(), created_at);
let signable = OuterRecordSignable {
    blob: blob.clone(),
    created_at,
    protocol_version: PROTOCOL_VERSION,
    pubkey: kp.public_key().to_z32(),
    recipient: None,
    share_ref: share_ref.clone(),
    ttl_seconds: 86400,
};
let signature = sign_record(&signable, kp).unwrap();
OuterRecord {
    blob: signable.blob,
    created_at: signable.created_at,
    protocol_version: signable.protocol_version,
    pubkey: signable.pubkey,
    recipient: signable.recipient,
    share_ref: signable.share_ref,
    signature,
    ttl_seconds: signable.ttl_seconds,
}
```

Copy verbatim into run_send; the only differences are `blob` is now `base64::STANDARD.encode(&age_ciphertext)`, `recipient` may be `Some(z32)` for share mode, and `ttl_seconds` comes from `--ttl` flag (default 86400).

**Wire-budget pre-check** — extracted from `tests/signed_packet_budget.rs:50-74`:
```rust
let name: pkarr::dns::Name<'_> = "_cipherpost".try_into().unwrap();
let txt: pkarr::dns::rdata::TXT<'_> = json.as_str().try_into().unwrap();
let packet = pkarr::SignedPacket::builder()
    .txt(name, txt, 300)
    .sign(&kp)
    .unwrap();
let dns_packet_len = packet.encoded_packet().len();
assert!(dns_packet_len <= 1000, ...);
```

In run_send (post-sign, pre-publish, per ARCHITECTURE.md step 15):
```rust
let json = serde_json::to_string(&record).map_err(|e| Error::Transport(Box::new(e)))?;
let name: pkarr::dns::Name<'_> = crate::DHT_LABEL_OUTER.try_into()
    .map_err(|_| Error::Config("dns name encode".into()))?;
let txt: pkarr::dns::rdata::TXT<'_> = json.as_str().try_into()
    .map_err(|_| Error::Config("txt encode".into()))?;
let packet = pkarr::SignedPacket::builder()
    .txt(name, txt, 300)
    .sign(&keypair)
    .map_err(|e| Error::Transport(Box::new(e)))?;
let encoded = packet.encoded_packet().len();
if encoded > 1000 {
    return Err(Error::WireBudgetExceeded { encoded, budget: 1000, plaintext: jcs_bytes.len() });
}
```

The `DhtTransport::publish` method already builds its own SignedPacket (src/transport.rs:99-102), so this is a separate pre-flight build. That is intentional per D-PS-01: two error paths, one client-side. Planner should document this defensive duplication.

**URI output format** — no analog. Add constant to `src/lib.rs`:
```rust
pub const SHARE_URI_SCHEME: &str = "cipherpost://";
```
Then `println!("cipherpost://{}/{}", identity.z32_pubkey(), share_ref);`

**Delta from generate:** run_send publishes to DHT (not to disk), takes inputs from CLI args (not a passphrase SecretBox alone), and emits a URI to stdout (generate emits fingerprints to stderr).

**Reuse opportunity:**
- `identity::load` (to get Identity after passphrase)
- `crypto::ed25519_to_x25519_public` (src/crypto.rs:64) for share-mode recipient
- `crypto::ed25519_to_x25519_secret` (src/crypto.rs:76) for self-mode recipient (via `to_public()`)
- `crypto::recipient_from_x25519_bytes` (src/crypto.rs:110)
- `crypto::age_encrypt` (src/crypto.rs:130)
- `crypto::jcs_serialize` (src/crypto.rs:367)
- `record::share_ref_from_bytes` (src/record.rs:68)
- `record::sign_record` (src/record.rs:96)
- `identity.z32_pubkey()` + `identity.public_key_bytes()` (src/identity.rs:65-71)
- `Transport::publish` (src/transport.rs:34)

---

### 3. `src/flow.rs::run_receive` — receive orchestration

**Analog:** `src/transport.rs::DhtTransport::resolve` (lines 109-126) for the resolve-and-verify opening; `src/identity.rs::resolve_passphrase` (lines 243-294) for the dialoguer TTY prompt idiom; `src/identity.rs::generate` for the state-write tail.

**Resolve-and-verify opening from `DhtTransport::resolve`** (lines 109-126):
```rust
fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error> {
    eprintln!("Resolving from DHT..."); // TRANS-05
    let pk = pkarr::PublicKey::try_from(pubkey_z32).map_err(|_| Error::NotFound)?;
    let packet = self
        .client
        .resolve_most_recent(&pk)
        .ok_or(Error::NotFound)?;

    for rr in packet.resource_records(DHT_LABEL_OUTER) {
        if let Some(rdata_str) = extract_txt_string(&rr.rdata) {
            let record: OuterRecord = serde_json::from_str(&rdata_str)
                .map_err(|_| Error::SignatureCanonicalMismatch)?;
            verify_record(&record)?; // inner sig check
            return Ok(record);
        }
    }
    Err(Error::NotFound)
}
```

**Critical:** `run_receive` does NOT re-implement resolve — it calls `transport.resolve(&sender_z32)?` and gets a pre-verified `OuterRecord` back. Verify-before-decrypt invariant (D-RECV-01, Pitfall #2) is thus enforced at the Transport trait boundary. run_receive's job is steps 4-11 (URI-match, TTL, decrypt, envelope, accept, write, ledger).

**TTL check** — no direct Phase 1 analog (Phase 1 has no time-check). Use `std::time::SystemTime`:
```rust
use std::time::{SystemTime, UNIX_EPOCH};
let now = SystemTime::now().duration_since(UNIX_EPOCH)
    .map_err(|_| Error::Config("system clock before epoch".into()))?
    .as_secs() as i64;
let expires_at = record.created_at + record.ttl_seconds as i64;
if now >= expires_at {
    return Err(Error::Expired);
}
```
D-15 hygiene: don't leak `now` / `expires_at` into the Display; `Error::Expired` already has its unified Display.

**age-decrypt into Zeroizing** — `src/crypto.rs::age_decrypt` (lines 145-156) already returns `Zeroizing<Vec<u8>>`:
```rust
pub fn age_decrypt(
    ciphertext: &[u8],
    identity: &x25519::Identity,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|_| Error::DecryptFailed)?;
    let mut plaintext = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| Error::DecryptFailed)?;
    std::io::copy(&mut reader, &mut plaintext).map_err(|_| Error::DecryptFailed)?;
    Ok(Zeroizing::new(plaintext))
}
```

Reuse directly. The returned `Zeroizing<Vec<u8>>` is the JCS bytes of `Envelope` — parse with `serde_json::from_slice(&jcs_bytes)?` (map serde errors to `Error::SignatureCanonicalMismatch` per D-RECV-01 step 7 — treat envelope-parse failure as sig failure, exit 3).

**Recipient derivation for decrypt (ed25519 → x25519 identity)** — exactly the same pair of calls as in `src/crypto.rs::encrypt_key_envelope_impl` lines 261-268 but using the loaded identity's secret:
```rust
// run_receive: derive own X25519 Identity from loaded Identity's secret
let seed = Zeroizing::new(identity.secret_key_bytes_for_leak_test());
// ^^ TODO: expose a non-"_for_leak_test" accessor; see src/identity.rs:82-84 — Phase 2 should add
//    `fn secret_seed(&self) -> Zeroizing<[u8; 32]>` as a proper API. Keep `..._for_leak_test` gated
//    or rename but preserve the Zeroizing return.
let x25519_secret = cipherpost::crypto::ed25519_to_x25519_secret(&seed);
let age_identity = cipherpost::crypto::identity_from_x25519_bytes(&x25519_secret)?;
let plaintext = cipherpost::crypto::age_decrypt(&ciphertext, &age_identity)?;
```

Confirm with the planner: Phase 2 should add a clean public accessor. The current name (`secret_key_bytes_for_leak_test`) is intentionally unpleasant — src/identity.rs:75-84 documents it as test-only. Decision: add `pub fn signing_seed(&self) -> Zeroizing<[u8; 32]>` returning `Zeroizing::new(self.keypair.secret_key())` and keep it in the Identity impl block. This is an additive change, not a breaking one.

**TTY check** — std::io::IsTerminal (stable since 1.70, available; Cargo.toml rust-version = 1.85):
```rust
use std::io::IsTerminal;
if !std::io::stderr().is_terminal() || !std::io::stdin().is_terminal() {
    return Err(Error::Config(
        "acceptance requires a TTY; non-interactive receive is deferred".into()
    ));
}
```
No existing analog (Phase 1's passphrase prompt uses `dialoguer::Password::interact()` which fails internally on non-TTY — mapped to `Error::Config` at src/identity.rs:289-292). Pattern to follow: explicit pre-check (D-ACCEPT-03 requires check BEFORE decrypt), not trust dialoguer's internal handling.

**Acceptance prompt via dialoguer** — analog is `identity::resolve_passphrase` step 5 (lines 289-293):
```rust
let pw = dialoguer::Password::new()
    .with_prompt("Cipherpost passphrase")
    .interact()
    .map_err(|_| Error::Config("TTY not available for passphrase prompt".into()))?;
```

For acceptance use `dialoguer::Input::<String>::new()` (not `Password` — user PASTES the z32; echoing it is fine and useful for visual verification against the banner):
```rust
let typed: String = dialoguer::Input::<String>::new()
    .with_prompt("> ")
    .interact_text()
    .map_err(|_| Error::Config("TTY not available for acceptance prompt".into()))?;
if typed.trim() != record.pubkey.as_str() {
    return Err(Error::Declined);
}
```
D-ACCEPT-01: `trim()` is explicitly allowed; no `--yes`; no default.

**State ledger and sentinel — exact template from `identity::generate`** (lines 97-131):
```rust
let dir = key_dir();
fs::create_dir_all(&dir).map_err(Error::Io)?;
let mut dir_perms = fs::metadata(&dir).map_err(Error::Io)?.permissions();
dir_perms.set_mode(0o700);
fs::set_permissions(&dir, dir_perms).map_err(Error::Io)?;

// Atomic write: tmp → rename → re-apply 0600
let mut file = fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(&tmp)
    .map_err(Error::Io)?;
file.write_all(&blob).map_err(Error::Io)?;
file.sync_all().map_err(Error::Io)?;
```

Phase 2 applies this exactly for:
- `state_dir()` — add next to `key_dir()` in `src/identity.rs` (or keep in flow.rs; planner's call). Consults `CIPHERPOST_HOME` first, falls back to `~/.cipherpost/state/`. Mirrors src/identity.rs:29-37 verbatim, substituting `.cipherpost/state` for `.cipherpost`.
- Sentinel: `state_dir().join("accepted").join(share_ref_hex)` — create with `OpenOptions::new().create_new(true).mode(0o600).open(&path)` (research recommends `create_new(true)` for TOCTOU safety; see RESEARCH.md Alternatives Considered table row `fs2`).
- Ledger: `state_dir().join("accepted.jsonl")` — open with `OpenOptions::new().append(true).create(true).mode(0o600)` and `writeln!(file, "{}", jsonl_line)`.

**CIPHERPOST_HOME override pattern** — src/identity.rs:29-37:
```rust
pub fn key_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("CIPHERPOST_HOME") {
        PathBuf::from(custom)
    } else {
        dirs::home_dir()
            .expect("no home directory found")
            .join(".cipherpost")
    }
}
```
Copy to `state_dir()` — same env var, same fallback base, append `.join("state")`. D-STATE-04 explicitly names CIPHERPOST_HOME as the override.

**Delta from generate:** ledger is append-only (not create_new), sentinel is empty (not a blob), multi-file (two paths: accepted.jsonl + accepted/<hex>).

**Reuse opportunity:**
- `Transport::resolve` (does outer + inner sig verify; D-RECV-01 steps 2+3)
- `record::verify_record` (called inside resolve — no direct call from run_receive)
- `crypto::age_decrypt` (src/crypto.rs:145)
- `crypto::identity_from_x25519_bytes` (src/crypto.rs:120)
- `crypto::ed25519_to_x25519_secret` (src/crypto.rs:76)
- `identity::show_fingerprints` (src/identity.rs:172) — for the acceptance-screen OpenSSH fingerprint row
- `Identity::z32_pubkey` + (new) `Identity::signing_seed` accessors
- `dialoguer::Input` (new crate usage — already in deps)

---

### 4. URI parse/format (`src/flow.rs` or new `src/uri.rs` — planner discretion; D-01/D-02 prefer flat)

**Analog:** `src/record.rs::verify_record` step 1 (lines 117-118) — only the z32 parsing step is cognate.

**z32 parse pattern** (src/record.rs:117-118):
```rust
let pk = pkarr::PublicKey::try_from(record.pubkey.as_str())
    .map_err(|_| Error::SignatureInner)?;
```

**Use in URI parsing:**
```rust
pub fn parse_share_uri(uri: &str) -> Result<(String, String), Error> {
    // D-URI-03: strict form only
    let rest = uri.strip_prefix(crate::SHARE_URI_SCHEME)
        .ok_or(Error::InvalidShareUri)?;
    let (z32, share_ref_hex) = rest.split_once('/')
        .ok_or(Error::InvalidShareUri)?;
    // Validate z32 by round-tripping through pkarr::PublicKey
    pkarr::PublicKey::try_from(z32).map_err(|_| Error::InvalidShareUri)?;
    // Validate share_ref: exactly 32 lowercase hex chars
    if share_ref_hex.len() != crate::record::SHARE_REF_HEX_LEN
        || !share_ref_hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err(Error::InvalidShareUri);
    }
    Ok((z32.to_string(), share_ref_hex.to_string()))
}
```

D-URI-03 mandates rejecting bare z32 — the `strip_prefix` fail path covers this. Add a specialized error message for "looks like bare z32" (optional polish): if `uri.len() == 52` and `uri` has no `/`, attach hint text per D-URI-03: `expected cipherpost:// URI, got bare pubkey; use the URI that send printed`.

**Delta:** no existing URI parser. Pattern is std string ops only, plus the pkarr z32 validation.

**Reuse opportunity:**
- `pkarr::PublicKey::try_from` (validation)
- `record::SHARE_REF_HEX_LEN` (src/record.rs:22 — `pub const SHARE_REF_HEX_LEN: usize = SHARE_REF_BYTES * 2;`)

---

### 5. `src/crypto.rs::hkdf_infos` — add three constants

**Analog:** Same module, existing constant (`src/crypto.rs:41-49`):
```rust
pub mod hkdf_infos {
    /// Key-encryption key for the identity file's CIPHPOSK envelope.
    ///
    /// INVARIANT: this string appears in `tests/hkdf_info_enumeration.rs` scan.
    /// Never use a different string for the identity KEK derivation.
    pub const IDENTITY_KEK: &str = "cipherpost/v1/identity-kek";
    // Phase 2 adds: SHARE_SENDER, SHARE_RECIPIENT, INNER_PAYLOAD
    // Phase 3 adds: RECEIPT_SIGN
}
```

The inline comment on line 47 is a TODO for exactly this extension. Phase 2 replaces that line with the three consts:

```rust
pub const SHARE_SENDER:    &str = "cipherpost/v1/share-sender";
pub const SHARE_RECIPIENT: &str = "cipherpost/v1/share-recipient";
pub const INNER_PAYLOAD:   &str = "cipherpost/v1/inner-payload";
```

**CRITICAL pattern invariant enforced by `tests/hkdf_info_enumeration.rs`:** that test walks `src/**/*.rs` and greps for every `"cipherpost/v1/..."` string literal, asserting all are (a) prefixed correctly, (b) distinct, (c) non-empty context. If Phase 2 adds a new literal anywhere (e.g., `format!("cipherpost/v1/share-sender")` in flow.rs), the enum test passes only if it's ALSO in `hkdf_infos`. **Planner directive:** ALL three constants MUST be added to `hkdf_infos` BEFORE any code in `flow.rs` or `payload.rs` references them. RESEARCH.md §Pattern 3 explicitly notes Phase 2 may not actually call HKDF (age handles internal derivation); these constants are namespace reservations. That's fine — the enumeration test filter `cap.len() > prefix.len()` excludes the bare prefix constant but WILL count a reserved-but-unused constant. No `#[allow(dead_code)]` needed (constants are pub).

**Delta:** purely additive — three new const lines inside the existing module.

**Reuse opportunity:** None for Phase 2 beyond adding the constants; they may be unreferenced in code bodies. That's intentional.

---

### 6. `src/error.rs` — three new variants

**Analog:** Same file, existing variants + exit_code match. `src/error.rs:10-68` + `exit_code` lines 72-85.

**thiserror variant pattern:**
```rust
#[error("wrong passphrase or identity decryption failed")]
DecryptFailed,

#[error("payload exceeds 64 KB limit")]
PayloadTooLarge { actual: usize, limit: usize },

#[error("not implemented yet (phase {phase})")]
NotImplemented { phase: u8 },
```

**New variants to add** (D-ERR-01):
```rust
#[error("share_ref in URI does not match resolved record")]
ShareRefMismatch,

#[error("share too large for PKARR packet: encoded={encoded} bytes, budget={budget} bytes (plaintext was {plaintext} bytes)")]
WireBudgetExceeded { encoded: usize, budget: usize, plaintext: usize },

#[error("invalid share URI")]
InvalidShareUri,
```

**exit_code arm extension** (src/error.rs:72-85) — new variants all map to the default `_ => 1` arm, so **no explicit match arms needed** (they fall through naturally):
```rust
pub fn exit_code(err: &Error) -> i32 {
    match err {
        Error::Expired => 2,
        Error::SignatureOuter
        | Error::SignatureInner
        | Error::SignatureCanonicalMismatch
        | Error::SignatureTampered => 3,
        Error::DecryptFailed | Error::IdentityPermissions | Error::PassphraseInvalidInput => 4,
        Error::NotFound => 5,
        Error::Network => 6,
        Error::Declined => 7,
        _ => 1,  // ShareRefMismatch, WireBudgetExceeded, InvalidShareUri all land here
    }
}
```
D-ERR-01 specifies exit 1 for all three new variants. Planner can either add explicit arms for auditability (recommended) or rely on the catchall (tighter diff). Either works.

**D-16 invariant preserved:** none of the new variants carry `"signature verification failed"` Display text — they are NOT sig failures. D-16 unified Display remains confined to `SignatureOuter | SignatureInner | SignatureCanonicalMismatch | SignatureTampered`.

**Also bump `Error::PayloadTooLarge`'s Display** per D-PS-03 (see Pattern #1 note above):
```rust
#[error("payload exceeds 64 KB limit: actual={actual}, cap={limit}")]
PayloadTooLarge { actual: usize, limit: usize },
```

**Delta:** purely additive + one Display-text edit.

**Reuse opportunity:** None — this IS the central enum.

---

### 7. `src/main.rs::dispatch` — Send and Receive arm bodies

**Analog:** `src/main.rs::dispatch::IdentityCmd::Show` (lines 53-65):
```rust
IdentityCmd::Show { passphrase_file, passphrase_fd, passphrase } => {
    let pw = cipherpost::identity::resolve_passphrase(
        passphrase.as_deref(),
        Some("CIPHERPOST_PASSPHRASE"),
        passphrase_file.as_deref(),
        passphrase_fd,
    )?;
    let id = cipherpost::identity::load(pw.as_secret())?;
    let (openssh, z32) = cipherpost::identity::show_fingerprints(&id);
    println!("{}", openssh);
    println!("{}", z32);
    Ok(())
}
```

**Template for Send arm:**
```rust
Command::Send { self_, share, purpose, material_file, ttl } => {
    // Resolve passphrase — same idiom as IdentityCmd::Show, but Send has no
    // per-command passphrase flags; pulls from env/prompt only.
    let pw = cipherpost::identity::resolve_passphrase(None, Some("CIPHERPOST_PASSPHRASE"), None, None)?;
    let id = cipherpost::identity::load(pw.as_secret())?;
    // ... resolve send mode (self_ / share) ...
    // ... call flow::run_send (DhtTransport by default; MockTransport only via --features mock in tests)
    cipherpost::flow::run_send(&id, mode, purpose, material_source, ttl_secs)?;
    Ok(())
}
```

**Note on passphrase flags:** Phase 1's `cli.rs::Send {..}` does NOT expose passphrase flags. That's a CLI design decision already locked. Send pulls passphrase only from env or TTY. Receive likewise. Planner may add optional `--passphrase-file`/`--passphrase-fd` flags to Send/Receive if needed, but since cli.rs is locked (Phase 1 D-11), they would have to be added via a separate amendment — flag that to the user if it comes up.

**Template for Receive arm:**
```rust
Command::Receive { share, output, dht_timeout } => {
    let share = share.ok_or_else(|| Error::Config("share URI required".into()))?;
    // D-RECV-02: sentinel-first, pre-passphrase even
    if let Some(prior) = cipherpost::flow::check_already_accepted(&share)? {
        eprintln!("already accepted at {}; not re-decrypting", prior.accepted_at);
        return Ok(());
    }
    let pw = cipherpost::identity::resolve_passphrase(None, Some("CIPHERPOST_PASSPHRASE"), None, None)?;
    let id = cipherpost::identity::load(pw.as_secret())?;
    cipherpost::flow::run_receive(&id, &share, output.as_deref(), dht_timeout)?;
    Ok(())
}
```

**Error propagation:** Uses `?` because `dispatch` returns `anyhow::Result<()>` and `Error: From<...>`. The downcast-to-Error in `main::run` (src/main.rs:21-30) already selects the right exit code. D-15 hygiene: no `{:?}` anywhere in the arm body.

**Delta from Identity::Show:** Send/Receive have no fingerprint-print tail; they delegate to flow which handles its own stdout/stderr split.

**Reuse opportunity:**
- `identity::resolve_passphrase` — same four-arg call
- `identity::load` — same usage
- `flow::run_send`, `flow::run_receive`, `flow::check_already_accepted` — new symbols Phase 2 defines

---

### 8. Integration tests — analog map

Each new `tests/phase2_*.rs` file inherits idioms from existing Phase 1 tests. Cargo.toml patterns to copy (from Cargo.toml:46-57):

**`[[test]]` block with `required-features` for mock-using tests:**
```toml
[[test]]
name = "mock_transport_roundtrip"
path = "tests/mock_transport_roundtrip.rs"
required-features = ["mock"]
```

All Phase 2 tests that exercise `run_send`/`run_receive` end-to-end via MockTransport must have `required-features = ["mock"]` in their `[[test]]` block. Tests that only exercise `payload::encode_envelope` round-tripping don't need the feature gate. The planner must enumerate these Cargo.toml additions explicitly.

**Serial + TempDir + CIPHERPOST_HOME pattern** — from `tests/identity_phc_header.rs:14-18` and `tests/debug_leak_scan.rs:13-18`:
```rust
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn my_phase2_test() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    // ... test body ...
}
```

`#[serial]` is REQUIRED on every test that sets `CIPHERPOST_HOME` (Cargo.toml:68-72 is explicit about this — `serial_test` was added in Phase 1 Plan 03 to serialize env-var-mutating tests).

**Per-test analog map:**

| New Phase 2 Test | Closest Analog(s) | Pattern to Reuse |
|------------------|-------------------|------------------|
| `phase2_self_round_trip.rs` | `mock_transport_roundtrip.rs` (entire file) | `MockTransport::new()`, `make_record()` helper → rewrite as `make_send_inputs()`. Test `run_send` produces a URI, then `run_receive(URI)` recovers the plaintext. Requires `required-features = ["mock"]`. |
| `phase2_share_round_trip.rs` | `mock_transport_roundtrip.rs` | Two identities (sender + recipient); `run_send` with `share=recipient.z32`; `run_receive` on a third identity fails with `DecryptFailed`; recipient succeeds. |
| `phase2_tamper_aborts_before_decrypt.rs` | `src/record.rs::tests::tampered_blob_fails_verify` (src/record.rs:196-224) + `mock_transport_roundtrip.rs` | Call `run_send`, reach into the MockTransport store (needs an `insert_raw` test helper on MockTransport, or use `publish_receipt`-style back-door), tamper the blob, call `run_receive`, assert `Error::SignatureInner` (display `"signature verification failed"`, exit 3). |
| `phase2_expired_share.rs` | `tests/mock_transport_roundtrip.rs` | Synthesize an OuterRecord with `created_at = 0, ttl_seconds = 1`, publish via MockTransport, `run_receive` → `Error::Expired` (exit 2). No time-mocking required. |
| `phase2_acceptance_screen.rs` | `tests/identity_passphrase_argv_rejected.rs` (assert_cmd subprocess) + `tests/identity_phc_header.rs` (TempDir + serial) | `assert_cmd::Command::cargo_bin("cipherpost")` with stdin piped (the z32 confirmation) via `Command::write_stdin()`. **BLOCKER:** `run_receive`'s D-ACCEPT-03 TTY check will fail inside `assert_cmd`-spawned subprocess because stdin is a pipe, not a TTY. Two mitigations: (a) test-only `CIPHERPOST_SKIP_TTY_CHECK=1` env override (ugly but pragmatic — document as test-only in src code); (b) a PTY-allocating crate like `expectrl` or `rexpect`. RESEARCH.md flags this as an open question. Planner must pick one — recommend (a) gated behind `#[cfg(any(test, feature = "mock"))]` so it can't be set in production builds. |
| `phase2_declined.rs` | same as acceptance_screen | Subprocess sends a WRONG z32 on stdin, assert exit code 7 + stderr contains "declined" (or whatever `Error::Declined` Display is). |
| `phase2_idempotent_re_receive.rs` | `tests/identity_phc_header.rs` (TempDir) + `tests/mock_transport_roundtrip.rs` | Two-step: first `run_receive` succeeds and writes sentinel; second `run_receive` returns immediately with "already accepted at X" on stderr, no network call (use MockTransport with a publish counter test helper to assert network was not hit). |
| `phase2_size_cap.rs` | `tests/signed_packet_budget.rs` | Feed 65537-byte plaintext to `run_send`, assert `Error::PayloadTooLarge { actual: 65537, limit: 65536 }`, assert Display contains both `65537` and `65536`. Separately, synthesize a ~600-byte plaintext that produces a >1000-byte wire packet, assert `Error::WireBudgetExceeded`. |
| `phase2_envelope_round_trip.rs` + `tests/fixtures/envelope_jcs_generic_secret.bin` | `tests/outer_record_canonical_form.rs` (entire file) + `tests/fixtures/outer_record_signable.bin` | Copy `outer_record_canonical_form.rs` verbatim, substitute `OuterRecordSignable` → `Envelope`, substitute fixture filename. Keep the `#[ignore] fn regenerate_fixture` idiom (src/fixtures.rs pattern). The committed `.bin` is the cross-impl protocol fingerprint. |
| `phase2_material_variants_unimplemented.rs` | `tests/hkdf_info_enumeration.rs` (src walker) — only for the file-walk idiom; this test is small | Instantiate `Material::X509Cert`, call `encode`, assert `Err(Error::NotImplemented { phase: _ })`. |
| `phase2_cli_help_examples.rs` | `tests/identity_passphrase_argv_rejected.rs` (assert_cmd subprocess) | `cargo run -- send --help`; `cargo run -- receive --help`; assert `stdout.contains("EXAMPLES")`. Already-passing: these EXAMPLES are baked into `cli.rs` long_about strings (src/cli.rs:35-37, 61-63). |
| `phase2_stderr_no_secrets.rs` | `tests/debug_leak_scan.rs` (byte-window scan) + `tests/identity_passphrase_argv_rejected.rs` (subprocess) | Run binary with bad URI / wrong passphrase / tampered record; scan stderr for hex-encoded chunks of the secret key bytes (8-byte windows, same as debug_leak_scan.rs:31-39); assert none present. Also scan for `age::`, `pkarr::`, `Os {` substrings per D-15. |

**Fixture-commit idiom (critical for envelope_round_trip test)** — `tests/outer_record_canonical_form.rs:37-44`:
```rust
#[test]
#[ignore] // run with --ignored to regenerate; commit result
fn regenerate_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {}", FIXTURE_PATH);
}
```

Copy this pattern 1:1 for `phase2_envelope_round_trip.rs`. The `#[ignore]` + `--ignored` + manual-commit workflow is load-bearing: it prevents CI from silently regenerating the fixture and erasing a protocol-breaking change.

---

## Shared Patterns

### Pattern A: Every new signable struct uses JCS via `crypto::jcs_serialize`

**Source:** `src/crypto.rs:367-374` (public helper), `src/record.rs:84-91` (local copy w/ dependency-avoidance rationale)

**Apply to:** `Envelope` serialization in `payload.rs`; any fixture bytes in tests.

```rust
let bytes = cipherpost::crypto::jcs_serialize(&envelope)?;
```

**Invariant:** `tests/crypto_no_floats_in_signable.rs` walks Value trees to reject f32/f64. `Envelope` fields are `String`, `Material`, `i64`, `u16` — no floats. Verify at planning time.

---

### Pattern B: Every secret buffer is `Zeroizing<Vec<u8>>` or `SecretBox<T>`

**Source:** `src/crypto.rs:148-156`, `src/identity.rs:105`, `src/identity.rs:208-210`

**Apply to:**
- `run_send` plaintext buffer: `Zeroizing<Vec<u8>>` around file-or-stdin read
- `run_receive` decrypted Envelope JCS bytes: already `Zeroizing` from `age_decrypt` — preserve
- `Material::GenericSecret.bytes`: NOT Zeroizing (serde requires owned Vec; lives inside Envelope); wrap the whole Envelope in a local Zeroizing container where possible, and zeroize the plaintext file bytes explicitly.

**Never:** `#[derive(Debug)]` on any struct that holds decrypted bytes. Use manual `Debug` that prints `[REDACTED <type>]` — template at src/identity.rs:56-61.

**Test coverage:** `tests/debug_leak_scan.rs` will be extended in `phase2_stderr_no_secrets.rs` to scan CLI stderr output.

---

### Pattern C: `CIPHERPOST_HOME`-overridable paths

**Source:** `src/identity.rs:29-42`

**Apply to:** new `state_dir()` function. Follow the exact template — env var first, `dirs::home_dir().expect()` fallback, `.join("...")` suffix:
```rust
pub fn state_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("CIPHERPOST_HOME") {
        PathBuf::from(custom).join("state")
    } else {
        dirs::home_dir()
            .expect("no home directory found")
            .join(".cipherpost")
            .join("state")
    }
}
```

Every integration test that writes to state MUST set `CIPHERPOST_HOME` to a TempDir (from `tempfile` crate) AND be marked `#[serial]` to prevent env-var race (Cargo.toml:68-72).

---

### Pattern D: File I/O permissions discipline (mode 0600 for files, 0700 for dirs)

**Source:** `src/identity.rs:97-131` (the generate() sequence)

**Apply to:** sentinel file creation, ledger create, state-dir + accepted-dir creation. Use explicit `.mode(0o600)` on `OpenOptions` AND re-apply permissions after creation (belt-and-suspenders against umask interference — see identity.rs:128-131). For directories, use `fs::create_dir_all` then `set_permissions(0o700)`.

**Test coverage:** reuse `tests/identity_perms_0600.rs` pattern — a new `phase2_state_perms.rs` should assert 0600 on sentinel + 0700 on `accepted/` dir after `run_receive`.

---

### Pattern E: Error construction never leaks secrets via Display

**Source:** `src/error.rs:27-37` (D-16 unified sig Display), `src/main.rs:19-32` (D-15 no source-chain walking)

**Apply to:** New `Error::WireBudgetExceeded { encoded, budget, plaintext }` Display CONTAINS `plaintext: usize` (the SIZE, not the CONTENT — that's fine). Verify planner doesn't accidentally put plaintext bytes into any Display.

D-16 invariant: the three new variants are not sig failures and must have their own distinct Display strings. `InvalidShareUri` specifically has its own text (not shared with `NotFound` or `Config`).

---

### Pattern F: `cfg(any(test, feature = "mock"))` gating for test-only symbols

**Source:** `src/transport.rs:194-290` (MockTransport module, gated)

**Apply to:**
- If Phase 2 needs a `MockTransport::insert_raw` test helper (for the tamper test), add it under the same `#[cfg(any(test, feature = "mock"))]` block.
- If Phase 2 needs a publish-counter or clock-mock, same gate.
- If Phase 2 adds a `CIPHERPOST_SKIP_TTY_CHECK` test override in flow.rs, gate the `env::var("CIPHERPOST_SKIP_TTY_CHECK")` lookup behind `#[cfg(any(test, feature = "mock"))]` so production builds cannot honor the env var. (Note: at library-crate level, integration tests DO NOT satisfy `cfg(test)` — that's the Phase 1 VERIFICATION.md note. Gate with `feature = "mock"` only, and add `required-features = ["mock"]` to the relevant `[[test]]` entries.)

---

### Pattern G: `pkarr::Keypair` and `pkarr::PublicKey` are the z32 gateway

**Source:** `src/record.rs:117-118` (verify_record step 1), `src/identity.rs:104, 161` (generate/load), `src/transport.rs:111` (resolve)

**Apply to:** every z32-string ↔ bytes conversion in flow.rs and URI parsing. NEVER use a hand-rolled z-base-32 decoder. Always go through `pkarr::PublicKey::try_from(&str)` + `.as_bytes()`.

---

## No Analog Found

Files/regions with no close Phase-1 match — planner falls back to RESEARCH.md and CONTEXT.md for guidance:

| File / Region | Role | Data Flow | Reason |
|---------------|------|-----------|--------|
| Acceptance-screen rendering (bordered banner, labeled rows, TTL remaining format) | UI / presentation | stderr formatting | Phase 1 has no TTY banner UX. Template literal in CONTEXT.md D-ACCEPT-02. `chrono` (new test-only dep per RESEARCH.md Standard Stack) provides the UTC + local time format; alternatively hand-rolled. |
| `base64_std_codec` serde-with module (Vec<u8> ↔ base64-std string) | codec helper | serde round-trip | Phase 1 uses `base64::STANDARD` inline at serialize/deserialize call sites (src/record.rs:103, 123); no existing `#[serde(with = ...)]` helper. Phase 2 authors the first. Define inline in payload.rs as `mod base64_std_codec { pub fn serialize<S>(bytes: &Vec<u8>, s: S) -> ...; pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error> ...; }`. |
| `dialoguer::Input::interact_text` usage (typed acceptance confirmation) | TTY prompt | request-response | Phase 1 only uses `dialoguer::Password::interact()` (src/identity.rs:289). Same crate, different entry point — map error the same way (`.map_err(\|_\| Error::Config(...))`). |
| Ledger JSONL append | file I/O | append-stream | Phase 1 writes only single-blob files via atomic tmp+rename. Appendig a JSONL line is a new idiom. Plain `OpenOptions::new().append(true).create(true).mode(0o600)` + `writeln!(file, "{}", line)` is stdlib; pattern is simple enough. |

---

## Metadata

**Analog search scope:**
- `src/*.rs` — all 11 Phase 1 source files (crypto, identity, transport, record, error, cli, main, lib, payload [stub], flow [stub], receipt [stub])
- `tests/*.rs` — all 13 Phase 1 test files
- `Cargo.toml` — test table conventions, feature gates
- `.planning/phases/01-*/01-CONTEXT.md` — Phase 1 locked decisions (D-01 through D-17)
- `.planning/phases/02-*/02-CONTEXT.md` — Phase 2 locked decisions (D-PS-*, D-URI-*, D-WIRE-*, D-RECV-*, D-ACCEPT-*, D-STATE-*, D-ERR-*)
- `.planning/phases/02-*/02-RESEARCH.md` — Architecture Responsibility Map + Standard Stack + Patterns 1-3

**Files scanned:** 27

**Pattern extraction date:** 2026-04-21

---

## PATTERN MAPPING COMPLETE

**Phase:** 02 - Send, receive, and explicit acceptance
**Files classified:** 6 source regions + 8 integration tests = 14
**Analogs found:** 14 / 14

### Coverage
- Files with exact analog: 11 (all payload/flow state ops; hkdf_infos; error variants; main.rs arms; round-trip + fixture tests)
- Files with role-match analog: 3 (URI parse; acceptance test subprocess; stderr-scan test)
- Files with no analog: 0 (acceptance-screen rendering, base64-serde-codec, dialoguer::Input, JSONL append all identified but have Phase-1-adjacent patterns to lean on)

### Key Patterns Identified
- **JCS-signable struct = alphabetical fields + full derive set + `crypto::jcs_serialize` path.** `Envelope` in payload.rs must mirror `OuterRecord`/`OuterRecordSignable` in record.rs exactly.
- **run_send and run_receive are orchestrators — call Phase-1 primitives, never reimplement.** Every crypto/transport/identity operation already has a function. Phase 2's `flow.rs` is pure composition with state transitions and error mapping.
- **Identity-file path discipline generalizes to state-file path discipline.** `identity::generate`'s mode-0700-dir + mode-0600-file + atomic-write + `CIPHERPOST_HOME`-override recipe applies verbatim to `~/.cipherpost/state/accepted.jsonl` and `~/.cipherpost/state/accepted/<hex>`.
- **Transport trait's `resolve()` already enforces the verify-before-decrypt invariant** (via `verify_record` called inline at src/transport.rs:121). run_receive consumes a pre-verified `OuterRecord` and owns only steps 4-11 of D-RECV-01.
- **`tests/hkdf_info_enumeration.rs` is a tripwire for namespace drift.** The three new constants (`SHARE_SENDER`, `SHARE_RECIPIENT`, `INNER_PAYLOAD`) must land in `crypto::hkdf_infos` BEFORE any flow.rs code references those strings, even if the constants are unused in Phase 2 bodies.
- **`serial_test` is mandatory on every test that mutates `CIPHERPOST_HOME`.** Phase 2 tests use TempDir-per-test; `#[serial]` prevents inter-test env race, which Phase 1 Plan 03 already established as a load-bearing test-runtime invariant.

### File Written
`/home/john/vault/projects/github.com/cipherpost/.planning/phases/02-send-receive-and-explicit-acceptance/02-PATTERNS.md`

### Ready for Planning
Pattern mapping complete. The planner can now produce PLAN.md files where each Phase 2 action references its analog file:line range and extracts code verbatim. No new modules are introduced. Flat-module layout (D-01/D-02) preserved. Every "closest analog" is a current Phase 1 file, not a RESEARCH.md idealization.
