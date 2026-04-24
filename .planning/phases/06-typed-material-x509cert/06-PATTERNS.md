# Phase 6: Typed Material — X509Cert — Pattern Map

**Mapped:** 2026-04-24
**Files analyzed:** 12 (7 modified, 5 new)
**Analogs found:** 11 / 12 (one net-new pattern — clap `ValueEnum` — called out under Architectural Decisions)

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `src/payload.rs` (modified) | model / serde schema | transform (struct ↔ JCS bytes) | `src/payload.rs` `Material::GenericSecret` variant (self) | exact (extend existing variant + accessor + Debug) |
| `src/payload/ingest.rs` (NEW) | utility / pure-function module | transform (raw bytes → typed Material) | `src/payload.rs::strip_control_chars` + `enforce_plaintext_cap` (pure byte-transform helpers at module boundary) | role-match |
| `src/preview.rs` (NEW) | utility / rendering module | transform (bytes → display String) | `src/flow.rs::format_unix_as_iso_utc` + `format_ttl_remaining` (free-fn renderers used by `TtyPrompter`) | role-match |
| `src/cli.rs` (modified) | config / clap schema | request-response (argv parse) | `src/cli.rs` `Command::Send` struct (self) + hidden `--passphrase` runtime-rejection pattern | exact (add field to existing struct) |
| `src/flow.rs` (modified) | controller / orchestrator | request-response | `src/flow.rs::run_send` + `run_receive` + `TtyPrompter::render_and_confirm` (self) | exact (extend call sites) |
| `src/error.rs` (modified) | model / error taxonomy | — | `src/error.rs::Error::PayloadTooLarge` + `WireBudgetExceeded` struct-like variants (self) | exact (add variant) |
| `src/lib.rs` (modified) | config / module graph | — | `src/lib.rs` existing `pub mod …` block | exact (add one line) |
| `src/main.rs` (modified) | controller / CLI dispatch | request-response | `src/main.rs` `Command::Send` arm (self) | exact (thread new flag, match on variant) |
| `Cargo.toml` (modified) | config | — | `Cargo.toml` existing `[dependencies]` entries (self) | exact |
| `tests/fixtures/material_x509_signable.bin` (NEW) | fixture binary | file-I/O | `tests/fixtures/envelope_jcs_generic_secret.bin` + `outer_record_signable.bin` + `receipt_signable.bin` | exact |
| `tests/material_x509_ingest.rs` (NEW) | test | transform negative/positive cases | `tests/phase2_material_variants_unimplemented.rs` + `tests/phase2_size_cap.rs` (error-variant assertion shape) | role-match |
| `tests/x509_roundtrip.rs` (NEW) | test / integration | request-response (send→receive under MockTransport) | `tests/phase2_self_round_trip.rs` (+ `phase2_share_round_trip.rs` deterministic-identity helper) | exact |

---

## Pattern Assignments

### `src/payload.rs` (modified — model, transform)

**Analog:** `src/payload.rs` itself (extend the existing `GenericSecret` patterns).

**Core variant pattern to mirror** (payload.rs:65-75):
```rust
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Material {
    GenericSecret {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,
    },
    X509Cert,   // <-- today: unit variant
    PgpKey,
    SshKey,
}
```

**Change:** Convert `X509Cert` from unit to struct variant using the exact same `#[serde(with = "base64_std")]` attribute as `GenericSecret`. The wire shape flips from `{"type":"x509_cert"}` to `{"type":"x509_cert","bytes":"<base64-std>"}` — the `#[serde(tag = "type", rename_all = "snake_case")]` on the enum handles the tag rename automatically, so the only addition is the data field.

**Debug-redaction pattern** (payload.rs:78-89) — copy verbatim, extend for X509Cert:
```rust
// Manual Debug — redacts GenericSecret bytes (Pitfall #7).
impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Material::GenericSecret { bytes } => {
                write!(f, "GenericSecret([REDACTED {} bytes])", bytes.len())
            }
            Material::X509Cert => write!(f, "X509Cert"),          // <-- unit stub today
            Material::PgpKey => write!(f, "PgpKey"),
            Material::SshKey => write!(f, "SshKey"),
        }
    }
}
```
**Change:** Phase 6 converts the `X509Cert` arm to `Material::X509Cert { bytes } => write!(f, "X509Cert([REDACTED {} bytes])", bytes.len())` — mirrors GenericSecret line-for-line. PgpKey/SshKey stay as unit stubs until Phase 7.

**Per-variant accessor pattern** (payload.rs:91-106) — the template for `as_x509_cert_bytes`:
```rust
impl Material {
    /// Return the Vec<u8> of a GenericSecret variant. Other variants return
    /// Error::NotImplemented { phase: 2 } — they are reserved for v1.0.
    pub fn as_generic_secret_bytes(&self) -> Result<&[u8], Error> {
        match self {
            Material::GenericSecret { bytes } => Ok(bytes.as_slice()),
            _ => Err(Error::NotImplemented { phase: 2 }),
        }
    }

    /// Construct a GenericSecret; non-generic-secret constructors are rejected at
    /// the public-API level in Phase 2.
    pub fn generic_secret(bytes: Vec<u8>) -> Self {
        Material::GenericSecret { bytes }
    }
}
```
**Change per D-P6-15:** `as_x509_cert_bytes()` follows this shape *except* the mismatch arm returns `Error::InvalidMaterial { variant: actual_variant_name, reason: "accessor called on wrong variant".into() }` instead of `NotImplemented { phase: 2 }`. The `as_generic_secret_bytes()` signature is preserved; its error arm stays `NotImplemented { phase: 2 }` for the legacy unit variants (PgpKey/SshKey). **Do not rename or retire the existing accessor.** Phase 7 will add `as_pgp_key_bytes()` / `as_ssh_key_bytes()` next to these.

**New `plaintext_size(&self) -> usize` method** — no direct analog (net-new), but the call-site shape mirrors `payload::enforce_plaintext_cap(bytes.len())`:
```rust
impl Material {
    pub fn plaintext_size(&self) -> usize {
        match self {
            Material::GenericSecret { bytes } => bytes.len(),
            Material::X509Cert { bytes } => bytes.len(),
            Material::PgpKey | Material::SshKey => 0, // unit stubs until Phase 7
        }
    }
}
```
Matches the "one method, exhaustive match" style of the existing `material_type_string` helper at `src/flow.rs:710-717`.

**base64 serde helper** (payload.rs:127-143) — unchanged, reused by the new variant:
```rust
/// serde-with module for Vec<u8> ↔ base64 standard with padding (D-WIRE-04).
/// Ban URL_SAFE_NO_PAD at this layer — the crate uses STANDARD everywhere else too.
mod base64_std {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
```
**Verified accessible:** `base64_std` is a `mod` (private to `payload.rs`). The new `X509Cert { bytes }` variant lives in the same module, so `#[serde(with = "base64_std")]` resolves identically to how `GenericSecret` uses it. No visibility change needed.

**Round-trip serde property-test pattern** (payload.rs:174-189) — copy for X509Cert test:
```rust
#[test]
fn material_generic_secret_serde_round_trip() {
    let m = Material::generic_secret(vec![0xde, 0xad, 0xbe, 0xef]);
    let s = serde_json::to_string(&m).unwrap();
    assert!(
        s.contains("\"type\":\"generic_secret\""),
        "serde tag should be snake_case: {}",
        s
    );
    assert!(
        s.contains("\"bytes\":\""),
        "GenericSecret.bytes should serialize as base64 string: {}",
        s
    );
    let back: Material = serde_json::from_str(&s).unwrap();
    assert_eq!(m, back);
}
```
**Change:** New test `material_x509_cert_serde_round_trip` swaps `generic_secret` constructor for a direct `Material::X509Cert { bytes: vec![...] }` and checks `"\"type\":\"x509_cert\""`.

---

### `src/payload/ingest.rs` (NEW — utility, transform)

**Analog:** No direct analog (net-new module) — closest peer is the same-module free-function pattern of `src/payload.rs::strip_control_chars` (payload.rs:111) and `enforce_plaintext_cap` (payload.rs:117):
```rust
/// Strip C0 (0x00..=0x1F), DEL (0x7F), and C1 (0x80..=0x9F) control characters.
pub fn strip_control_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Enforce the 64 KB plaintext cap (PAYL-03, D-PS-01). Pure client-side, pre-encrypt.
pub fn enforce_plaintext_cap(len: usize) -> Result<(), Error> {
    if len > PLAINTEXT_CAP {
        return Err(Error::PayloadTooLarge {
            actual: len,
            limit: PLAINTEXT_CAP,
        });
    }
    Ok(())
}
```

**Pattern — pure, module-level, `Result<_, Error>` return, no side-effects.** The new `ingest::x509_cert(raw: &[u8]) -> Result<Material, Error>` follows this exact shape — in-memory only, no I/O, returns a constructed `Material` variant or `Error::InvalidMaterial`.

**Module-vs-file question (D-P6-05):** Either `pub mod ingest { ... }` inline at the bottom of `src/payload.rs`, OR a new `src/payload/ingest.rs` file (requires converting `src/payload.rs` into `src/payload/mod.rs`). Recommended direction per D-P6-05: new file, because Phase 7 adds `pgp_key()` and `ssh_key()` peer functions and file-level grouping is cheaper to read. **Planner flags this as Architectural Decision 2 below.**

**Error-return shape to mirror** — identical Result-with-struct-variant pattern from `enforce_plaintext_cap`. `ingest::x509_cert` returns:
- Happy: `Ok(Material::X509Cert { bytes: canonical_der })`
- PEM sniff fail / body decode fail / BER fail / trailing bytes / etc.: `Err(Error::InvalidMaterial { variant: "x509_cert".into(), reason: "<short generic reason>".into() })`

---

### `src/preview.rs` (NEW — utility, rendering)

**Analog:** `src/flow.rs::format_unix_as_iso_utc` (flow.rs:1015) + `format_ttl_remaining` (flow.rs:1007) — free functions that take primitive inputs and return `String` for use inside `TtyPrompter::render_and_confirm`.

**Template** (flow.rs:1007-1022):
```rust
/// Format `<Xh YYm>` for TTL remaining. Hand-rolled — no chrono dep.
fn format_ttl_remaining(seconds: u64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    format!("{}h {:02}m", h, m)
}

/// Format a unix-seconds timestamp as `YYYY-MM-DD HH:MM UTC`. Reuses the
/// civil-from-days helper already in this file (Plan 02).
fn format_unix_as_iso_utc(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let rem = unix.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m, d, hour, minute)
}
```

**Change per D-P6-17:** The new `preview::render_x509_preview(bytes: &[u8]) -> Result<String, Error>` is similar — pure, String-returning, no I/O — BUT differs in two ways:
1. It returns `Result<String, Error>` (because parse can fail) rather than infallible `String`. Error maps to `Error::InvalidMaterial { variant: "x509_cert", reason: "..." }`, consistent with ingest.
2. It lives in a new module (`src/preview.rs`) rather than `flow.rs` private helpers, because D-P6-17 explicitly keeps `x509-parser` imports out of `flow.rs` and `payload.rs`.

**Reuse `format_unix_as_iso_utc` for NotBefore/NotAfter rendering.** Research §X509-04 confirms x509-parser's `ASN1Time::timestamp()` returns `i64` unix seconds — feed directly into the existing formatter. **Do NOT append a second `" UTC"` suffix** — Phase 2 UAT note at `flow.rs:1143-1146`:
```rust
#[test]
fn format_unix_as_iso_utc_epoch() {
    // Pins the suffix: callers must NOT append another " UTC" after
    // `format_unix_as_iso_utc(...)` — see UAT-2 2026-04-21 double-UTC bug.
    assert_eq!(format_unix_as_iso_utc(0), "1970-01-01 00:00 UTC");
}
```
Planner must ensure `render_x509_preview` calls `format_unix_as_iso_utc(t)` bare — or make the formatter function `pub(crate)` if it's currently private (it is — needs visibility bump). Flag as sub-decision in plan.

**Multi-line String output pattern** — mirror the direct-write shape already used inside `TtyPrompter::render_and_confirm` (flow.rs:1066-1078):
```rust
eprintln!("=== CIPHERPOST ACCEPTANCE ===============================");
eprintln!("Purpose:     \"{}\"", safe_purpose);
eprintln!("Sender:      {}", sender_openssh_fp);
eprintln!("             {}", sender_z32);
eprintln!("Share ref:   {}", share_ref_hex);
eprintln!("Type:        {}", material_type);
eprintln!("Size:        {} bytes", size_bytes);
eprintln!(
    "TTL:         {} remaining (expires {} / {} local)",
    ttl_str, expires_utc, expires_local
);
eprintln!("=========================================================");
eprintln!("To accept, paste the sender's z32 pubkey and press Enter:");
```
**Key difference per D-P6-17 / CONTEXT §specifics banner mockup:** `render_x509_preview` returns a **String** (no `eprintln!` side effects) — caller (`TtyPrompter`) owns the emission. Shape:
```rust
pub fn render_x509_preview(bytes: &[u8]) -> Result<String, Error> {
    // parse cert via x509_parser (errors map to Error::InvalidMaterial)
    // build multi-line string using writeln!(buf, ...) into a String
    // lines: "--- X.509 " + "-".repeat(57) / Subject / Issuer / Serial / NotBefore / NotAfter / Key / SHA-256
    // no leading "\n", no trailing "\n" (caller owns outer layout per D-P6-17)
    Ok(buf)
}
```

---

### `src/cli.rs` (modified — config, argv schema)

**Analog:** `src/cli.rs::Command::Send` struct (cli.rs:41-77) — extend with new field using the same `#[arg(long)]` attributes pattern.

**Template for flag additions** (cli.rs:55-77):
```rust
Send {
    /// Encrypt to self (recipient = own identity)
    #[arg(long, conflicts_with = "share")]
    self_: bool,

    /// Encrypt to a recipient's PKARR pubkey (z-base-32 or OpenSSH format)
    #[arg(long, conflicts_with = "self_")]
    share: Option<String>,

    /// Purpose string (signed, sender-attested)
    #[arg(short, long)]
    purpose: Option<String>,

    /// Read payload from PATH or `-` for stdin
    #[arg(long)]
    material_file: Option<String>,

    /// TTL in seconds (default 86400 = 24h)
    #[arg(long)]
    ttl: Option<u64>,
    // ... passphrase_file, passphrase_fd, passphrase (hidden), material_stdin ...
}
```

**Change per D-P6-01 + Claude's Discretion row:** Add a `material: MaterialVariant` field with clap `ValueEnum`. No existing ValueEnum in the codebase — **this is the one net-new clap pattern in Phase 6.** Minimal idiomatic shape (plan should verify against clap 4.5 docs):

```rust
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[clap(rename_all = "kebab-case")]
pub enum MaterialVariant {
    #[default]
    GenericSecret,
    X509Cert,
    PgpKey,
    SshKey,
}
```
And in the `Send` struct:
```rust
/// Typed material variant. Default is `generic-secret`.
#[arg(long, value_enum, default_value_t = MaterialVariant::GenericSecret)]
material: MaterialVariant,
```

**Hidden-flag + runtime-rejection analog** (cli.rs:68-72) — closest existing pattern for parse-at-clap / reject-at-runtime:
```rust
/// REJECTED — inline passphrases leak via argv / /proc/<pid>/cmdline / ps.
/// Use CIPHERPOST_PASSPHRASE env, --passphrase-file, or --passphrase-fd instead.
/// This flag exists only so the runtime rejection path returns a clear error (exit 4).
#[arg(long, value_name = "VALUE", hide = true)]
passphrase: Option<String>,
```
**Applicability:** D-P6-01 dictates `pgp-key` and `ssh-key` *parse* at clap level but dispatch returns `Error::NotImplemented { phase: 7 }`. This is the same "accept-at-parse, reject-at-dispatch" pattern as the hidden `--passphrase` flag (accepted by clap so the runtime rejection can return a clean typed error rather than an ugly clap-level "unknown value"). The planner should mirror: include `PgpKey` / `SshKey` as ValueEnum arms, then in `main.rs` dispatch emit `Err(Error::NotImplemented { phase: 7 })` for those values.

**`Receive` struct `--armor` addition** (cli.rs:86-109) — extend with the same `#[arg(long)]` pattern, boolean flag:
```rust
// In Receive { ... }:
/// Emit PEM armor for certificate outputs (x509-cert only in Phase 6).
#[arg(long)]
armor: bool,
```
No analog needed — mirrors existing booleans like `self_: bool` in `Send`. Runtime behavior per Claude's Discretion row: if `armor == true` and material variant is not X509Cert, reject with `Error::Config(...)` in `run_receive`.

---

### `src/flow.rs` (modified — controller, orchestrator)

**Analog:** `src/flow.rs` itself — extend `run_send` (flow.rs:220-337), `run_receive` (flow.rs:398-565), and `TtyPrompter::render_and_confirm` (flow.rs:1036-1103).

**`run_send` dispatch-through-ingest pattern** — current hard-coded call site (flow.rs:240-242):
```rust
// 4. build Envelope + JCS-serialize
let created_at = now_unix_seconds()?;
let envelope = Envelope {
    created_at,
    material: Material::generic_secret(plaintext_bytes.to_vec()),   // <-- hardcoded
    protocol_version: PROTOCOL_VERSION,
    purpose: stripped_purpose,
};
```

**Change per D-P6-18 + CONTEXT §specifics "Cap check order":** Replace hard-coded `Material::generic_secret(...)` with a variant-matched call through `payload::ingest::<variant>()` *before* the cap check. New order (from CONTEXT.md specifics):
1. `read_material` → `raw bytes`
2. `let material = match variant { GenericSecret => ingest::generic_secret(raw), X509Cert => ingest::x509_cert(raw), PgpKey|SshKey => return Err(Error::NotImplemented{phase:7}) }?;`
3. `payload::enforce_plaintext_cap(material.plaintext_size())?;` — note: now called with `plaintext_size()`, not `plaintext_bytes.len()`. Crucially: the ingest runs BEFORE the cap — a 1 MB PEM decodes to ~100 KB DER, cap fires on the DECODED size.
4. `strip_control_chars(purpose)` (unchanged)
5. Build `Envelope { material, ... }` (use the pre-constructed `material`, do not re-wrap)

**Signature change note:** `run_send` today takes `material_source: MaterialSource`. Plan must decide: (a) thread a new `variant: MaterialVariant` parameter, OR (b) thread a pre-constructed `Material` (callers do ingest). Option (a) keeps symmetry with `MaterialSource`; option (b) is simpler inside `run_send`. Flag this as Architectural Decision 3 below.

**`run_receive` match-on-variant at step 8** — current code (flow.rs:458-471):
```rust
// STEP 8: acceptance prompt — BEFORE this point, NO payload field has been
// printed. The Prompter sees the full fields and renders the screen + reads
// confirmation.
let (sender_openssh_fp, _z32_again) = sender_openssh_fingerprint_and_z32(&record.pubkey)?;
// Non-generic material variants return NotImplemented (exit 1).
let material_bytes = envelope.material.as_generic_secret_bytes()?;
let ttl_remaining = (expires_at - now).max(0) as u64;
prompter.render_and_confirm(
    &envelope.purpose,
    &sender_openssh_fp,
    &record.pubkey,
    &record.share_ref,
    material_type_string(&envelope.material),
    material_bytes.len(),
    ttl_remaining,
    expires_at,
)?; // Err(Error::Declined) on mismatch → exit 7
```

**Change per CONTEXT §Integration Points:** Replace the hard-coded `as_generic_secret_bytes()?` with a match on `envelope.material`, calling the appropriate `as_*_bytes()` for each variant. PgpKey/SshKey still return the `NotImplemented { phase: 2 }` error from the existing accessor until Phase 7 adds their accessors.

**`TtyPrompter::render_and_confirm` preview-subblock call site** (flow.rs:1066-1078) — insert new `eprintln!` block between the `Size:` line (flow.rs:1072) and the `TTL:` line (flow.rs:1073) ONLY when material variant is `X509Cert`:
```rust
eprintln!("Size:        {} bytes", size_bytes);
// NEW: subblock for typed variants (D-P6-09)
if let Some(subblock) = preview_subblock {  // pre-rendered by caller or self
    eprintln!("{}", subblock);
}
eprintln!(
    "TTL:         {} remaining (expires {} / {} local)",
    ttl_str, expires_utc, expires_local
);
```

**Key decision point:** WHO renders the subblock — the Prompter or the caller? Flag this as **Architectural Decision 1 (the Prompter trait signature question)** below. Both approaches have evidence in the existing code; they differ in whether `render_and_confirm` needs new parameters (material bytes + material variant string) or just a pre-rendered `Option<String>`.

**Test-prompter analogs** — `AutoConfirmPrompter` / `DeclinePrompter` (flow.rs:920-955):
```rust
#[cfg(any(test, feature = "mock"))]
pub mod test_helpers {
    use super::*;

    pub struct AutoConfirmPrompter;

    impl Prompter for AutoConfirmPrompter {
        fn render_and_confirm(
            &self,
            _purpose: &str,
            _sender_openssh_fp: &str,
            _sender_z32: &str,
            _share_ref_hex: &str,
            _material_type: &str,
            _size_bytes: usize,
            _ttl_remaining_seconds: u64,
            _expires_unix_seconds: i64,
        ) -> Result<(), Error> {
            Ok(())
        }
    }
    // ... DeclinePrompter mirrors ...
}
```
**Change:** If the trait signature gains new parameters (Architectural Decision 1), every impl (`TtyPrompter` + both test prompters + any future ones) must be updated. The test prompters already ignore all args with `_` prefix, so they need only the new underscored parameter(s) added. Keep the `#[allow(clippy::too_many_arguments)]` already at flow.rs:82 (or add it to any new impl).

---

### `src/error.rs` (modified — model, error taxonomy)

**Analog:** `src/error.rs::Error::PayloadTooLarge` + `WireBudgetExceeded` (error.rs:51-62) — struct-like thiserror variants with named fields.

**Template** (error.rs:51-62):
```rust
#[error("payload exceeds 64 KB limit: actual={actual}, cap={limit}")]
PayloadTooLarge { actual: usize, limit: usize },

#[error("share_ref in URI does not match resolved record")]
ShareRefMismatch,

#[error("share too large for PKARR packet: encoded={encoded} bytes, budget={budget} bytes (plaintext was {plaintext} bytes)")]
WireBudgetExceeded {
    encoded: usize,
    budget: usize,
    plaintext: usize,
},
```

**Change per D-P6-03:** Add the new variant (suggested placement: after `WireBudgetExceeded`, before `InvalidShareUri`, keeping the existing logical grouping of "payload/wire-size" errors together):
```rust
#[error("invalid material: variant={variant}, reason={reason}")]
InvalidMaterial { variant: String, reason: String },
```
**Error-oracle constraint (per D-P6-03 + CONTEXT §code_context "Error-oracle hygiene"):** The Display string must be **generic** — no `x509-parser::`-internal strings, no nom parse-position strings, no parser-internal error text. `reason` is a short hand-chosen string like `"malformed DER"`, `"PEM body decode failed"`, `"trailing bytes after certificate"`, `"accessor called on wrong variant"`. Plan 04 (or the existing Plan 03 test-bundle) adds an enumeration test that constructs every `InvalidMaterial` the code produces and asserts Display contains no `x509-parser::` or `X509Error` identifiers.

**`#[source]` / `#[from]` pattern** (error.rs:10-13, 77, 80):
```rust
#[derive(Debug, Error)]
pub enum Error {
    #[error("io error")]
    Io(#[from] std::io::Error),
    // ...
    #[error("crypto error")]
    Crypto(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("transport error")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
}
```
**Applicability:** `InvalidMaterial` **does not** use `#[source]` or `#[from]` — it carries a sanitized `String` precisely to prevent source-chain leakage of `x509-parser::X509Error`. This is a deliberate departure from the `Crypto`/`Transport` variants. Planner should add a code comment documenting this (pattern: "reason is a curated short string; do not wrap x509-parser's error type here — Display-leak bait").

**Exit-code mapping** (error.rs:85-99) — add one arm:
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
        Error::ShareRefMismatch | Error::WireBudgetExceeded { .. } | Error::InvalidShareUri(_) => 1,
        _ => 1,
    }
}
```
**Change per D-P6-03 / X509-08:** `InvalidMaterial { .. }` maps to exit 1. It already falls into the `_ => 1` default arm — an explicit arm isn't strictly necessary but can be added for documentation. Either is acceptable; recommend explicit for grep-ability.

---

### `src/lib.rs` (modified — config, module graph)

**Analog:** `src/lib.rs:8-16` — existing `pub mod …` block.
```rust
pub mod cli;
pub mod crypto;
pub mod error;
pub mod flow;
pub mod identity;
pub mod payload;
pub mod receipt;
pub mod record;
pub mod transport;
```
**Change:** Add `pub mod preview;` (alphabetical placement would go between `payload` and `receipt`). No other change.

---

### `src/main.rs` (modified — controller, CLI dispatch)

**Analog:** `src/main.rs::Command::Send` arm (main.rs:80-204) — extend the flag destructuring + thread the new arg into `run_send`.

**Destructuring pattern to extend** (main.rs:80-90):
```rust
Command::Send {
    self_,
    share,
    purpose,
    material_file,
    ttl,
    passphrase,
    passphrase_file,
    passphrase_fd,
    material_stdin,
} => {
    // ...
}
```
**Change:** Add `material,` (the new ValueEnum field) to the destructuring. Add a match arm on `material` before the `run_send` call:
```rust
// Dispatch: reject PGP/SSH until Phase 7 per D-P6-01.
match material {
    MaterialVariant::GenericSecret | MaterialVariant::X509Cert => { /* ok, fall through */ }
    MaterialVariant::PgpKey | MaterialVariant::SshKey => {
        return Err(Error::NotImplemented { phase: 7 }.into());
    }
}
```
Or, preferred: push the match into `run_send` along with the new parameter. See Architectural Decision 3.

**Receive extension** (main.rs:205-282):
```rust
Command::Receive {
    share,
    output,
    dht_timeout: _,
    passphrase,
    passphrase_file,
    passphrase_fd,
} => { ... }
```
**Change:** Add `armor,` to the destructuring. If `armor == true` and the resolved material variant is not X509Cert, return `Error::Config("--armor requires --material x509-cert".into())` (per Claude's Discretion row + safer default). Thread `armor` as a new parameter to `run_receive` OR to the OutputSink construction — planner decides; either works.

---

### `Cargo.toml` (modified — config)

**Analog:** Existing `[dependencies]` entries.

**Template** (Cargo.toml:22-23 for a similar "disable default features, pick specific ones" pattern):
```toml
# DHT transport — no_relays + dht feature only; inherits ed25519-dalek 3.x pre-release
pkarr = { version = "5.0.3", default-features = false, features = ["dht"] }
```

**Change per CONTEXT §Dependency additions + RESEARCH §Standard Stack:**
```toml
# X.509 DER/PEM parsing (Phase 6). `verify` feature STAYS OFF — would pull `ring`
# which is on the supply-chain rejected list. `default-features = false` is
# belt-and-suspenders: 0.16 has `default = []` so the result is identical, but
# explicit intent aids audit. See .planning/research/SUMMARY.md §Phase 6.
x509-parser = { version = "0.16", default-features = false }
```
**CI guard:** RESEARCH specifies `cargo tree | grep -E "ring|aws-lc"` must be empty after the add. Plan 01 acceptance criterion.

**Note on CONTEXT.md's `features = ["std"]`** — RESEARCH §Installation flags this as incorrect: x509-parser 0.16 has no `std` feature in its manifest (implicitly std-requiring). Plan 01 should drop `features = ["std"]` and commit only `default-features = false`.

**New `[[test]]` stanzas** — pattern (Cargo.toml:50-53):
```toml
[[test]]
name = "mock_transport_roundtrip"
path = "tests/mock_transport_roundtrip.rs"
required-features = ["mock"]
```
**Add two new stanzas:**
```toml
[[test]]
name = "material_x509_ingest"
path = "tests/material_x509_ingest.rs"

[[test]]
name = "x509_roundtrip"
path = "tests/x509_roundtrip.rs"
required-features = ["mock"]
```
Ingest tests do not need `mock` (they call `ingest::x509_cert` directly, no transport). Round-trip does (uses MockTransport).

---

### `tests/fixtures/material_x509_signable.bin` (NEW — fixture binary)

**Analog:** `tests/fixtures/envelope_jcs_generic_secret.bin` + `tests/fixtures/outer_record_signable.bin` + `tests/fixtures/receipt_signable.bin` — three existing JCS-fixture `.bin` files, all loaded by the same pattern.

**Pattern — fixture-loading test** (tests/phase2_envelope_round_trip.rs:9-30):
```rust
const FIXTURE_PATH: &str = "tests/fixtures/envelope_jcs_generic_secret.bin";

fn fixture_envelope() -> Envelope {
    Envelope {
        created_at: 1_700_000_000,
        material: Material::generic_secret(vec![0, 1, 2, 3]),
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}

#[test]
fn envelope_jcs_bytes_match_committed_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_envelope_fixture` to create it",
    );
    assert_eq!(
        bytes, expected,
        "Envelope JCS bytes changed — past signatures invalidated!"
    );
}

#[test]
#[ignore] // run with --ignored to regenerate; commit result
fn regenerate_envelope_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {}", FIXTURE_PATH);
}
```

**Pattern — plain byte-locked fixture test** (tests/outer_record_canonical_form.rs:22-44):
```rust
const FIXTURE_PATH: &str = "tests/fixtures/outer_record_signable.bin";

#[test]
fn outer_record_signable_bytes_match_committed_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_fixture` to create it",
    );
    assert_eq!(
        bytes, expected,
        "OuterRecordSignable JCS bytes changed — past signatures invalidated!"
    );
}

#[test]
#[ignore] // run with --ignored to regenerate; commit result
fn regenerate_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {}", FIXTURE_PATH);
}
```

**What Phase 6's fixture is (per CONTEXT.md + RESEARCH X509-07):** The fixture is **the JCS bytes of an `Envelope` whose material is a `Material::X509Cert { bytes: <hand-crafted static DER> }`** — NOT the DER bytes themselves. The DER certificate bytes are **a second artifact** that could either be committed as a sibling `.der` file or inlined into the test as `const FIXTURE_DER: &[u8] = &[0x30, 0x82, …];`. Either works — planner's call.

**Fixture cert spec** (CONTEXT §specifics): minimal Ed25519-keyed self-signed cert, Subject `CN=cipherpost-fixture, O=cipherpost, C=XX`, valid 2026-01-01 → 2028-01-01, serial `0x01`. **Generator is NOT committed** — bytes are generated once offline (RESEARCH rejects `rcgen` because it pulls `ring`; use a one-off tool or pre-captured bytes from openssl) and checked in. Reproduction note in `tests/fixtures/material_x509_signable.txt` per CONTEXT's discretion row.

**Change:** New test file `tests/phase6_material_x509_envelope_round_trip.rs` (or fold the JCS-fixture assertion into the material_x509_ingest.rs test suite) mirrors `phase2_envelope_round_trip.rs` with the X509Cert variant in place of GenericSecret. Same `#[ignore] regenerate_…_fixture` pattern.

---

### `tests/material_x509_ingest.rs` (NEW — test)

**Analog:** `tests/phase2_material_variants_unimplemented.rs` (error-variant assertion style) + `tests/phase2_size_cap.rs` (positive + negative path test structure).

**Error-assertion pattern** (phase2_material_variants_unimplemented.rs:7-14):
```rust
#[test]
fn x509_cert_bytes_access_returns_not_implemented_phase_2() {
    let err = Material::X509Cert.as_generic_secret_bytes().unwrap_err();
    assert!(
        matches!(err, cipherpost::Error::NotImplemented { phase: 2 }),
        "expected NotImplemented{{phase:2}}, got {:?}",
        err
    );
}
```
**Change:** This exact test becomes OBSOLETE at Phase 6 for the X509Cert arm (the variant now carries data and has its own accessor). Recommend the planner DELETES or RENAMES the x509 case in `phase2_material_variants_unimplemented.rs` as part of the Phase 6 work, leaving PgpKey/SshKey cases intact. Replacement assertions for X509Cert's *new* `as_x509_cert_bytes` accessor go into `tests/material_x509_ingest.rs` with a different expected error (`Error::InvalidMaterial { variant: "generic_secret", reason: "accessor called on wrong variant" }` when called on a `Material::GenericSecret`).

**Cases to cover** (from CONTEXT.md "NEW: tests/material_x509_ingest.rs" line + RESEARCH §X509-01..08):
- `x509_cert_happy_der` — raw DER bytes → `Material::X509Cert { bytes }`, `bytes == input` (canonical-DER invariant).
- `x509_cert_happy_pem` — PEM input → same variant, `bytes` equals the PEM-body-decoded DER (not the PEM text).
- `x509_cert_malformed_pem_rejected` — PEM header present, body garbage → `InvalidMaterial { reason: "PEM body decode failed" }` (or similar generic wording).
- `x509_cert_ber_rejected` — known-BER (indefinite-length) cert → `InvalidMaterial { reason: "malformed DER" }` — exercises the x509-parser strict profile.
- `x509_cert_trailing_bytes_rejected` — valid DER cert plus `[0xFF, 0xFF]` appended → `InvalidMaterial { reason: "trailing bytes after certificate" }` (D-P6-07).
- `x509_cert_accessor_wrong_variant` — call `Material::GenericSecret{...}.as_x509_cert_bytes()` → `InvalidMaterial { variant: "generic_secret", reason: "accessor called on wrong variant" }` (D-P6-15).
- Error-oracle hygiene: enumerate every Display and assert no `x509-parser`, `X509Error`, `nom`, or parse-position strings leak.

**Positive+negative pairing pattern** (phase2_size_cap.rs:24-128) — two tests in the same file, one happy-path assertion on error variant match, one assertion on Display shape:
```rust
let err = run_send(...).unwrap_err();
assert!(
    matches!(err, cipherpost::Error::PayloadTooLarge { actual: 65537, limit: 65536 }),
    "expected PayloadTooLarge{{actual:65537,limit:65536}}, got {:?}",
    err
);
let disp = format!("{}", err);
assert!(disp.contains("65537"), "Display must contain actual size, got: {}", disp);
assert!(disp.contains("65536"), "Display must contain cap, got: {}", disp);
```
**Change:** For `InvalidMaterial`, assert the *opposite* on Display — that parser-internal strings do NOT appear.

---

### `tests/x509_roundtrip.rs` (NEW — test, integration)

**Analog:** `tests/phase2_self_round_trip.rs` (exact shape) + optionally `tests/phase2_share_round_trip.rs` (deterministic-identity helper).

**Template** (phase2_self_round_trip.rs:14-59):
```rust
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn self_round_trip_recovers_plaintext() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();

    let seed_zeroizing = id.signing_seed();
    let seed: [u8; 32] = *seed_zeroizing;
    let kp = pkarr::Keypair::from_secret_key(&seed);

    let plaintext = b"topsecret1".to_vec();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        DEFAULT_TTL_SECONDS,
    )
    .expect("run_send self-mode");

    let uri = ShareUri::parse(&uri_str).expect("run_send must return a valid URI");

    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(&id, &transport, &kp, &uri, &mut sink, &AutoConfirmPrompter)
        .expect("run_receive self-mode");

    match sink {
        OutputSink::InMemory(buf) => {
            assert_eq!(buf, plaintext, "recovered plaintext must match sent")
        }
        _ => panic!("expected InMemory sink"),
    }
}
```

**Change for x509_roundtrip.rs per X509-09:** Swap `plaintext = b"topsecret1".to_vec()` for the hand-crafted fixture DER bytes (`const FIXTURE_DER: &[u8] = &[...]` or `include_bytes!("fixtures/material_x509_fixture.der")`). The `run_send` signature may grow a `material_variant: MaterialVariant` parameter (per Architectural Decision 3 below) — thread `MaterialVariant::X509Cert` through. The decoded sink bytes should equal `FIXTURE_DER` verbatim (canonical-DER round-trip invariant).

**CIPHERPOST_HOME + #[serial] invariant** (tests that mutate `CIPHERPOST_HOME` must gate with `#[serial]` per `serial_test = "3"` — CONTEXT §code_context "Test convention"). The template above already uses both. Preserve.

**Share-mode optional second test** — `phase2_share_round_trip.rs:27-47` provides the `deterministic_identity_at(home, seed)` helper if the planner wants an A→B X509 cross-identity test under MockTransport (not strictly required by X509-09 which says self-mode is sufficient; cross-identity real-DHT is Phase 9). If included, copy the helper verbatim.

**Wire-budget negative case** (CONTEXT §specifics last bullet) — optional but recommended: include one test case with a fixture large enough to trip the 1000-byte PKARR budget, asserting the error is `WireBudgetExceeded` (not `InvalidMaterial`, not a PKARR-internal panic). Pattern lives at `phase2_size_cap.rs:68-128` (the `plaintext_under_64k_but_over_wire_budget` test); adapt for an X509Cert input.

---

## Shared Patterns

### Authentication / Identity

**Source:** `src/identity.rs` + the `resolve_passphrase` + `identity::generate` + `identity::load` call triple.

**Apply to:** `tests/x509_roundtrip.rs` (uses `identity::generate` to produce a fresh identity; the `seed_zeroizing → seed → Keypair::from_secret_key` bridge is boilerplate). Already baked into the `phase2_self_round_trip.rs` template above. No change.

### Error Handling / Propagation

**Source:** `src/error.rs` + `src/main.rs::run`'s `downcast_ref::<Error>` → `exit_code` dispatcher (main.rs:15-31).
```rust
fn run() -> i32 {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => 0,
        Err(e) => {
            let code = if let Some(ce) = e.downcast_ref::<Error>() {
                eprintln!("{}", user_message(ce));
                exit_code(ce)
            } else {
                eprintln!("{}", e);
                1
            };
            code
        }
    }
}
```
**Apply to:** New `Error::InvalidMaterial` flows unchanged through this dispatcher. As long as the variant is added to `Error` (with a generic `#[error("...")]` Display) and `exit_code` returns 1 (either via the `_ => 1` default or an explicit arm), no change to `main.rs::run` is needed.

### Pre-emit surface hygiene

**Source:** `src/flow.rs::run_receive` D-RECV-01 comment block (flow.rs:398-411) + Anti-pattern 6 in CONTEXT §code_context ("Do NOT emit cert bytes... to stderr BEFORE the acceptance prompt returns Ok(())").

**Apply to:** All of `run_receive`'s step 8 changes. `render_x509_preview` returns a String that the Prompter emits; the Prompter treats that emission as part of the acceptance banner itself (not a separate side-effect). No cert field reaches stderr before the typed-z32 prompt reads a line.

### Test-env isolation

**Source:** `serial_test = "3"` + `#[serial]` on every test that writes `CIPHERPOST_HOME`. Visible on every test in `tests/phase2_*_round_trip.rs` + `phase2_size_cap.rs` + `phase2_expired_share.rs` + the identity/debug tests.

**Apply to:** `tests/x509_roundtrip.rs` (needs `#[serial]` because it calls `identity::generate` → writes to `CIPHERPOST_HOME`). `tests/material_x509_ingest.rs` **does NOT need `#[serial]`** — pure ingest functions touch no filesystem, no env.

### Debug redaction leak-scan

**Source:** `tests/debug_leak_scan.rs` — enumerates secret-holding structs and asserts `format!("{:?}", x)` never contains key bytes in hex windows.

**Apply to:** Phase 6 per D-P6-08 extends this test to cover all four Material variants. Either (a) add new test cases in the existing file or (b) add a new `tests/material_debug_leak_scan.rs`. Either works. The leak-scan window-search logic (debug_leak_scan.rs:31-43) copies directly:
```rust
for win in secret_bytes.windows(8) {
    let hex: String = win.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    });
    assert!(
        !debug_str.contains(&hex),
        "Debug leak: seed bytes {:?} found in format!({{:?}}, identity). Full debug: {:?}",
        hex,
        debug_str
    );
}
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| (none fully un-analogized; `clap::ValueEnum` derivation is the one micro-pattern net-new — see Architectural Decision 2 below) | | | |

Every file touched in Phase 6 has a strong existing analog. The closest thing to a gap is that this codebase does not yet use clap's `ValueEnum` derive macro anywhere — `SendMode` is constructed from two booleans at the `main.rs` dispatch layer rather than via `ValueEnum`. Planner must introduce the idiom once (documented above under `src/cli.rs`) and from that point forward it is a codebase pattern Phase 7 can reuse.

---

## Architectural Decisions Surfaced

These are places where the existing patterns do not uniquely determine the approach; the planner must pick.

### AD-1 — Prompter trait signature: pre-render in caller vs render inside impl

**Question:** Who calls `preview::render_x509_preview(bytes)` — the caller of `Prompter::render_and_confirm`, or the impl itself?

**Option A (pre-render in caller):** `run_receive` calls `preview::render_x509_preview(material_bytes)?` to produce an `Option<String>`, passes it as a new parameter `preview_subblock: Option<&str>` to `render_and_confirm`. Pros: `TtyPrompter` stays ignorant of x509-parser; test prompters get a trivial new `_preview_subblock: Option<&str>` parameter. Cons: trait signature grows by one arg; all three impls (TtyPrompter + AutoConfirmPrompter + DeclinePrompter) touch.

**Option B (render inside impl):** Pass the raw material variant + bytes to `render_and_confirm`; `TtyPrompter` matches on variant internally and calls `preview::render_x509_preview(bytes)` inline. Test prompters ignore (they do not render). Pros: caller stays simple; the Prompter owns its rendering end-to-end. Cons: `TtyPrompter` now depends on `preview` module; trait gains **two** new args (variant enum or tag string + `&[u8]`).

**Existing evidence:** The current trait signature already passes `material_type: &str` + `size_bytes: usize` as separate args (flow.rs:82-94), which leans toward Option B (Prompter knows how to render what it's told to render). But `TtyPrompter` today renders nothing cert-specific — adding x509 rendering inside the impl is a new crosscut.

**Planner recommendation:** Option B is more aligned with today's trait design; flag for explicit plan-level decision.

### AD-2 — `src/payload/ingest.rs` file vs `payload::ingest` inline submodule

**Question:** Does Phase 6 create a new `src/payload/ingest.rs` file (requires renaming `src/payload.rs` → `src/payload/mod.rs`), or add `pub mod ingest { ... }` inline at the bottom of `src/payload.rs`?

**Existing evidence:** Every module in `src/` today is a single file; no multi-file modules exist. Converting to a directory module is low-risk but visible in the file-tree.

**Planner recommendation:** Inline `pub mod ingest` inside `src/payload.rs` keeps things flat for Phase 6; revisit when Phase 7 adds `pgp_key()` and `ssh_key()` and the inline block gets long. D-P6-05 explicitly phrases this as "new module OR submodule" — both are acceptable.

### AD-3 — `run_send` signature: thread `MaterialVariant` or pre-constructed `Material`?

**Question:** Does `run_send`'s signature gain a new `variant: MaterialVariant` parameter (dispatches ingest internally), or does the caller (`main.rs`) pre-ingest and pass a pre-built `Material` instead of `MaterialSource`?

**Option A (variant param):** `run_send(..., material_source: MaterialSource, material_variant: MaterialVariant, ...)` — `run_send` calls `ingest::<variant>(raw)` internally. Pros: `main.rs` dispatch stays thin; `run_send` keeps end-to-end ownership of the send pipeline; tests pass `MaterialSource::Bytes` + `MaterialVariant::GenericSecret` unchanged.

**Option B (pre-constructed):** `run_send(..., material: Material, ...)` — caller ingests first. Pros: `run_send` gets simpler (no dispatch logic); ingest tests directly test the variant construction. Cons: PASS-09 + every existing round-trip test signature changes — they pass `MaterialSource::Bytes(...)` today.

**Existing evidence:** `MaterialSource` exists specifically to avoid coupling the send orchestrator to the caller's data-source choice. Deleting it or re-purposing it would be a larger refactor.

**Planner recommendation:** Option A preserves `MaterialSource` (unchanged across all 5+ existing round-trip tests) and keeps the new `MaterialVariant` orthogonal to the source. Every existing test compiles unchanged (default-value `GenericSecret` picked up via a `..Default::default()`-style pattern at call site, or via an explicit wrapper `run_send_generic_secret` that calls `run_send(..., MaterialVariant::GenericSecret)` for back-compat). Flag for explicit plan-level decision — the call-site migration is the biggest change this surfaces.

---

## Metadata

**Analog search scope:** `src/**/*.rs`, `tests/**/*.rs`, `tests/fixtures/`, `Cargo.toml`
**Files scanned:** 18 (7 source files, 11 test files + 4 fixture files + 1 Cargo.toml)
**Pattern extraction date:** 2026-04-24

## PATTERN MAPPING COMPLETE
