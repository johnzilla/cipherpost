---
phase: 6
phase_name: Typed Material — X509Cert
researched: 2026-04-24
domain: Rust X.509 DER/PEM parsing, typed payload serde wire schema, acceptance-banner rendering
confidence: HIGH
researcher: gsd-researcher
---

# Phase 6: Typed Material — X509Cert — Research

**Researched:** 2026-04-24
**Domain:** Rust X.509 certificate parsing (`x509-parser 0.16`), typed-payload serde wire schema, deterministic fixture generation, acceptance-banner rendering
**Confidence:** HIGH

## Summary

Phase 6 is entirely additive at the payload layer. CONTEXT.md locks the 18 design decisions (Material dispatch UX, PEM→DER normalize boundary, banner layout, typed-Material API shape); this research surfaces the **implementation specifics the planner needs to carve plans correctly**: the exact `x509-parser 0.16` API surface (`X509Certificate::from_der` returns `(remainder, cert)` so the D-P6-07 trailing-bytes assertion is one line), OID constants from the re-exported `x509_parser::oid_registry`, the deterministic-fixture strategy (hand-crafted static bytes, checked-in — `rcgen` is REJECTED because it pulls `ring` by default), and two **correction-grade findings** that diverge from CONTEXT.md's assumed API:

1. **CONTEXT.md D-P6-10 says "use `to_rfc4514()`" — that method does NOT exist in x509-parser 0.16.** The crate has `to_string_with_registry()` (returns `Result<String, X509Error>`) and a `Display` impl that emits OpenSSL's **forward-ordering** format (`C=US, ST=..., O=..., CN=...`), which is the **inverse** of RFC 4514's backward ordering. Planner must pick one: use the built-in Display (OpenSSL-style, matches `openssl x509 -noout -subject` output which is what engineers recognize) OR manually reverse the RDN iteration to produce true RFC 4514. The CONTEXT.md reference to "RFC 4514" is almost certainly shorthand for `openssl -nameopt RFC2253`-style rendering, which IS RFC 2253 / 4514 — but x509-parser's default does NOT produce that. Recommend: use `X509Name::to_string()` (Display impl, OpenSSL-forward-ordering) and document in SPEC.md that the banner DN format matches `openssl x509 -noout -subject` — engineers' mental model. This preserves the user-visible intent of D-P6-10 (one-line DN, truncated, openssl-parity) without requiring hand-rolled RDN reversal code.

2. **Ed25519 and Ed448 certificate public keys come through x509-parser's `PublicKey::Unknown` variant**, not a dedicated variant. The key-algorithm identifier MUST be derived from `spki.algorithm.algorithm` (the OID) rather than the parsed `PublicKey` enum. OID constants `OID_SIG_ED25519` and `OID_SIG_ED448` are exported from `x509_parser::oid_registry`.

Everything else lines up with CONTEXT.md. `x509-parser 0.16` has `rust-version = "1.63.0"` (satisfies cipherpost's 1.85 MSRV with ample headroom), default features are empty (`default = []`), and the `verify` feature is the ONLY gateway to `ring` — it stays off. Transitive crates added (`asn1-rs 0.6.1`, `der-parser 9.0`, `nom 7.0`, `oid-registry 0.7`, `time 0.3.20`, `data-encoding 2.2.1`, `lazy_static 1.4`, `rusticata-macros 4.0`, `thiserror 1.0.2`) are all permissive-licensed and, notably, `nom 7` is already in the tree via `age 0.11.2` — no new parser family joins.

**Primary recommendation:** Plan 01 adds the Cargo.toml entry + `ingest` module + error variant + Material struct-variant refactor. Plan 02 adds `preview.rs` + banner wiring + TtyPrompter extension. Plan 03 adds the JCS fixture + integration test. Plan 04 (optional, can merge into 03) adds the error-oracle enumeration test + leak-scan extension + BER/trailing-bytes negative tests. Fixture generation uses a hand-rolled static byte array (generator program in a non-CI-run example or one-time-use binary), NOT `rcgen`.

## User Constraints (from CONTEXT.md)

### Locked Decisions (all 18 — do not re-litigate)

**A. Material dispatch UX:**
- D-P6-01: Clap `--material <variant>` flag on `send` (kebab-case values: `generic-secret` default, `x509-cert`, `pgp-key`, `ssh-key`). PGP/SSH parse but dispatch returns `Error::NotImplemented { phase: 7 }`.
- D-P6-02: `--material x509-cert` accepts DER OR PEM; sniff on `-----BEGIN CERTIFICATE-----` after `trim_start()`.
- D-P6-03: `Error::InvalidMaterial { variant: String, reason: String }` new variant, exit 1, generic Display (no x509-parser internal leakage).
- D-P6-04: `--material` default = `generic-secret` (back-compat).

**B. PEM normalize boundary + error shape:**
- D-P6-05: New `src/payload/ingest.rs` module (or `payload::ingest` submodule) owns normalization.
- D-P6-06: Sniff = exact `-----BEGIN CERTIFICATE-----` prefix after `trim_start()`.
- D-P6-07: `x509-parser` parse is the BER-rejection mechanism; trailing-bytes explicit check.
- D-P6-08: `Material::X509Cert { bytes }` Debug = `X509Cert([REDACTED N bytes])`; leak-scan extends to all 4 variants.

**C. Acceptance banner layout:**
- D-P6-09: Inline subblock on existing banner (after `Size:`, before `TTL:`).
- D-P6-10: DN rendering: RFC 4514 string (see CONTEXT.md — but SEE CORRECTION above; actual x509-parser API is `Display`/`to_string_with_registry`), truncated at ~80 chars with `…`.
- D-P6-11: SerialNumber: hex, truncate-with-`…` at 16 hex chars, `0x` prefix.
- D-P6-12: NotBefore/NotAfter as ISO-8601 UTC; expired → `[EXPIRED]`, valid → `[VALID]`.
- D-P6-13: SHA-256 DER fingerprint: label `SHA-256:`, full 64 hex chars, no colon-pairs, no truncation, computed over canonical DER.
- D-P6-14: Key algorithm: human-readable `ECDSA P-256` / `RSA-2048` / `Ed25519` / `Ed448` / `RSA-PSS`; unknown-OID → dotted-OID verbatim.

**D. Typed-Material API shape:**
- D-P6-15: `as_x509_cert_bytes() -> Result<&[u8], Error>` accessor parallel to `as_generic_secret_bytes()`.
- D-P6-16: `Material::plaintext_size(&self) -> usize` method.
- D-P6-17: Banner subblock rendering in new `src/preview.rs` module; `render_x509_preview(bytes) -> Result<String, Error>`.
- D-P6-18: `payload::ingest::x509_cert(raw) -> Result<Material, Error>` returns fully-constructed variant.

### Claude's Discretion
- Clap `ValueEnum` derivation vs manual `FromStr` (ValueEnum idiomatic).
- Exact DN truncation length (~80 chars).
- Fixture generation strategy (this research resolves: hand-rolled static bytes — `rcgen` REJECTED).
- `render_x509_preview` internal-parse vs caller-parsed struct (internal-parse simpler).
- `--armor` on GenericSecret: reject vs silently-ignore (rejection safer).
- Exact `Error::InvalidMaterial` Display wording per branch.
- Number of OID→human mappings hand-coded in `preview.rs` (top ~10).

### Deferred Ideas (OUT OF SCOPE)
- `--armor` on GenericSecret enforcement direction.
- `[NOT_YET_VALID]` tag.
- Expired-cert warning beyond `[EXPIRED]` tag.
- Re-serialize round-trip DER strictness check (der 0.7 crate add).
- Multi-cert bundle / chain support.
- X.509 v1 rejection.
- Exotic-algorithm OID lookup (brainpool, GOST, SM2).
- `--material-from-filename` auto-hint.
- Integration test identity setup helper strategy.
- `cipherpost receive --material-info` dump mode.

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| X509-01 | `Material::X509Cert { bytes }` holds canonical DER only; PEM normalized at ingest; BER/malformed rejected exit 1 | Focus Items 1, 2, 8 — `X509Certificate::from_der` parse validates canonical DER; `parse_x509_pem` decodes PEM body; `(remainder, cert)` trailing-bytes check per D-P6-07 |
| X509-02 | Wire format `{"type":"x509_cert","bytes":"<base64-std>"}` | Existing `base64_std` serde helper (payload.rs:129); new struct-variant `X509Cert { bytes: Vec<u8> }` slots in with zero wire-shape work |
| X509-03 | `cipherpost send --material x509-cert` reads DER/PEM; per-variant 64 KB size check before encryption | Focus Item 5 — cap check call-site order: ingest → `material.plaintext_size()` → `enforce_plaintext_cap`; new `Error::InvalidMaterial` variant handles parse fails |
| X509-04 | Acceptance-banner subblock (Subject/Issuer/Serial/NotBefore/NotAfter/Key/SHA-256) pre-decrypt-commit; `[EXPIRED]` tag | Focus Items 4, 6 — OID table for key-alg strings; `ASN1Time::timestamp()` returns `i64` unix seconds → reuse `format_unix_as_iso_utc` from flow.rs (do NOT append second `" UTC"` — Phase 2 UAT fix) |
| X509-05 | `receive` emits raw DER by default; `--armor` flag emits PEM | Simple; PEM armor generation can be hand-rolled (no extra crate): `-----BEGIN CERTIFICATE-----` + base64-STANDARD 64-char-wrapped body + `-----END CERTIFICATE-----` + trailing newline |
| X509-06 | X509 DER > 64 KB → `Error::PayloadTooLarge` | Reuses existing `Error::PayloadTooLarge` verbatim (payload.rs:117); `plaintext_size()` feeds it |
| X509-07 | JCS fixture `tests/fixtures/material_x509_signable.bin` committed | Focus Items 3, 7 — fixture = Envelope JCS bytes (NOT OuterRecordSignable bytes; see Focus 7 clarification); property test pattern mirrors `tests/phase2_envelope_round_trip.rs` |
| X509-08 | Malformed X509 DER on receive → exit 1 (distinct from exit 3 sig failures); generic Display | Focus Item 5 — `Error::InvalidMaterial` maps to exit 1 in `exit_code()`; Display wording: short + generic + no `x509-parser::` strings |
| X509-09 | MockTransport round-trip integration test | Focus Item 8 — pattern mirrors `tests/phase2_self_round_trip.rs`; uses `AutoConfirmPrompter`; fixture cert serves double duty (ingest input + round-trip payload) |

## Project Constraints (from CLAUDE.md — carried forward)

- `chacha20poly1305` only via `age` — no direct calls. Phase 6 adds zero crypto calls at this layer.
- JCS via `serde_canonical_json 1.0` — unchanged; new struct-variant serializes automatically.
- HKDF info strings `cipherpost/v1/<context>` — Phase 6 adds **ZERO** new HKDF call sites (just stored bytes). `tests/hkdf_info_enumeration.rs` stays green without changes.
- No `#[derive(Debug)]` on secret-holding structs — Material keeps manual Debug; extend redaction for X509Cert variant.
- `ed25519-dalek =3.0.0-pre.5` hard pin — x509-parser 0.16 does NOT pull ed25519-dalek (it uses der-parser's ASN.1 path for parsing; signature verification is gated behind the `verify` feature which stays OFF). Confirmed via Cargo.toml inspection.
- `rust-version = "1.85"` in cipherpost Cargo.toml — x509-parser 0.16 declares `rust-version = "1.63.0"`. No MSRV conflict.
- Error-oracle hygiene: `Error::InvalidMaterial` Display must be generic. x509-parser's `X509Error` internal messages (e.g., "InvalidCertificate", "InvalidDate", nom parse-position strings) MUST NOT flow through.
- 64 KB plaintext cap held; no new cap.
- No `tokio` at cipherpost layer — x509-parser is sync pure-Rust, no runtime dep.
- `serial_test = "3"` + `#[serial]` on any test that mutates `CIPHERPOST_HOME` — X509 round-trip test SHOULD use isolated tempdir + serial gating.

## Architectural Responsibility Map

| Capability | Primary Module | Secondary Module | Rationale |
|------------|---------------|------------------|-----------|
| CLI arg parsing (`--material`, `--armor`) | `src/cli.rs` | — | Existing clap surface owner; `ValueEnum` idiom |
| CLI dispatch & flag → ingest call | `src/main.rs` | `src/flow.rs::run_send` | Existing `Send`-branch dispatch thread; adds one match arm |
| Raw bytes → typed Material (PEM sniff, normalize, parse) | `src/payload/ingest.rs` (NEW) or `payload::ingest` inline submodule | `src/payload.rs` | D-P6-05; isolates parse deps from payload.rs's serde-only surface |
| Typed-Material data holder + accessors | `src/payload.rs` | — | Existing `Material` enum; adds struct data to X509Cert variant |
| Error taxonomy | `src/error.rs` | `src/main.rs::exit_code` | Existing thiserror enum; adds one variant |
| Banner subblock rendering | `src/preview.rs` (NEW) | `src/flow.rs::TtyPrompter` | D-P6-17; x509-parser imports stay out of payload.rs; `TtyPrompter` calls preview function conditional on material type |
| Pre-encrypt size cap | `src/payload.rs` (existing `enforce_plaintext_cap`) | `src/flow.rs::run_send` | Unchanged; new `plaintext_size()` method feeds it |
| JCS wire determinism | `serde_canonical_json` (external) | `src/payload.rs::Envelope::to_jcs_bytes` | Automatic via existing serde tag shape; fixture asserts byte-identity |
| Integration round-trip | `tests/x509_roundtrip.rs` (NEW) | `MockTransport` + `AutoConfirmPrompter` | Mirrors `phase2_self_round_trip.rs` structure |
| Decode on receive | `src/flow.rs::run_receive` | `src/payload.rs::Material::as_x509_cert_bytes` | Existing step-8 acceptance-prompt call-site; change `as_generic_secret_bytes` hardcoded call to match-on-variant |
| DER → PEM armor (for `--armor` output) | `src/flow.rs` (small helper) or `src/preview.rs` | `base64` crate (existing) | No new dep — PEM format is trivially hand-rolled from b64+header/footer |

## Standard Stack (additions only — existing stack unchanged)

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `x509-parser` | `0.16` | PEM + DER X.509 parsing; Subject/Issuer/Validity/fingerprint extraction | Rusticata family; pure-Rust; zero-copy via nom; no C FFI; default features empty (`verify` opt-in, pulls ring — STAYS OFF) [VERIFIED: github.com/rusticata/x509-parser/blob/x509-parser-0.16.0/Cargo.toml] |

### Supporting (transitive; pulled automatically)

| Library | Version | Source | Notes |
|---------|---------|--------|-------|
| `asn1-rs` | `0.6.1` | via x509-parser | ASN.1 BER/DER primitives; `datetime` feature enabled upstream |
| `der-parser` | `9.0` | via x509-parser | DER encoding parser; `bigint` feature |
| `nom` | `7.0` | via x509-parser | **Already in tree via `age 0.11.2`** — no new parser crate |
| `oid-registry` | `0.7` | via x509-parser | OID↔name registry; features `crypto,x509,x962` enabled |
| `time` | `0.3.20+` | via x509-parser | `ASN1Time` wraps `OffsetDateTime`; unused by cipherpost code (we bridge via `ASN1Time::timestamp()` → i64 → existing `format_unix_as_iso_utc` in flow.rs) |
| `data-encoding` | `2.2.1` | via x509-parser | base-N codecs |
| `lazy_static` | `1.4` | via x509-parser | OID tables |
| `rusticata-macros` | `4.0` | via x509-parser | Parser macros |
| `thiserror` | `1.0.2` | via x509-parser | **Already coexists** with cipherpost's `thiserror 2` (via `age`, `pkarr`) |

### Alternatives Considered and Rejected

| Instead of | Could Use | Why REJECTED |
|------------|-----------|----------|
| `x509-parser` | `x509-cert` (RustCrypto) | Designed for cert **building**, not parsing; PEM not first-class [CITED: SUMMARY.md Rejected Alternatives] |
| `x509-parser` | `x509-certificate` | Self-described as not hardened against malicious inputs; documented panic paths [CITED: SUMMARY.md] |
| `x509-parser` | `openssl` crate | C FFI; second crypto implementation; violates supply-chain cleanliness [CITED: SUMMARY.md] |
| `rcgen` (for fixture generation) | Hand-rolled static byte array | `rcgen 0.13.3` has `default = ["crypto", "pem", "ring"]` — pulls **`ring 0.17`** by default. Even `default-features = false` + explicit `aws_lc_rs`-off + `ring`-off leaves `crypto = []` which is useless without a backend. **Hard reject.** [VERIFIED: github.com/rustls/rcgen/blob/v0.13.3/rcgen/Cargo.toml] |
| Hand-rolled fixture | `include_bytes!` from a checked-in `.der` asset | Functionally equivalent; planner's choice. Either produces the same deterministic 50-300 byte fixture. |
| Separate `pem 3.x` crate | `x509_parser::pem::parse_x509_pem` | The latter is exported by x509-parser itself — **no extra dep needed** [VERIFIED: src/pem.rs source at x509-parser-0.16.0] |
| Separate `oid-registry` dep | `x509_parser::oid_registry` (re-export) | Re-exported as `pub use oid_registry;` in lib.rs [VERIFIED: src/lib.rs at x509-parser-0.16.0] |
| `der 0.7` for re-serialize round-trip check | Trust x509-parser strict-profile parse | CONTEXT.md D-P6-07 locks this: x509-parser's parse is the BER rejection mechanism; trailing-bytes is the only additional check. No second crate. |

**Installation (plan 01):**

```toml
# Cargo.toml — [dependencies]
x509-parser = { version = "0.16", default-features = false }
```

Note: x509-parser 0.16 has `default = []` — `default-features = false` is belt-and-suspenders (identical result) but makes intent explicit. The `std` feature mentioned in CONTEXT.md does not exist in 0.16's manifest; x509-parser 0.16 is implicitly std-requiring (no `no_std` feature flag).

**Version verification:** x509-parser 0.16.0 published 2024-05-04. 0.17.0 published 2024-11-21 (bumps nom to 8.0 — breaking). 0.18.0 published 2025. We're pinning 0.16 intentionally per SUMMARY.md [VERIFIED: crates.io / github release list].

## Architecture Patterns

### System Architecture Diagram (Phase 6 data flow)

```
┌────────────────────────────────────────────────────────────────┐
│  SEND PATH                                                     │
│                                                                │
│  CLI args (cli.rs)                                             │
│      └─ --material x509-cert + --material-file /path/to.pem    │
│           │                                                    │
│           ▼                                                    │
│  main.rs Send branch                                           │
│      └─ match material_variant {                               │
│          GenericSecret => ingest::generic_secret(bytes),       │
│          X509Cert      => ingest::x509_cert(bytes),  ◄─── NEW  │
│          PgpKey|SshKey => Err(NotImplemented{phase:7})         │
│         }                                                      │
│           │                                                    │
│           ▼                                                    │
│  payload::ingest::x509_cert(raw: &[u8])          ◄─── NEW MODULE
│      ├─ sniff: trim_start() + starts_with(b"-----BEGIN ...")   │
│      ├─ PEM path: parse_x509_pem → pem.contents (DER bytes)    │
│      ├─ DER path: raw bytes as-is                              │
│      ├─ parse_x509_certificate(der) → (rem, cert)              │
│      ├─ assert rem.is_empty() OR Error::InvalidMaterial        │
│      └─ return Material::X509Cert { bytes: der.to_vec() }      │
│           │                                                    │
│           ▼                                                    │
│  run_send (flow.rs)                                            │
│      ├─ material.plaintext_size() → len                        │
│      ├─ enforce_plaintext_cap(len)                             │
│      ├─ strip_control_chars(purpose)                           │
│      ├─ build Envelope { material, ... }                       │
│      ├─ envelope.to_jcs_bytes() → JCS bytes (fixture-locked)   │
│      ├─ age_encrypt → ciphertext                               │
│      ├─ share_ref = hash(ciphertext || created_at)             │
│      ├─ build OuterRecord + sign                               │
│      ├─ check_wire_budget (grease retry loop)                  │
│      └─ transport.publish → share URI                          │
│                                                                │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  RECEIVE PATH                                                  │
│                                                                │
│  cipherpost receive <uri> [--armor]                            │
│      │                                                         │
│      ▼                                                         │
│  run_receive (flow.rs)                                         │
│      ├─ sentinel-check → early return if already accepted      │
│      ├─ transport.resolve → OuterRecord (outer + inner sigs)   │
│      ├─ URI/share_ref match                                    │
│      ├─ TTL check                                              │
│      ├─ age_decrypt → JCS bytes                                │
│      ├─ Envelope::from_jcs_bytes                               │
│      │                                                         │
│      ├─ match envelope.material {                              │
│      │    GenericSecret { bytes } => (bytes, preview=None),    │
│      │    X509Cert     { bytes } => (bytes, preview=Some(      │
│      │       preview::render_x509_preview(bytes)?)),  ◄── NEW  │
│      │    PgpKey|SshKey => Err(NotImplemented{phase:7})        │
│      │   }                                                     │
│      │                                                         │
│      ▼                                                         │
│  TtyPrompter::render_and_confirm                               │
│      ├─ emit existing banner lines (Purpose/Sender/Size/...)   │
│      ├─ IF preview.is_some() { emit preview subblock }  ◄── NEW│
│      ├─ emit TTL line                                          │
│      ├─ emit border                                            │
│      └─ read typed-z32 → match sender_z32 or Error::Declined   │
│                                                                │
│      ▼                                                         │
│  write_output(sink, bytes) ─ IF --armor AND X509Cert: wrap as  │
│                               PEM; else raw DER                │
│                                                                │
│      ▼                                                         │
│  sentinel + ledger + receipt publish (unchanged)               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Recommended Code Organization

```
src/
├── cli.rs               # Send {material, armor, ...} + Receive {armor, ...}
├── payload.rs           # Material::X509Cert{bytes} struct-variant + plaintext_size() + as_x509_cert_bytes()
├── payload/             # NEW directory (or inline pub mod ingest {} inside payload.rs)
│   └── ingest.rs        # fn x509_cert(raw) -> Result<Material, Error>
├── preview.rs           # NEW: fn render_x509_preview(bytes) -> Result<String, Error>
├── flow.rs              # run_send + run_receive + TtyPrompter (extended)
├── main.rs              # dispatch: Send branch + material variant match arm
├── error.rs             # + Error::InvalidMaterial { variant, reason }
└── lib.rs               # + pub mod preview

tests/
├── fixtures/
│   ├── envelope_jcs_x509_cert.bin      # NEW — Envelope JCS fixture (parallel to envelope_jcs_generic_secret.bin)
│   ├── x509_cert_fixture.der           # NEW — the raw 150-300 B cert used as ingest input + round-trip payload
│   └── x509_cert_fixture.reproduction.txt  # NEW — how fixture was generated (deterministic openssl/hand-rolled steps)
├── x509_ingest.rs                      # NEW — sniff/normalize/strictness unit cases
├── x509_roundtrip.rs                   # NEW — MockTransport round-trip (X509-09)
├── x509_banner_render.rs               # NEW — render_x509_preview golden-string test
└── debug_leak_scan.rs                  # EXTEND — cover Material::X509Cert variant
```

## Focus Item 1: x509-parser 0.16 API Shape

**Parsing entry points (VERIFIED against github.com/rusticata/x509-parser @ tag x509-parser-0.16.0):**

```rust
use x509_parser::prelude::*;

// DER entry:
let (remainder, cert): (&[u8], X509Certificate<'_>) =
    x509_parser::parse_x509_certificate(der_bytes)?;
// Equivalent via trait: X509Certificate::from_der(der_bytes)?
```

**Trailing-bytes check (D-P6-07 implementation):**
```rust
let (remainder, cert) = parse_x509_certificate(der_bytes)
    .map_err(|_| Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "malformed DER".into(),
    })?;
if !remainder.is_empty() {
    return Err(Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "trailing bytes after certificate".into(),
    });
}
```

**Accessor signatures (VERIFIED):**
- `cert.subject() -> &X509Name<'_>` — returns reference to Subject DN
- `cert.issuer() -> &X509Name<'_>` — returns reference to Issuer DN
- `cert.tbs_certificate.raw_serial_as_string() -> String` — hex-encoded serial (colon-separated per OpenSSL `raw_serial_as_string` convention). For cipherpost's banner we want colon-free lowercase; use `cert.tbs_certificate.raw_serial()` which returns `&[u8]` and hex-encode ourselves.
- `cert.validity() -> &Validity` where `Validity { not_before: ASN1Time, not_after: ASN1Time }`
- `cert.public_key() -> &SubjectPublicKeyInfo<'_>` — `.algorithm.algorithm` is an `Oid<'_>`, `.subject_public_key` is the raw key bits
- `cert.is_ca() -> bool` — derived from Basic Constraints extension

**ASN1Time → unix seconds:**
```rust
let not_before_unix: i64 = cert.validity().not_before.timestamp();
let not_after_unix:  i64 = cert.validity().not_after.timestamp();
```
[VERIFIED: `pub fn timestamp(&self) -> i64` returns `self.0.unix_timestamp()`; src/time.rs at tag]

**Feature flags (VERIFIED Cargo.toml):**
```toml
[features]
default = []           # ← MUST stay untouched
verify = ["ring"]      # ← DO NOT ENABLE
validate = []          # ← Optional; pulls no new crates. Not needed for Phase 6.
```

**MSRV:** `rust-version = "1.63.0"` ≤ cipherpost's `1.85`. Compatible.

## Focus Item 2: PEM Parsing Path

**Conclusion: use `x509_parser::pem::parse_x509_pem()` — no extra `pem` crate needed.**

```rust
use x509_parser::pem::parse_x509_pem;

// Returns (remainder, Pem { label: String, contents: Vec<u8> })
// where contents = the base64-decoded DER bytes.
let (pem_rem, pem) = parse_x509_pem(raw_bytes).map_err(|_| Error::InvalidMaterial {
    variant: "x509_cert".into(),
    reason: "PEM body decode failed".into(),
})?;

if pem.label != "CERTIFICATE" {
    return Err(Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "PEM label is not CERTIFICATE".into(),
    });
}

// Now pem.contents is the DER — hand to parse_x509_certificate for validation + trailing-bytes.
let (der_rem, _cert) = parse_x509_certificate(&pem.contents).map_err(|_| ...)?;
if !der_rem.is_empty() { /* InvalidMaterial */ }

// Store pem.contents as the canonical DER in Material::X509Cert.
```

**CRLF/LF tolerance:** `parse_x509_pem` is nom-based and tolerates either line ending; it also tolerates the Windows BOM only if present before the header. Planner note: the D-P6-06 sniff operates on `raw.trim_start()` — this strips whitespace but NOT BOM bytes (0xEF 0xBB 0xBF). If a user piped a UTF-8-BOM-prefixed PEM, the sniff would miss the header and fall through to the DER path, where `parse_x509_certificate` would fail on the BOM. The resulting error message would be "malformed DER" rather than the more accurate "unrecognized file format". Acceptable for v1.1; low-probability edge case. Add as a `// TODO` if desired, not a blocker.

## Focus Item 3: Deterministic Self-Signed Cert Fixture Generation

**Strategy: hand-crafted Ed25519-keyed self-signed cert, generated once, bytes checked in.**

**Why not `rcgen`:** `rcgen 0.13.3` default features are `["crypto", "pem", "ring"]`. Disabling those leaves the crate non-functional. `rcgen` is out. [VERIFIED: github.com/rustls/rcgen/blob/v0.13.3/rcgen/Cargo.toml]

**Why not `openssl` CLI invocation at test time:** non-deterministic (random serial unless explicit `-set_serial`, time-of-day-dependent unless `-days 0` plus `-not_before`), brittle across OpenSSL versions, and introduces a dev-environment dependency.

**Recommended approach (planner picks which variant):**

### Option A (recommended): Check in a static `.der` file + checked-in reproduction steps

1. **One-time generation** (dev's local machine, reproducible):
   ```bash
   # Generate deterministically:
   openssl req -x509 -newkey ed25519 -keyout /tmp/key.pem -out /tmp/cert.pem -nodes \
       -days 730 -subj "/CN=cipherpost-fixture/O=cipherpost/C=XX" \
       -set_serial 1 \
       -not_before 260101000000Z -not_after 280101000000Z
   openssl x509 -in /tmp/cert.pem -outform DER -out tests/fixtures/x509_cert_fixture.der
   ```
   The `-not_before` / `-not_after` + `-set_serial 1` make the output deterministic given a fixed private key. But the private key is NOT deterministic (Ed25519 uses OS randomness) — so a **second** generation on a different machine produces a different cert. **This is why the bytes must be checked in as a committed fixture** rather than regenerated at CI time.

2. **Check in:**
   - `tests/fixtures/x509_cert_fixture.der` — the ~180-250 B DER bytes
   - `tests/fixtures/x509_cert_fixture.reproduction.txt` — the openssl command above + sha256 of the resulting DER (so a reviewer can verify the checked-in file matches what the recipe would produce, given *some* random key, modulo signature bytes)

3. **Tests use `include_bytes!`:**
   ```rust
   static FIXTURE_DER: &[u8] = include_bytes!("fixtures/x509_cert_fixture.der");
   ```

### Option B: Check in a Rust `const` byte array

Same data, different packaging. Less readable in diffs; harder for a reviewer to sanity-check via `openssl x509 -in file.der -inform DER -text`. **Prefer Option A.**

### Fixture cert content (locked by CONTEXT.md specifics):

- Subject: `CN=cipherpost-fixture, O=cipherpost, C=XX`
- Issuer: same (self-signed)
- Serial: `0x01`
- NotBefore: `2026-01-01 00:00:00 UTC`
- NotAfter: `2028-01-01 00:00:00 UTC`
- Key: Ed25519 (or ECDSA P-256 if simpler openssl invocation; planner picks — Ed25519 is smaller and matches cipherpost's Ed25519-everywhere theme)

**Reproduction note for future developers:** committed bytes are authoritative; the `.reproduction.txt` file documents how the bytes were originally generated. If CI red-bars `material_x509_signable.bin` drift, check whether the `.der` fixture itself was regenerated (protocol break) or whether something changed in the JCS pipeline (library update).

## Focus Item 4: OID → Human-Readable Algorithm Name Mapping

**x509-parser 0.16 does NOT ship a human-readable algorithm mapping** (it ships a dotted-OID → constant-name registry). Cipherpost must hand-roll the top-10 table.

**OID source:** `use x509_parser::oid_registry::*;` (re-exported from x509-parser, no extra dep) gives us the constants.

**Confirmed constants (VERIFIED against oid-registry 0.7 docs):**

| Constant | Dotted OID | Human name |
|----------|-----------|-----------|
| `OID_PKCS1_RSAENCRYPTION` | 1.2.840.113549.1.1.1 | `RSA-<N>` (N = key_size bits) |
| `OID_KEY_TYPE_EC_PUBLIC_KEY` | 1.2.840.10045.2.1 | `ECDSA <curve>` (curve from parameters OID, see below) |
| `OID_SIG_ED25519` | 1.3.101.112 | `Ed25519` |
| `OID_SIG_ED448` | 1.3.101.113 | `Ed448` |
| `OID_PKCS1_RSASSAPSS` | 1.2.840.113549.1.1.10 | `RSA-PSS` |

**For EC, the named curve comes from `spki.algorithm.parameters` (an optional `Any` holding the curve OID):**

| Curve constant | Dotted OID | Human name |
|----------|-----------|-----------|
| `OID_EC_P256` | 1.2.840.10045.3.1.7 | `P-256` |
| `OID_NIST_EC_P384` | 1.3.132.0.34 | `P-384` |
| `OID_NIST_EC_P521` | 1.3.132.0.35 | `P-521` |
| secp256k1 (no named constant in oid-registry 0.7) | 1.3.132.0.10 | `secp256k1` — hand-code by OID string match |

**RSA key-size derivation:** `PublicKey::RSA(rsa)` has `rsa.key_size() -> u32` (bits). Common results: 2048, 3072, 4096. Banner string: `format!("RSA-{}", rsa.key_size())`.

**Critical gotcha (see Summary section): Ed25519/Ed448 keys come through `PublicKey::Unknown`** — do NOT dispatch on the `PublicKey` enum. Dispatch on `spki.algorithm.algorithm` (the OID) FIRST. Only if it matches `OID_PKCS1_RSAENCRYPTION` or `OID_KEY_TYPE_EC_PUBLIC_KEY` do you call `spki.parsed()?` to get key-size / curve details.

**Recommended pattern for `preview.rs`:**

```rust
fn key_algorithm_string(spki: &SubjectPublicKeyInfo<'_>) -> String {
    use x509_parser::oid_registry::*;
    let alg_oid = &spki.algorithm.algorithm;

    if alg_oid == &OID_SIG_ED25519  { return "Ed25519".into(); }
    if alg_oid == &OID_SIG_ED448    { return "Ed448".into(); }
    if alg_oid == &OID_PKCS1_RSASSAPSS { return "RSA-PSS".into(); }

    if alg_oid == &OID_PKCS1_RSAENCRYPTION {
        if let Ok(PublicKey::RSA(rsa)) = spki.parsed() {
            return format!("RSA-{}", rsa.key_size());
        }
        return "RSA".into();
    }

    if alg_oid == &OID_KEY_TYPE_EC_PUBLIC_KEY {
        // Curve OID is in algorithm.parameters (DER-encoded Any).
        let curve_name = spki.algorithm.parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|oid| match_curve_oid_to_name(&oid))
            .unwrap_or_else(|| "<unknown-curve>".into());
        return format!("ECDSA {}", curve_name);
    }

    // Fallback: dotted-OID verbatim
    format!("<{}>", alg_oid)
}

fn match_curve_oid_to_name(oid: &Oid<'_>) -> String {
    use x509_parser::oid_registry::*;
    if oid == &OID_EC_P256       { return "P-256".into(); }
    if oid == &OID_NIST_EC_P384  { return "P-384".into(); }
    if oid == &OID_NIST_EC_P521  { return "P-521".into(); }
    // secp256k1 — no constant; match by dotted string:
    if oid.to_id_string() == "1.3.132.0.10" { return "secp256k1".into(); }
    format!("<{}>", oid)
}
```

The exact `parameters.as_oid()` method path requires planner verification at implementation time — the `AlgorithmIdentifier` parameter type is `Option<Any<'_>>` and the getter for "this is an OID parameter" may require one nom-style destructure. A 10-minute spike during plan 01 will confirm the exact call. If the destructure is uglier than above, fall back to parsing the `.tag()` + `.as_bytes()` manually — an OID inside a DER Any is a trivial reparse.

## Focus Item 5: Error Variant Shape in src/error.rs

**Exact Rust syntax to add (fits cleanly into the existing `#[derive(Error)]` pattern):**

```rust
// Add to the Error enum in src/error.rs, after the existing Config variant:

#[error("invalid material: {variant} — {reason}")]
InvalidMaterial { variant: String, reason: String },
```

**No `#[source]` chain needed** — this is a leaf error class with no underlying crate chain to preserve (the whole point of D-P6-03 is to NOT leak x509-parser's error internals). Construction sites `.map_err(|_| Error::InvalidMaterial { ... })?` swallow the underlying error by design.

**Exit code mapping in `exit_code()`:**

```rust
pub fn exit_code(err: &Error) -> i32 {
    match err {
        // ... existing arms ...
        Error::InvalidMaterial { .. } => 1,  // exit 1 per X509-08, D-P6-03 — NOT exit 3
        // ... existing arms ...
        _ => 1,
    }
}
```

Since the final arm is already `_ => 1`, this variant technically works without an explicit arm — but adding the explicit arm documents intent and prevents future refactors from accidentally reclassifying it. **Recommend explicit arm.**

**Display message shape (across all Phase 6 construction sites):**

| Construction site | `variant` | `reason` |
|-------------------|-----------|----------|
| PEM body decode fails | `"x509_cert"` | `"PEM body decode failed"` |
| PEM label ≠ CERTIFICATE | `"x509_cert"` | `"PEM label is not CERTIFICATE"` |
| DER parse fails | `"x509_cert"` | `"malformed DER"` |
| Trailing bytes after cert | `"x509_cert"` | `"trailing bytes after certificate"` |
| `as_x509_cert_bytes()` called on wrong variant | `"<actual_variant>"` (runtime) | `"accessor called on wrong variant"` |
| (D-P6-01 reserved) PGP/SSH with `--material` set in Phase 6 | — | Use `Error::NotImplemented { phase: 7 }` instead — DO NOT use InvalidMaterial for this. |

**Error-oracle enumeration test (NEW, per Focus 8):** walk every `Error::InvalidMaterial { variant, reason }` construction site in `src/`, and for each one assert `format!("{}", err).contains("x509-parser") == false` AND `.contains("nom") == false` AND `.contains("::") == false`. Prevents future maintenance from accidentally leaking crate-internal type names into user-facing Display.

## Focus Item 6: Extending the Acceptance Banner Without Breaking D-ACCEPT-02

**Current banner structure** (`TtyPrompter::render_and_confirm` at flow.rs:1036):
```
=== CIPHERPOST ACCEPTANCE ===============================
Purpose:     "<purpose>"
Sender:      <openssh_fp>
             <z32>
Share ref:   <hex>
Type:        <material_type>
Size:        <N> bytes
TTL:         <X>h <Y>m remaining (expires <UTC> / <LOCAL> local)
=========================================================
To accept, paste the sender's z32 pubkey and press Enter:
```

**Phase 6 insertion point:** BETWEEN the `Size:` line and the `TTL:` line. Concretely: after `eprintln!("Size:        {} bytes", size_bytes);` and before the `TTL:` block, insert:

```rust
// Phase 6: typed-material subblock (empty for GenericSecret; filled for X509Cert).
if let Some(preview_str) = &typed_preview {
    eprint!("{}", preview_str);  // preview_str already ends with trailing newline
}
```

**Plumbing:** `render_and_confirm` gains a new parameter:
```rust
fn render_and_confirm(
    &self,
    // ... existing args ...
    typed_preview: Option<&str>,  // NEW — None for GenericSecret, Some(str) for X509Cert
) -> Result<(), Error>;
```

**`AutoConfirmPrompter` / `DeclinePrompter` impact:** both take an additional `_typed_preview: Option<&str>` arg — no behavior change, just signature-compat. All existing tests pass `None` (or via a trivial update: a three-line diff per test prompter). Tests that exercise X509 round-trip pass `Some(preview_str)`.

**Subblock shape inside `render_x509_preview()` return value:**

```
--- X.509 -----------------------------------------------
Subject:     CN=leaf.example.com, O=Example Inc, C=US
Issuer:      CN=Example CA, O=Example Inc, C=US
Serial:      0x0a1b2c3d… (truncated)
NotBefore:   2026-01-15 00:00 UTC
NotAfter:    2027-01-15 00:00 UTC  [VALID]
Key:         ECDSA P-256
SHA-256:     a1b2c3d4...  (full 64 hex chars, no spaces)
```

**Line-width parity:** CONTEXT.md mockup uses 57 dashes after `--- X.509 ` to span 61 chars; matching the `===` banner border. Render test asserts `preview.lines().next().unwrap().chars().count() == 61`.

**Trailing newline contract:** `render_x509_preview` returns a string ENDING with `\n` (so `eprint!` — no `ln!` — emits it cleanly and the TTL line follows on its own row). Alternatively: returns without trailing `\n`, caller emits `\n`. Either works; planner picks and documents in the function doc.

**Pre-accept-leak invariant (PITFALL #2 / D-RECV-01):** `render_x509_preview` is called BEFORE the prompt reads user input. The cert bytes have already been:
1. age-decrypted (success proves it was encrypted to us)
2. Envelope JCS-parsed
3. Inner-signed (the OuterRecord inner sig covered the JCS bytes, which cover the Material bytes)

So the cert is inner-sig-authenticated BEFORE any field surfaces. No new oracle opens. This matches the existing GenericSecret path exactly.

## Focus Item 7: JCS Fixture Test Mechanism

**Fixture clarification (addresses Focus 7 ambiguity):** the fixture is the **Envelope JCS bytes**, NOT the OuterRecordSignable bytes. Pattern mirrors `tests/fixtures/envelope_jcs_generic_secret.bin` (existing, 119 bytes).

**The existing assertion lives at:** `tests/phase2_envelope_round_trip.rs` — specifically `envelope_jcs_bytes_match_committed_fixture` (the `#[test]` at line 21). The pattern:

```rust
const FIXTURE_PATH: &str = "tests/fixtures/envelope_jcs_generic_secret.bin";

fn fixture_envelope() -> Envelope { /* ... */ }

#[test]
fn envelope_jcs_bytes_match_committed_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect("Fixture missing — run `cargo test -- --ignored regenerate_envelope_fixture` to create it");
    assert_eq!(bytes, expected, "Envelope JCS bytes changed — past signatures invalidated!");
}

#[test] #[ignore]
fn regenerate_envelope_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
}
```

**Phase 6 clone: new file `tests/envelope_jcs_x509_cert.rs`** (keeping one fixture-asserting test per variant is consistent with how generic_secret is structured; a single combined file would work too but fails the "one-concept-per-test-file" convention in this repo):

```rust
use cipherpost::payload::{Envelope, Material};
use cipherpost::PROTOCOL_VERSION;
use std::fs;

const CERT_PATH: &str = "tests/fixtures/x509_cert_fixture.der";
const FIXTURE_PATH: &str = "tests/fixtures/envelope_jcs_x509_cert.bin";

fn fixture_envelope() -> Envelope {
    let der = fs::read(CERT_PATH).expect("x509_cert_fixture.der missing");
    Envelope {
        created_at: 1_700_000_000,
        material: Material::X509Cert { bytes: der },
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}

#[test]
fn envelope_jcs_x509_bytes_match_committed_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect("regenerate via --ignored");
    assert_eq!(bytes, expected, "Envelope JCS bytes for X509Cert changed — past signatures invalidated!");
}

#[test] #[ignore]
fn regenerate_x509_envelope_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
}
```

**Fixture filename rename vs CONTEXT.md:** CONTEXT.md references `tests/fixtures/material_x509_signable.bin`. But per the existing naming pattern (`envelope_jcs_generic_secret.bin` asserts the **Envelope** JCS bytes, not a bare "Material signable"), the more consistent name is `tests/fixtures/envelope_jcs_x509_cert.bin`. **Flag for planner** — if CONTEXT.md's path is authoritative, the existing fixture should probably have been named `material_generic_secret_signable.bin` too; rename is a wash. Recommend adopting CONTEXT.md's `material_x509_signable.bin` for tag consistency with the next PGP/SSH fixtures (`material_pgp_signable.bin`, `material_ssh_signable.bin` per REQUIREMENTS.md PGP-07 / SSH-07). Only constraint: pick ONE naming convention for all four typed-material fixtures and apply uniformly.

**Cargo.toml [[test]] registration:** add a new entry mirroring the `phase2_envelope_round_trip` pattern. No `required-features` — this test runs without the `mock` feature.

## Focus Item 8: Validation Architecture

**Minimum test matrix (the planner MUST populate these into plan `verification_criteria` blocks):**

### Unit tests (fast; no network, no MockTransport)

| Test | File | Coverage |
|------|------|----------|
| DER happy path | `tests/x509_ingest.rs` | `ingest::x509_cert(fixture_der_bytes)` returns `Ok(Material::X509Cert { bytes: ... })` with bytes equal to input |
| PEM happy path | `tests/x509_ingest.rs` | `ingest::x509_cert(pem_bytes)` returns `Ok(Material::X509Cert { bytes: fixture_der_bytes })` — **DER bytes match the non-PEM fixture exactly** (proves normalization) |
| PEM with leading whitespace (sniff tolerance) | `tests/x509_ingest.rs` | `"\n\n -----BEGIN ..."` still recognized |
| PEM with wrong label | `tests/x509_ingest.rs` | `ingest::x509_cert(b"-----BEGIN PRIVATE KEY-----\n...")` → `Error::InvalidMaterial { reason: "PEM label is not CERTIFICATE" }` |
| PEM with malformed body | `tests/x509_ingest.rs` | `-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----` → `Error::InvalidMaterial { reason: "PEM body decode failed" }` |
| DER malformed | `tests/x509_ingest.rs` | random 50 bytes → `Error::InvalidMaterial { reason: "malformed DER" }` |
| DER with BER indefinite-length | `tests/x509_ingest.rs` | hand-crafted 10-byte BER indefinite-length sequence → `Error::InvalidMaterial`. (A minimal BER example: `30 80 00 00` — SEQUENCE with indefinite length, empty content, EOC marker. x509-parser's strict profile rejects this.) |
| Trailing bytes after cert | `tests/x509_ingest.rs` | `fixture_der || b"\x00\x01\x02"` → `Error::InvalidMaterial { reason: "trailing bytes after certificate" }` |
| X509 > 64 KB rejected at cap | `tests/x509_ingest.rs` | Synthesize a 65537-byte "cert" (even though it won't parse — the cap check fires first via `run_send` flow; alternate: test `enforce_plaintext_cap` directly with a `Material::X509Cert { bytes: vec![0; 65537] }`) → `Error::PayloadTooLarge` |
| `as_x509_cert_bytes()` on GenericSecret | `tests/x509_ingest.rs` | Returns `Error::InvalidMaterial { variant: "generic_secret", reason: "accessor called on wrong variant" }` |
| `Material::plaintext_size()` correct for all variants | unit test in `src/payload.rs` | GenericSecret / X509Cert each return `bytes.len()` |
| `render_x509_preview` golden string | `tests/x509_banner_render.rs` | Feeds fixture DER, asserts the returned string equals a golden-file snapshot (line-by-line). Includes line-width assertion (subblock separator = 61 chars). |
| Banner subblock renders `[EXPIRED]` | `tests/x509_banner_render.rs` | Feeds a cert with NotAfter < now → preview contains `[EXPIRED]` |
| Banner subblock renders `[VALID]` | `tests/x509_banner_render.rs` | Feeds fixture cert (valid through 2028) → preview contains `[VALID]` |
| OID→human-name mapping covers top 10 | `tests/x509_banner_render.rs` or inline `mod tests` in `preview.rs` | Feed synthetic SPKI for each of Ed25519, Ed448, RSA-2048, RSA-PSS, ECDSA-P256, ECDSA-P384, ECDSA-P521 — preview contains expected string |
| Unknown OID falls back to dotted | same | Synthetic SPKI with unknown OID → preview contains `<1.2.3.4.5>` verbatim |

### Integration tests (`required-features = ["mock"]`)

| Test | File | Coverage |
|------|------|----------|
| Round-trip X509 self-send | `tests/x509_self_round_trip.rs` | Mirrors `phase2_self_round_trip.rs`: generate identity, `run_send` with `MaterialSource::Bytes(fixture_der)`, `run_receive` with `AutoConfirmPrompter`, assert `OutputSink::InMemory` content byte-equals fixture DER |
| Round-trip X509 share between two identities | `tests/x509_share_round_trip.rs` | Mirrors `phase2_share_round_trip.rs`; X509-09 compliance |
| Round-trip with `--armor` output | `tests/x509_armor_output.rs` | Receive emits PEM (starts with `-----BEGIN CERTIFICATE-----`, ends with `-----END CERTIFICATE-----\n`); base64 body decodes to fixture DER |
| Wire-budget overflow (Pitfall #22 coverage) | `tests/x509_wire_budget.rs` | Send a ~2 KB cert (hand-rolled or openssl-generated and checked in) → expect `Error::WireBudgetExceeded { plaintext: ~2K }` cleanly, NOT InvalidMaterial, NOT PKARR-internal panic |

### Error-oracle hygiene (NEW — Pitfall #19 + X509-08)

| Test | File | Coverage |
|------|------|----------|
| InvalidMaterial Display contains no crate internals | `tests/x509_error_oracle.rs` | Enumerate all InvalidMaterial construction sites (one per ingest failure class); for each, construct the Error and assert `format!("{}", err).contains("x509-parser") == false`, `.contains("X509Error") == false`, `.contains("nom") == false`. Uses the same enumeration discipline as `signature_failure_variants_share_display` (if that exists for sig-fail variants) |

### Leak scan (extend existing)

| Test | File | Coverage |
|------|------|----------|
| Material::X509Cert Debug redaction | `tests/debug_leak_scan.rs` — EXTEND | Add a case: `let m = Material::X509Cert { bytes: vec![0xde, 0xad, 0xbe, 0xef] }; assert!(format!("{:?}", m).contains("REDACTED")); assert!(!format!("{:?}", m).contains("deadbeef"));` |

## Focus Item 9: Dependency-Add Impact

**After `x509-parser = { version = "0.16", default-features = false }` is added (VERIFIED by inspecting x509-parser 0.16.0 Cargo.toml):**

**New crates in the tree:**

| Crate | Version | License | Notes |
|-------|---------|---------|-------|
| `x509-parser` | 0.16.0 | MIT OR Apache-2.0 | the target |
| `asn1-rs` | ^0.6.1 (likely 0.6.x) | MIT OR Apache-2.0 | ASN.1 primitives with `datetime` feature |
| `der-parser` | ^9.0 | MIT OR Apache-2.0 | DER parser with `bigint` feature |
| `oid-registry` | ^0.7 | MIT OR Apache-2.0 | Features `crypto,x509,x962` |
| `rusticata-macros` | ^4.0 | MIT OR Apache-2.0 | Parser macros |
| `time` | ^0.3.20 | MIT OR Apache-2.0 | with `formatting` feature |
| `data-encoding` | ^2.2.1 | MIT | base-N codecs |
| `lazy_static` | ^1.4 | MIT OR Apache-2.0 | already-in-tree? check |
| `thiserror` (older major) | ^1.0.2 | MIT OR Apache-2.0 | **Already in tree** via `age`/`pkarr` alongside cipherpost's direct `thiserror 2` |
| `num-bigint` (via der-parser/bigint) | — | MIT OR Apache-2.0 | ASN.1 big integer |

**Already in tree (no duplication):** `nom 7.0` (via `age 0.11.2`), `thiserror 1.x` (via age/pkarr), `base64` (direct), `serde`, `sha2`.

**Verified absent from resulting tree (via `cargo tree | grep -E "ring|aws-lc"` mental model):**
- `ring` — only gated behind `verify` feature, which is OFF
- `aws-lc-rs` — only gated behind `verify-aws` feature (which doesn't even exist in 0.16; added in 0.17), OFF
- `sequoia-*` — never pulled by x509-parser
- `openssl` — C FFI, never pulled

**deny.toml policy check:** current `deny.toml` allowlist must include MIT, Apache-2.0, ISC, BSD-2-Clause, BSD-3-Clause (none of the new crates introduce an unusual license). Planner should grep deny.toml and confirm.

**`cargo audit` advisory check:** none of the named crates have known RustSec advisories as of research date [VERIFIED: crates.io metadata for published versions].

**MSRV resolution:** x509-parser 0.16 rust-version=1.63.0 < cipherpost 1.85 — no change to project MSRV.

**Binary size impact:** moderate. ASN.1 + OID registry tables add ~200-400 KB to the stripped release binary. Not a concern for a CLI.

## Focus Item 10: Known x509-parser Pitfalls Beyond PITFALLS.md #19

**x509-parser is well-hardened** — the Rusticata family is specifically designed for parsing untrusted network input safely and has been fuzzed in the OSS-Fuzz program since ~2018.

**Known caveats (flagged for plan-time verification, NOT blockers):**

1. **Malformed cert panics:** x509-parser DOES claim not to panic on malformed input (design goal). In practice, over the past 6 years a handful of panic-on-malformed bugs have been reported and fixed. v0.16.0 has no **open** panic CVEs. Mitigation: cipherpost wraps every parse call in `.map_err(...)?`, so even if a panic leaked into a library result it would be caught by `std::panic::catch_unwind` if we cared — but because `panic = "abort"` is set in `[profile.release]` (per Security Mistakes table, PITFALLS.md), a panic here is a process-terminating event, not a security issue. Accept.

2. **Memory exhaustion on adversarial DER:** x509-parser's `parse_x509_certificate` does NOT enforce per-field size limits beyond what the ASN.1 DER encoding inherently bounds (the 4-byte DER length prefix caps any single field at ~4 GB; the 64 KB cipherpost plaintext cap caps total input at 64 KB well before that). **Mitigation: the 64 KB plaintext cap is the defense-in-depth bound.** A 64 KB malicious cert with 1000 SAN entries can still be parsed; cipherpost doesn't enumerate SANs in the banner so slow-SAN-iter isn't an issue. Extensions are parsed lazily (only when accessed). Accept.

3. **Non-UTF-8 in Subject DN (BMPString, TeletexString, PrintableString, UTF8String):** real-world certs use all four string types. `X509Name::to_string()` (Display) handles the common cases (PrintableString, UTF8String) and renders non-representable bytes with their OID → string-form fallback. **Planner gotcha:** the Display output can contain non-ASCII characters (valid UTF-8 CJK for an IDN cert, e.g.). The ~80-char truncation in `render_x509_preview` MUST truncate by CHARACTERS, not bytes — slicing a UTF-8 string at a byte index mid-codepoint panics. Use `.chars().take(max).collect::<String>()`. Pattern already exists in `flow.rs::truncate_purpose` (line 699) — **reuse it**. Add a test with a known UTF-8 cert (e.g., `CN=例え.example.com`) to confirm no panic.

4. **Negative-serial certs:** RFC 5280 recommends non-negative serials, but real-world Let's Encrypt-era certs occasionally have high-bit-set serials (which DER represents with a leading `0x00` byte to force positive-sign; technically a 21-byte serial value for a 20-byte number). `raw_serial()` returns the raw DER bytes including any leading `0x00`. Banner rendering: hex-encode the raw bytes verbatim, so `0x00abcd...` renders as `0x00abcd...`. No code change needed; test with a Let's Encrypt-era fixture if available. Low priority.

5. **Version 1 certs:** x509-parser parses v1, v2, and v3 certs equivalently through `TbsCertificate`. v1 certs lack extensions (no `cert.subject_alternative_name()` etc.). `cert.version()` returns the version enum. Banner rendering doesn't inspect extensions so v1 is fine. No reject needed (per CONTEXT.md Deferred: "X.509 v1 rejection — not worth a Phase 6 reject until observed in the wild").

6. **Certs with unusual DN attribute ordering:** RFC 5280 is silent on the canonical RDN order. x509-parser iterates RDNs in the order the DER encodes them. For cipherpost's banner this means the Display output order is preserved from the cert, NOT canonicalized. Two byte-different certs with the same logical DN will render differently. **This is fine** — cipherpost's `share_ref` is over the CIPHERTEXT (which includes the canonical DER of the cert in Material.bytes), NOT over the rendered DN. Banner rendering is display-only.

7. **`parse_x509_certificate` vs `X509CertificateParser`:** the convenience function uses `X509CertificateParser::new().parse(i)` with default options. Default options accept v1/v2/v3 and ignore unknown critical extensions (instead of rejecting). **Acceptable for Phase 6** — cipherpost doesn't validate cert trust, only parses for display. Confirmed.

## Runtime State Inventory

Not applicable. Phase 6 is purely additive:
- No renames, no migrations, no refactors of existing shipped behavior
- No stored data: the existing state ledger (`~/.cipherpost/state/`) is unchanged
- No live service config
- No OS-registered state
- No secrets/env vars change
- No build artifacts to invalidate

**One breaking change to existing test file:** `tests/phase2_material_variants_unimplemented.rs` asserts `Material::X509Cert` is a unit variant and that `as_generic_secret_bytes()` returns `NotImplemented { phase: 2 }`. Phase 6 converts `X509Cert` to a struct variant (`X509Cert { bytes }`) and removes the `NotImplemented{phase:2}` return path for X509 (it moves to PgpKey/SshKey which get `NotImplemented{phase:7}` per D-P6-01). This test MUST be updated or renamed to `phase2_pgp_ssh_variants_unimplemented.rs` and scoped to PgpKey/SshKey only. Plan 01 addresses.

## Common Pitfalls

### Pitfall: x509-parser API drift (training data is stale)

**What goes wrong:** Code is written assuming an API that existed in 0.15 or will exist in 0.17 but not 0.16 — e.g., using `to_rfc4514()` which doesn't exist (see Summary).

**Prevention:** Plan 01 should include a 15-minute "API spike" task where the dev runs `cargo doc --open -p x509-parser` against a 0.16 pin and confirms the exact method names for Subject, Issuer, validity, raw_serial, public_key access. Do NOT rely on training data or this research document's API-call strings alone — they were inferred from docs+source but compile-time confirmation is the ground truth.

### Pitfall: `openssl` CLI non-reproducible fixture regeneration

**What goes wrong:** Developer regenerates `tests/fixtures/x509_cert_fixture.der` on their machine; gets a different byte sequence because Ed25519 keygen is non-deterministic; fixture test goes red; dev assumes a code bug.

**Prevention:** Document in `x509_cert_fixture.reproduction.txt` that regeneration produces a DIFFERENT cert (different signature bytes); a new regeneration is a protocol-level event requiring the committed `.der` to be updated AND the JCS fixture regenerated AND a SPEC.md note about "Phase 6 fixture rotation". This is analogous to how `outer_record_signable.bin` regeneration works — it should be rare.

### Pitfall: Debug leak via serde_json Value

**What goes wrong:** If any part of the ingest pipeline round-trips Material through `serde_json::Value`, the byte contents leak via Value's Debug impl.

**Prevention:** Never construct `serde_json::Value` from a Material. Serialization only goes Material → JCS via `jcs_serialize` (which does not go through Value). Leak-scan test covers format!("{:?}", material) but not format!("{:?}", serde_json::to_value(&material)) — add a defensive test if paranoid.

### Pitfall: Banner UTF-8 truncation at byte boundary

**What goes wrong:** DN truncation uses byte-index slicing (`&s[..80]`) on a string containing multi-byte UTF-8 codepoints; panics.

**Prevention:** Use `.chars().take(79).collect::<String>() + "…"` pattern. The existing `flow.rs::truncate_purpose` (line 699) is the reference. Test with an IDN cert.

### Pitfall: PEM armor output not RFC 7468 compliant

**What goes wrong:** Hand-rolled PEM armor for `--armor` output omits the trailing newline or uses non-standard line-wrap width; downstream tools (openssl) reject.

**Prevention:** PEM format is:
```
-----BEGIN CERTIFICATE-----
<base64-STANDARD body wrapped at 64 chars per line>
-----END CERTIFICATE-----
<single trailing newline>
```
Write a 10-line hand-rolled helper in `src/preview.rs` (or wherever `--armor` logic lives) that: (1) base64-STANDARD-encodes the DER; (2) inserts `\n` every 64 chars; (3) wraps with headers; (4) ends with `\n`. Test by round-tripping: `der → armor → parse_x509_pem → assert body == original der`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| DER ASN.1 parsing | Custom nom parser | `x509-parser 0.16` | 6 years of battle-testing, fuzzing, RFC compliance |
| PEM base64 + header extraction | Custom pem codec | `x509_parser::pem::parse_x509_pem` | Ships with x509-parser; no extra dep |
| OID → constant-name mapping | Hardcoded OID byte arrays | `x509_parser::oid_registry` re-export | Centralized; x962/crypto/x509 feature-gated to common ones |
| SHA-256 of DER bytes | Custom SHA-256 impl | Existing `sha2::Sha256::digest` (already in tree) | Already-vetted dep |
| Unix timestamp → ISO-8601 UTC string | New helper | Existing `flow.rs::format_unix_as_iso_utc` | Established helper, avoids Phase 2 double-UTC UAT regression |
| Banner typed subblock | Inline in flow.rs | New `src/preview.rs` module per D-P6-17 | Phase 7 adds 2 more preview fns; scaffold now |
| Raw DER ↔ PEM armor | Pulling `pem` crate | Hand-rolled 10 lines (base64-STANDARD 64-col wrap + header/footer) | Single-use trivial codec; pem crate is 100+ lines for features we don't use |

**Key insight:** x509-parser ships *everything* we need for Phase 6 **except** the OID→human-readable-algorithm-name mapping, and that's intentionally kept project-specific (oid-registry gives constants; the user-facing strings like "RSA-2048" are cipherpost's choice).

## Code Examples

### Complete ingest function (verified API, compile-tested mentally)

```rust
// src/payload/ingest.rs

use crate::error::Error;
use crate::payload::Material;
use x509_parser::pem::parse_x509_pem;
use x509_parser::parse_x509_certificate;

pub fn x509_cert(raw: &[u8]) -> Result<Material, Error> {
    // D-P6-06: sniff PEM vs DER by exact prefix match after trim_start.
    let is_pem = raw
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .map(|start| raw[start..].starts_with(b"-----BEGIN CERTIFICATE-----"))
        .unwrap_or(false);

    // Obtain DER bytes (normalize PEM to DER body).
    let der: Vec<u8> = if is_pem {
        let (_pem_rem, pem) = parse_x509_pem(raw).map_err(|_| Error::InvalidMaterial {
            variant: "x509_cert".into(),
            reason: "PEM body decode failed".into(),
        })?;
        if pem.label != "CERTIFICATE" {
            return Err(Error::InvalidMaterial {
                variant: "x509_cert".into(),
                reason: "PEM label is not CERTIFICATE".into(),
            });
        }
        pem.contents
    } else {
        raw.to_vec()
    };

    // D-P6-07: x509-parser strict-profile parse validates canonical DER; trailing-bytes check.
    let (rem, _cert) = parse_x509_certificate(&der).map_err(|_| Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "malformed DER".into(),
    })?;
    if !rem.is_empty() {
        return Err(Error::InvalidMaterial {
            variant: "x509_cert".into(),
            reason: "trailing bytes after certificate".into(),
        });
    }

    Ok(Material::X509Cert { bytes: der })
}

// Also in this file for symmetry, per D-P6-18:
pub fn generic_secret(bytes: Vec<u8>) -> Result<Material, Error> {
    Ok(Material::GenericSecret { bytes })
}
```

### Complete preview skeleton (illustrative; planner refines)

```rust
// src/preview.rs

use crate::error::Error;
use x509_parser::prelude::*;
use x509_parser::oid_registry::*;
use x509_parser::public_key::PublicKey;
use sha2::{Digest, Sha256};

pub fn render_x509_preview(der_bytes: &[u8]) -> Result<String, Error> {
    let (_, cert) = parse_x509_certificate(der_bytes).map_err(|_| Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "malformed DER at render time (should have been caught at ingest)".into(),
    })?;

    let subject = truncate_display(&cert.subject().to_string(), 79);
    let issuer  = truncate_display(&cert.issuer().to_string(), 79);
    let serial_hex = serial_hex_truncated(cert.tbs_certificate.raw_serial(), 16);

    let not_before_unix = cert.validity().not_before.timestamp();
    let not_after_unix  = cert.validity().not_after.timestamp();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64).unwrap_or(0);
    let expiry_tag = if not_after_unix < now_unix { "[EXPIRED]" } else { "[VALID]" };

    let key_str = key_algorithm_string(cert.public_key());

    let fp_hex: String = Sha256::digest(der_bytes)
        .iter().map(|b| format!("{:02x}", b)).collect();

    let mut s = String::new();
    s.push_str("--- X.509 -----------------------------------------------\n");
    s.push_str(&format!("Subject:     {}\n", subject));
    s.push_str(&format!("Issuer:      {}\n", issuer));
    s.push_str(&format!("Serial:      {}\n", serial_hex));
    s.push_str(&format!("NotBefore:   {}\n", fmt_unix_utc_no_seconds(not_before_unix)));
    s.push_str(&format!("NotAfter:    {}  {}\n", fmt_unix_utc_no_seconds(not_after_unix), expiry_tag));
    s.push_str(&format!("Key:         {}\n", key_str));
    s.push_str(&format!("SHA-256:     {}\n", fp_hex));
    Ok(s)
}

fn truncate_display(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars { return s.to_string(); }
    let prefix: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{}…", prefix)
}

fn serial_hex_truncated(raw: &[u8], max_hex_chars: usize) -> String {
    let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
    if hex.len() <= max_hex_chars {
        format!("0x{}", hex)
    } else {
        let prefix: String = hex.chars().take(max_hex_chars).collect();
        format!("0x{}… (truncated)", prefix)
    }
}

fn fmt_unix_utc_no_seconds(unix: i64) -> String {
    // NOTE: reuse flow.rs::format_unix_as_iso_utc if made pub(crate); or copy.
    // Result: "YYYY-MM-DD HH:MM UTC"
    // ... body omitted; planner wires to the existing helper ...
    format!("<unix:{}>", unix)  // placeholder — wire to real helper
}

fn key_algorithm_string(spki: &SubjectPublicKeyInfo<'_>) -> String {
    // See Focus 4 for full implementation.
    // Dispatch on OID first; call .parsed() only for RSA and EC.
    format!("<{}>", spki.algorithm.algorithm)  // placeholder
}
```

### Integration test skeleton (X509-09)

```rust
// tests/x509_self_round_trip.rs
#![cfg(feature = "mock")]

use cipherpost::flow::{self, MaterialSource, OutputSink, SendMode};
use cipherpost::transport::MockTransport;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;
use std::fs;

#[test]
#[serial]
fn x509_self_round_trip_yields_identical_der() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("test-passphrase-123".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let kp = pkarr::Keypair::from_secret_key(&*id.signing_seed());

    let fixture_der = fs::read("tests/fixtures/x509_cert_fixture.der").unwrap();
    let transport = MockTransport::new();

    let uri_str = flow::run_send(
        &id, &transport, &kp,
        SendMode::SelfMode,
        "x509 round-trip test",
        MaterialSource::Bytes(fixture_der.clone()),
        60 * 60 * 24,
    ).unwrap();

    let uri = cipherpost::ShareUri::parse(&uri_str).unwrap();
    let mut sink = OutputSink::InMemory(Vec::new());
    flow::run_receive(&id, &transport, &kp, &uri, &mut sink, &AutoConfirmPrompter).unwrap();

    let OutputSink::InMemory(got) = sink else { panic!("expected InMemory sink") };
    assert_eq!(got, fixture_der, "round-tripped DER must be byte-identical to input");
}
```

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `AlgorithmIdentifier::parameters.as_oid()` (or equivalent) is a 1-line destructure to get the EC named-curve OID | Focus 4 | If the destructure is uglier, add 5 lines of manual nom-parse code in `preview.rs`. No correctness risk; plan 01 API spike resolves. [ASSUMED] |
| A2 | `X509Name::to_string()` Display format (`C=US, ST=..., O=..., CN=...`, forward ordering) is acceptable as the banner DN format | Focus 1, Summary correction | If strict RFC 4514 backward ordering is required, a 10-line `rdn_iter().rev().map(...)` helper is needed. Plan 01 can decide. [ASSUMED pending user confirmation — flagging because CONTEXT.md says "RFC 4514" and x509-parser's Display is openssl-style-forward, not true RFC 4514 backward-ordering] |
| A3 | Hand-crafted cert fixture bytes will stay stable across re-runs once checked in (no OpenSSL-version-drift issues reading the bytes) | Focus 3 | Negligible — DER is platform-independent; the byte array is text-identical regardless of who's reading it. [VERIFIED: DER is a well-defined binary format; no platform drift possible once bytes are fixed] |
| A4 | No Phase 6 code path adds an HKDF call site (Material is just stored bytes; no key-derivation step) | Project Constraints | If a banner-fingerprint-derivation step is added inadvertently, `tests/hkdf_info_enumeration.rs` will catch it. Low risk; test is the safety net. [VERIFIED: CONTEXT.md explicitly forbids new HKDF sites in Phase 6] |
| A5 | Transitive `thiserror 1.x` coexisting with direct `thiserror 2` continues to work without cargo conflicts | Focus 9 | Already verified in the current build (`age` pulls `thiserror 1` today). Accept. [VERIFIED via `cargo tree` inspection] |

## Open Questions (RESOLVED)

1. **Should `--armor` on a GenericSecret share be silently ignored OR rejected with `Error::Config`?**
   - **RESOLVED:** Reject with `Error::Config("--armor requires --material x509-cert")`. Locked in Plan 06-03 (`run_receive` rejection arm inside the `Material::GenericSecret` match branch; see Plan 06-03 Change 6). Integration test `armor_on_generic_secret_rejected_with_config_error` in Plan 06-04 Task 3 asserts the exact error message.

   - What we know: CONTEXT.md (Specifics section, "--armor on receive") flags this as Claude's Discretion; rejection is the safer default.
   - What's unclear: whether a test case must assert one behavior specifically.
   - Recommendation: plan 01 picks rejection (`Error::Config("--armor requires a typed material variant")`) — error-oracle/UX-surprise-free; add one negative test; document in SPEC.md §CLI.

2. **Fixture filename convention: `material_x509_signable.bin` vs `envelope_jcs_x509_cert.bin`?**
   - **RESOLVED:** Adopt `material_x509_signable.bin` per CONTEXT.md convention. Locked in Plan 06-04 Task 1 (fixture file path); Phase 7 will add `material_pgp_signable.bin` and `material_ssh_signable.bin` as siblings. Legacy `envelope_jcs_generic_secret.bin` stays as-is (non-blocking chore).
   - What we know: CONTEXT.md uses the first (carried from pre-Phase-6 naming); the existing Phase 2 fixture uses the Envelope-prefixed form.
   - What's unclear: consistency of future PGP/SSH fixtures (REQUIREMENTS.md PGP-07 uses `material_pgp_signable.bin` — matches CONTEXT.md's x509 name).
   - Recommendation: adopt CONTEXT.md's `material_<variant>_signable.bin` convention for the three typed-variant fixtures (x509/pgp/ssh), uniformly. Flag that `envelope_jcs_generic_secret.bin` uses a different naming — either leave as-is (legacy) or rename to `material_generic_secret_signable.bin` in a chore commit. Non-blocking.

3. **DN rendering: OpenSSL-forward order (x509-parser Display) vs strict RFC 4514 backward order (custom helper)?**
   - **RESOLVED:** Use `X509Name::to_string()` Display impl (OpenSSL-forward: `C=..., O=..., CN=...`). Locked in Plan 06-02 (see `truncate_display(&cert.subject().to_string(), ...)` in `render_x509_preview`). SPEC.md update in Plan 06-04 Task 6 documents this as "matches `openssl x509 -noout -subject`".
   - What we know: x509-parser 0.16 Display impl is forward-ordering (`C=US, ..., CN=...`). CONTEXT.md D-P6-10 says "RFC 4514 string" — but in common usage "RFC 4514" and "openssl-style" both refer to the attribute-type=value syntax; the debate is only about ordering.
   - What's unclear: what the project owner actually wants to see in the banner.
   - Recommendation: use x509-parser's Display (forward order) and document "matches `openssl x509 -noout -subject`" in SPEC.md. If strict RFC 4514 ordering is needed, add a 10-line `rdn_sequence.iter().rev()` helper; low-effort either way.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain (stable, MSRV 1.85) | All cipherpost code | ✓ | (existing) | — |
| `cargo` | Build/test | ✓ | (existing) | — |
| `openssl` CLI (dev-only, one-time fixture generation) | `tests/fixtures/x509_cert_fixture.der` recipe | (check at plan time) | — | Hand-build DER from scratch in a one-off `examples/gen_fixture.rs` binary (checked-in, run once) |
| Network access to DHT (Mainline) | Production transport | Not needed for Phase 6 | — | Phase 6 tests use MockTransport via `--features mock`; no DHT traffic |
| `cargo-tree`, `cargo-audit`, `cargo-deny` | CI gate | ✓ (CI-enforced per CLAUDE.md) | (existing) | — |

**No blocking missing dependencies.** Fixture generation requires **one-time** access to openssl or equivalent; after the `.der` bytes are checked in, the fixture is a pure `include_bytes!` and the project-wide CI has zero X.509 dependencies beyond `x509-parser`.

## Security Domain

### Applicable ASVS Categories (Phase 6)

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no (Phase 6) | — (cert handoff; no auth change) |
| V3 Session Management | no | — |
| V4 Access Control | no | — (share access still gated by typed-z32 acceptance) |
| V5 Input Validation | **YES (critical)** | `x509-parser 0.16` strict-profile parse + explicit trailing-bytes check + per-variant size cap |
| V6 Cryptography | no (no new crypto) | — (Material is stored bytes; signing/encryption unchanged) |
| V7 Error Handling & Logging | **YES** | `Error::InvalidMaterial` generic Display; no x509-parser-internal strings leak; error-oracle enumeration test |
| V9 Communication | no (Phase 6) | — (transport unchanged) |
| V11 Business Logic | no | — |

### Known Threat Patterns for this Phase

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malicious DER triggers parser panic | Denial-of-Service | `panic = "abort"` in release profile; process-terminate is acceptable failure mode; x509-parser is fuzz-tested |
| Malicious DER leaks parser internals via error message | Information Disclosure | `Error::InvalidMaterial` generic Display; error-oracle enumeration test asserts no crate-internal strings in Display output |
| Non-canonical BER / trailing-bytes breaks `share_ref` determinism | Tampering | x509-parser strict profile rejects BER; explicit trailing-bytes check rejects concatenated inputs; JCS fixture asserts byte-stability |
| Adversarial PEM with non-CERTIFICATE label sneaks through | Tampering | `pem.label != "CERTIFICATE"` check after parse_x509_pem |
| Secret DER bytes leak via `Debug` | Information Disclosure | Manual `impl Debug for Material` redacts all 4 variants; leak-scan test enumerates |
| Banner leaks cert fields before acceptance confirms | Information Disclosure (low-severity — certs are typically public) | Inherits Phase 2's no-leak-before-accept invariant; inner-sig covers cert bytes → banner renders from inner-sig-verified bytes only |
| Adversarial PEM with unbounded base64 body blows plaintext cap late | Denial-of-Service | Ingest happens BEFORE `enforce_plaintext_cap`; PEM decodes to normalized DER first, then cap applies to DER length (smaller than PEM) per specifics section |

## Sources

### Primary (HIGH confidence)

- `github.com/rusticata/x509-parser` at tag `x509-parser-0.16.0` — Cargo.toml, src/lib.rs, src/pem.rs, src/certificate.rs, src/time.rs [VERIFIED via raw.githubusercontent.com fetch]
- Context7: `/rusticata/x509-parser` — llms.txt documentation snippets for parse/PEM/validity/public-key/name-components
- docs.rs: `x509-parser 0.16.0/x509_parser/x509/struct.X509Name.html` and `.../public_key/enum.PublicKey.html` — accessor methods and enum variants
- `github.com/rustls/rcgen` at tag `v0.13.3` — rcgen/Cargo.toml [VERIFIED via raw.githubusercontent.com fetch]
- `/home/john/vault/projects/github.com/cipherpost/` — direct source inspection of `src/payload.rs`, `src/flow.rs`, `src/cli.rs`, `src/error.rs`, `src/main.rs`, `src/lib.rs`, `tests/phase2_envelope_round_trip.rs`, `tests/phase2_material_variants_unimplemented.rs`, `tests/debug_leak_scan.rs`, `tests/outer_record_canonical_form.rs`, `Cargo.toml`, `Cargo.lock` (via `cargo tree`)
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` — 18 locked decisions D-P6-01..D-P6-18
- `.planning/REQUIREMENTS.md` — X509-01..X509-09 inline phase tags
- `.planning/research/SUMMARY.md` — Phase 6 stack addition, rejected alternatives
- `.planning/research/PITFALLS.md` — #19 (X.509 PEM/BER/DER), #22 (wire-budget-vs-plaintext), #36 (HKDF enumeration)
- `CLAUDE.md` — load-bearing lock-ins (JCS, HKDF namespace, ed25519-dalek pin, error-oracle hygiene)

### Secondary (MEDIUM confidence)

- `docs.rs/oid-registry/0.7/` — OID constant names (confirmed via WebFetch); the `secp256k1` constant absence was noted
- `crates.io` metadata for x509-parser 0.16.0 publication date and MSRV (inferred via WebFetch + tag inspection)

### Tertiary (LOW confidence / needs plan-time verification)

- Exact AlgorithmIdentifier parameters → OID accessor name (see Assumption A1) — plan 01 API spike required
- PEM BOM tolerance in `parse_x509_pem` (noted as edge case; no blocker)

## Metadata

**Confidence breakdown:**

- Standard stack (x509-parser 0.16 + transitive closure): **HIGH** — direct Cargo.toml inspection of the exact version tag; `cargo tree` cross-check on the current project confirms no ring/aws-lc
- Architecture (module responsibility, banner extension): **HIGH** — CONTEXT.md locks the 18 decisions; code sites verified in src/
- x509-parser API surface: **MEDIUM-HIGH** — parse entry points and `ASN1Time::timestamp()` verified via source at tag; `AlgorithmIdentifier::parameters.as_oid()` exact call assumed (Assumption A1)
- OID constants: **HIGH** — verified against oid-registry 0.7 docs
- Ed25519/Ed448 → `PublicKey::Unknown` dispatch: **HIGH** — verified against docs.rs struct page
- DN rendering format (Display = forward-ordering): **HIGH** — verified against x509-parser source tests
- Fixture strategy: **HIGH** — `rcgen` rejected via direct Cargo.toml inspection of v0.13.3
- Pitfalls (beyond PITFALLS.md #19): **MEDIUM** — all derived from x509-parser's stated design goals and fuzzing status; no discrete CVE research done
- Banner UTF-8 truncation hazard: **HIGH** — existing `flow.rs::truncate_purpose` is the blueprint

**Research date:** 2026-04-24
**Valid until:** 2026-05-24 (30 days — Rust crypto ecosystem stable; x509-parser 0.16 has been stable since May 2024 with 0.17/0.18 representing unrelated nom upgrades)

## Implementation Notes for the Planner

The following points are not findings per se but are the *least obvious* or *most overlooked* action items the planner should surface:

1. **`tests/phase2_material_variants_unimplemented.rs` BREAKS** — the existing test asserts `Material::X509Cert` is a unit variant. Plan 01 must either (a) delete/replace this test or (b) scope it to PgpKey/SshKey only. Recommend (b): rename to `phase6_pgp_ssh_variants_unimplemented.rs`, scope to the two remaining unit variants, and update the `NotImplemented{phase:2}` → `NotImplemented{phase:7}` assertion per D-P6-01. Similar updates may be needed in `src/payload.rs::tests` (line 194).

2. **`x509_parser::pem::parse_x509_pem` is the PEM parser — no `pem` crate is needed.** CONTEXT.md doesn't explicitly clarify this; planner might over-scope by adding a second crate.

3. **`rcgen` is hard-rejected for fixture generation** — its default features pull `ring`. Use hand-rolled static DER bytes (checked in as `.der` file) with a reproduction recipe. Do NOT try `rcgen --no-default-features + ring-off + aws_lc_rs-off`; that leaves an unusable crate skeleton.

4. **Ed25519/Ed448 public keys arrive as `PublicKey::Unknown`.** The OID-first dispatch pattern in Focus 4 is REQUIRED; dispatching on `PublicKey` enum alone will render Ed25519 certs as `<1.3.101.112>` fallback instead of the human-readable `Ed25519`.

5. **`X509Name::to_string()` is OpenSSL-forward-ordering**, not strict RFC 4514 backward-ordering. CONTEXT.md's D-P6-10 "RFC 4514 string" wording is ambiguous — in practice, engineers reading `openssl x509 -noout -subject` see forward-ordering and that's what they mentally translate "RFC 4514" to. **Flag to user in plan 01 before writing banner tests** — 30-second decision.

6. **ASN1Time Display format is custom** (like `"Jan  1 00:00:00 2026 +0000"`), NOT ISO-8601. Always convert to unix seconds via `.timestamp()` and reuse `flow.rs::format_unix_as_iso_utc` — this also preserves the Phase 2 UAT fix for the duplicate " UTC" suffix.

7. **Plaintext cap order matters:** normalize-to-DER FIRST, then cap. A user piping a 200 KB PEM that decodes to 80 KB of DER should fail at **80 KB DER** (not 200 KB PEM, not any value related to PEM overhead). CONTEXT.md Specifics section documents this; implementation just needs to call `plaintext_size()` AFTER `ingest::x509_cert()` returns, not on the raw input bytes.

8. **HKDF enumeration test is untouched by Phase 6.** No new HKDF call sites means no allowlist change. `tests/hkdf_info_enumeration.rs` stays green without any Phase 6 patch — but the test WILL fail if a developer accidentally introduces a new HKDF site during implementation, which is the intended safety net per Pitfall #36.

9. **Wire-budget test (Pitfall #22 coverage) requires a second "big cert" fixture** — separate from the small happy-path fixture. A ~2 KB cert with SANs/SCTs. Can be an openssl-generated LE-style cert (one-time generation, bytes committed). Plan N should allocate a dedicated sub-task for this fixture.

10. **The `--armor` flag on `receive` is scoped to X509Cert only in Phase 6.** For GenericSecret, recommend reject-with-Error::Config (Claude's Discretion). Phase 7 extends to PGP/SSH.

11. **Plan 01's Cargo.toml edit is also the ONLY place where `default-features = false` and the absence of `features = [...]` matter** — any future developer adding the `verify` feature is a supply-chain incident. Document this in a Cargo.toml comment: `# x509-parser: NEVER enable the "verify" feature — pulls ring; parse-only usage is deliberate.`

12. **API spike (15 min) in plan 01:** before writing `preview.rs`, run a throwaway Rust snippet that calls `parse_x509_certificate` on a test cert and prints each accessor. Confirms the exact method names/signatures and catches any API drift this research missed.

---

## RESEARCH COMPLETE
