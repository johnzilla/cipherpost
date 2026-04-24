# Phase 6: Typed Material — X509Cert - Context

**Gathered:** 2026-04-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Ship the first non-generic `Material` variant end-to-end (`Material::X509Cert { bytes: Vec<u8> }`), establishing the typed-payload pattern Phase 7 applies mechanically to `PgpKey` and `SshKey`. User-visible deliverable: `cipherpost send --material x509-cert` accepts either DER or PEM, normalizes to canonical DER, renders an X.509 acceptance subblock pre-decrypt, and `receive` writes raw DER by default (`--armor` for PEM). Round-trip proven under MockTransport; JCS fixture `tests/fixtures/material_x509_signable.bin` byte-locked in CI.

**In scope:**
- Clap `--material <variant>` flag on `send` (values: `generic-secret` [default], `x509-cert`; reserved stubs for `pgp-key` / `ssh-key` rejected with `NotImplemented { phase: 7 }`)
- New `src/payload/ingest.rs` module (or `payload::ingest` submodule) with `x509_cert(raw: &[u8]) -> Result<Material, Error>`
- New `src/preview.rs` module with `render_x509_preview(bytes: &[u8]) -> Result<String, Error>`
- `Material::X509Cert { bytes: Vec<u8> }` variant gains a data field; `as_x509_cert_bytes()` accessor parallel to the existing `as_generic_secret_bytes()`; manual `Debug` redaction extended
- `Material::plaintext_size(&self) -> usize` method
- `Error::InvalidMaterial { variant: String, reason: String }` new variant (exit 1, generic Display — no x509-parser internals leaked)
- `receive --armor` flag (emits PEM); default stdout remains raw bytes per variant
- JCS fixture `tests/fixtures/material_x509_signable.bin` committed + property test asserts byte-for-byte determinism
- Integration test round-tripping an X509Cert share under MockTransport (parallel to existing Phase 2/3 tests)
- SPEC.md §3.2 prose update documenting `x509_cert.bytes` carries normalized DER regardless of CLI input format

**Out of scope (noted for deferral):**
- `PgpKey` + `SshKey` implementation — Phase 7 (applies this same pattern twice)
- `--pin` / `--burn` encryption modes — Phase 8
- Real-DHT cross-identity round trip for typed variants — Phase 9
- X.509 chain validation, CRL / OCSP checking, CA bundle handling — explicit REQUIREMENTS.md non-goal
- Multi-cert bundles or certificate-chain payloads — single-leaf only; senders bundle chains externally
- PGP `--armor` question (deferred to Phase 7 per X509-01)

</domain>

<decisions>
## Implementation Decisions

### A. Material dispatch UX (CLI surface Phase 7 extends)

- **D-P6-01 · `--material <variant>` flag on `send`.** Values: `generic-secret` (default), `x509-cert`, `pgp-key`, `ssh-key`. Clap kebab-case values; wire shape (snake_case) stays in `payload.rs` serde tags. Omitting the flag yields `generic-secret` — preserves every shipped Phase 5 script. `pgp-key` / `ssh-key` parse at clap level but dispatch returns `Error::NotImplemented { phase: 7 }` with exit 1. **Rejected:** positional subcommand (`send x509-cert …`) — breaks `send --self/--share` flat surface and PASS-09's canonical invocation. **Rejected:** auto-detect from file bytes — violates "explicit is better than magic," breaks error-oracle, clashes with SC1's explicit `--material` pattern.

- **D-P6-02 · `--material x509-cert` accepts either DER or PEM; sniff decides.** Ingest tests `input.trim_start().starts_with(b"-----BEGIN CERTIFICATE-----")`; if true, PEM path (strip armor → base64-decode → DER bytes); else DER path. Both paths converge to `x509_parser::parse_x509_certificate()` for canonical-DER validation. **Rejected:** DER-only (X509-01 explicitly promises PEM acceptance at CLI). **Rejected:** try-parse cascade (masks non-cert PEM as "malformed DER"). **Rejected:** separate `--input-format pem|der` (re-opens the flag for Phase 7 PGP armor; redundant with sniff).

- **D-P6-03 · `--material` mismatch → `Error::InvalidMaterial { variant, reason }` → exit 1.** New error variant. Display message names variant (`x509_cert`) and a generic reason (`"malformed DER"`, `"PEM header found but body decodes to non-certificate bytes"`) but **never** leaks `x509-parser` internal error chains. Pattern Phase 7 reuses for PGP packet-parse failure and SSH format-rejection. Distinct from `Error::Config` (CLI-argument validation) and `Error::PayloadTooLarge` (size cap). Exit code 1, not 3 (sig-fail) — X509-08 compliance.

- **D-P6-04 · `--material` default is `generic-secret`.** Back-compat for every existing script; no churn on Phase 5 `--help` examples or SC1-style automation.

### B. PEM normalize boundary + error shape

- **D-P6-05 · New `src/payload/ingest.rs` module (or `payload::ingest` submodule) owns normalization.** `pub fn x509_cert(raw: &[u8]) -> Result<Material, Error>` returns the fully-constructed `Material::X509Cert { bytes: canonical_der }`. Called from `run_send` after `read_material()`, before `enforce_plaintext_cap`. Phase 7 adds `ingest::pgp_key()` and `ingest::ssh_key()` next to it. **Rejected:** inline in `run_send` (Phase 7 fattens `run_send` with three variant branches; tests for ingest need heavy setup). **Rejected:** normalize in `main.rs` dispatch (splits pipeline across files; integration tests using `MaterialSource::Bytes` lose ingest coverage).

- **D-P6-06 · Sniff = exact `-----BEGIN CERTIFICATE-----` prefix match** after `trim_start()`. Permits leading whitespace only; does NOT tolerate missing header or mismatched `END CERTIFICATE-----` footer silently. A file that starts with the header but fails PEM body parse returns `InvalidMaterial { variant: "x509_cert", reason: "PEM body decode failed" }` (not "looks like DER with a weird header"). Raw DER starting with `0x30 0x82 …` (SEQUENCE of length > 127) cannot conflict because `0x30` ≠ `0x2D`.

- **D-P6-07 · `x509-parser`'s parse is the BER-rejection mechanism; add a trailing-bytes check.** `x509_parser::parse_x509_certificate(der)` enforces canonical DER per RFC 5280 strict profile (rejects indefinite-length constructed encodings, etc.) — satisfies Pitfall #19's "run through the parser" prevention rule. Ingest additionally asserts the parser consumed the entire input (no trailing junk / concatenated certs); trailing bytes → `InvalidMaterial { reason: "trailing bytes after certificate" }`. Phase 7 PGP applies the same "one packet, no trailer" check; Phase 7 SSH applies "one key, no trailer." **Rejected:** re-serialize round-trip check via `der 0.7` crate — doubles the surface and pulls an extra crate without catching cases `x509-parser`'s strict parse misses.

- **D-P6-08 · `Material::X509Cert { bytes }` Debug = `X509Cert([REDACTED N bytes])`.** Same shape as existing `GenericSecret([REDACTED N bytes])`. Even though public CA-signed leaf certs are often public information, the pattern **must** be uniform because Phase 7 SSH / PGP **secret** keys will reuse this variant shell. One-rule-for-all beats per-variant Debug carve-outs. Leak-scan test (Pitfall #7 enforcement) extends to cover all four Material variants; asserts `format!("{:?}", material)` never contains any byte sequence from the underlying data.

### C. Acceptance banner layout (pattern Phase 7 copies for PGP + SSH)

- **D-P6-09 · Inline subblock on the existing single-block banner.** After the existing `Type:` and `Size:` lines, insert a `--- X.509 -----------------------------------------------` subheader and cert-specific fields (Subject, Issuer, Serial, NotBefore, NotAfter, Key, SHA-256). TTL line stays at the bottom as today. One banner, typed-subblock underneath. Phase 7 inserts `--- OpenPGP ---` and `--- SSH ---` subblocks the same way. **Rejected:** two-block banner (triples variant-label churn for Phase 7). **Rejected:** column/table layout (breaks fixed-width TTY assumptions; z32 pubkey already wraps).

- **D-P6-10 · DN rendering: RFC 4514 string, truncated at ~80 chars with ellipsis.** Use `x509-parser`'s `to_rfc4514()` (matches `openssl -nameopt RFC2253`). Render on one line per DN (`Subject:` and `Issuer:`). Truncation: if rendered string > 80 chars, cut at 79 and append `…`. Full detail available via `openssl x509 -in <file> -text -noout` — cipherpost is transport, not X.509 audit. **Rejected:** CN-only + wrapped-DN (fails on valid no-CN certs; doubles banner height). **Rejected:** ASCII-strip with no truncation (silently eats IDN / EV UTF-8 DNs; unbounded banner height).

- **D-P6-11 · SerialNumber rendering: hex, truncate-with-`…` at 16 hex chars.** Certs can have 20-byte serials (40 hex). First 16 hex is sufficient for visual identification; the full serial is a (public) field inside the DER that anyone can extract via `openssl`. Render prefix `0x` (`Serial:      0x0a1b2c3d… (truncated)`). Short serials (≤16 hex) render whole, no ellipsis.

- **D-P6-12 · NotBefore / NotAfter rendered as ISO-8601 UTC; expired cert gets `[EXPIRED]` tag, valid cert gets `[VALID]` tag after NotAfter.** X509-04 mandates `[EXPIRED]` not-blocking; we extend with `[VALID]` on the NotAfter line for symmetry. Comparison against `now_unix_seconds()`; `NotAfter < now` → `[EXPIRED]`, else `[VALID]`. No third `[NOT_YET_VALID]` tag — vanishingly rare in practice, and an eager sender who sends a cert with future NotBefore is out-of-contract; the field is shown honestly and the receiver sees the timestamp. Uses existing `format_unix_as_iso_utc` helper (no double `" UTC"` suffix — see 2026-04-21 UAT note in `flow.rs`).

- **D-P6-13 · SHA-256 DER fingerprint: label `SHA-256:`, full 64 hex chars, no colon-pairs, no truncation.** Line reads `SHA-256:     <64-hex-lowercase>`. Computed over **canonical DER bytes** (so `share_ref` determinism and fingerprint determinism share the same normalization). Labeling disambiguates from the sender identity line above (`Sender: ed25519:SHA256:<slug>` + z32). The sender fingerprint uses OpenSSH-style algo-prefixed slug; the cert fingerprint uses the labeled-full-hex form. **Rejected:** colon-pair byte form (95 chars wide, runs off 80-col TTYs). **Rejected:** both forms rendered (invites diff-confusion).

- **D-P6-14 · Key algorithm string: human-readable `ECDSA P-256` / `RSA-2048` / `Ed25519` / `Ed448` / `RSA-PSS`.** Maps from `x509-parser`'s `SubjectPublicKeyInfo::algorithm` OID + curve parameter. Matches `openssl x509 -noout -text` conventions (what security engineers expect). Unknown-OID fallback: dotted-OID verbatim (`<1.2.840.113549.1.9.1>`). Curve parameter included for EC (`P-256`, `P-384`, `P-521`, `secp256k1`). Bit-size included for RSA (`RSA-2048`, `RSA-3072`, `RSA-4096`).

### D. Typed-Material API shape (library-internal; Phase 7 applies twice)

- **D-P6-15 · Per-variant byte accessors: `as_x509_cert_bytes() -> Result<&[u8], Error>` parallel to existing `as_generic_secret_bytes()`.** Variant mismatch returns `Error::InvalidMaterial { variant: "<actual>", reason: "accessor called on wrong variant" }` (developer-facing; should never fire in normal flow because callers match the variant first). Phase 7 adds `as_pgp_key_bytes()` and `as_ssh_key_bytes()`. The existing `as_generic_secret_bytes()` signature is preserved — no migration to rename. **Rejected:** unified `Material::bytes() -> &[u8]` (loses the Result-based mismatch guardrail; today's `NotImplemented { phase: 2 }` pattern depends on it). **Rejected:** `TypedMaterial` trait with per-variant impls (significantly more surface; over-engineered for v1.1).

- **D-P6-16 · `Material::plaintext_size(&self) -> usize` method; returns raw-byte length of the variant's `bytes` field.** Single call site in `run_send`: `payload::enforce_plaintext_cap(material.plaintext_size())`. Method, not free fn — consistent with existing `Material::as_generic_secret_bytes()` style. Returns plaintext length, not JCS-expanded length — the wire-budget guard (`check_wire_budget`) already handles post-encryption size correctly; pre-encrypt cap is specifically about plaintext per X509-06. The method handles all four variants (GenericSecret, X509Cert in Phase 6; PgpKey, SshKey will plug in during Phase 7).

- **D-P6-17 · Banner subblock rendering lives in new `src/preview.rs`.** `pub fn render_x509_preview(bytes: &[u8]) -> Result<String, Error>` returns the formatted multi-line subblock (no leading/trailing newlines; caller owns the outer banner layout). `TtyPrompter::render_and_confirm` calls it conditional on material type via a match. Phase 7 adds `render_pgp_preview()` and `render_ssh_preview()` in the same module. **Rejected:** method on Material (pulls x509-parser as a dep of `payload.rs`, which today has zero parse deps — serde-only tests pay the ASN.1 parser compile cost). **Rejected:** inline in `TtyPrompter` (Phase 7 adds two more typed renderings; `AutoConfirmPrompter` test path skips real rendering already).

- **D-P6-18 · `payload::ingest::x509_cert(raw: &[u8]) -> Result<Material, Error>` returns the fully-constructed variant.** Ingest owns both the sniff/normalize (D-P6-06/07) and the `Material::X509Cert { bytes: der }` constructor call — one place enforces the "bytes field carries canonical DER" invariant. `run_send` calls ingest, receives a `Material`, calls `material.plaintext_size()`, checks the cap, builds the Envelope. Phase 7 `ingest::pgp_key()` and `ingest::ssh_key()` return `Material::PgpKey { bytes }` / `Material::SshKey { bytes }` — same shape. **Rejected:** returning `Vec<u8>` of bytes and letting `run_send` wrap (duplicates variant-construction across callers). **Rejected:** returning `(Material, size)` tuple (micro-optimization; `plaintext_size()` is already cheap).

### Claude's Discretion

- Exact clap `ValueEnum` derivation or manual `impl FromStr` for `--material` values. `ValueEnum` is the idiomatic path and plays well with `--help` generation.
- Exact truncation length on DN rendering (~80 chars). Test with a few real CA-issued certs (including an EV cert with long `O=` field) at plan time to confirm the banner stays readable.
- Fixture generation strategy for `tests/fixtures/material_x509_signable.bin` — likely a minimal hand-crafted Ed25519-keyed self-signed cert checked in as bytes (so determinism doesn't depend on a re-runnable generator). Planner decides cert content exactly; reproduction note in a sibling `.txt` file.
- Whether `render_x509_preview` runs the x509-parser inside the function, or the function takes a pre-parsed struct. Inside-the-function is simpler and avoids leaking `x509-parser` types up the call stack.
- Whether `--armor` on `receive` for a GenericSecret share is silently-ignored or rejected with `Error::Config`. Rejection is more defensible (error-oracle / UX-surprise-free); planner can pick.
- Exact wording of `Error::InvalidMaterial` Display strings for each branch (malformed DER, trailing bytes, PEM body decode, variant mismatch) — follow the "generic, no internal leakage" rule per X509-08.
- How many x509-parser OID-to-human-string mappings to hand-code in `preview.rs` vs. falling back to dotted-OID. Cover the top 10 common combos (P-256/384/521 ECDSA, RSA 2048/3072/4096, Ed25519, Ed448, RSA-PSS, secp256k1); everything else dotted-OID.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` §Typed Material: X.509 certificates (X509) — X509-01..09 (inline phase tags)
- `.planning/REQUIREMENTS.md` §Out of Scope — chain validation, PGP sig verify, cert conversion explicitly rejected
- `.planning/ROADMAP.md` §Phase 6 — goal + success criteria SC1–SC5

### Domain pitfalls (load-bearing, each cited by a specific decision above)
- `.planning/research/PITFALLS.md` #19 — X.509 PEM/BER/DER non-canonicity → D-P6-06, D-P6-07
- `.planning/research/PITFALLS.md` #7 — no Debug leak on secret-holding structs → D-P6-08
- `.planning/research/PITFALLS.md` #22 — wire-budget-vs-plaintext-cap distinction → D-P6-16 (cap=plaintext; wire-budget guard already handles encoded size)
- `.planning/research/PITFALLS.md` #36 — per-variant size checks before JCS encode (referenced in SUMMARY.md)

### Research synthesis
- `.planning/research/SUMMARY.md` §Phase 6 — Material::X509Cert (Pattern-Establish) — locks x509-parser 0.16, `verify` feature OFF, no `ring`/`aws-lc`
- `.planning/research/SUMMARY.md` §Stack Additions Table — `x509-parser 0.16` MIT/Apache-2.0; Rusticata family
- `.planning/research/SUMMARY.md` §Rejected Alternatives — `openssl` crate, `x509-cert`, `x509-certificate` all rejected with reasons

### Prior-phase context (decisions carried forward)
- `.planning/phases/05-non-interactive-automation-e2e/05-CONTEXT.md` §D-P5-01 — passphrase precedence `fd > file > env > TTY` (applies to new passphrase-file-driven integration tests)
- `.planning/phases/05-non-interactive-automation-e2e/05-CONTEXT.md` §D-P5-05 — positional `-` shorthand for stdin payload (applies to X509 stdin ingest path)
- v1.0 Phase 2 → `Envelope::to_jcs_bytes` / `Envelope::from_jcs_bytes` contract unchanged; `Material::from_jcs_bytes` parse-fail still maps to `Error::SignatureCanonicalMismatch` (exit 3)

### Project convention
- `CLAUDE.md` §Load-bearing lock-ins — `chacha20poly1305` only via age; JCS via `serde_canonical_json`; HKDF info `cipherpost/v1/<context>`; no `#[derive(Debug)]` on secret holders; ed25519-dalek =3.0.0-pre.5 pin
- `.planning/PROJECT.md` §Constraints — 64 KB plaintext cap; no chain validation; "primitive first, workflows second"
- `.planning/PROJECT.md` §Key Decisions — "Skeleton uses generic-secret payload type only" row (Phase 6 extends the `Material` tag enum; X509Cert/PgpKey/SshKey stubs return NotImplemented until their respective phases)

### Spec sections to edit in Phase 6
- `SPEC.md` §3.2 (Material variants) — add X509Cert wire shape (`{"type":"x509_cert","bytes":"<base64-std>"}`); document "bytes carries normalized DER regardless of CLI input format"
- `SPEC.md` §Exit-code taxonomy — add `Error::InvalidMaterial` → exit 1 row (X509-08)
- `SPEC.md` §CLI — document `--material` flag on `send`; `--armor` flag on `receive`
- `SPEC.md` §Acceptance banner (or add one if absent) — document subblock structure (D-P6-09)

### Existing code — primary edit sites
- `src/payload.rs:67-75` — `Material` enum: add data field to `X509Cert { bytes: Vec<u8> }` variant (base64-encoded via existing `base64_std` serde helper)
- `src/payload.rs:78-89` — `impl Debug for Material` — extend redaction for X509Cert (D-P6-08)
- `src/payload.rs:91-106` — `impl Material` — add `as_x509_cert_bytes()` accessor (D-P6-15); add `plaintext_size()` method (D-P6-16)
- `src/payload.rs` — new `pub mod ingest { ... }` submodule OR new `src/payload/ingest.rs` file (D-P6-05, D-P6-18)
- `src/cli.rs:41-77` — `Send` struct: add `material: MaterialVariant` clap arg (ValueEnum) (D-P6-01, D-P6-04)
- `src/cli.rs:86-109` — `Receive` struct: add `armor: bool` clap flag (D-P6-09 / X509-05)
- `src/flow.rs:185-337` — `run_send`: route through `payload::ingest::<variant>()` based on `--material`; use `material.plaintext_size()` for cap check (D-P6-16, D-P6-18)
- `src/flow.rs:455-473` — acceptance call site in `run_receive`: thread material into preview rendering (D-P6-17)
- `src/flow.rs:710-717` — `material_type_string`: unchanged (already handles X509Cert)
- `src/flow.rs:1036-1103` — `TtyPrompter::render_and_confirm`: call `preview::render_x509_preview(bytes)` after the `Size:` line when material is X509Cert (D-P6-09, D-P6-17)
- `src/error.rs` — add `Error::InvalidMaterial { variant: String, reason: String }` with exit 1 mapping; Display returns generic message (D-P6-03)
- `src/lib.rs` — expose new `preview` module
- NEW: `src/preview.rs` — X.509 subblock rendering (D-P6-17)
- NEW: `tests/fixtures/material_x509_signable.bin` — committed JCS fixture (X509-07)
- NEW: `tests/material_x509_ingest.rs` — sniff/normalize/strictness cases (happy PEM, happy DER, malformed PEM, BER rejected, trailing bytes rejected, wrong material type)
- NEW: `tests/x509_roundtrip.rs` — self-send round-trip under MockTransport (X509-09)

### Dependency additions
- `Cargo.toml` — add `x509-parser = { version = "0.16", default-features = false, features = ["std"] }` (NO `verify` feature — per SUMMARY.md rejection of `ring`/`aws-lc`)
- Confirm via `cargo tree | grep -E "ring|aws-lc"` after add — both MUST be absent

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `payload::enforce_plaintext_cap(len: usize) -> Result<(), Error>` at `src/payload.rs:117` — per-variant cap check; `plaintext_size()` feeds this directly.
- `payload::strip_control_chars(s: &str)` at `src/payload.rs:111` — unchanged; applies to `purpose` field independent of material variant.
- `Envelope` + `Material` + `base64_std` serde module at `src/payload.rs:27-143` — all reusable; Material just gains a data-carrying variant.
- `check_wire_budget()` at `src/flow.rs:347` — real SignedPacket build + retry on grease re-sample; unchanged. X.509 certs approaching the ~550-byte wire budget retry automatically.
- `Error::PayloadTooLarge { actual, limit }` — reused verbatim for X509 > 64 KB cap (X509-06). No new error for the size bucket.
- `Error::SignatureCanonicalMismatch` — reused for post-decrypt Envelope parse failure (exit 3); `Error::InvalidMaterial` is for pre-encrypt / post-decrypt variant/content failures that should NOT collapse into the sig-fail oracle bucket.
- `TtyPrompter::render_and_confirm` at `src/flow.rs:1036` — banner renderer; extends with one conditional preview call.
- `AutoConfirmPrompter` / `DeclinePrompter` at `src/flow.rs:920-957` — test prompters; round-trip tests drive X509 decode without TTY.
- `MockTransport` — carries Phase 6 integration tests without touching DHT.
- `format_unix_as_iso_utc(i64)` at `src/flow.rs` — reused for NotBefore/NotAfter rendering; do NOT append a second `" UTC"` (see Phase 2 UAT note in code).

### Established Patterns
- Manual `Debug` impl on anything holding variant bytes (Pitfall #7); enumerate-all-variants leak-scan test.
- `Material` serde tag `#[serde(tag = "type", rename_all = "snake_case")]` at `src/payload.rs:66` — `X509Cert` already renders as `x509_cert` on the wire. Adding the `{ bytes: Vec<u8> }` data field uses the existing `base64_std` serde helper with no configuration change.
- JCS determinism enforcement: every signable struct has a committed fixture at `tests/fixtures/`; Phase 6 adds `material_x509_signable.bin` alongside `outer_record_signable.bin` + `receipt_signable.bin` + `envelope_jcs_generic_secret.bin`.
- Exit-code taxonomy: exit 1 for CLI / content errors; exit 3 reserved for sig failures; `Error::InvalidMaterial` goes in the exit-1 bucket per X509-08.
- Error-oracle hygiene: Display strings for every `InvalidMaterial::reason` must be short, generic, and free of parser-internal strings. A test enumerates all constructed `InvalidMaterial` variants and asserts the Display doesn't contain any `x509-parser::` identifier or internal error text.
- Test convention: new CLI-env-touching tests use `serial_test = "3"` + `#[serial]`; X509 round-trip uses per-test isolated `CIPHERPOST_HOME` with serial gating.
- `base64_std` module at `src/payload.rs:129-143` — the only base64-STANDARD helper; never mix in `URL_SAFE_NO_PAD`.

### Integration Points
- `Envelope.material` field (src/payload.rs:30) — `X509Cert { bytes }` slots in with zero changes to `Envelope` itself.
- `run_send` step 4 (Envelope construction) currently hard-codes `Material::generic_secret(plaintext_bytes.to_vec())` — Phase 6 replaces this with the variant-dispatched ingest call; GenericSecret path becomes `ingest::generic_secret(bytes)` for symmetry (no change in behavior).
- `run_receive` step 8 (acceptance prompt) currently calls `envelope.material.as_generic_secret_bytes()?` — Phase 6 changes this to match-on-variant, calling the appropriate `as_*_bytes()` and passing variant + bytes to the preview path.
- `main.rs::dispatch` `Send` branch — thread new `material` clap arg into `run_send` parameters.
- No change to `Transport`, `OuterRecord`, `Receipt`, or PKARR publish path — Phase 6 is strictly a payload-layer addition.
- No change to JCS fixture for `outer_record_signable.bin` / `receipt_signable.bin` — they're over OuterRecord / Receipt, not Envelope.

### Anti-patterns to avoid (from prior phases + this discussion)
- Do NOT enable `x509-parser`'s `verify` feature. Pulls `ring`/`aws-lc` — both on the supply-chain rejected list in SUMMARY.md. `cargo tree | grep -E "ring|aws-lc"` must remain empty.
- Do NOT let any `x509-parser` error chain reach user-facing stderr (Display leak). Error-oracle hygiene + X509-08 compliance.
- Do NOT `#[derive(Debug)]` on the new `Error::InvalidMaterial` variant fields if `reason` could contain parser-internal strings — the variant stores a `String`, so the Display path is the gate; the `#[derive(Debug)]` on the outer enum is fine.
- Do NOT collapse `InvalidMaterial` into `Error::Config` (Phase 7 reuses `InvalidMaterial` three more times; one unified bucket now is cheaper than a refactor later).
- Do NOT add a new HKDF call site in Phase 6 (none is needed — X.509 is just typed-payload serialization). The existing `cipherpost/v1/<context>` enumeration test will flag any accidental addition.
- Do NOT emit cert bytes (Subject, Serial, fingerprint, any field) to stderr BEFORE the acceptance prompt returns `Ok(())` — the banner IS the surface, and the banner is the acceptance surface; `preview::render_x509_preview` returns the string which the Prompter owns emitting.
- Do NOT normalize by writing to a temp file and re-reading — ingest is pure in-memory (bytes → bytes).

</code_context>

<specifics>
## Specific Ideas

- **Banner mockup approved (D-P6-09):**
  ```
  === CIPHERPOST ACCEPTANCE ===============================
  Purpose:     "onboarding leaf cert"
  Sender:      ed25519:SHA256:…
               yx8a3…iq8jo
  Share ref:   a1b2c3d4…
  Type:        x509_cert
  Size:        1342 bytes
  --- X.509 -----------------------------------------------
  Subject:     CN=leaf.example.com, O=Example Inc, C=US
  Issuer:      CN=Example CA, O=Example Inc, C=US
  Serial:      0x0a1b2c3d… (truncated)
  NotBefore:   2026-01-15 00:00 UTC
  NotAfter:    2027-01-15 00:00 UTC  [VALID]
  Key:         ECDSA P-256
  SHA-256:     a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890
  TTL:         23h remaining (expires 2026-04-25 13:11 UTC / 2026-04-25 09:11 EDT local)
  =========================================================
  To accept, paste the sender's z32 pubkey and press Enter:
  ```
  Any drift from this exact field set or ordering in implementation is a regression — Phase 7 PGP / SSH subblocks mimic this shape.

- **Subblock separator width:** 57 dashes after `--- X.509 ` to match the existing `===` banner border (61 chars including leading `--- X.509 `). Verifiable with a render test asserting line-width parity.

- **Cap check order in `run_send`:** (1) `read_material` → raw bytes; (2) `payload::ingest::<variant>(raw)?` → `Material`; (3) `payload::enforce_plaintext_cap(material.plaintext_size())?`; (4) `strip_control_chars(purpose)`; (5) build Envelope. Ingest runs BEFORE cap — small but strictly safer: a 1 MB PEM-encoded cert that decodes to 100 KB of DER should fail at cap with the **decoded** size, not the input-encoding size.

- **Fixture cert:** minimal Ed25519-keyed self-signed cert, Subject `CN=cipherpost-fixture, O=cipherpost, C=XX`, valid 2026-01-01 → 2028-01-01, serial `0x01`. Generated once, bytes committed. Property test round-trips through JCS and asserts byte-identity with the committed fixture.

- **Wire-budget note (Pitfall #22):** a realistic CA-issued X.509 with SANs and SCTs frequently exceeds the 550-byte PKARR OuterRecord budget. The existing `check_wire_budget` returns a clean `Error::WireBudgetExceeded { encoded, budget, plaintext }` with grease retry; no Phase 6 code change needed. Integration test should include one expected-to-fail case with a fixture cert large enough to trip the budget — to verify the error surfaces cleanly as `WireBudgetExceeded`, not `InvalidMaterial` or a PKARR-internal panic.

- **`--armor` on receive applies ONLY when material is X509Cert in Phase 6.** For `GenericSecret`, the flag is either silently ignored or rejected with `Error::Config("--armor requires a typed material variant")` — Claude's Discretion (D-P6 discretion row); rejection is the safer default. Phase 7 will extend to PGP / SSH.

</specifics>

<deferred>
## Deferred Ideas

- **`--armor` on GenericSecret** — question raised but not in X509-05's scope; let the implementation pick reject vs silently-ignore. Revisit if a user asks.
- **`[NOT_YET_VALID]` tag** — valid cert shown with future NotBefore currently renders normally (just the timestamp). If user reports "I got a cert 30 minutes before it's valid and didn't notice," add the tag. Low priority.
- **Expired-cert warning beyond `[EXPIRED]` tag** — e.g., a stderr warning line before the typed-z32 prompt. Ideation only; `[EXPIRED]` on the NotAfter line is sufficient per X509-04 ("display but not block").
- **Re-serialize round-trip DER strictness check** — stronger BER rejection than x509-parser's strict profile. Not worth the `der 0.7` crate addition; revisit if a Pitfall #19 regression surfaces.
- **Multi-cert bundle / cert-chain support** — explicit OUT-OF-SCOPE per REQUIREMENTS.md. Senders bundle chains externally. If user demand appears, open as a new phase (v1.2+).
- **X.509 v1 rejection** — all current-era certs are v3. If a v1 cert comes through, x509-parser will parse it but the SAN / fingerprint display could vary. Not worth a Phase 6 reject until observed in the wild.
- **Human-friendly OID table in preview.rs beyond top 10** — extending with exotic algorithms (brainpool curves, GOST, SM2) is easy but zero-demand. Dotted-OID fallback is fine for now.
- **`--material-from-filename` auto-hint** — CLI sniffs `*.pem` / `*.crt` / `*.cer` file extensions to infer `--material x509-cert`. Out of scope; explicit flag is the contract.
- **Integration test identity setup** — whether X509 round-trip uses a shared `CIPHERPOST_HOME` helper or per-test isolated tempdir. Claude's Discretion (planner picks at plan time).
- **`cipherpost receive --material-info` dump** — print parsed X.509 fields without decrypting payload. Out of scope; use `openssl x509 -text` after `receive`.

</deferred>

---

*Phase: 06-typed-material-x509cert*
*Context gathered: 2026-04-24*
