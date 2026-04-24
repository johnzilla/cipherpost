# Phase 6: Typed Material — X509Cert - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in `06-CONTEXT.md` — this log preserves the alternatives considered.

**Date:** 2026-04-24
**Phase:** 06-typed-material-x509cert
**Areas discussed:** Material dispatch UX, PEM normalize boundary, Acceptance banner layout, Typed-Material API shape

---

## Area 1: Material dispatch UX

### Q1.1 — How should `send` select the material variant?

| Option | Description | Selected |
|--------|-------------|----------|
| `--material` flag (Recommended) | `send --material x509-cert ...`. Clap `ValueEnum`, explicit, preserves flat surface. | ✓ |
| Positional subcommand | `send x509-cert ...`. Groups material-specific flags under subcommand. Breaks existing `--self/--share`. | |
| Auto-detect from bytes | Ingest sniffs PEM/DER/packet-tag. Ambiguous for raw-binary; violates "explicit > magic." | |

**User's choice:** `--material` flag.

### Q1.2 — For `--material x509-cert`, which input encodings does the CLI accept?

| Option | Description | Selected |
|--------|-------------|----------|
| Either DER or PEM (sniff) (Recommended) | Sniff `-----BEGIN CERTIFICATE-----` prefix → PEM path; else DER. Both normalize to DER. | ✓ |
| DER only; require pre-conversion | Users must run `openssl x509 -outform DER` first. | |
| Separate `--pem` / `--der` flags | Extra flag surface; re-opens for Phase 7 PGP armor. | |

**User's choice:** sniff.

### Q1.3 — What happens when `--material x509-cert` is passed but file doesn't parse as X.509?

| Option | Description | Selected |
|--------|-------------|----------|
| Exit 1, named-variant msg (Recommended) | New `Error::InvalidMaterial { variant, reason }` variant; generic message; no parser internals leaked. Reused by Phase 7. | ✓ |
| Exit 1, reuse `Error::Config` | No new error variant; mixes CLI errors with content errors. | |
| Downgrade to GenericSecret | Silent fallback. Breaks audit trail; error oracle issue. | |

**User's choice:** named-variant exit 1 msg.

### Q1.4 — What is the default when `--material` is omitted on `send`?

| Option | Description | Selected |
|--------|-------------|----------|
| Default to `generic-secret` (Recommended) | Preserves every shipped Phase 5 script / recipe. | ✓ |
| Require `--material` explicitly | No default; clap parse error on omission. Churns existing scripts. | |

**User's choice:** default `generic-secret`.

---

## Area 2: PEM normalize boundary + error shape

### Q2.1 — Where should PEM→DER normalization live?

| Option | Description | Selected |
|--------|-------------|----------|
| New `payload::ingest` module (Recommended) | `ingest::x509_cert(raw) -> Result<Material, Error>`. Phase 7 adds sibling fns. Clean co-location. | ✓ |
| Inside `run_send` body | Inline sniff+normalize; Phase 7 fattens `run_send`. | |
| CLI-layer (main.rs dispatch) | Splits pipeline; integration tests lose ingest coverage. | |

**User's choice:** new module.

### Q2.2 — How should ingest decide "this is PEM, not DER"?

| Option | Description | Selected |
|--------|-------------|----------|
| Exact prefix match (Recommended) | `trim_start().starts_with(b"-----BEGIN CERTIFICATE-----")`. Unambiguous. | ✓ |
| Try-parse cascade | Try PEM first, fall through to DER. Masks errors. | |
| Require ASCII-armor with matching footer | Stricter than openssl; rejects valid PEM variants. | |

**User's choice:** prefix match.

### Q2.3 — What enforces "canonical DER only, reject BER"?

| Option | Description | Selected |
|--------|-------------|----------|
| x509-parser's parse is authoritative (Recommended) | Strict DER profile enforced by the crate's parse fn. Matches Pitfall #19 prevention. + trailing-bytes check (planner adds this per D-P6-07). | ✓ |
| Re-serialize round-trip check | Parse + re-encode + compare. Belt-and-suspenders; pulls `der 0.7`. | |
| Parse + unused-trailing-bytes check | Middle ground — just trailing-bytes check on top of parse. | |

**User's choice:** x509-parser authoritative (trailing-bytes check added in D-P6-07 per the third option's idea).

**Notes:** the user's selection plus trailing-bytes check was merged into D-P6-07 — x509-parser's parse is authoritative for BER/DER strictness AND ingest additionally asserts the parser consumed the entire input.

### Q2.4 — How should `Material::X509Cert { bytes }` render under Debug?

| Option | Description | Selected |
|--------|-------------|----------|
| Redacted, byte-count only (Recommended) | `X509Cert([REDACTED N bytes])` — mirrors existing GenericSecret pattern. Uniform across all variants. | ✓ |
| Show fingerprint + size | `X509Cert(sha256=<first-8-hex>…, N bytes)`. Leaks derived bytes; Phase 7 secret-key variants can't follow. | |
| Full bytes (hex) | Violates leak-scan invariant. | |

**User's choice:** redacted byte-count only.

---

## Area 3: Acceptance banner layout

### Q3.1 — Which banner structure should X509Cert acceptance use?

| Option | Description | Selected |
|--------|-------------|----------|
| Extend existing banner inline (Recommended) | `--- X.509 ---` subblock under existing `Type:` / `Size:` lines. Phase 7 inserts `--- OpenPGP ---` / `--- SSH ---` same way. | ✓ |
| Two-block banner | Separate `=== X.509 CERTIFICATE ===` block. More vertical space. | |
| Table / columns | Compact; breaks fixed-width TTY assumptions. | |

**User's choice:** inline subblock. Preview approved as shown in 06-CONTEXT.md `<specifics>`.

### Q3.2 — How should Subject and Issuer DNs be rendered when long?

| Option | Description | Selected |
|--------|-------------|----------|
| RFC 4514 string, trunc at N chars (Recommended) | `to_rfc4514()`; truncate ~80 chars with `…`. Matches openssl default. | ✓ |
| CN-only line + full DN on wrap | Two fields per DN; fails on no-CN certs. | |
| Strip to printable ASCII, no trunc | Silently eats IDN / EV UTF-8; unbounded height. | |

**User's choice:** RFC 4514 trunc ~80.

### Q3.3 — How should the X.509 SHA-256 fingerprint be labeled?

| Option | Description | Selected |
|--------|-------------|----------|
| Colon-prefixed, ALL-CAPS algo (Recommended) | `SHA-256:    <64-hex>`. Bare hex, no colon-pairs. Disambiguates from sender's OpenSSH fingerprint. | ✓ |
| Full label + colon-pairs | `Cert SHA-256:  A1:B2:C3:…`. 95 chars on 80-col TTYs. | |
| Both formats (plain + colon) | Two lines; invites diff-confusion. | |

**User's choice:** labeled bare-hex.

### Q3.4 — How should the key algorithm string be formatted?

| Option | Description | Selected |
|--------|-------------|----------|
| Human: ECDSA P-256 / RSA-2048 / Ed25519 (Recommended) | Matches `openssl x509 -noout -text` conventions. Unknown-OID fallback: dotted. | ✓ |
| OID-dotted with parenthetical | `1.2.840.10045.2.1 (id-ecPublicKey, P-256)`. Noisy. | |
| Short name only | `EC` / `RSA` without curve/size. Elides discriminator. | |

**User's choice:** human readable.

---

## Area 4: Typed-Material API shape

### Q4.1 — How should Material's byte-accessor API evolve?

| Option | Description | Selected |
|--------|-------------|----------|
| Per-variant accessors + helper (Recommended) | `as_x509_cert_bytes()` parallel to `as_generic_secret_bytes()`. Phase 7 adds two more. | ✓ |
| Unified `bytes() -> &[u8]` | Loses Result-based mismatch guardrail. | |
| Replace with `TypedMaterial` trait | Over-engineered for v1.1. | |

**User's choice:** per-variant.

### Q4.2 — Where should the `--- X.509 ---` subblock rendering live?

| Option | Description | Selected |
|--------|-------------|----------|
| New `src/preview.rs` module (Recommended) | `render_x509_preview(bytes) -> Result<String, Error>`. Keeps x509-parser out of payload.rs. | ✓ |
| Method on `Material` enum | Pulls x509-parser as payload.rs dep; serde-only tests pay parser compile cost. | |
| Inline in `TtyPrompter` | Fattens trait surface; AutoConfirmPrompter tests lose coverage. | |

**User's choice:** `src/preview.rs`.

### Q4.3 — What should `material_plaintext_size()` return, and where does it live?

| Option | Description | Selected |
|--------|-------------|----------|
| Method on `Material`, raw-bytes length (Recommended) | `impl Material { pub fn plaintext_size(&self) -> usize }`. Wire-budget check stays separate. | ✓ |
| Method on `Material`, JCS-expanded length | Double-checks wire budget pre-encrypt; noisy vs existing guard. | |
| Free fn in payload module | Inconsistent with existing method style. | |

**User's choice:** method, raw-bytes length.

### Q4.4 — What does `payload::ingest::x509_cert()` return?

| Option | Description | Selected |
|--------|-------------|----------|
| Returns `Material::X509Cert` directly (Recommended) | `fn x509_cert(raw) -> Result<Material, Error>`. One place enforces bytes-are-canonical-DER invariant. | ✓ |
| Returns `Vec<u8>` of canonical bytes | Looser coupling; variant construction duplicates at call sites. | |
| Returns `(Material, size)` tuple | Micro-optimization; `plaintext_size()` covers this. | |

**User's choice:** returns `Material`.

---

## Claude's Discretion (deferred to planner)

- Exact clap `ValueEnum` derivation syntax vs manual `impl FromStr` for `--material`.
- Exact DN truncation length (~80 chars); tune at plan time with real CA certs.
- Fixture cert bytes (minimal Ed25519-keyed self-signed; Subject `CN=cipherpost-fixture, O=cipherpost, C=XX`; serial `0x01`).
- Whether `render_x509_preview` takes raw bytes or pre-parsed struct (raw bytes is simpler, avoids leaking x509-parser types).
- `--armor` on GenericSecret: silent-ignore vs reject with `Error::Config` (rejection preferred; planner decides).
- Exact `Error::InvalidMaterial` Display wording per branch (malformed DER, trailing bytes, PEM body decode, variant mismatch).
- OID-to-human-string coverage (top 10 common combos hand-coded; else dotted-OID fallback).
- Integration-test `CIPHERPOST_HOME` scoping convention (shared helper vs per-test tempdir).

## Deferred Ideas (out of scope for Phase 6)

- `--armor` on GenericSecret (Phase 6 Claude's Discretion; behavior locked at plan time)
- `[NOT_YET_VALID]` tag
- Expired-cert stderr warning beyond `[EXPIRED]` tag
- Re-serialize round-trip DER strictness check
- Multi-cert bundle / cert-chain support (out-of-scope per REQUIREMENTS.md)
- X.509 v1 rejection
- Extended OID table (brainpool, GOST, SM2)
- `--material-from-filename` auto-hint
- `cipherpost receive --material-info` dump without decrypting
