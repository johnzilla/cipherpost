---
phase: 06-typed-material-x509cert
reviewed: 2026-04-24
depth: standard
status: issues_found
findings:
  critical: 0
  warnings: 1
  info: 8
---

# Phase 6: Code Review Report

**Reviewed:** 2026-04-24
**Depth:** standard
**Files Reviewed:** 13 (source + scoped tests)
**Status:** issues_found

## Files Reviewed

- `src/payload/ingest.rs` (NEW)
- `src/payload/mod.rs`
- `src/preview.rs` (NEW)
- `src/cli.rs`
- `src/flow.rs`
- `src/main.rs`
- `src/error.rs`
- `src/lib.rs`
- `tests/material_x509_ingest.rs`
- `tests/x509_roundtrip.rs`
- `tests/x509_banner_render.rs`
- `tests/x509_error_oracle.rs`
- `tests/debug_leak_scan.rs`

## Summary

Phase 6 delivers the X509Cert typed material variant cleanly. All load-bearing lock-ins hold (JCS via `jcs_serialize` for Envelope signable bytes; no new HKDF call-sites; no direct `chacha20poly1305` usage; manual `Debug` redaction on Material with X509Cert mirroring GenericSecret's `[REDACTED N bytes]` form; `Error::InvalidMaterial` Display genuinely generic with no `#[source]`/`#[from]` chain). Dual-signature ordering preserved: outer PKARR + inner Ed25519 verify complete before `age_decrypt` → `from_jcs_bytes` → `render_x509_preview`. `--armor` gated post-verify and rejected on non-X509 variants. `WireBudgetExceeded` path reachable and positively pinned by a real 388-byte fixture DER.

One warning-class finding: PEM ingest path does not enforce the "trailing bytes after certificate" invariant promised by the module docstring (D-P6-07). Everything else is info-grade.

## Warnings

### WR-01: PEM path silently accepts trailing data after `-----END CERTIFICATE-----`

**File:** `src/payload/ingest.rs:56-67` (and duplicated invariant in `src/preview.rs:56-65`)

**Issue:** `ingest::x509_cert` promises (doc comment lines 4-5 and 39-41) that trailing bytes after the certificate (D-P6-07) are rejected — concatenated-cert attack defense. The DER path enforces this via the `remainder` check on `parse_x509_certificate`. The PEM path does not.

`parse_x509_pem(raw)` returns `(bytes_read_remainder, pem)` — per x509-parser 0.16, "only the *first* PEM block is decoded." The function returns `_pem_rem` (bytes after the first END CERTIFICATE marker) which this code discards:

```rust
let (_pem_rem, pem) =
    x509_parser::pem::parse_x509_pem(raw).map_err(|_| Error::InvalidMaterial { ... })?;
```

Then `parse_x509_certificate(&der_bytes)` runs against `pem.contents`, not `raw`, so its own `remainder.is_empty()` check only covers DER-level trailing bytes inside the first block. Bytes after `-----END CERTIFICATE-----` are silently dropped.

**Impact:**
- Concatenated-cert input like `"<cert-A-PEM>\n<cert-B-PEM>\n"` ingests cert A with zero indication that cert B was dropped.
- An attacker-controlled PEM input can smuggle arbitrary trailing data past the receiver's "canonical DER" invariant. Canonical DER stored in `Material::X509Cert { bytes }` is still well-formed (so share_ref determinism holds), but the input-to-output mapping is non-injective in a way that contradicts the stated invariant.
- `tests/material_x509_ingest.rs` exercises the DER trailing-bytes path but has no PEM trailing-data test.

Warning rather than critical because share_ref is deterministic over canonical DER (no signature-forgery oracle), sender is already authenticated (dual-sig before decode), and real-world attack surface is narrow. Still — the docstring explicitly promises trailing-bytes rejection across both paths.

**Fix:**
```rust
let (pem_rem, pem) =
    x509_parser::pem::parse_x509_pem(raw).map_err(|_| Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "PEM body decode failed".into(),
    })?;
if pem.label != "CERTIFICATE" {
    return Err(Error::InvalidMaterial { ... });
}
// D-P6-07 for the PEM path
if pem_rem.iter().any(|b| !b.is_ascii_whitespace()) {
    return Err(Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "trailing bytes after certificate".into(),
    });
}
```

Add regression test `x509_cert_pem_with_trailing_second_cert_rejected` to `tests/material_x509_ingest.rs`.

## Info

### IN-01: PEM wrong-label arm has no integration test
`src/payload/ingest.rs:61-66` rejects mis-labeled PEM with `reason: "PEM label is not CERTIFICATE"`. Arm listed in `EXPECTED_REASONS` but no integration test feeds a `-----BEGIN PRIVATE KEY-----` wrapper through `ingest::x509_cert`.

### IN-02: `x509_parser::parse_x509_certificate` is called twice on receive
`run_receive` for an X509Cert envelope re-parses via `render_x509_preview`. Defensive (JCS round-trip could theoretically yield non-parsing bytes), not incorrect. Out of scope per v1 performance policy.

### IN-03: `expect()` in `pem_armor_certificate` base64→UTF-8 conversion
`src/flow.rs:798` — `std::str::from_utf8(chunk).expect("base64 output is ASCII")`. Structurally safe (base64 STANDARD is ASCII); could be written byte-based to avoid the `expect`.

### IN-04: `write!`/`writeln!` against `String` uses `.expect()` boilerplate
`src/preview.rs:82, 92-99, 121`. Writing to String via `fmt::Write` is infallible in practice; `expect`s are harmless but noisy.

### IN-05: `render_serial_hex` leading-zero stripping can produce odd-length hex
`src/preview.rs:118-132`. Serial `0x01` renders as `0x1`, not `0x01` — diverges from `openssl x509 -serial` convention. Golden-string test pins this behavior intentionally, but may confuse copy-paste users.

### IN-06: `expired_or_valid_tag` fail-open comment / semantics
`src/preview.rs:138-148`. On clock failure, falls back to `now = 0` → `[VALID]` tag. TTL check in `run_receive` aborts on clock failure before preview renders, so inconsistency is only reachable in direct unit tests.

### IN-07: Default `MaterialVariant::GenericSecret` correct but no Clap test pins default
`src/cli.rs:22-30`. Backward-compat default is exercised implicitly; no direct assertion that `cipherpost send --self -p 'x' -` (no `--material`) produces `GenericSecret`.

### IN-08: `phase2_material_variants_unimplemented.rs` module docstring stale
Module doc says "PAYL-02: Material::X509Cert / PgpKey / SshKey variants serialize their type tag" but X509Cert's serde shape is now asserted in `payload::tests::material_x509_cert_serde_round_trip`, not this file.

## Positive Notes (load-bearing lock-ins confirmed)

- **JCS-only for signable bytes**: `Envelope::to_jcs_bytes` → `crypto::jcs_serialize`. No `serde_json::to_vec` on signable paths.
- **HKDF info strings**: No new HKDF call-sites added in phase 6.
- **No direct chacha20poly1305**: Confirmed via grep.
- **Debug redaction**: Manual `impl Debug` on Material with both GenericSecret and X509Cert → `[REDACTED N bytes]`. Positively tested in `tests/debug_leak_scan.rs`.
- **Error-oracle hygiene**: `Error::InvalidMaterial` no `#[source]`/`#[from]`. Display pinned by `x509_error_oracle.rs::invalid_material_display_is_generic_for_every_source_reason`.
- **Exit-code mapping**: InvalidMaterial → exit 1, distinct from Signature* → 3. Pinned.
- **Dual-sig ordering**: `transport.resolve` (outer + inner verify) → `age_decrypt` → `from_jcs_bytes` → material inspection/preview. Preview output only reaches stderr via `prompter.render_and_confirm` AFTER all sig + JCS gates.
- **`--armor` gating**: `Error::Config("--armor requires --material x509-cert")` at `src/flow.rs:489-493`, pinned.
- **64 KB cap**: `enforce_plaintext_cap(material.plaintext_size())` — decoded DER length is capped, not raw PEM input.
- **share_ref determinism**: Canonical DER stored in `Material::X509Cert { bytes }` ensures reproducibility.
- **Wire budget `WireBudgetExceeded`**: Actually reachable, pinned by real 388-byte fixture DER. `#[ignore]`d round-trips are genuine architectural deferrals.
- **Dep-tree guard**: `x509_dep_tree_guard.rs` asserts no `ring`, no `aws-lc*`, pins `x509-parser v0.16.x`.
- **JCS envelope fixture**: Committed 626-byte `tests/fixtures/material_x509_signable.bin` pinned as protocol-break canary.

---

_Reviewer: gsd-code-reviewer_
_Depth: standard_
