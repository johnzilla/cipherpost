# Phase 7: Typed Material PgpKey + SshKey — Pattern Map

**Mapped:** 2026-04-24
**New/modified files:** 24
**Phase 6 analogs found:** 22 / 24 (2 files have a Phase-7-specific addition with no Phase 6 analog)

Phase 7 is mechanical replication of the Phase 6 X.509 ship-gate bundle, applied
twice (PGP, SSH). Each PGP file's analog is the X.509 counterpart; each SSH file's
analog is the same X.509 counterpart with one extra delta. New code that has *no*
Phase 6 analog is flagged explicitly: the `[WARNING: SECRET key]` line (PGP),
the `[DEPRECATED]` tag (SSH), the `Error::SshKeyFormatNotSupported` variant, and
the `--armor` matrix gating function (extension of an existing pattern).

## File Classification

| New / Modified File | Role | Data Flow | Closest Phase 6 Analog | Match Quality |
|---------------------|------|-----------|------------------------|---------------|
| `src/payload/ingest.rs` (extended: +`pgp_key`, +`ssh_key`) | parser/normalizer | transform | `src/payload/ingest.rs::x509_cert` (lines 43-99) | exact (per-variant fn pattern locked Phase 6) |
| `src/preview.rs` (extended: +`render_pgp_preview`, +`render_ssh_preview`) | renderer | transform | `src/preview.rs::render_x509_preview` (lines 54-101) | exact (pure-fn template) |
| `src/payload/mod.rs` (struct upgrades + accessors + plaintext_size arms + Debug arms) | model | n/a | `src/payload/mod.rs` X509Cert variant (lines 75-78, 122-130, 134-140, 87-100) | exact |
| `src/error.rs` (new `Error::SshKeyFormatNotSupported`) | error | n/a | `src/error.rs::Error::InvalidMaterial` (lines 64-73) | partial — distinct variant per D-P7-12, NOT a reuse of `InvalidMaterial` |
| `src/flow.rs` (`run_send` arms; `run_receive` match arms; `--armor` matrix) | dispatch | request-response | `src/flow.rs::run_send` lines 241-249 + `run_receive` lines 487-506 | exact (mechanical extension) |
| `src/main.rs` (swap NotImplemented for live dispatch) | dispatch | request-response | `src/main.rs` lines 123-128 (PGP/SSH guard) | exact (delete the guard) |
| `Cargo.toml` (new `pgp` + `ssh-key` deps + 6+ `[[test]]` stanzas) | config | n/a | Phase 6 Plan 01 added `x509-parser 0.16` (`Cargo.toml` from 06-01) | exact |
| `tests/fixtures/material_pgp_signable.bin` + `.reproduction.txt` | fixture | n/a | `tests/fixtures/material_x509_signable.bin` + `.reproduction.txt` | exact |
| `tests/fixtures/material_ssh_signable.bin` + `.reproduction.txt` | fixture | n/a | same as above | exact |
| `tests/material_pgp_ingest.rs` | test | transform | `tests/material_x509_ingest.rs` (10 tests) | exact (negative-matrix shape) |
| `tests/material_ssh_ingest.rs` | test | transform | same — with format-rejection arm extension | exact + 1 delta |
| `tests/pgp_roundtrip.rs` | test | request-response | `tests/x509_roundtrip.rs` (6 tests, 3 ignored) | exact (Ed25519-minimal target IS expected to pass per D-P7-03) |
| `tests/ssh_roundtrip.rs` | test | request-response | same — measurement-gated per D-P7-03 fallback | exact |
| `tests/pgp_banner_render.rs` | test | n/a | `tests/x509_banner_render.rs` (4 golden-string pins) | exact + SECRET-warning delta |
| `tests/ssh_banner_render.rs` | test | n/a | same + DEPRECATED tag delta | exact + 1 delta |
| `tests/pgp_error_oracle.rs` | test | n/a | `tests/x509_error_oracle.rs` (EXPECTED_REASONS × variants × forbidden) | exact (extend EXPECTED_REASONS) |
| `tests/ssh_error_oracle.rs` | test | n/a | same | exact (extend EXPECTED_REASONS + handle SshKeyFormatNotSupported) |
| `tests/material_pgp_envelope_round_trip.rs` | test | n/a | `tests/material_x509_envelope_round_trip.rs` (lines 14-69) | exact (JCS byte-identity pin) |
| `tests/material_ssh_envelope_round_trip.rs` | test | n/a | same | exact |
| `tests/pgp_dep_tree_guard.rs` (or extend `tests/x509_dep_tree_guard.rs`) | test | n/a | `tests/x509_dep_tree_guard.rs` (3 tests) | exact (planner picks new file vs. extend) |
| `tests/ssh_dep_tree_guard.rs` (or extend) | test | n/a | same — adds `cargo tree -p ed25519-dalek` SSH-10 evidence | exact + SSH-10 delta |
| `tests/debug_leak_scan.rs` (extended) | test | n/a | `tests/debug_leak_scan.rs` lines 70-113 | exact (mechanical: append 2 tests) |
| `SPEC.md` (§3.2 / §5.1 / §5.2 / §6 extensions) | docs | n/a | Phase 6 Plan 04 SPEC.md diffs (06-04 SUMMARY) | exact |

---

## Pattern Assignments

### `src/payload/ingest.rs` extensions — `pgp_key` + `ssh_key`

**Analog:** `src/payload/ingest.rs::x509_cert` (lines 43-99)

**Pipeline pattern to mirror** (lines 43-99): sniff strict prefix → format-specific path → parse via crate → trailing-bytes assertion → return `Material::<Variant> { bytes }`.

**Imports pattern** (lines 22-23): `use super::Material; use crate::error::Error;` — peer functions in the same module; nothing else needed.

**Strict-prefix sniff pattern** (lines 47-52):
```rust
let first_non_ws = raw
    .iter()
    .position(|b| !b.is_ascii_whitespace())
    .unwrap_or(raw.len());
let trimmed = &raw[first_non_ws..];
let is_pem = trimmed.starts_with(b"-----BEGIN CERTIFICATE-----");
```

**Reuse for PGP** (D-P7-05): mirror the same `trim_start` + `starts_with` test, but **inverted** — armor presence is a REJECT condition. Test `trimmed.starts_with(b"-----BEGIN PGP")` (catches both `PUBLIC KEY BLOCK` and `PRIVATE KEY BLOCK`). On match, return `Error::InvalidMaterial { variant: "pgp_key", reason: "ASCII-armored input rejected — supply binary packet stream" }`.

**Reuse for SSH** (D-P7-12): mirror the trim, then test `!trimmed.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----")`. Negative match → return the new `Error::SshKeyFormatNotSupported` (NOT `InvalidMaterial` — D-P7-12 dictates a distinct variant because the user-facing hint is variant-specific).

**Trailing-bytes pattern** (lines 91-96, the WR-01-corrected check):
```rust
if !remainder.is_empty() {
    return Err(Error::InvalidMaterial {
        variant: "x509_cert".into(),
        reason: "trailing bytes after certificate".into(),
    });
}
```

**WR-01 invariant for Phase 7** (per CONTEXT.md `<canonical_refs>` reference to 06-REVIEW-FIX.md): both `pgp_key` and `ssh_key` MUST enforce the same parser-consumed-entire-input check. PGP: count top-level packets and assert no trailing bytes after the last packet. SSH: assert `ssh-key`'s decoder consumed the entire blob (canonical re-encode per D-P7-11 gives this for free — re-encoded bytes have no trailing slack).

**Error-string-construction pattern** (lines 57-66): every error literal is a short, curated `String` — never wrap a parser error chain. Phase 7 PGP/SSH MUST follow.

**Test placeholder unit-test pattern** (lines 122-148): keep ingest's inline tests trivial; full integration matrix lives in the dedicated `material_pgp_ingest.rs` / `material_ssh_ingest.rs` files.

**Phase-7-specific delta:** PGP needs a primary-key-count check after parse (D-P7-06; tag-5/tag-6 enumeration). SSH needs the canonical re-encode through `ssh-key` (D-P7-11) before constructing `Material::SshKey { bytes }`. No Phase 6 analog for either — both are variant-specific validation extensions of the parse step.

---

### `src/preview.rs` extensions — `render_pgp_preview` + `render_ssh_preview`

**Analog:** `src/preview.rs::render_x509_preview` (lines 54-101)

**Pure-function shape** (lines 54-101): `pub fn render_<variant>_preview(bytes: &[u8]) -> Result<String, Error>`; no I/O; no leading/trailing `\n`; sanitized `Error::InvalidMaterial` on parse fail; oracle-hygiene reasons identical to ingest's.

**Subblock construction pattern** (lines 87-101):
```rust
let separator: String = format!("--- X.509 {}", "-".repeat(SEPARATOR_DASH_COUNT));
let mut out = String::new();
out.push_str(&separator);
out.push('\n');
writeln!(out, "Subject:     {}", subject).expect("String write");
// ... per-field writeln! lines ...
write!(out, "SHA-256:     {}", fingerprint_hex).expect("String write");  // last line: write! not writeln! (D-P6-17 no trailing \n)
Ok(out)
```

**Truncation helper** (lines 105-114): `truncate_display(s, limit)` — Unicode-scalar-value-based, ellipsis suffix. Reusable as-is for PGP UID and SSH comment truncation (D-P7-08 UID ≤64; D-P7-15 comment ≤64).

**`expired_or_valid_tag` pattern** (lines 138-148) for PGP key expiry (if PGP key has expiration subpacket): same fail-open-on-clock-error semantics. SSH has no expiry concept — skip.

**`format_unix_as_iso_utc` reuse** (line 17 import + Phase 6 Plan 02 promoted to `pub(crate)`): use directly for PGP `Created:` line. No SSH analog (SSH keys have no creation timestamp inside the OpenSSH v1 blob).

**SHA-256 fingerprint pattern** (lines 78-85): Phase 7 PGP fingerprint is computed by the `pgp` crate (v4: 40-hex SHA-1; v5: 64-hex SHA-256), NOT this manual SHA-256-of-bytes. SSH fingerprint is `SHA256:<base64-unpadded>` — extract from `ssh-key`'s `PublicKey::fingerprint(HashAlg::Sha256)`. Both delegate to the crate; do NOT reuse the X.509 manual `Sha256::digest(bytes)` shape.

**Separator width** (line 38, `SEPARATOR_DASH_COUNT = 57`): Phase 6 uses `--- X.509 ` + 57 dashes = 67 chars. CONTEXT.md `<specifics>` says PGP uses `--- OpenPGP ` + 53 dashes = 65 chars and SSH uses `--- SSH ` + 57 dashes = 65 chars. Banner width-render test should pin per-variant counts.

**Phase-7-specific delta — PGP `[WARNING: SECRET key]` line (D-P7-07):**
NO Phase 6 analog. When the parsed primary is `tag-5` (Secret-Key packet), `render_pgp_preview` emits a warning line BEFORE the separator. Per D-P7-07 (Claude's discretion row in CONTEXT.md), the planner picks one of:
- Embed the warning as the FIRST line of the returned string: `[WARNING: SECRET key — unlocks cryptographic operations]\n\n--- OpenPGP ...`
- Return a struct `{ warning: Option<String>, subblock: String }` and let `run_receive` thread the warning into the prompter's main banner area

Both satisfy D-P7-07. The single-string variant is mechanically closer to Phase 6 (return type stays `Result<String, Error>`); the struct variant requires extending `Prompter::render_and_confirm` with a new `warning_line: Option<&str>` parameter.

**Phase-7-specific delta — SSH `[DEPRECATED]` tag (D-P7-14):** mirrors the `[VALID]/[EXPIRED]` tag pattern (lines 138-148) but on the `Key:` line, not a NotAfter line. Trigger: DSA (any size) or RSA<2048. Inline tag like `Key:         ssh-rsa 1024 [DEPRECATED]`. Display-only, no warning line. Reuse the constant-style return-`&'static str` pattern from `expired_or_valid_tag`.

---

### `src/payload/mod.rs` modifications — Material struct-variant upgrade

**Analog:** `src/payload/mod.rs` X509Cert handling (lines 75-78, 87-100, 122-130, 134-140, 145-152)

**Struct-variant declaration** (lines 75-78):
```rust
X509Cert {
    #[serde(with = "base64_std")]
    bytes: Vec<u8>,
},
```

**Apply mechanically:** change `PgpKey,` → `PgpKey { #[serde(with = "base64_std")] bytes: Vec<u8> },` and same for `SshKey`. Wire shape automatically becomes `{"type":"pgp_key","bytes":"<b64>"}` / `{"type":"ssh_key","bytes":"<b64>"}` per D-WIRE-04 (no serde rename change needed; `rename_all = "snake_case"` on the enum already matches).

**Manual Debug redaction pattern** (lines 87-100):
```rust
Material::X509Cert { bytes } => {
    write!(f, "X509Cert([REDACTED {} bytes])", bytes.len())
}
Material::PgpKey => write!(f, "PgpKey"),
Material::SshKey => write!(f, "SshKey"),
```

**Apply mechanically:** replace the unit-variant arms with `Material::PgpKey { bytes } => write!(f, "PgpKey([REDACTED {} bytes])", bytes.len())` and same for `SshKey`. The "no Debug derive on secret holders" Pitfall #7 invariant is preserved.

**Accessor pattern** (lines 122-130):
```rust
pub fn as_x509_cert_bytes(&self) -> Result<&[u8], Error> {
    match self {
        Material::X509Cert { bytes } => Ok(bytes.as_slice()),
        other => Err(Error::InvalidMaterial {
            variant: variant_tag(other).to_string(),
            reason: "accessor called on wrong variant".to_string(),
        }),
    }
}
```

**Apply mechanically twice:** `as_pgp_key_bytes()` and `as_ssh_key_bytes()` — identical body, different variant arm. Reuses the existing `variant_tag` helper (lines 145-152) which already returns `"pgp_key"` / `"ssh_key"` for the unit variants — works unchanged after the struct-variant upgrade because the match patterns become `Material::PgpKey { .. }` / `Material::SshKey { .. }`.

**`plaintext_size()` arms** (lines 134-140):
```rust
Material::GenericSecret { bytes } => bytes.len(),
Material::X509Cert { bytes } => bytes.len(),
Material::PgpKey | Material::SshKey => 0,
```

**Apply mechanically:** swap the placeholder `0` arm for `Material::PgpKey { bytes } => bytes.len(), Material::SshKey { bytes } => bytes.len()`. Now `plaintext_size()` is exhaustive over four real arms (no placeholders).

**`variant_tag` helper** (lines 145-152): change `Material::PgpKey =>` to `Material::PgpKey { .. } =>` (and same for `SshKey`). Return strings unchanged.

---

### `src/error.rs` — new `Error::SshKeyFormatNotSupported` variant

**Analog:** `Error::InvalidMaterial` declaration (lines 64-73) + `exit_code` arm (line 108).

**No exact analog — this is a NEW variant** per D-P7-12. Distinguished from `InvalidMaterial` because the user-facing message embeds a copy-paste `ssh-keygen` hint that is variant-specific. Mirror the same `#[error("...")]` annotation style and the same "no `#[source]` chain" oracle-hygiene rule.

**Pattern to follow** (lines 64-73):
```rust
/// D-P6-03 (Phase 6): typed-material ingest failure ...
/// Do NOT use `#[source]` or `#[from]` here — that would bait a Display-chain leak ...
#[error("invalid material: variant={variant}, reason={reason}")]
InvalidMaterial { variant: String, reason: String },
```

**Apply for SSH** (D-P7-12 final wording resolved at plan time):
```rust
#[error("SSH key format not supported — convert to OpenSSH v1 via `ssh-keygen -p -o -f <path>`")]
SshKeyFormatNotSupported,
```

The error has NO fields (per D-P7-12 last paragraph: "String field should be a curated short label, never a wrapped parser error"). If a discriminator is needed (e.g., to log "detected legacy-PEM RSA header" vs "FIDO header"), planner may add a `detected: &'static str` field — Claude's discretion in CONTEXT.md `<deferred>` row "Key-type explicit rejection list".

**Exit-code mapping** (line 108): mirror the `Error::InvalidMaterial { .. } => 1` arm; add `Error::SshKeyFormatNotSupported => 1`. SPEC.md §6 row gets the new entry.

---

### `src/flow.rs` modifications — `run_send` + `run_receive` arm extensions

**Analog:** `src/flow.rs::run_send` lines 241-249 + `run_receive` lines 487-506

**`run_send` ingest dispatch** (lines 241-249):
```rust
let material = match material_variant {
    MaterialVariant::GenericSecret => {
        payload::ingest::generic_secret(plaintext_bytes.to_vec())?
    }
    MaterialVariant::X509Cert => payload::ingest::x509_cert(&plaintext_bytes)?,
    MaterialVariant::PgpKey | MaterialVariant::SshKey => {
        return Err(Error::NotImplemented { phase: 7 });
    }
};
```

**Apply mechanically:** swap the `PgpKey | SshKey` rejection arm for two live dispatch arms:
```rust
MaterialVariant::PgpKey => payload::ingest::pgp_key(&plaintext_bytes)?,
MaterialVariant::SshKey => payload::ingest::ssh_key(&plaintext_bytes)?,
```

The cap-on-decoded-size pattern (line 254, `payload::enforce_plaintext_cap(material.plaintext_size())?`) works unchanged — the new `plaintext_size()` arms (above) feed it.

**`run_receive` material match** (lines 487-506):
```rust
let (material_bytes, preview_subblock): (&[u8], Option<String>) = match &envelope.material {
    Material::GenericSecret { .. } => {
        if armor {
            return Err(Error::Config(
                "--armor requires --material x509-cert".into(),
            ));
        }
        (envelope.material.as_generic_secret_bytes()?, None)
    }
    Material::X509Cert { .. } => {
        let bytes = envelope.material.as_x509_cert_bytes()?;
        let sub = preview::render_x509_preview(bytes)?;
        (bytes, Some(sub))
    }
    Material::PgpKey | Material::SshKey => {
        return Err(Error::NotImplemented { phase: 7 });
    }
};
```

**Apply mechanically + extend `--armor` matrix per D-P7-13:** swap the unit-variant rejection arm for two live arms. PGP arm calls `as_pgp_key_bytes()` + `render_pgp_preview()`. SSH arm calls `as_ssh_key_bytes()` + `render_ssh_preview()`, AND rejects `armor=true` with `Error::Config("--armor not applicable to ssh-key — OpenSSH v1 is self-armored")`.

**`--armor` matrix decision (D-P7-13):** the existing `if armor { return Err(Error::Config(...)) }` at line 489-493 is the GenericSecret-specific guard. Phase 7 SSH adds an analogous guard inside the `Material::SshKey { .. }` arm. PGP arm allows `armor=true` (per D-P7-13: "accepted for x509-cert AND pgp-key"). The aggregate validation may be lifted to a `validate_armor_matrix(variant, armor) -> Result<(), Error>` helper called once at the top — Claude's discretion.

**Phase-6 error-string update needed:** the existing `"--armor requires --material x509-cert"` literal (line 491) becomes stale — Phase 7 widens the accepted set to `x509-cert OR pgp-key`. Update to e.g. `"--armor requires --material x509-cert or pgp-key"`. The two existing tests that pin this exact string (`tests/x509_roundtrip.rs::armor_on_generic_secret_rejected_with_config_error` line 309 and any SPEC.md / phase-6 docs) need a coordinated update.

**`pem_armor_certificate` helper** (line 792): X.509-specific, stays as-is. PGP `--armor` output uses the `pgp` crate's armor-serialize API (NOT this helper) — call site lives in the new `run_receive` PGP arm or a sibling `pgp_armor` helper.

**Phase-7 PGP armor helper (new):** no Phase 6 analog because the X.509 helper hand-rolls armor without a crate (line 792 is base64+CERTIFICATE wrapper). PGP must use `pgp::armor::write` (or whatever the crate exposes for ASCII-armor serialization). Naming convention: `pgp_armor(bytes: &[u8]) -> Result<Vec<u8>, Error>` to match `pem_armor_certificate`'s signature shape.

**`material_type_string` helper** (lines 766-790): exhaustive match over Material variants — needs PGP/SSH arms to return `"pgp_key"` / `"ssh_key"` if not already. Already covers them in unit-variant form; pattern-match update is mechanical (`Material::PgpKey { .. }`, `Material::SshKey { .. }`).

---

### `src/main.rs` — swap `NotImplemented` guard for live routing

**Analog:** `src/main.rs` lines 123-128.

**Pattern to delete:**
```rust
// D-P6-01: reject unimplemented typed variants at dispatch ...
if matches!(material, MaterialVariant::PgpKey | MaterialVariant::SshKey) {
    return Err(cipherpost::Error::NotImplemented { phase: 7 }.into());
}
```

**Apply:** delete this block entirely. The `run_send` library-level dispatch (Phase 6 belt-and-suspenders) is also removed in `flow.rs` (above), so both layers go live in lock-step. Per D-P7-19, all 8 plans are autonomous with `autonomous: true`.

---

### `Cargo.toml` — new `pgp` + `ssh-key` deps + test stanzas

**Analog:** Phase 6 Plan 01 added `x509-parser = { version = "0.16", default-features = false }`.

**Apply for PGP** (D-P7-04): `pgp = { version = "0.x", default-features = false, features = ["alloc"] }`. Exact version resolved at plan-01 time via `cargo search`. Verify `cargo tree | grep -E "ring|aws-lc"` returns no matches (extends Phase 6 dep-tree-guard contract).

**Apply for SSH** (D-P7-10): `ssh-key = { version = "0.6", default-features = false, features = ["alloc"] }`. Pre-flight measurement: `cargo tree -p ed25519-dalek` MUST show only `3.0.0-pre.5` (the load-bearing pin from CLAUDE.md `<lock-ins>`); fallback if the `ed25519` feature pulls `2.x` is documented coexistence per D-P7-10.

**Test stanzas pattern** (Phase 6 Plan 04 added 6 `[[test]]` stanzas): each new test file gets a `[[test]] name = "..."` stanza. Files that hit `MockTransport` need `required-features = ["mock"]`.

---

### Test fixtures — `material_pgp_signable.bin` + `material_ssh_signable.bin`

**Analog:** `tests/fixtures/material_x509_signable.bin` (626 B; SHA-256 recorded in 06-04 SUMMARY) + `tests/fixtures/x509_cert_fixture.reproduction.txt` (the recipe note).

**Pattern:** commit byte-locked JCS bytes once; pair with a `.reproduction.txt` sibling documenting the recipe (with deterministic-vs-random fields called out — per CONTEXT.md `<specifics>`, PGP UID + Created are deterministic but key bytes + signature are random; SSH key bytes are random but the canonical-re-encoded blob structure is deterministic).

**PGP fixture (CONTEXT.md `<specifics>`):** `gpg --batch --quick-gen-key` or `pgp` crate test utils. UID = `cipherpost-fixture <fixture@cipherpost.test>` (43 chars). Created = pinned timestamp (e.g., `2026-01-01T00:00:00Z`).

**SSH fixture (CONTEXT.md `<specifics>`):** `ssh-keygen -t ed25519 -C "" -N "" -f /tmp/cipherpost-fixture` once. Empty comment, no passphrase. Bytes committed as `tests/fixtures/material_ssh_fixture.openssh-v1`. Reproduction recipe in `.txt` sibling.

---

### `tests/material_pgp_envelope_round_trip.rs` + `tests/material_ssh_envelope_round_trip.rs`

**Analog:** `tests/material_x509_envelope_round_trip.rs` (full file, 70 lines).

**Apply mechanically:** rename `X509Cert` → `PgpKey` / `SshKey`, swap fixture paths, swap snake_case tags. The 4 tests (fixture-bytes-match, JCS-round-trip-byte-identical, JCS-shape-contains-tag, regenerate-helper-`#[ignore]`) translate one-for-one.

**Key lines to copy** (lines 14-22, the `fixture_envelope()` constructor):
```rust
fn fixture_envelope() -> Envelope {
    Envelope {
        created_at: 1_700_000_000,
        material: Material::X509Cert {
            bytes: DER_FIXTURE.to_vec(),
        },
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}
```

**Regeneration helper** (lines 62-69): `#[ignore]`-gated regenerate-the-fixture helper — copy verbatim.

---

### `tests/material_pgp_ingest.rs` + `tests/material_ssh_ingest.rs`

**Analog:** `tests/material_x509_ingest.rs` (10 tests, 235 lines).

**Test matrix to mirror** (lines 39-235):
- happy path produces variant
- format normalization to canonical bytes (PGP: armor REJECTED instead — see delta; SSH: re-encode produces canonical OpenSSH v1)
- malformed bytes rejected with generic reason
- trailing bytes rejected (WR-01 invariant)
- empty input rejected
- accessor on wrong variant returns `InvalidMaterial { reason: "accessor called on wrong variant" }`
- Display oracle hygiene (no parser internals leak)

**Phase-7 delta — PGP-specific tests** (D-P7-05, D-P7-06):
- `pgp_armor_input_rejected` — `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----BEGIN PGP PRIVATE KEY BLOCK-----` both rejected with `Error::InvalidMaterial { variant: "pgp_key", reason: "ASCII-armored input rejected — supply binary packet stream" }`
- `pgp_multi_primary_rejected` — concatenated two primary public keys → `Error::InvalidMaterial { reason: "PgpKey must contain exactly one primary key; keyrings are not supported in v1.1 (found N primary keys)" }` (with N substituted)

**Phase-7 delta — SSH-specific tests** (D-P7-12):
- `ssh_legacy_pem_rsa_rejected` — `-----BEGIN RSA PRIVATE KEY-----` → `Error::SshKeyFormatNotSupported` (NOT `InvalidMaterial`)
- `ssh_rfc4716_rejected` — `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----` → same
- `ssh_fido_rejected` — `-----BEGIN OPENSSH-FIDO PRIVATE KEY-----` → same
- `ssh_legacy_pem_dsa_rejected`, `ssh_legacy_pem_ec_rejected` — same
- `ssh_canonical_re_encode_round_trip` — input through `ingest::ssh_key` produces bytes that re-feed cleanly (D-P7-11 canonical-blob invariant)

**Helper-fn pattern** (lines 14-37): `pem_armor_der` + `pem_armor_der_crlf`. PGP test file may need a `gpg_armor_pubkey` / `gpg_armor_seckey` helper to construct the rejection input. SSH test file may need OpenSSH-v1 fixture concatenation helpers.

---

### `tests/pgp_roundtrip.rs` + `tests/ssh_roundtrip.rs`

**Analog:** `tests/x509_roundtrip.rs` (6 tests; 3 `#[ignore]`'d for wire-budget; 3 active including the `expected-to-fail` positive surface test).

**Phase-7 delta (D-P7-02 + D-P7-03):** unlike Phase 6, Phase 7 EXPECTS Ed25519-minimal round-trip to PASS (per D-P7-03 success floor). Active tests:
- `pgp_self_round_trip_recovers_packet_stream` (NO `#[ignore]` — D-P7-03)
- `pgp_send_realistic_key_surfaces_wire_budget_exceeded_cleanly` (mirrors the X509 positive `expected-to-fail` test at lines 226-270)
- `armor_on_ssh_rejected_with_config_error` (mirrors lines 277-313 — `Error::Config` exact-string match)
- `pgp_malformed_packet_send_rejected_at_ingest` (mirrors lines 318-342)

**SSH analogs:** same shape, with `ssh_self_round_trip_recovers_canonical_bytes` as the active round-trip; downgrade to `#[ignore]` ONLY if plan-01 measurement (CONTEXT.md `<specifics>` wire-budget bullet) shows the floor exceeds 1000 B.

**Identity setup helper** (lines 42-51, `fresh_identity`): copy verbatim. Returns `(Identity, Keypair, TempDir)`; uses `CIPHERPOST_HOME` env override and the standard test passphrase.

**`#[serial]` invariant:** every test that mutates `CIPHERPOST_HOME` MUST carry `#[serial]` (CLAUDE.md `<lock-ins>` `serial_test = "3"` rule). Phase 6 file uses it on every test (lines 72, 117, 179, 227, 276, 318) — replicate exactly.

**`AutoConfirmPrompter` shim:** import from `cipherpost::flow::test_helpers::AutoConfirmPrompter` (line 30). The Prompter trait already accepts `Option<&str>` for `preview_subblock` after Phase 6 Plan 03 — no changes needed.

---

### `tests/pgp_banner_render.rs` + `tests/ssh_banner_render.rs`

**Analog:** `tests/x509_banner_render.rs` (4 golden-string tests, 145 lines).

**Test pattern** (lines 19-103): assert per-line prefix (`Subject:     `, `Issuer:      `, etc.), then assert per-line content for the deterministic fixture fields. Mirror exactly with PGP fields (Fingerprint, Primary UID, Key, Subkeys, Created) and SSH fields (Key, Fingerprint, Comment).

**SHA-256 line independence** (lines 105-120): X.509 computes SHA-256 over the raw DER and pins the last line. PGP equivalent: assert the fingerprint line matches an independent computation via the `pgp` crate. SSH equivalent: assert the SHA-256 fingerprint matches `ssh-key`'s `PublicKey::fingerprint(HashAlg::Sha256)`.

**Layout invariants** (lines 123-145): `no_leading_or_trailing_newline` + separator-dash-count tests. Mirror exactly with per-variant dash counts (PGP = 53; SSH = 57 per CONTEXT.md `<specifics>`).

**Phase-7 delta — PGP `[WARNING: SECRET key]` test:**
NO Phase 6 analog. New test `render_pgp_preview_secret_key_includes_warning_line`: load a tag-5 (Secret-Key) primary fixture, assert the returned string starts with `[WARNING: SECRET key — unlocks cryptographic operations]\n` (or, if planner picked the struct-return variant, assert `result.warning.is_some()`).

**Phase-7 delta — SSH `[DEPRECATED]` test:**
NO Phase 6 analog. New test `render_ssh_preview_dsa_key_carries_deprecated_tag`: load a DSA fixture (or RSA<2048), assert the `Key:         ssh-dss [DEPRECATED]` line ends with the bracketed tag. Mirror the structure of the Phase 6 `[VALID]` tag check at line 99 (`lines[5].ends_with("  [VALID]")`).

---

### `tests/pgp_error_oracle.rs` + `tests/ssh_error_oracle.rs`

**Analog:** `tests/x509_error_oracle.rs` (3 tests, 104 lines).

**`EXPECTED_REASONS` extension** (lines 21-27):
```rust
const EXPECTED_REASONS: &[&str] = &[
    "malformed DER",
    "trailing bytes after certificate",
    "PEM body decode failed",
    "PEM label is not CERTIFICATE",
    "accessor called on wrong variant",
];
```

**Apply for PGP:** append:
- `"ASCII-armored input rejected — supply binary packet stream"` (D-P7-05)
- `"PgpKey must contain exactly one primary key; keyrings are not supported in v1.1"` (D-P7-06; without the dynamic N count — assert via `starts_with` if N is variable)
- `"malformed PGP packet stream"` (parse failure; exact wording at plan time)
- `"trailing bytes after PGP packet stream"` (WR-01 mirror)

**Apply for SSH:** append:
- `"malformed OpenSSH v1 blob"` (parse failure; wording at plan time)
- `"trailing bytes after OpenSSH v1 blob"` (WR-01 mirror)

**FORBIDDEN_DISPLAY_TOKENS** (lines 31-41): extend with PGP/SSH parser-internal markers — e.g., `"pgp::errors"`, `"ssh_key::Error"`, `"pgp::packet"`, `"PgpError"`, etc. (exact set at plan time after observing what each crate's Display chain looks like).

**Variants list** (line 46): `&["generic_secret", "x509_cert", "pgp_key", "ssh_key"]` — already correct, no change. The matrix expands automatically.

**Exit-code tests** (lines 73-104): mirror `invalid_material_exit_code_is_always_1` and `exit_3_is_still_reserved_for_signature_failures`. SSH file gains an extra test: `ssh_key_format_not_supported_exit_code_is_1` — pins the new variant's exit-1 mapping.

**Oracle-hygiene `EXPECTED_REASONS` location:** CONTEXT.md `<decisions>` Claude-discretion row notes "may move to a shared `tests/common.rs`" — planner picks. Default: keep inlined per-test-file (current Phase 6 convention).

---

### `tests/pgp_dep_tree_guard.rs` + `tests/ssh_dep_tree_guard.rs` (or extend `x509_dep_tree_guard.rs`)

**Analog:** `tests/x509_dep_tree_guard.rs` (3 tests, 77 lines).

**Pattern to mirror** (lines 12-23, `cargo_tree_text` helper):
```rust
fn cargo_tree_text() -> String {
    let out = Command::new("cargo")
        .arg("tree")
        .output()
        .expect("cargo tree must run in test environment");
    assert!(out.status.success(), ...);
    String::from_utf8(out.stdout).expect(...)
}
```

**`ring` / `aws-lc` absence** (lines 25-54): copy verbatim; the assertion is dep-tree-wide and already covers PGP/SSH transitives.

**Version-pin assertion** (lines 56-77): mirror per-crate. PGP: `cargo tree -p pgp` → first line starts with `pgp v0.x.`. SSH: `cargo tree -p ssh-key` → first line starts with `ssh-key v0.6.`.

**Phase-7 delta — SSH-10 `cargo tree -p ed25519-dalek` evidence test (D-P7-10):**
NO Phase 6 analog. New test in the SSH dep-tree file: run `cargo tree -p ed25519-dalek`, assert output contains `3.0.0-pre.5` and (per the D-P7-10 fallback path) document whether `2.x` also appears. The test FAILS if `3.0.0-pre.5` is absent (load-bearing pin per CLAUDE.md `<lock-ins>`); the test WARNS but passes if both `2.x` and `3.0.0-pre.5` are present (D-P7-10 documented coexistence).

**Planner choice** (D in `<canonical_refs>`): extend the existing `x509_dep_tree_guard.rs` with the new assertions, OR add new files. Either way, `cargo test dep_tree` runs all guards (test-name-based filter).

---

### `tests/debug_leak_scan.rs` extension

**Analog:** `tests/debug_leak_scan.rs` lines 70-113 (Phase 6 Plan 04's extension).

**Pattern to mirror** (lines 89-105, `material_x509_cert_debug_redacts_bytes`):
```rust
#[test]
fn material_x509_cert_debug_redacts_bytes() {
    use cipherpost::payload::Material;
    let m = Material::X509Cert {
        bytes: vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A],
    };
    let dbg = format!("{:?}", m);
    assert!(dbg.contains("REDACTED"), ...);
    assert!(!dbg.contains("abcdef123456789a"), "X509Cert Debug leaked bytes: {:?}", dbg);
}
```

**Apply mechanically twice:** `material_pgp_key_debug_redacts_bytes` and `material_ssh_key_debug_redacts_bytes`. Same body shape, same hex byte-window assertion.

**DELETE** the Phase 6 placeholder test `material_pgp_and_ssh_unit_variant_debug_no_bytes` (lines 107-113) — no longer applies once the variants gain `bytes` fields.

---

### `SPEC.md` extensions (§3.2 / §5.1 / §5.2 / §6)

**Analog:** Phase 6 Plan 04 (commit `d231d99`) extended these exact sections.

| Section | Phase 6 pattern | Apply for Phase 7 |
|---------|-----------------|-------------------|
| §3.2 Material variants | Added X509Cert wire-form table + canonical-DER + supply-chain note + OpenSSL-forward DN + oracle-hygiene + Pitfall #22 | Add PgpKey wire-form `{"type":"pgp_key","bytes":"<b64>"}` + binary-packet-stream invariant + `pgp` crate supply-chain note. Add SshKey wire-form + canonical-OpenSSH-v1 invariant + `ssh-key` crate supply-chain note + ed25519-dalek pin evidence. Extend Pitfall #22 to cover both variants. Resolve the Phase 6 "pgp_key/ssh_key Phase 7 deferral" note (delete it). |
| §5.1 Send | Inserted ingest + cap-on-decoded-size steps; documented `--material <variant>` | Update `--material` accepted-values list to `generic-secret \| x509-cert \| pgp-key \| ssh-key`. No new ingest step (the existing one dispatches by variant). |
| §5.2 Receive | Inserted X.509 subblock layout; documented `--armor` + GenericSecret rejection | Insert PGP subblock layout (with `[WARNING: SECRET key]` line callout) + SSH subblock (with `[DEPRECATED]` tag callout). Update `--armor` matrix: accepted for `x509-cert + pgp-key`; rejected for `ssh-key + generic-secret`. Update the Phase-6 `"--armor requires --material x509-cert"` literal everywhere it appears. |
| §6 Exit codes | Extended exit-1 row with `InvalidMaterial { variant, reason }` | Add `Error::SshKeyFormatNotSupported` → exit 1 row alongside `InvalidMaterial`. No new exit codes (per CONTEXT.md `<domain>` `In scope` last bullet). |

**lychee link-check** (Phase 6 ran 12/12 OK locally): re-verify after edits. Same CI gate.

---

## Shared Patterns

### Material variant struct upgrade
**Source:** `src/payload/mod.rs` lines 75-78 + 87-100 + 122-130 + 134-140 + 145-152 (single Phase 6 plan, single Material variant)
**Apply to:** `Material::PgpKey { bytes }` + `Material::SshKey { bytes }` — identical 5-touchpoint upgrade (struct-variant decl, Debug arm, accessor, plaintext_size arm, variant_tag pattern-match).

### Per-variant ingest function
**Source:** `src/payload/ingest.rs::x509_cert` lines 43-99 (sniff → parse → trailing-bytes → return Material)
**Apply to:** `payload::ingest::pgp_key` + `payload::ingest::ssh_key` — same pipeline shape; only the parser library and the strict-prefix logic differ.

### Pure-function preview renderer
**Source:** `src/preview.rs::render_x509_preview` lines 54-101 + helpers 105-214
**Apply to:** `preview::render_pgp_preview` + `preview::render_ssh_preview` — same return-`Result<String, Error>` contract; same no-leading/trailing-`\n`; same `writeln!`/`write!` build pattern; same oracle-hygiene reasons.

### Oracle-hygiene enumeration matrix
**Source:** `tests/x509_error_oracle.rs` lines 21-27 (`EXPECTED_REASONS`) + 31-41 (`FORBIDDEN_DISPLAY_TOKENS`) + 43-71 (the matrix test)
**Apply to:** every Phase 7 file that constructs `Error::InvalidMaterial`. Test files extend `EXPECTED_REASONS` with new literals. The matrix test grows by N×4 assertions per added reason (4 = number of variants).

### Debug-leak-scan extension
**Source:** `tests/debug_leak_scan.rs` lines 89-105
**Apply to:** PGP and SSH variants — append two new tests with the same hex-window assertion shape.

### Wire-budget positive-surface test
**Source:** `tests/x509_roundtrip.rs::x509_send_realistic_cert_surfaces_wire_budget_exceeded_cleanly` lines 226-270
**Apply to:** PGP and SSH per D-P7-02 — `<variant>_send_realistic_key_surfaces_wire_budget_exceeded_cleanly` with the same `match err { Error::WireBudgetExceeded { .. } => ... }` shape.

### Dep-tree guard via `cargo tree` subprocess
**Source:** `tests/x509_dep_tree_guard.rs` lines 12-23 + 25-54
**Apply to:** `pgp` + `ssh-key` version-pin assertions, and SSH-10 `ed25519-dalek` evidence test (Phase 7 NEW).

### `#[serial]` on env-mutating tests
**Source:** every Phase 6 test that calls `fresh_identity()` (CIPHERPOST_HOME setter)
**Apply to:** every Phase 7 round-trip test. CLAUDE.md `<lock-ins>` rule: nextest parallel runner races otherwise.

---

## No Analog Found

Files / code that have NO Phase 6 analog and require Phase-7-specific design:

| New code | Reason | Where in PATTERNS.md |
|----------|--------|----------------------|
| `[WARNING: SECRET key]` line in PGP preview | Phase 6 had only public X.509 certs; no secret-bearing variant warned at preview time | `src/preview.rs` section, "Phase-7-specific delta — PGP `[WARNING: SECRET key]` line" |
| `[DEPRECATED]` tag on SSH `Key:` line for DSA / RSA<2048 | Phase 6 `[VALID]/[EXPIRED]` is on a TIME field; Phase 7 `[DEPRECATED]` is on an ALGORITHM field — different trigger | `src/preview.rs` section, "Phase-7-specific delta — SSH `[DEPRECATED]` tag" |
| `Error::SshKeyFormatNotSupported` variant | Phase 6 only added `InvalidMaterial`. SSH needs a distinct variant because the user-facing message embeds a copy-paste `ssh-keygen` hint that varies with the input format | `src/error.rs` section |
| PGP armor output helper (`pgp_armor` or similar) | Phase 6 hand-rolled `pem_armor_certificate` because base64+header was trivial. PGP armor is non-deterministic + crate-specific — must call `pgp` crate's armor-write API | `src/flow.rs` section, "Phase-7 PGP armor helper" |
| `--armor` matrix validation function | Phase 6 had a single inline `if armor` guard inside the GenericSecret arm. Phase 7 widens to a proper matrix (4 variants × {armor, no-armor}); planner may extract a `validate_armor_matrix` helper | `src/flow.rs` section, "`--armor` matrix decision (D-P7-13)" |
| Multi-primary-key rejection logic for PGP | Phase 6 X.509 has at most one cert per input; Phase 7 PGP must count tag-5/tag-6 packets and reject keyrings | `src/payload/ingest.rs` section, "Phase-7-specific delta — PGP" |
| Canonical re-encode for SSH (`PrivateKey::to_bytes_openssh()`) | Phase 6 X.509 stores input DER directly when in DER form; Phase 7 SSH always re-encodes to canonicalize | `src/payload/ingest.rs` section, "Phase-7-specific delta — SSH" |
| SSH-10 `ed25519-dalek` pin evidence test | Phase 6 didn't introduce ed25519-dalek concerns; SSH crate may pull `2.x` and trip the load-bearing pin | `tests/pgp_dep_tree_guard.rs / ssh_dep_tree_guard.rs` section |

---

## Metadata

**Analog search scope:** `src/`, `tests/`, `tests/fixtures/`, `.planning/phases/06-typed-material-x509cert/` (all 4 SUMMARY.md files)
**Files scanned:** 11 source files + 7 test files + 4 phase-6 SUMMARY.md files
**Pattern extraction date:** 2026-04-24
**Phase 6 ship-gate template (per 06-04 SUMMARY):** "fixtures → JCS byte-identity → ingest negative matrix → golden-string banner → oracle-hygiene enumeration → leak-scan extension → CI dep-tree assertion → SPEC.md update" — Phase 7 replicates twice (PGP + SSH), 8 plans total per D-P7-17.
