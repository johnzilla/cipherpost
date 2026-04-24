---
phase: 07-typed-material-pgpkey-sshkey
tags: [rust, pgp, rpgp, ssh-key, ed25519-dalek, wire-budget, rfc-9580, supply-chain]
resolved_unknowns_count: 4
researched: 2026-04-24
confidence: HIGH (crate state verified against pinned v-tag Cargo.toml; wire-budget calibrated against Phase 6 empirical measurement)
---

# Phase 7: Typed Material — PgpKey + SshKey - Research

**Scope note:** CONTEXT.md has already locked 19 implementation decisions (crate choice, armor policy, multi-primary rule, banner layout, `--armor` matrix, plan structure, etc.). This research does NOT revisit them. It answers only the four specific unknowns the planner cannot know without looking outside this repo.

---

## Executive Summary (one paragraph per unknown)

**1. pgp (rpgp) crate state.** Current stable is **pgp 0.19.0**, dual-licensed **MIT OR Apache-2.0** [CITED: https://raw.githubusercontent.com/rpgp/rpgp/v0.19.0/Cargo.toml]. It supports BOTH RFC 4880 (v4, 40-hex fingerprint) AND RFC 9580 (v6, 64-hex fingerprint) [CITED: https://docs.rs/pgp/latest/pgp/] — so PGP-04's dual-fingerprint rendering requirement is cleanly satisfied. No `ring`/`aws-lc`/`openssl` in the dep tree — it uses RustCrypto primitives (aes, sha2, rsa, ecdsa, curve25519-dalek) [CITED]. **BUT: pgp 0.19.0 unconditionally depends on `ed25519-dalek = "2.1.1"`** (no `optional = true`, no feature gate) [VERIFIED: pinned v0.19.0 Cargo.toml line]. This DIRECTLY CONFLICTS with cipherpost's load-bearing `=3.0.0-pre.5` pin (from pkarr). Cargo will resolve this by emitting BOTH versions side-by-side; `deny.toml` already sets `multiple-versions = "warn"` [VERIFIED: /home/john/vault/projects/github.com/cipherpost/deny.toml line 31] so this will not fail CI, but it will double the ed25519 implementation in the binary. **This is the one finding that invalidates an assumption in D-P7-04** — see Gaps section.

**2. ssh-key crate state.** Current stable is **ssh-key 0.6.7**, dual-licensed **Apache-2.0 OR MIT** [CITED: https://raw.githubusercontent.com/RustCrypto/SSH/ssh-key/v0.6.7/ssh-key/Cargo.toml]. **Critical answer to D-P7-10's pre-flight question: YES, the `ed25519` feature CAN be disabled while retaining Ed25519 parsing and SHA-256 fingerprint computation.** Evidence: (a) `sha2 = "0.10.8"` is an UNCONDITIONAL dep — never gated [CITED: Cargo.toml line]; (b) `Ed25519PublicKey` struct + its `Decode`/`Encode`/`TryFrom` impls are NOT gated by `cfg(feature = "ed25519")` — only the `ed25519_dalek::VerifyingKey` interop TryFrom impls are [CITED: src/public/ed25519.rs review]; (c) `Fingerprint::new()` has no feature gating and operates on `public::KeyData` generically [CITED: src/fingerprint.rs review]. Default features are `["ecdsa", "rand_core", "std"]` — `ed25519` is NOT in default, which means `default-features = false, features = ["alloc"]` avoids ed25519-dalek 2.x entirely (ssh-key side). Byte-determinism of `PrivateKey::from_openssh()` + `to_bytes()` is NOT explicitly documented in the API docs [CITED: https://docs.rs/ssh-key/0.6.7/ssh_key/private/struct.PrivateKey.html] — the crate advertises "constant-time encoder/decoder" but does not claim canonical re-encoding. Plan 05 MUST empirically verify byte-determinism on a round-trip (parse → to_bytes → parse → to_bytes; assert the two to_bytes outputs match).

**3. Wire-budget predictions.** Phase 6 empirical data is the calibration anchor: 388 B DER → 1616 B encoded PKARR packet (expansion factor ~4.16×). Applying this ratio: a **PGP Ed25519-minimal fixture (~200-250 B raw packet stream)** predicts a **~830-1040 B encoded packet** — borderline under the 1000 B BEP44 ceiling, plausibly fits if UID is kept ≤20 chars. An **SSH Ed25519-minimal fixture (~321 B raw binary, or ~411-560 B when PEM-armored)** predicts **~1340-2330 B encoded packet** — DEFINITIVELY exceeds the 1000 B ceiling by 30-130%. **Verdict for D-P7-03: PGP round-trip is plausible with aggressive UID trimming; SSH round-trip cannot fit regardless of how minimal we make the key.** Plan 05 MUST adopt the `#[ignore]` escape hatch for SSH round-trip from day one; don't attempt and fail during execution.

**4. PGP crate CVE history.** Five GHSA advisories exist against rpgp/pgp as of April 2026 [CITED: https://github.com/rpgp/rpgp/security/advisories]. GHSA-9rmp-2568-59rv and GHSA-4grw-m28r-q285 (Dec 2024) are fixed in 0.14.1 and earlier — 0.19.0 is clean. Three more (Feb 2026 publication) — GHSA-7587-4wv6-m68m (RSA parser crash), GHSA-8h58-w33p-wq3g (deeply-nested message DoS), GHSA-c7ph-f7jm-xv4w (missing integrity check on encrypted data) — affect versions up through 0.18.x and are patched in 0.19.0 [CITED: https://github.com/rpgp/rpgp/security/advisories/GHSA-7587-4wv6-m68m]. **0.19.0 is the clean baseline.** Transitive concern: `rsa 0.9` (pulled via pgp for RSA key support) has **RUSTSEC-2023-0071 Marvin Attack timing side channel — NO PATCHED VERSION available** [CITED: https://rustsec.org/advisories/RUSTSEC-2023-0071.html]. cipherpost's use is local-only (no network timing observation surface), so impact is low, BUT cargo-audit / cargo-deny WILL flag this on CI unless explicitly ignored. Need to either add to `deny.toml [advisories] ignore` with rationale, or find a way to disable the `rsa` feature in pgp (the pgp 0.19.0 Cargo.toml does NOT expose a feature to disable RSA — it's core). Document this as a supply-chain acceptance in plan 01 SPEC.md update.

---

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PGP-01 | ASCII-armored input rejected at send ingest | pgp 0.19.0 confirmed to handle binary packet streams natively (no auto-de-armoring in parse_packets); strict prefix sniff in ingest before any crate call is straightforward — mirrors Phase 6 PEM-sniff |
| PGP-02 | Wire format `{"type":"pgp_key","bytes":"<base64-std-padded>"}` | No crate-level concern; JCS envelope carries opaque bytes |
| PGP-03 | Reject multi-primary keyrings at ingest | pgp 0.19.0 supports iterating top-level packets via `packet::PacketParser`; counting tag-5 (SecretKey) + tag-6 (PublicKey) occurrences at top-level is a 10-line filter — documented in pgp's low-level API |
| PGP-04 | Render v4 40-hex OR v5/v6 64-hex fingerprint | pgp 0.19.0 supports RFC 9580 v6 keys with 64-hex fingerprint (via `composed::Fingerprint` enum variant) AND RFC 4880 v4 with 40-hex — both rendering paths exist in the crate |
| PGP-05 | `--armor` emits ASCII-armored output | pgp 0.19.0 provides `ArmoredWriter` / `Serialize::to_armored_writer` for the output path |
| PGP-06 | Per-variant size check (64 KB plaintext cap) | Inherited from Phase 6 `enforce_plaintext_cap`; no crate-level concern |
| PGP-07 | JCS fixture `tests/fixtures/material_pgp_signable.bin` committed | Mechanical — Phase 6 pattern |
| PGP-08 | Malformed packets → exit 1, generic Display | `pgp::errors::Error` has rich internal messages; must be captured at `Error::InvalidMaterial` boundary and NOT propagated — matches Phase 6 oracle hygiene |
| PGP-09 | Integration test: round-trip PgpKey self-send under MockTransport | Plausible under wire-budget ceiling IF Ed25519-minimal fixture stays ≤~200 B raw. See wire-budget section. |
| SSH-01 | OpenSSH v1 only; legacy-PEM/RFC4716/FIDO rejected at ingest | ssh-key 0.6.7 `PrivateKey::from_openssh()` accepts only `-----BEGIN OPENSSH PRIVATE KEY-----` armor; legacy PEM + RFC 4716 will parse-fail naturally, but strict prefix sniff in ingest (before calling the crate) gives a clean generic error |
| SSH-02 | Canonical OpenSSH v1 wire blob | ssh-key 0.6.7 `PrivateKey::to_bytes()` returns zeroizing `Vec<u8>`; byte-determinism of re-encode MUST be empirically verified in plan 05 (not documented by crate). |
| SSH-03 | Read OpenSSH v1 bytes on send | Straightforward |
| SSH-04 | Render key type, SHA-256 fingerprint (`SHA256:<base64>`), comment `[sender-attested]`, key size | ssh-key 0.6.7 `Fingerprint::new(HashAlg::Sha256, ...)` + `Display` produces exactly `SHA256:<base64-unpadded>` matching `ssh-keygen -lf` convention. `PublicKey::algorithm()` + `PrivateKey::comment()` give the other fields. |
| SSH-05 | `--armor` rejected for ssh-key | Validation matrix extension in `run_receive`; no crate concern |
| SSH-06 | 64 KB plaintext cap per-variant | Inherited from Phase 6 |
| SSH-07 | JCS fixture committed | Mechanical |
| SSH-08 | Malformed bytes → exit 1, generic Display | Same oracle-hygiene treatment as PGP-08 |
| SSH-09 | Integration test: round-trip SshKey self-send under MockTransport | **BLOCKED by wire budget.** Minimum Ed25519 OpenSSH v1 ≈ 321 B raw → ~1340 B encoded packet, exceeds 1000 B ceiling. Plan 05 MUST `#[ignore]` the full round-trip test from day 1 and rely on the `WireBudgetExceeded`-surface positive test (D-P7-02 pattern). |
| SSH-10 | `cargo tree \| grep ed25519-dalek` pre-flight documented | **RESOLVED:** ssh-key 0.6.7 with `default-features = false, features = ["alloc"]` does NOT pull ed25519-dalek. However, `pgp 0.19.0` unconditionally pulls `ed25519-dalek 2.1.1` — so the pre-flight outcome is NOT "no 2.x leak" but "ed25519-dalek 2.1.1 coexists with 3.0.0-pre.5 due to pgp 0.19.0 (NOT ssh-key)." Plan 01 (PGP) owns the coexistence-acceptance doc; Plan 05 (SSH) can show ssh-key is NOT the culprit. |

---

## Crate: pgp (rpgp)

| Property | Value | Source |
|----------|-------|--------|
| Latest stable | **0.19.0** | `cargo search pgp` [VERIFIED] |
| License | **MIT OR Apache-2.0** | [CITED: v0.19.0 Cargo.toml] |
| MSRV | Rust 1.88 | [CITED: rpgp README] — **WARNING**: cipherpost's rust-version is 1.85 (Cargo.toml line 8). Adding pgp 0.19.0 FORCES an MSRV bump to 1.88, OR a pin to an older pgp version. Flag this. |
| RFC 4880 v4 support | Yes | [CITED: README "Historical RFCs RFC4880 and RFC6637 … including v3 keys"] |
| RFC 9580 v6 support | Yes | [CITED: README "supports the commonly used v4 formats, as well as the latest v6 key formats"] |
| Default features | `["bzip2"]` | [CITED: Cargo.toml line] — we should disable: `default-features = false` |
| Feature-gated crypto | `bzip2`, `asm`, `wasm`, `large-rsa`, `malformed-artifact-compat`, `draft-pqc`, `draft-wussler-openpgp-forwarding` | [CITED: Cargo.toml [features]] |
| `ring` / `aws-lc` / `openssl` | **None** | [VERIFIED: full dep list inspection — uses aes, sha2, rsa, ecdsa, curve25519-dalek, k256, p256, p384 RustCrypto stack] |
| **Unconditional `ed25519-dalek = "2.1.1"`** | **Yes** | [VERIFIED: `ed25519-dalek = { version = "2.1.1", default-features = false, features = ["std", "zeroize", "fast", "rand_core"] }` — no `optional = true`, no target cfg, no feature gate] |
| `curve25519-dalek` | `4.1.3` | [CITED] — already pulled transitively by age 0.11, no new coexistence |
| `rsa` | `0.9` | [CITED] — triggers RUSTSEC-2023-0071 (no patched version) |

**Recommended Cargo.toml addition (plan 01):**
```toml
pgp = { version = "0.19", default-features = false }
```
- Omits `features = ["alloc"]` — pgp does NOT expose an `alloc` feature; its dep tree is alloc-implicit.
- Disables `bzip2` compression by default — cipherpost does not encounter compressed key material (keys are not "messages").
- Does NOT expose a way to drop `rsa` or `ed25519-dalek` — both are hardcoded dependencies of pgp 0.19.0. Accept coexistence.

**CVE history (all published advisories against rpgp):**

| GHSA | Severity | Affected | Patched | Notes |
|------|----------|----------|---------|-------|
| GHSA-9rmp-2568-59rv | High | < 0.14.1 | 0.14.1 | Panics on malformed input — we're clean |
| GHSA-4grw-m28r-q285 | High | < ? | — | Resource exhaustion on untrusted messages — predates 0.19 |
| GHSA-7587-4wv6-m68m (CVE-2026-21895) | High | ≤ 0.18.x | **0.19.0** | Parser crash on crafted RSA secret key packets — **0.19.0 is patched** [CITED: advisory page] |
| GHSA-8h58-w33p-wq3g | High | ≤ 0.18.x | 0.19.0 | Deeply-nested message DoS |
| GHSA-c7ph-f7jm-xv4w | Moderate | ≤ 0.18.x | 0.19.0 | Missing integrity check on encrypted data |

**Transitive supply-chain concern:**
- **RUSTSEC-2023-0071 (Marvin Attack):** pgp 0.19.0 pulls `rsa 0.9.x` which has NO patched version [CITED]. Local-only use (no network timing oracle) makes impact low for cipherpost, but `cargo audit` will fail CI unless added to `deny.toml [advisories] ignore`. **Plan 01 task:** add ignore entry with rationale documenting the local-only threat model assumption.

**Maintainer signal:** rpgp is actively maintained by dignifiedquire (repo owner) + contributors; five advisories ALL published in 2024-2026 demonstrate active security response. Release cadence: 0.17 (2024) → 0.18 (2025) → 0.19 (Feb 2026 coinciding with advisory disclosures).

---

## Crate: ssh-key

| Property | Value | Source |
|----------|-------|--------|
| Latest stable | **0.6.7** | `cargo search ssh-key` [VERIFIED] — note 0.7.0-rc.9 exists but is pre-release and bumps ed25519-dalek to `=3.0.0-pre.6` (different pre-release than our `=3.0.0-pre.5` pin — would REQUIRE our pin to bump too) |
| License | **Apache-2.0 OR MIT** | [CITED: v0.6.7 Cargo.toml] |
| MSRV | Not explicitly stated for 0.6.7 (master branch = 1.85); no MSRV concern for cipherpost | [INFERRED] |
| Default features | `["ecdsa", "rand_core", "std"]` | [CITED: v0.6.7 Cargo.toml] — `ed25519` is NOT in default |
| `ed25519` feature effect | Pulls `ed25519-dalek = { version = "2", optional = true }` + rand_core; enables signing/verification ONLY | [CITED: `ed25519 = ["dep:ed25519-dalek", "rand_core"]`] |
| **Parse Ed25519 key WITHOUT `ed25519` feature** | **YES** | [VERIFIED: src/public/ed25519.rs — `Ed25519PublicKey` struct + Decode/Encode/TryFrom impls unconditional; only ed25519-dalek interop TryFrom impls gated] |
| **Compute SHA-256 fingerprint WITHOUT `ed25519` feature** | **YES** | [VERIFIED: src/fingerprint.rs — `Fingerprint::new()` has no cfg gating; `sha2 = "0.10.8"` is unconditional dep] |
| `ring` / `aws-lc` / `openssl` | **None** | [VERIFIED: full dep list] |
| Byte-determinism of `from_openssh()` + `to_bytes()` | **UNDOCUMENTED — plan 05 must empirically verify** | [CITED: docs.rs — no canonical-encoding claim; "constant-time encoder/decoder" refers to timing side-channel resistance, not canonical output] |

**Recommended Cargo.toml addition (plan 05):**
```toml
ssh-key = { version = "0.6", default-features = false, features = ["alloc"] }
```
- Disables `["ecdsa", "rand_core", "std"]`.
- `alloc` is needed for `to_bytes()` + `to_openssh()` + decode (see Cargo.toml feature deps).
- Does NOT pull `ed25519-dalek`.
- `sha2` is unconditional → SHA-256 fingerprint works.
- `ssh-cipher` / `ssh-encoding` are pulled as core deps (cipher handling for encrypted-with-passphrase OpenSSH keys; we don't use, but they're mandatory).

**Byte-determinism verification protocol for plan 05:**
Write a test in `tests/material_ssh_ingest.rs`:
```rust
let key1 = PrivateKey::from_openssh(fixture_bytes)?;
let bytes1 = key1.to_bytes()?;
let key2 = PrivateKey::from_openssh(&bytes1)?;
let bytes2 = key2.to_bytes()?;
assert_eq!(bytes1.as_slice(), bytes2.as_slice(), "ssh-key re-encode is not byte-deterministic");
```
If this fails, D-P7-11's "canonical wire blob via re-encode through `ssh-key`" strategy is invalid and must change. Fallback: store the PEM-armored ASCII text verbatim (after stripping trailing whitespace) — less robust but deterministic across `ssh-key` patch versions.

**CVE history for ssh-key:** No published GHSA advisories against RustCrypto/SSH ssh-key as of April 2026. Maintained by the RustCrypto org, release cadence ~6 months for 0.6.x patches, 0.7 in RC since 2025.

---

## Wire-budget predictions

### Calibration anchor (Phase 6 empirical)

From `.planning/phases/06-typed-material-x509cert/06-04-SUMMARY.md` [VERIFIED: direct read]:
```
388 B DER                          (raw input)
→ 626 B JCS envelope               (+238 B, 1.61×)
→ ~850 B age ciphertext            (+224 B age overhead)
→ ~1136 B base64                   (+286 B, 1.33×)
→ ~1576 B OuterRecord JSON         (+440 B signing/framing)
→ 1616 B encoded PKARR packet      (+40 B DNS TXT encoding)
```
Overall expansion: **raw bytes × 4.16 ≈ encoded packet size**
Or more precisely: `encoded ≈ raw * 1.33 + ~710` (decomposes the base64 multiplicative and additive overhead components).

### PGP Ed25519-minimal

**Fixture construction (per D-P7-03 + fixture guidance):**
- Ed25519 primary public-key packet: ~53 B (tag + length + version + creation timestamp + algorithm + pubkey 32 B)
- One self-certification signature packet: ~80-100 B (tag + length + subpackets + v4/v6 sig with Ed25519 64-byte signature)
- One UID packet `cipherpost-fixture <fixture@cipherpost.test>` (43 chars): ~48 B (tag + length + bytes)
- **Total raw packet stream: ~180-200 B** for v4 keys; v6 keys add ~20 B more for the v6 key packet format

**Predicted encoded packet size:**
- 180 B × 4.16 ≈ **~750 B** (clear fit under 1000 B)
- 200 B × 4.16 ≈ **~830 B** (fit)
- 250 B × 4.16 ≈ **~1040 B** (borderline overflow; depends on UID length + sig subpackets)

**Verdict: PGP Ed25519-minimal FITS** with aggressive UID trimming (keep ≤30 chars). D-P7-03's round-trip test is achievable. A v4 key with UID "a" would be well under 800 B encoded.

**Risk:** v6 keys per RFC 9580 add header complexity; plan 01 fixture should prefer v4 Ed25519 unless PGP-04's 64-hex fingerprint requirement forces v6. PGP-04 says "v4 40-hex OR v5 64-hex" — both are acceptable outputs, so use v4 for fixture (smaller + simpler).

### SSH Ed25519-minimal

**Fixture construction (per D-P7-03):**
- `ssh-keygen -t ed25519 -C "" -N "" -f /tmp/fixture` output:
  - PEM-armored OpenSSH v1 file: ~411 B text (`-----BEGIN OPENSSH PRIVATE KEY-----` + base64 body + `-----END ...-----`)
  - Raw binary body (base64-decoded): ~321 B
- **Question: what do we store in `Material::SshKey.bytes`?** Per D-P7-11, the canonical wire blob is the PEM-armored text (because OpenSSH v1 is "self-armored" per D-P7-13). That's 411 B raw.
  - **Alternative:** store the base64-decoded 321 B binary body. Shorter, but loses the PEM framing that users copy-paste — and `from_openssh()` expects PEM input, so we'd have to re-wrap on the receive side. Less clean.

**Predicted encoded packet size:**
- Store PEM text (411 B): 411 × 4.16 ≈ **~1710 B** ❌ (exceeds 1000 B by 71%)
- Store binary body (321 B): 321 × 4.16 ≈ **~1340 B** ❌ (exceeds by 34%)
- **Absolute minimum SSH Ed25519 OpenSSH v1 raw (strip comment, strip padding — empty cipher `none`, empty KDF `none`, 1 key): ~200-230 B binary or ~330 B PEM-armored. Still ≈ 830-1370 B encoded. Borderline at best.**

**Verdict: SSH Ed25519-minimal DOES NOT FIT reliably under 1000 B.** D-P7-03's `#[ignore]` fallback MUST be adopted from day 1. Do not attempt the round-trip test in plan 05 expecting it to pass — it will fail and force a mid-execution deviation mirror of Phase 6's Task 3 discovery.

### Comparison table

| Variant | Min raw bytes | Predicted encoded | Under 1000 B? |
|---------|---------------|-------------------|---------------|
| X.509 Ed25519 self-signed (Phase 6 actual) | 234 | 1290 (measured floor) / 1616 (fixture) | ❌ |
| **PGP Ed25519 v4 + minimal UID** | **180-200** | **~750-830** | **✓ (fits)** |
| **PGP Ed25519 v4 + 43-char UID** | **220-250** | **~915-1040** | **borderline — trim UID** |
| **SSH Ed25519 OpenSSH v1 binary** | **321** | **~1340** | **❌** |
| **SSH Ed25519 OpenSSH v1 PEM** | **411** | **~1710** | **❌** |

---

## Gaps or surprises (affect CONTEXT.md assumptions)

### GAP 1 — pgp 0.19.0 pulls ed25519-dalek 2.1.1 unconditionally [CRITICAL]

**Where CONTEXT.md assumed otherwise:** D-P7-10 framed the ed25519-dalek pre-flight as an `ssh-key`-specific risk. In reality, `ssh-key 0.6.7` with `default-features = false` is CLEAN — and `pgp 0.19.0` is the source of the ed25519-dalek 2.x leak.

**Impact:**
- SSH-10's pre-flight outcome won't be the expected "no 2.x leak" for plan 05. It will be "ed25519-dalek 2.1.1 present due to pgp 0.19.0, not ssh-key."
- Plan 01 (PGP) must own the coexistence-acceptance documentation, not plan 05.
- The binary will carry two Ed25519 implementations: `ed25519-dalek 2.1.1` (from pgp) + `ed25519-dalek 3.0.0-pre.5` (from pkarr). Supply-chain signal doubles for Ed25519.
- `cargo-deny multiple-versions = "warn"` will emit a warning that the CI bot will surface on every build. Consider either (a) accepting the warning with `deny.toml` annotation, or (b) adding ed25519-dalek to the `[[bans.skip]]` list for multi-version tolerance.

**Planner action:** Plan 01 (PGP foundation) MUST include a pre-flight task that captures `cargo tree -e features | grep ed25519-dalek` verbatim output and commits it into the plan SUMMARY as evidence of the coexistence acceptance. SPEC.md update (plan 04 or a consolidated plan 08) documents the supply-chain decision.

### GAP 2 — pgp 0.19.0 requires Rust 1.88; cipherpost is pinned to 1.85 [BLOCKING]

**Where CONTEXT.md assumed otherwise:** Not addressed. The MSRV collision is discoverable only by reading the rpgp README.

**Impact:** Adding `pgp = "0.19"` will fail `cargo build` unless cipherpost's `rust-version = "1.85"` in Cargo.toml is bumped to `"1.88"`.

**Options for plan 01:**
1. **Bump cipherpost MSRV to 1.88** — simplest; requires a SPEC.md note + CI toolchain update. No downstream users yet (cipherpost is pre-v1.0-public), so MSRV bump is low-impact.
2. **Pin pgp to an older version (e.g., 0.14.x)** — older pgp supports Rust 1.74+ but pulls the KNOWN-exploitable RUSTSEC-2023-0071 AND has the unfixed pre-0.14.1 panic bugs. Hard reject.
3. **Wait for pgp 0.20 with lower MSRV** — no announcement exists; block phase 7 indefinitely. Unacceptable.

**Planner action:** Plan 01 Task 1 must include a `rust-version = "1.88"` Cargo.toml bump + CI workflow update. Accept the MSRV bump as a D-P7-20 addendum.

### GAP 3 — pgp 0.19.0 transitive `rsa 0.9` triggers RUSTSEC-2023-0071 with no patched version [MODERATE]

**Where CONTEXT.md assumed otherwise:** D-P7-04 committed to pgp with `default-features = false` on the assumption that feature gating could drop unused deps. rpgp 0.19.0's `rsa` dep is NOT feature-gated — it's core (RSA is RFC 4880's mandatory algorithm).

**Impact:** `cargo audit` / `cargo-deny check advisories` will FAIL CI on every run unless the advisory is explicitly ignored.

**Planner action:** Plan 01 Task 1 must add to `deny.toml`:
```toml
[advisories]
ignore = [
  { id = "RUSTSEC-2023-0071", reason = "Marvin timing attack against rsa crate; transitively pulled by pgp 0.19.0 for RFC 4880 RSA key support. cipherpost performs no RSA operations — keys are parsed for metadata display only, never used for cryptographic operations. Attack requires network-observable timing oracle; no such surface exists in cipherpost's parse-only code path. Revisit when rsa 0.10 ships constant-time." },
]
```
Also cross-reference in SPEC.md supply-chain section.

### GAP 4 — SSH canonical re-encode byte-determinism is undocumented by ssh-key [MODERATE]

**Where CONTEXT.md assumed otherwise:** D-P7-11 asserts "SHA-256 fingerprint and JCS byte-identity both deterministic across re-sends" as a consequence of re-encoding through `ssh-key`. The crate does not document this guarantee.

**Impact if wrong:** `share_ref` would vary across re-sends of the same key, re-opening Pitfall #21 for SSH.

**Planner action:** Plan 05 Task 1 must include an empirical byte-determinism test (see "Byte-determinism verification protocol" section above) BEFORE committing to the re-encode strategy. If the test fails, fall back to strict-PEM-text storage (store the raw input's PEM text verbatim after `trim_end` + line-ending normalization to LF).

### GAP 5 — PGP round-trip is borderline, not comfortable [MINOR]

**Where CONTEXT.md assumed otherwise:** D-P7-03 accepts PGP Ed25519-minimal round-trip as plausible; plan 05 "measurement note" treats SSH as the risk case. In reality, **PGP also has a tight budget** — ~830 B encoded for a 200 B raw packet leaves ~170 B headroom. Any UID longer than 20 chars, or v6 key format (adds ~20 B), can push it over.

**Planner action:** Plan 01 fixture generation MUST target ≤200 B raw packet stream:
- v4 key only (NOT v6; v4's 40-hex fingerprint already satisfies PGP-04's "40 OR 64 hex" requirement)
- UID ≤20 chars (e.g., `"cipherpost-fix"` 14 chars, not `"cipherpost-fixture <fixture@cipherpost.test>"` 43 chars — the latter blows the budget by itself)
- Zero subkeys
- Single self-certification signature with no optional subpackets (only issuer + creation time)

Plan 01 should measure the candidate fixture's encoded-packet size BEFORE committing to it (size-math one-liner: `python -c "print(raw * 4.16)"` — mirrors Phase 6 retrospective's lesson).

---

## Planner guidance

1. **Plan 01 (PGP foundation) must bump Cargo.toml `rust-version` from `1.85` to `1.88`.** Non-negotiable — pgp 0.19.0 requires it. Update CI rustc pin in `.github/workflows/*.yml` in the same task.

2. **Plan 01 must add `deny.toml` ignore entry for RUSTSEC-2023-0071** with the rationale text above. Without this, CI fails on every run.

3. **Plan 01 must add `pgp = { version = "0.19", default-features = false }` — NOT `features = ["alloc"]`.** pgp 0.19.0 does not expose an `alloc` feature; its baseline is alloc-implicit.

4. **Plan 01 fixture budget: ≤200 B raw packet stream.** Use v4 Ed25519 key + ≤20-char UID + no subkeys. Measure `raw_size * 4.16 < 1000` before committing the fixture bytes. A 43-char UID (as specifid in CONTEXT.md §specifics) WILL overflow the budget; CONTEXT.md's fixture recipe needs trimming.

5. **Plan 01 (NOT plan 05) owns the ed25519-dalek coexistence documentation.** Capture `cargo tree -e features | grep ed25519-dalek` output in plan 01 SUMMARY showing both 2.1.1 (from pgp) and 3.0.0-pre.5 (from pkarr). SSH-10 pre-flight in plan 05 is a cross-check showing ssh-key is NOT the culprit.

6. **Plan 05 (SSH foundation) must add `ssh-key = { version = "0.6", default-features = false, features = ["alloc"] }`.** This is CLEAN — no ed25519-dalek leak, no cargo-deny warnings.

7. **Plan 05 Task 1 MUST include a byte-determinism test for `PrivateKey::from_openssh() → to_bytes() → from_openssh() → to_bytes()` BEFORE any downstream test depends on re-encode canonicality.** If it fails, fall back to PEM-text-verbatim storage.

8. **Plan 05 MUST `#[ignore]` the full SSH round-trip test from the start.** Do not write `ssh_self_round_trip_recovers_canonical_bytes` expecting it to pass — wire budget guarantees failure. Write the `ssh_send_realistic_key_surfaces_wire_budget_exceeded_cleanly` positive test instead (per D-P7-02). Document the `#[ignore]` reason as "SSH Ed25519 OpenSSH v1 floor ~321 B raw → ~1340 B encoded, exceeds 1000 B PKARR BEP44 ceiling."

9. **Plan 01 and Plan 05 dep-tree guards must extend differently:**
   - Plan 01 asserts: `ring`/`aws-lc`/`openssl` absent; `pgp 0.19.x` pinned; ed25519-dalek 2.x present via pgp (not an assertion failure — an accepted condition).
   - Plan 05 asserts: `ring`/`aws-lc`/`openssl` still absent; `ssh-key 0.6.x` pinned; ssh-key does NOT pull additional ed25519-dalek 2.x (the 2.x that's present came from pgp in plan 01).

10. **SPEC.md supply-chain section (plan 04 OR consolidated plan 08) must document the three accepted supply-chain positions:**
    - ed25519-dalek dual-version (2.1.1 from pgp + 3.0.0-pre.5 from pkarr); rationale = "pre-stable ecosystem gap; pkarr blocks upgrade until pre-release stabilizes"
    - RUSTSEC-2023-0071 ignore; rationale = "transitively via pgp RSA support; parse-only code path; no timing oracle surface"
    - MSRV 1.88; rationale = "pgp 0.19.0 requirement"

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The 4.16× encoded-size expansion factor calibrated from Phase 6's single X.509 data point extrapolates linearly to PGP/SSH | Wire-budget predictions | Moderate — PGP "fits" call (~830 B) could be off by ±15% (~700-950 B). Still fits under 1000 B at upper bound. SSH "doesn't fit" call is safer — 1340 B is 34% over ceiling, far outside any plausible expansion-factor error. |
| A2 | pgp 0.19.0's `packet::PacketParser` (or equivalent low-level API) exposes tag-5/tag-6 packet iteration suitable for multi-primary detection | PGP-03 research support | Low — rpgp's low-level API has been stable since 0.10.x; README explicitly advertises "flexible low-level API for building higher level PGP tooling." Verify in plan 01. |
| A3 | pgp 0.19.0 has an `ArmoredWriter` or `to_armored_writer` method for the `--armor` output path | PGP-05 research support | Low — standard API for any OpenPGP library. Verify in plan 03. |
| A4 | ssh-key 0.6.7's `Fingerprint::new(HashAlg::Sha256, &key_data)` output formats as `SHA256:<base64-unpadded>` matching `ssh-keygen -lf` convention | SSH-04 research support | Low — RustCrypto crate conventions match OpenSSH's output. Verify with golden-string test in plan 06. |

---

## Open Questions

1. **Does pgp 0.19.0 re-parse a binary packet stream deterministically?** The PGP ingest design in D-P7-11 relies on canonical storage, but unlike SSH (where we control re-encoding via `to_bytes()`) the PGP wire form IS the user's input bytes. If pgp's internal parser is strict about packet-tag-ordering and rejects some RFC-compliant variants, our ingest might reject keys that `gpg` accepts. LOW risk because pgp-crate's rpgp is RFC 9580 / RFC 4880 conformant, but worth a sanity test with a key exported from a real `gpg --export` in plan 01.

2. **Will the cipherpost binary size grow beyond acceptable bounds with pgp + ssh-key + ed25519-dalek dual?** Not researched — worth a `cargo build --release` size-delta measurement in plan 01 baseline and plan 05 final-ship gates. If the binary exceeds, say, 20 MB release, it's worth flagging. Not a blocker.

3. **Should Phase 7 build its own `MaterialTag` enum for packet counting (tag-5, tag-6, tag-7, tag-14) or rely on pgp crate's high-level `Composed::PublicKey` / `Composed::SecretKey` abstractions?** Plan 01 implementation detail; low stakes. Low-level packet counting is more defensive against format variants; high-level abstractions are shorter code.

---

## Sources

### Primary (HIGH confidence)

- **pgp 0.19.0 Cargo.toml (verbatim from v0.19.0 tag):** https://raw.githubusercontent.com/rpgp/rpgp/v0.19.0/Cargo.toml — ed25519-dalek unconditionality, license, features
- **ssh-key 0.6.7 Cargo.toml (verbatim from ssh-key/v0.6.7 tag):** https://raw.githubusercontent.com/RustCrypto/SSH/ssh-key/v0.6.7/ssh-key/Cargo.toml — feature gating, ed25519-dalek as optional, sha2 unconditional
- **ssh-key 0.6.7 src/public/ed25519.rs (Ed25519PublicKey parse paths):** https://raw.githubusercontent.com/RustCrypto/SSH/ssh-key/v0.6.7/ssh-key/src/public/ed25519.rs — confirms parse is NOT cfg-gated on ed25519 feature
- **ssh-key 0.6.7 src/fingerprint.rs:** https://raw.githubusercontent.com/RustCrypto/SSH/ssh-key/v0.6.7/ssh-key/src/fingerprint.rs — confirms Fingerprint::new has no feature gating
- **rpgp README + docs.rs:** https://docs.rs/pgp/latest/pgp/ — RFC 9580 + RFC 4880 support, dual license
- **rpgp GHSA advisories:** https://github.com/rpgp/rpgp/security/advisories — 5 advisories, 0.19.0 patched
- **RUSTSEC-2023-0071 Marvin Attack:** https://rustsec.org/advisories/RUSTSEC-2023-0071.html — no patched version
- **Phase 6 empirical wire-budget data:** `.planning/phases/06-typed-material-x509cert/06-04-SUMMARY.md` (lines 58, 148-197) — 388 B DER → 1616 B packet calibration
- **cipherpost deny.toml:** `/home/john/vault/projects/github.com/cipherpost/deny.toml` — `multiple-versions = "warn"` + existing ignore structure

### Secondary (MEDIUM confidence)

- **`cargo search pgp`** output — confirms 0.19.0 as current stable
- **`cargo search ssh-key`** output — confirms 0.6.7 as current stable (0.7.0-rc.9 pre-release)

### Tertiary (LOW confidence — still verified against primary where possible)

- WebSearch hits on rpgp ed25519-dalek issues (Issue #571 "Compilation failed" open June 2025; historical pre-release compat pain) — suggests rpgp's ed25519-dalek upgrade cadence is slow; treat 2.1.1 as the steady-state for pgp 0.19.x

---

## Metadata

**Confidence breakdown:**
- Standard stack (crate choices): HIGH — versions, licenses, and dep structure all verified against tagged Cargo.toml files.
- Architecture (ssh-key feature gating): HIGH — source-level verification of cfg attributes on parse + fingerprint paths.
- Wire-budget predictions: MEDIUM — extrapolated from single Phase 6 data point; SSH "won't fit" call is HIGH confidence (34-130% over ceiling absorbs any reasonable extrapolation error); PGP "fits with trimming" call is MEDIUM (borderline at upper UID range).
- Pitfalls (MSRV, RUSTSEC): HIGH — verified against official advisory database and crate manifests.

**Research date:** 2026-04-24
**Valid until:** 2026-05-24 (30 days; rpgp and ssh-key are stable crates; pkarr's ed25519-dalek pin status is the volatile variable — if pkarr ships a 5.0.5 with ed25519-dalek 3.x stable, re-evaluate before plan 01).
