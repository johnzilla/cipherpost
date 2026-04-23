# Research Summary — Cipherpost v1.1 "Real v1"

**Project:** Cipherpost v1.1 "Real v1"
**Domain:** Self-sovereign CLI for cryptographic-material handoff (Rust, Mainline DHT, age encryption)
**Researched:** 2026-04-23
**Confidence:** HIGH (STACK, FEATURES, ARCHITECTURE from direct source inspection; cclink survey BLOCKED — see Prerequisites)

---

## v1.1 At a Glance

- **What changes:** Three new Material variants (X509Cert, PgpKey, SshKey) close the PRD's typed-payload scope; `--pin` and `--burn` modes complete the encryption-mode surface; `--passphrase-file`/`--passphrase-fd` on `send`/`receive` reaches parity with identity subcommands; real-DHT cross-identity round trip runs as a release-acceptance gate.
- **New crates added:** Exactly three — `x509-parser 0.16`, `pgp 0.14` (rPGP), `ssh-key 0.6`. Phases 5, 8, and 9 add zero new crates.
- **Wire format impact:** New Material variant fields are wire-additive (v1.0 receivers see unknown tag, return exit 3 — correct behavior). New `burn_after_read` field in `Envelope` and `pin_required` field in `OuterRecord`/`OuterRecordSignable` use `skip_serializing_if = is_false` to preserve byte-identity with v1.0 for non-pin/non-burn shares. JCS fixtures must be regenerated and committed for all new Material variants and for pin/burn Envelope fields.
- **Explicitly out of scope for v1.1:** TUI wizard, exportable audit log, destruction attestation, multi-recipient, PGP keyrings, FIDO/PKCS#11 SSH formats, PIN recovery, burn-as-cryptographic-destruction, non-interactive PIN at receive time.
- **Prerequisite before Phase 8 planning:** Manual cclink survey (`cclink/src/crypto/mod.rs` pin KDF; `cclink/src/transport/mod.rs` burn path) — researcher was blocked from that directory. See Open Questions.
- **Prerequisite before Phase 7 implementation:** `cargo tree | grep ed25519-dalek` to confirm `ssh-key 0.6` does not introduce a version collision with cipherpost's `=3.0.0-pre.5` pin.
- **Prerequisite before Phase 9 planning:** Confirm whether `pkarr 5.0.4`'s `ClientBuilder` accepts custom bootstrap nodes before committing to `mainline::Testnet` for the CI-gate real-DHT test.

---

## Stack Additions Table

### New Dependencies

| Crate | Version | Phase | Purpose | License | Rationale |
|-------|---------|-------|---------|---------|-----------|
| `x509-parser` | `0.16` | 6 | PEM + DER X.509 parsing; Subject/Issuer/Validity/fingerprint extraction | MIT OR Apache-2.0 | Pure Rust; zero-copy; Rusticata family; no C FFI; no `ring`/`aws-lc` in default features |
| `pgp` (rPGP) | `0.14` | 7 | Single-key OpenPGP parsing (public + secret); fingerprint + UID extraction | MIT OR Apache-2.0 | Pure Rust; no GPL in tree; Deltachat production usage; sequoia rejected on LGPL grounds |
| `ssh-key` | `0.6` | 7 | OpenSSH v1 private + public key parsing; SHA-256 fingerprint; comment extraction | MIT OR Apache-2.0 | RustCrypto org pedigree; same family as ed25519-dalek; parsing-only (no bcrypt-pbkdf needed) |

Phases 5, 8, 9: zero new crates. Phase 8 uses the already-present `argon2 0.5` for PIN KDF derivation within age scrypt.

### Rejected Alternatives (Anti-Stack)

| Crate | Reason Rejected |
|-------|----------------|
| `sequoia-openpgp` | LGPL-2.0-or-later — incompatible with MIT distribution; LGPL obligations under Rust monomorphization are ambiguous; also heavyweight |
| `openssl` crate | C FFI; violates supply-chain cleanliness policy; second crypto implementation |
| `x509-cert` (RustCrypto) | Designed for cert building, not parsing; PEM not first-class |
| `x509-certificate` | Self-described as not hardened against malicious inputs; documented panic paths on malformed ASN.1 |
| `tokio` as direct dep | Already absent at cipherpost layer; pkarr's internal runtime is sufficient |
| `ring` or `aws-lc-rs` | Not needed for parsing-only X.509; pulled by `x509-parser`'s `verify` feature — do not enable that feature |
| `chacha20poly1305` direct calls | Still prohibited — ChaCha only via `age`; pin mode uses nested age scrypt satisfying the constraint without modification |

### v1.0 Pin Reality Check (All Bless as Shipped)

All v1.0 crate pins are current, unyanked, and have no RustSec advisories as of 2026-04-23. SPEC.md should state API version ranges (`serde_canonical_json >= 1.0.0, implementing RFC 8785 JCS`), not exact version numbers in prose. Cargo.toml and deny.toml carry version authority; SPEC.md prose that cites exact version numbers implies a deployment recommendation it cannot make.

---

## Feature Table Stakes vs. Differentiators

### Table Stakes (must-have, grouped by phase)

**Phase 5 — Non-interactive passphrase (complexity: S throughout)**

| Feature | Detail |
|---------|--------|
| `--passphrase-file <path>` on `send` and `receive` | Mode-0600 enforcement; exact one-LF strip (not greedy `.trim()`); parity with identity subcommands |
| `--passphrase-fd <n>` on `send` and `receive` | `BorrowedFd`, not `FromRawFd`; caller is responsible for closing the fd |
| `send - --passphrase-fd 3` combination | Stdin payload (fd 0) + passphrase from fd 3 must not conflict |
| Non-TTY with no passphrase source | Exit 1, never hangs |
| DHT label audit | Written "keep as-is" confirmation; CI assertion that label constants match SPEC.md text |
| SPEC.md pin-version blessing | API-range form, not exact version prose; Cargo.toml is canonical |
| Traceability-table drift fix | Drop table (body checkboxes canonical) — no external parsers exist to break |

**Phase 6 — X509Cert (complexity: M for parse/display, S for plumbing)**

| Feature | Detail |
|---------|--------|
| Acceptance screen fields | Type, Subject, Issuer, Serial (truncated), Valid from/until (`[EXPIRED]` tag), Key alg, SHA-256 DER fingerprint, Size |
| Normalized DER storage | PEM accepted at CLI then stripped to DER; BER rejected via x509-parser parse validation |
| Stdout output | Raw DER by default; PEM via `--armor` flag |
| Parse failure | Malformed DER yields exit 1 with message naming variant — NOT exit 3 (that is signature failure) |
| JCS fixture | `tests/fixtures/envelope_x509cert.bin` committed before Phase 6 ships |
| Per-variant size check | `material_plaintext_size()` method on `Material`; pre-encrypt enforcement |

**Phase 7 — PgpKey + SshKey (complexity: M for PGP, S for SSH)**

| Feature | Detail |
|---------|--------|
| PGP acceptance screen | Full v4/v6 fingerprint (40/64 hex), primary UID, key alg, subkey count+types, creation date |
| PGP binary packet stream storage | Strip armor at ingest; store raw RFC 4880 binary; discard Version/Comment headers |
| PGP single-primary-key enforcement | Keyring with N>1 primary keys yields exit 1 naming the count |
| PGP secret-key warning | Secret key (packet tag 5) receives `[WARNING: SECRET KEY]` on acceptance screen; not rejected |
| SSH acceptance screen | Key type, SHA256 fingerprint (OpenSSH-style `SHA256:<base64>`), comment (labeled non-cryptographic) |
| SSH wire blob storage | Comment column stripped from `.pub` format; wire blob stored |
| SSH unsupported formats | Legacy PEM, FIDO/U2F sk-* yield `Error::SshKeyFormatNotSupported` with conversion guidance |
| JCS fixtures | `envelope_pgpkey.bin` and `envelope_sshkey.bin` committed |

**Phase 8 — pin and burn (complexity: M for pin crypto/flow, S for burn)**

| Feature | Detail |
|---------|--------|
| `--pin` on send | TTY PIN prompt, no echo; minimum 8-character enforcement; rejection with `Error::InvalidInput` if shorter |
| PIN crypto | Nested age scrypt: outer age-scrypt envelope keyed to PIN, inner standard age X25519 keyed to identity. PIN AND identity key both required (true second factor, not alternative) |
| `pin_required: bool` in OuterRecord | skip_serializing_if false; receiver prompts for PIN BEFORE typed-z32 acceptance, not after |
| Wrong PIN behavior | Same user-facing message and exit code as any decrypt failure (exit 4, identical message to passphrase failure); no `PinIncorrect` variant with distinct Display |
| `--burn` on send | `burn_after_read: bool` in Envelope (inner-signed); skip_serializing_if false |
| Burn second-receive | Exit 7 ("share already consumed"); sentinel never deleted |
| Burn + receipt | Receipt IS published after burn-mode acceptance (Option A); receipt = burn delivery confirmation |
| Acceptance screen additions | `PIN mode: yes` displayed before z32 prompt; `Mode: burn-after-read` displayed before z32 prompt |
| PIN input contract | `CIPHERPOST_PIN` env var + `--pin-file <path>`; argv-inline rejected; `--pin-fd` deferred to v1.2 |
| `src/pin.rs` | `pin_wrap` / `pin_unwrap`; HKDF info `cipherpost/v1/pin_wrap`; isolated from `crypto.rs` |
| THREAT-MODEL.md additions | Burn-is-local-state-only section; PIN offline-brute-force limitation section |

**Phase 9 — Real-DHT gate (complexity: M throughout)**

| Feature | Detail |
|---------|--------|
| `tests/real_dht_e2e.rs` | `#[cfg(feature = "real-dht")]` + `#[ignore]`; cross-identity round trip via real `DhtTransport`; manual release gate, not CI |
| `tests/concurrent_receipt_racer.rs` | `#[cfg(feature = "mock")]`; true concurrent threads + `std::sync::Barrier`; MockTransport CAS semantics enforced |
| MockTransport CAS semantics | Reject stale publish (seq conflict) so racer test can verify correct retry behavior |
| Pre-flight UDP check | Inside real-DHT test; skip gracefully (not fail) if bootstrap node unreachable within 5s |
| PKARR budget coexistence test | `OuterRecord` + one `_cprcpt-*` receipt within 1000-byte budget confirmed empirically |

### Differentiators (beyond baseline)

| Feature | Phase | Value |
|---------|-------|-------|
| X.509 acceptance shows Subject AND Issuer before decrypt | 6 | Security property: confirm chain context before accepting private key |
| Material type on acceptance screen before commit | 6, 7 | No other handoff tool shows payload type pre-accept; typed payloads make this meaningful |
| Nested age scrypt for PIN (PIN AND identity key both required) | 8 | Correct second-factor semantics; no new AEAD surface; satisfies CLAUDE.md constraint |
| Burn enforced by state-ledger sentinel (receipt confirms consumption) | 8 | Single-consumption without a server; receipt IS the burn confirmation to sender |
| Real-DHT round trip as a release gate (not CI-optional) | 9 | Protocol correctness signal that other PKARR projects do not enforce |

### Anti-Features (v1.1 will NOT ship)

| Anti-Feature | Redirect |
|--------------|---------|
| PGP keyring support | Send each key individually; single-key is by design |
| X.509 chain validation | `openssl verify -CAfile <root>` post-receive |
| PIN with OTP/TOTP | Requires an operator — violates no-server principle |
| Auto-renew TTL on receive | Sender re-sends with new share |
| Destruction attestation | Deferred to v1.2 |
| PGP subkey-only shares | Send full single-key Cert; recipient extracts subkey |
| DHT deletion of a burn share | Impossible on public DHT; burn = single-consumption, not physical destruction |
| Multi-recipient pin-protected send | Deferred to v1.2 multi-recipient scope |
| TUI wizard | Deferred to v1.2 |
| Non-interactive PIN at receive time | PIN is a human second factor; scripted-receive with PIN bypasses the threat model; defer to v1.2+ |

---

## Architectural Integration Points

| Phase | File | Change Type | Purpose |
|-------|------|-------------|---------|
| 5 | `src/cli.rs` | modified | Add `passphrase_file`, `passphrase_fd`, hidden `passphrase` to `Send` and `Receive` structs |
| 5 | `src/main.rs` | modified | Thread new passphrase fields through `resolve_passphrase` in Send/Receive dispatch |
| 5 | `SPEC.md` | modified | Bless pin versions in API-range form; confirm DHT labels stable; FD preference ordering in section 7 |
| 6 | `src/payload.rs` | modified | Add `{ bytes: Vec<u8> }` to `X509Cert` variant; update `Debug` redaction; update `as_bytes()` |
| 6 | `src/flow.rs` | modified | Update `material_type_string`; add `material_plaintext_size` pre-encrypt check |
| 6 | `tests/fixtures/envelope_x509cert.bin` | new | JCS fixture for X509Cert Envelope; property test asserts byte-for-byte determinism |
| 7 | `src/payload.rs` | modified | Add `{ bytes: Vec<u8> }` to `PgpKey` and `SshKey`; extend `Debug` redaction |
| 7 | `tests/fixtures/envelope_pgpkey.bin` | new | JCS fixture for PgpKey Envelope |
| 7 | `tests/fixtures/envelope_sshkey.bin` | new | JCS fixture for SshKey Envelope |
| 8 | `src/pin.rs` | new | `pin_wrap` / `pin_unwrap`; HKDF info `cipherpost/v1/pin_wrap`; isolated from `crypto.rs` |
| 8 | `src/payload.rs` | modified | Add `burn_after_read: bool` to `Envelope` (skip_serializing_if false) |
| 8 | `src/record.rs` | modified | Add `pin_required: bool` to `OuterRecord` + `OuterRecordSignable` (skip_serializing_if false) |
| 8 | `src/flow.rs` | modified | `run_send`: pin-wrap branch; `run_receive`: pin-unwrap before age-decrypt; burn sentinel logic in step 12 |
| 8 | `src/cli.rs` | modified | Add `pin_file`, `burn` to `Send`; `pin_file` to `Receive`; hidden `pin` rejected on both |
| 8 | `src/main.rs` | modified | Thread pin/burn flags through dispatch |
| 9 | `tests/real_dht_e2e.rs` | new | `#[cfg(feature = "real-dht")]` + `#[ignore]`; cross-identity round trip via `DhtTransport` |
| 9 | `tests/concurrent_receipt_racer.rs` | new | `#[cfg(feature = "mock")]`; Barrier-synchronized concurrent `publish_receipt` race |
| 9 | `Cargo.toml` | modified | Add `real-dht = []` feature flag |

**Load-bearing invariants every v1.1 change must preserve:**
- JCS via `serde_canonical_json 1.0.0` — no raw `serde_json` bytes on signable structs
- HKDF info strings: `cipherpost/v1/<context>` — never empty; enumeration test must be extended for `cipherpost/v1/pin_wrap`
- Dual-signature ordering: outer PKARR verify FIRST, then pin-unwrap (if `pin_required`), then age-decrypt, then inner Ed25519 verify
- `chacha20poly1305` only via `age` — no direct calls anywhere in `src/`; nested age scrypt satisfies this for pin mode
- No `#[derive(Debug)]` on secret holders; manual redacting Debug impl; leak-scan test must cover all four Material variants
- All sig-verify error variants share identical user-facing Display (error-oracle hygiene, exit 3)
- Receipt published only after full verification + typed-z32 acceptance (tamper-zero invariant); burn mode does not suppress receipt
- No async runtime at cipherpost layer
- `serial_test = "3"` + `#[serial]` on any test mutating `CIPHERPOST_HOME` or `CIPHERPOST_PIN`

---

## Watch Out For (Top 10 Pitfalls, Severity x Probability Order)

**Phase 6 / Pitfall 19 — X.509 PEM/BER/DER non-canonicity breaks share_ref determinism**
Warning signal: two sends of the "same" cert from different tools produce different `share_ref`s. Prevention: store normalized DER only; reject BER at ingest via `x509-parser` parse (validates canonical DER encoding); commit `tests/fixtures/envelope_x509cert.bin` before Phase 6 ships. Design-in requirement, not a retrofit.

**Phase 7 / Pitfall 20 — OpenPGP armor headers are non-deterministic; store binary packet stream**
Warning signal: `gpg --version` changes between sends, breaking re-send idempotency. Prevention: strip armor at ingest (decode body, discard Version/Comment headers); store raw RFC 4880 binary packet stream; reject secret-key packet tags 5/7 with `Error::InvalidMaterial`. Commit `tests/fixtures/envelope_pgpkey.bin`.

**Phase 8 / Pitfall 23 — PIN mode creates a distinguishable oracle at the age decryption layer**
Warning signal: adding a `PinIncorrect` error variant with distinct Display or a distinct exit code. Prevention: wrong PIN must surface as the same user-facing message and exit 4 as any decrypt failure. Extend `signature_failure_variants_share_display` enumeration test to cover all PIN error paths in Phase 8 plan 01, before any PIN error path is written.

**Phase 8 / Pitfall 25 — Burn is local-state-only; a second receiver on a fresh machine still decrypts**
Warning signal: burn documentation that says "prevents re-decryption" without the "on this device, from this state ledger" caveat. Prevention: THREAT-MODEL.md section on burn semantics before Phase 8 implementation begins; acceptance screen warns explicitly.

**Phase 7 / Pitfall 21 — SSH .pub comment field breaks share_ref determinism**
Warning signal: two sends of the same SSH key from machines with different hostnames produce different `share_ref`s. Prevention: split `.pub` file on whitespace at ingest, take only the base64 blob (column 2), discard comment column. Commit `tests/fixtures/envelope_sshkey.bin`.

**Phase 5 / Pitfall 30 — Greedy `.trim()` on passphrase file corrupts passphrases with trailing spaces**
Warning signal: `passphrase_content.trim()` in the passphrase-file reading path. Prevention: strip exactly one trailing LF (or CRLF), nothing else. Unit test: `"mysecret \n"` yields parsed passphrase `"mysecret "` (space preserved).

**Phase 5 / Pitfall 31 — `FromRawFd` closes the passphrase fd on drop (double-close hazard)**
Warning signal: `unsafe { std::fs::File::from_raw_fd(fd) }` without `ManuallyDrop`. Prevention: use `BorrowedFd` (Rust 1.63+); test fd lifecycle explicitly.

**Phase 9 / Pitfall 28 — Concurrent-racer test written as sequential calls, not actually concurrent**
Warning signal: "concurrent" test with no `Barrier`, no spawned threads — just two sequential `publish_receipt` calls. Prevention: `std::sync::Barrier` to synchronize both threads past the resolve step before either calls publish; MockTransport must enforce CAS semantics.

**Phase 8 / Pitfall 24 — PIN entropy insufficient for offline brute force**
Warning signal: `--pin` accepts any length with no validation. Prevention: enforce minimum 8-character PIN at send time with `Error::InvalidInput`; document in THREAT-MODEL.md that offline brute force against short PINs is feasible against DHT-exfiltrated ciphertext.

**Phase 8 / Pitfall 26 — Burn sentinel deleted after emit (inverts the invariant)**
Warning signal: any code path calling `remove_file` on the sentinel after emit, or overwriting the ledger entry with `accepted: false`. Prevention: keep v1.0 `mark-then-emit` ordering; sentinel is never deleted; test with simulated stdout-failure under burn mode.

---

## Open Questions and Prerequisites

### Before Phase 8 Planning: cclink Pin/Burn Survey (BLOCKED — highest priority prerequisite)

All three research agent threads were access-denied on the cclink directory. Run manually before Phase 8 planning:

```bash
find /home/john/vault/projects/github.com/cclink/src -name "*.rs" | sort
grep -r "pin\|burn\|ttl_zero\|one_time\|read_once" \
  /home/john/vault/projects/github.com/cclink/src/ \
  --include="*.rs" -l
```

Then read `cclink/src/crypto/mod.rs`. Determine: (a) Does `derive_pin_key()` or equivalent exist? If yes, what are the Argon2id parameters? (b) Is there a "burn" or one-time record path in `transport/mod.rs`?

Guidance pending survey: vendor the PIN KDF section verbatim, substituting HKDF info string from `cclink-pin-v1` to `cipherpost/v1/pin_wrap`. If no burn transport path exists in cclink, the sentinel-only approach is the complete implementation.

### Before Phase 7 Implementation: ed25519-dalek Version Conflict Check

After adding `ssh-key = { version = "0.6" }` to Cargo.toml, run `cargo tree | grep ed25519-dalek`. If `ssh-key 0.6` requires `ed25519-dalek 2.x` alongside cipherpost's `=3.0.0-pre.5`, Cargo compiles both as distinct crates (usually fine). If not fine, mitigation: add `ssh-key` without the `ed25519` feature flag.

### Before Phase 9 Planning: pkarr Bootstrap Configurability

Verify whether `pkarr 5.0.4`'s `ClientBuilder` exposes a `bootstrap` field. Check via `cargo doc --open` at Phase 9 plan time. If not configurable: use `mainline` directly (already a transitive dep) for the DHT-layer CI test; note that the PKARR SignedPacket layer is not tested against local Testnet and is covered only by the manual real-DHT release gate.

### Before Phase 8 Implementation: Burn+Receipt Decision in PROJECT.md

Must be recorded as an explicit Key Decision before Phase 8 implementation begins. Research recommends Option A: publish receipt in burn mode (receipt is the delivery confirmation, not a trace to suppress).

---

## Reconciled Design Decisions

**1. pin_required field name and location**
Field name: `pin_required` (not `pin_protected`). Location: `OuterRecord` and `OuterRecordSignable` (outer-signed, pre-decrypt readable). Receiver must know to prompt for PIN before age-decrypt; inner-only placement creates a circular dependency. Name matches `ttl_seconds`-style convention.

**2. burn_after_read field name and location**
Field name: `burn_after_read` (not `burn`). Location: `Envelope` (inner-signed, post-decrypt). DHT observers must not see that a share is burn-marked — consistent with "ciphertext only on the wire." Explicit name avoids crypto-literature collision.

**3. PIN crypto design — nested age scrypt, no direct chacha20poly1305 calls**
Nested age scrypt passphrase-recipient: outer age-scrypt envelope keyed to PIN; inner standard age X25519 keyed to identity. Both layers use age's streaming interface. No direct `chacha20poly1305` calls in `src/`. The CLAUDE.md constraint holds without modification.

**4. cclink pin/burn survey — BLOCKED**
Plan-time prerequisite for Phase 8. Not a blocker for Phases 5–7.

**5. Exit code for burn "already consumed"**
Exit 7 ("share already consumed"). Reuses existing semantic bucket (user declined / transaction intentionally stopped). Avoids adding a new exit code and updating the full taxonomy.

**6. pgp crate version**
`pgp 0.14` for v1.1. Avoids RFC 9580 v6 format churn. v6 key support (available in `pgp 0.19`) deferred to a minor release.

**7. rpgp vs. sequoia-openpgp**
rpgp (`pgp` crate) only. sequoia-openpgp LGPL-2.0-or-later — ambiguous LGPL obligations under Rust monomorphization for a MIT-licensed binary. Definitive rejection on license grounds.

**8. ssh-key + ed25519-dalek conflict risk**
Plan-time pre-flight check, not a blocking concern. Run `cargo tree -d` after adding `ssh-key`. If conflict exists, disable the `ed25519` feature on `ssh-key`.

**9. Non-interactive PIN at receive time**
Defer `--pin-fd` to v1.2+. PIN is a second-factor authentication mechanism for a human receiver. Automated-script receive with programmatic PIN bypasses the threat model.

**10. Parse failure exit code for new Material variants**
Exit 1 (content error). Malformed DER / corrupt PGP packet / unsupported SSH format at receive time yields exit 1 with message naming variant and failure. Must NOT be confused with exit 3 (signature verification failure).

---

## Build Order Justification

The original 5 -> 6 -> 7 -> 8 -> 9 sequence is confirmed as optimal.

Phase 8 technically can layer on GenericSecret alone (does not require typed payloads). The ordering is still better as-is: (1) typed payloads give pin/burn semantic value; (2) JCS fixture work for typed variants and pin/burn Envelope fields should not be interleaved; (3) Phase 6/7 establish patterns (Debug redaction, per-variant size checks, HKDF enumeration extension) that Phase 8 must not skip.

The concurrent-racer test (`tests/concurrent_receipt_racer.rs`) can be written in any phase after Phase 3's MockTransport infrastructure. Assigning it to Phase 9 is organizational convenience, not a hard dependency.

Phase 5 is mandatory first. The passphrase-file/fd wiring unlocks scripted CI recipes Phases 6-8 depend on.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack additions (new crates) | HIGH | docs.rs verified; licenses confirmed; dep trees assessed |
| Phase 5 passphrase plumbing | HIGH | `resolve_passphrase()` already supports all four sources; work is mechanical clap surface wiring |
| Typed material receive UX conventions | HIGH | Sourced from canonical tools: openssl, gpg, ssh-keygen; all cross-referenced |
| PIN crypto design | HIGH | Nested age scrypt resolves CLAUDE.md constraint; age semantics verified |
| Burn semantics | HIGH | Extension of v1.0 state-ledger idempotency; no new architectural primitives |
| Phase 8 cclink vendoring | LOW | cclink directory access-denied; indirect evidence strong but Argon2id params and burn path unconfirmed |
| Phase 9 mainline::Testnet | MEDIUM | Testnet type confirmed to exist; pkarr bootstrap configurability unverified against 5.0.4 |
| Real-DHT propagation timing | MEDIUM | p50 ~1 minute from Mainline DHT literature; no empirical cipherpost-specific data |
| v1.0 pin reality check | HIGH | All crates spot-checked; no yanks or advisories found 2026-04-23 |

**Overall confidence: HIGH** with two bounded gaps (cclink survey, pkarr bootstrap config) that are prerequisites for specific phases, not blockers for the milestone as a whole.

### Gaps to Address

- **cclink pin/burn survey:** Must be done before Phase 8 planning. Argon2id params for PIN KDF and burn transport path existence are unknown.
- **pkarr bootstrap configurability:** Check at Phase 9 plan time. If not configurable, scope CI-gate to `mainline` direct and document the gap.
- **PGP fixture generation:** Cannot use a real key (determinism requires a known byte vector). Phase 7 plan must specify how to generate a minimal deterministic test PGP public key packet for `tests/fixtures/envelope_pgpkey.bin`.
- **Burn+receipt decision:** Must be recorded in PROJECT.md Key Decisions before Phase 8 implementation. Research recommends Option A (publish receipt in burn mode).

---

## Implications for Roadmap

### Phase 5 — Non-Interactive Automation E2E

**Rationale:** Unlocks scripted CI recipes Phases 6-8 depend on. Mechanical plumbing. Clears traceability-table debt. Fastest phase in the milestone.
**Delivers:** Scripted send/receive without TTY; SPEC.md pin-version blessing; DHT label stability confirmation; single-source-of-truth requirements format.
**Pitfalls owned:** 30, 31, 32, 33, 34, 35.
**Research flag:** No deeper research needed.

### Phase 6 — Material::X509Cert (Pattern-Establish)

**Rationale:** Establishes the typed-material pattern that Phase 7 applies mechanically. X.509 has the richest acceptance screen — get it right here.
**Delivers:** End-to-end X.509 send/receive; normalized DER storage; `tests/fixtures/envelope_x509cert.bin` committed.
**Pitfalls owned:** 19 (critical — plan 01), 22, 36.
**Research flag:** No deeper research needed. Verify `x509-parser 0.16` DN accessor API at plan time via `cargo doc`.

### Phase 7 — Material::PgpKey + Material::SshKey

**Rationale:** Applies Phase 6 pattern twice. PgpKey is M complexity; SshKey is S complexity. Both in one phase as planned.
**Delivers:** PGP single-key send/receive; SSH public/private key send/receive; JCS fixtures for both variants.
**Pitfalls owned:** 20 (critical — plan 01), 21 (critical — plan 01), 22, 36.
**Research flag:** Run `cargo tree | grep ed25519-dalek` at plan time before adding `ssh-key` to Cargo.toml.

### Phase 8 — --pin and --burn Encryption Modes

**Rationale:** New crypto surface and new state-machine behavior. Must follow Phase 7 so pin/burn has full typed-payload value.
**Delivers:** `--pin` TTY second factor; nested age scrypt unwrap; `--burn` single-consumption enforcement; `src/pin.rs`; THREAT-MODEL.md updates.
**Pitfalls owned:** 23, 24, 25, 26, 27, 37 — all must be addressed in plan 01 before any implementation.
**Research flag:** REQUIRES cclink pin/burn survey before this phase can be planned.

### Phase 9 — Real-DHT Cross-Identity Round Trip + CAS Racer

**Rationale:** Release-acceptance gate, not a feature gate. Validates the protocol over real Mainline DHT.
**Delivers:** `tests/real_dht_e2e.rs` (manual release gate); `tests/concurrent_receipt_racer.rs` (CI); MockTransport CAS semantics; RELEASE-CHECKLIST.md entry.
**Pitfalls owned:** 28, 29 — both must be in plan 01.
**Research flag:** Check pkarr bootstrap configurability at plan time.

---

## Sources

### Primary (HIGH confidence)
- Direct `src/` inspection: payload.rs, flow.rs, cli.rs, main.rs, transport.rs, error.rs, record.rs, identity.rs — 2026-04-23
- `.planning/PROJECT.md`, `.planning/RETROSPECTIVE.md`, `CLAUDE.md`, `SPEC.md`, `THREAT-MODEL.md`
- docs.rs: x509-parser 0.18.1, pgp 0.19.0, ssh-key 0.6.7, pkarr 5.0.4, age 0.11.2, serde_canonical_json 1.0.0
- openssl x509 manpage, GnuPG documentation, ssh-keygen fingerprint format references
- age authentication model (Filippo Valsorda) — nested vs. multi-recipient semantics

### Secondary (MEDIUM confidence)
- Mainline DHT Wikipedia / Pubky medium — p50 lookup latency ~1 minute
- pkarr GitHub (pubky/pkarr) — 1000-byte budget, TXT records, republish semantics
- age discussions #256 and #685 — fd passphrase behavior; trailing newline stripping precedent
- crypt.fyi GitHub — burn-after-read + password-protection reference
- mainline::Testnet docs.rs — Testnet type existence confirmed; full API unverified

### Tertiary (LOW confidence — requires plan-time verification)
- cclink/src/crypto/mod.rs — PIN KDF existence inferred from v1.0 STACK.md; not directly inspected
- cclink/src/transport/mod.rs — burn path existence unknown; requires manual survey
- pkarr 5.0.4 ClientBuilder bootstrap configurability — unverified; check via `cargo doc` at Phase 9 plan time

---

*Research completed: 2026-04-23*
*Milestone: v1.1 "Real v1"*
*Ready for requirements: yes, with Phase 8 gated on cclink survey (see Open Questions)*
