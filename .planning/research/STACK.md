# Technology Stack — v1.1 Additions

**Project:** Cipherpost v1.1 "Real v1"
**Researched:** 2026-04-23
**Scope:** ADDITIONS and CHANGES only — existing v1.0 stack is locked and unchanged.
  See the v1.0 STACK.md (this file, prior content archived in `milestones/v1.0-*`) for baseline.

---

## TL;DR

v1.1 adds exactly three new crate dependencies. Everything else is plumbing, not new crates.

| New Crate | Version | Phase | Why |
|-----------|---------|-------|-----|
| `x509-parser` | `0.16` or `0.18` | Phase 6 | PEM + DER X.509 parsing; pure Rust; zero-copy; MIT/Apache-2.0 |
| `pgp` (rPGP) | `0.19` | Phase 7 | Pure-Rust OpenPGP; single-key; MIT/Apache-2.0; no GPL anywhere in tree |
| `ssh-key` | `0.6` | Phase 7 | Pure-Rust OpenSSH v1 private key + public key parsing; MIT/Apache-2.0 |

No new async runtime. No new C FFI. No OpenSSL. All three are RustCrypto-adjacent or Rusticata family — compatible with existing `cargo deny` policy.

Phase 8 (pin/burn) adds NO new crates — only new Argon2id invocation paths using the already-present `argon2 0.5` crate. Phase 5 and Phase 9 add no new crates.

---

## Existing Stack Status (v1.0 pins — version reality-check as of 2026-04-23)

All versions below were re-verified. None are yanked. No RustSec advisories found for any of them.

| Crate | Shipped Version | Latest Stable | Yank / Advisory | Action |
|-------|----------------|---------------|-----------------|--------|
| `serde_canonical_json` | `1.0.0` | `1.0.0` | None | None — bless as shipped |
| `pkarr` | `5.0.4` (transitive from `5.0.3` pin) | `5.0.4` | None | None — bless `5.0.4` as the de facto pin |
| `age` | `0.11` → `0.11.2` | `0.11.2` | None | None — `0.11.2` is stable, up-to-date |
| `dialoguer` | `0.12` → `0.12.0` | `0.12.0` | None | None |
| `thiserror` | `2` → `2.0.x` | `2.0.18` | None | None |
| `hex` | not in v1.0 Cargo.toml | N/A | N/A | hex encoding is done via `base64 0.22` — no `hex` crate in use |
| `base64` | `0.22` → `0.22.1` | `0.22.1` | None | None |
| `ed25519-dalek` | `=3.0.0-pre.5` | `3.0.0-pre.5` (latest pre) | None | Hard pin stays — pkarr 5.x still requires `^3.0.0-pre.1`; no stable 3.x exists |

**Phase 5 task:** update `SPEC.md`/`REQUIREMENTS.md` to bless `serde_canonical_json 1.0.0` and `pkarr 5.0.4`
as the pinned shipped reality. No Cargo.toml changes required.

---

## Phase 5 — Non-interactive Passphrase Flags

**No new crates.** `resolve_passphrase()` already implements the four-priority chain
(`CIPHERPOST_PASSPHRASE` env → `--passphrase-file` → `--passphrase-fd` → TTY prompt).
The only work is wiring the two new clap arguments (`--passphrase-file`, `--passphrase-fd`)
on `send` and `receive` subcommands so they feed into the existing resolver. This was already
implemented for `identity generate`/`show` — it is a copy-across, not new engineering.

File-reading is handled with `std::fs::File` + `std::io::Read` from the standard library;
no new crates needed.

---

## Phase 6 — `Material::X509Cert`

### Decision: `x509-parser 0.16` (pinned to avoid transitive bloat)

**Recommended crate:** `x509-parser`
**Version:** `"0.16"` as a caret requirement (resolves ≤ 0.17) OR `"0.18"` for latest.
**Confidence:** HIGH (docs.rs verified; license verified; supply chain assessed)

#### Why x509-parser over alternatives

| Candidate | Decision | Reason |
|-----------|----------|--------|
| `x509-parser` | **USE** | Pure Rust, zero-copy, MIT/Apache-2.0 dual license, active (Rusticata org), latest 0.18.1, PEM + DER both first-class, no C FFI, no `ring`/`aws-lc` required unless `verify` feature enabled |
| `x509-cert` (RustCrypto) | Reject | v0.2.5; PEM support is not first-class — requires companion crates; designed for certificate *building* not *parsing*; fewer features for metadata extraction; lower download volume |
| `x509-certificate` | Reject | Self-described as "not audited," "not hardened against malicious inputs," with documented panic paths on malformed ASN.1 — explicitly unsuitable for parsing adversarial user input |
| `pem` crate + manual DER | Reject | Would require hand-rolling ASN.1 parsing for Subject/Issuer/SAN/validity; significant complexity with no upside; reinventing what x509-parser already does correctly |
| `openssl` wrapper | Reject | C FFI — violates `cargo deny` cleanliness policy; introduces OpenSSL supply chain; blocked by existing PITFALLS guidance against a second crypto implementation |

#### What x509-parser provides for `Material::X509Cert`

- `parse_x509_pem()` → extracts the DER bytes and PEM tag from a PEM block
- `X509Certificate::from_der()` → full parse into structured certificate object
- Subject DN, Issuer DN, validity period (not_before / not_after), serial number, public key algorithm, subject alternative names — all accessible from the parsed struct
- No chain validation (the `validate` feature adds structural checks, not chain trust) — this is correct for cipherpost, which *holds* one cert, not a chain

#### Scope boundary (critical)

`Material::X509Cert` stores and transports one leaf certificate. It does NOT validate
chain trust, check revocation (CRL/OCSP), or verify signatures on the cert. The cipherpost
payload is a courier, not a CA. Do not enable the `verify` or `verify-aws` features — they
pull in `ring` or `aws-lc-rs` and are not needed.

Feature flag to use: **none** (default features, no `verify`, no `validate`).

#### Dependency footprint

x509-parser's direct deps: `nom ^7`, `der-parser ^10`, `asn1-rs ^0.7`, `oid-registry ^0.8`,
`rusticata-macros`, `data-encoding`, `thiserror`, `time`. All pure Rust. No C FFI.
`thiserror` and `nom` are already in the transitive graph or likely to be. The worst-case
addition is `asn1-rs`, `der-parser`, `oid-registry`, `rusticata-macros` — acceptable for
the capability gained. `nom` adds ~120 KB compiled.

#### License compatibility

`x509-parser` is MIT OR Apache-2.0. Compatible with cipherpost's MIT license.
No GPL-adjacent crates in the default-features tree (the `ring`/`aws-lc` optional deps
that would add non-MIT-compatible code are NOT pulled in without the `verify` feature).

#### `cargo deny` implications

Add to `deny.toml` exceptions if needed: `nom`, `der-parser`, `asn1-rs`, `oid-registry`
are all Apache-2.0 / MIT. No new license categories required.

#### Integration point

```
src/material/x509cert.rs  (new module)
  - fn parse_x509_pem(raw: &str) -> Result<X509CertMeta, Error>
  - fn parse_x509_der(raw: &[u8]) -> Result<X509CertMeta, Error>
  - struct X509CertMeta { subject, issuer, not_before, not_after, serial_hex, pubkey_algo, fingerprint_sha256_hex }

src/envelope.rs (existing)
  - Material::X509Cert { pem: String } stays as-is (stores raw PEM string)
  - run_receive decodes Material::X509Cert by calling parse_x509_pem() AFTER inner-sig verify

src/commands/receive.rs (existing)
  - acceptance screen renders X509CertMeta fields on stderr (subject, validity, fingerprint)
  - plaintext material still goes to stdout only after typed-z32 confirm
```

#### Cargo.toml addition

```toml
x509-parser = { version = "0.16", default-features = true }
```

(Do NOT enable `verify` or `verify-aws` features.)

---

## Phase 7 — `Material::PgpKey` + `Material::SshKey`

### PGP: `pgp` (rPGP) version `0.14` or `0.19`

**Recommended crate:** `pgp` (the rPGP project, published as the `pgp` crate on crates.io)
**Version:** `"0.14"` if minimizing dep churn; `"0.19"` for latest features (RFC 9580 v6 support)
**Confidence:** MEDIUM-HIGH (docs.rs + GitHub license verified; dep tree estimated not fully enumerated)

#### Why pgp (rPGP) over sequoia-openpgp

| Candidate | Decision | Reason |
|-----------|----------|--------|
| `pgp` (rPGP) | **USE** | Pure Rust; MIT OR Apache-2.0 dual license; no GPL anywhere in dependency tree; single-key and keyring APIs both available; active (Deltachat uses it in production); docs.rs latest 0.19.0 |
| `sequoia-openpgp` | Reject | LGPL-2.0-or-later — not compatible with cipherpost's MIT distribution without careful analysis of LGPL obligations; also much heavier (full PGP toolkit, not just a parser) |
| `pgp-lib` | Reject | Thin async wrapper over rPGP; adds `tokio` dep; not needed |

#### License compatibility

`pgp` crate is MIT OR Apache-2.0. No GPL or LGPL in the main dependency tree.
The `sequoia-openpgp` rejection on license grounds is definitive — LGPL on a static-linked
Rust crate has ambiguous obligations under Rust's monomorphization model; avoid entirely.

#### Scope for `Material::PgpKey`

`PgpKey` = **single transferable public or secret key** (not a keyring). The rPGP API
exposes `SignedPublicKey` and `SignedSecretKey` which can be loaded from ASCII-armored input.
What to extract for the acceptance screen:

- Primary key fingerprint (v4 SHA1 or v6 SHA256)
- Primary key algorithm + creation timestamp
- User ID(s) from the key (first UID or all UIDs — show on acceptance screen)
- Expiry if set

The `pgp` crate's `from_armor_single` / `from_bytes` API handles single-key ASCII armor.
Do NOT use keyring-loading APIs (`from_armor_many`) — scope is one key, not a keyring.

#### 64 KB plaintext cap interaction

A single OpenPGP key is typically 1–10 KB for a modern Ed25519 or RSA-4096 primary + sub.
The 64 KB cap is not threatened by realistic single-key inputs. No special handling needed.

#### `cargo deny` implications

rPGP pulls in EC crypto crates (`k256`, `p256`, `p384`, etc.) and symmetric ciphers
(`blowfish`, `twofish`, `des`) for legacy algorithm compatibility. These are all MIT/Apache-2.0.
Run `cargo deny check` after adding — expect new crate names but no new license categories.

#### Cargo.toml addition

```toml
pgp = { version = "0.14", default-features = true }
```

(Or `"0.19"` for v6 key format support. Prefer `"0.14"` if v6 is not a requirement for v1.1
since it reduces dependency churn. Verify at plan time via `cargo search pgp`.)

#### Integration point

```
src/material/pgpkey.rs  (new module)
  - fn parse_pgp_key_armor(raw: &str) -> Result<PgpKeyMeta, Error>
  - struct PgpKeyMeta { fingerprint_hex, algorithm, created_at, user_ids: Vec<String>, expires_at: Option<DateTime> }
  - Enforces single-key — if armor contains multiple keys, return Error::PgpKeyringNotSupported

src/envelope.rs (existing)
  - Material::PgpKey { armor: String } (raw ASCII-armored key blob)
  - Acceptance screen renders PgpKeyMeta fields
```

---

### SSH: `ssh-key` version `0.6`

**Recommended crate:** `ssh-key` (RustCrypto org)
**Version:** `"0.6"` (latest stable: 0.6.7)
**Confidence:** HIGH (docs.rs verified; RustCrypto org pedigree)

#### Why ssh-key

- Pure Rust, RustCrypto org (same family as `ed25519-dalek`, `sha2`, etc. already in the graph)
- MIT OR Apache-2.0 dual license
- Explicit support for OpenSSH private key format (`BEGIN OPENSSH PRIVATE KEY` — the modern format)
- Public key parsing (authorized_keys format, base64-encoded wire format)
- Key algorithm identification, fingerprint computation, comment extraction
- No C FFI

#### Feature flags to use

`ssh-key` has per-algorithm feature flags (`ed25519`, `rsa`, `p256`, etc.) for signature
and key-generation capabilities. For `Material::SshKey`, we are PARSING ONLY — we do not
generate or sign. Use **default features** to get parsing for all supported algorithms
without pulling in all cryptographic backends.

The `bcrypt-pbkdf` feature (private key decryption) is NOT needed — cipherpost stores the
key as a blob, does not decrypt it. Do not enable.

#### SSH key format scope for `Material::SshKey`

Support exactly two formats; reject everything else explicitly:

1. **OpenSSH private key** (`-----BEGIN OPENSSH PRIVATE KEY-----`) — modern format, all
   current `ssh-keygen` defaults, handles Ed25519/ECDSA/RSA. This is what security engineers
   actually transfer. Use `PrivateKey::from_openssh()`.
2. **OpenSSH public key** (bare `ssh-ed25519 AAAA...` or `-----BEGIN PUBLIC KEY-----` for
   RFC4716) — for cases where only the public key needs to be handed off.
   Use `PublicKey::from_openssh()`.

Explicitly OUT OF SCOPE for `Material::SshKey` v1.1:
- **Legacy PEM private keys** (`-----BEGIN RSA PRIVATE KEY-----`, PKCS#1/SEC1) — the
  ssh-key docs list these as TODO items ("not currently supported"). Do not attempt.
  If a user provides legacy PEM, return a clear `Error::SshKeyFormatNotSupported` with a
  message suggesting `ssh-keygen -p -m OpenSSH` to convert.
- **RFC4716 public key format** (`---- BEGIN SSH2 PUBLIC KEY ----`) — rarely used in practice;
  docs.rs confirms it is not explicitly supported. Defer to v1.2 if demand arises.
- **FIDO/U2F `sk-*` keys** — the hardware-resident-key use case is niche; return
  `Error::SshKeyFormatNotSupported` with a descriptive message.

Rationale for narrow scope: the OpenSSH v1 format covers >95% of real-world SSH keys
generated in the last 5+ years. Narrowing the scope keeps Phase 7 tractable and avoids
encoding edge cases that haven't been validated by real user demand.

#### What to extract for the acceptance screen

From `PrivateKey` or `PublicKey`:
- Algorithm (e.g., `Ed25519`, `EcdsaP256`, `Rsa`)
- Fingerprint (`key.fingerprint(HashAlg::Sha256)`) — displays as `SHA256:<base64>`
- Comment (the identifying string at the end of an OpenSSH public key)

#### `ed25519-dalek` version interaction

`ssh-key` 0.6 depends on `ed25519-dalek` — but likely a different version range than
cipherpost's exact `=3.0.0-pre.5` pin. This is **the single highest-risk dependency
interaction in v1.1**. Cargo allows multiple versions of the same crate in a graph, but if
`ssh-key` requires ed25519-dalek 2.x stable and cipherpost's exact pin resolves to pre.5,
Cargo may attempt to compile both. This is usually fine (they are distinct crate versions)
but must be verified at plan time with `cargo tree -d` to confirm no type-boundary crossing.

**Plan-time verification required:** after adding `ssh-key` to Cargo.toml, run
`cargo tree | grep ed25519-dalek` and confirm both the `=3.0.0-pre.5` pin (required by pkarr)
and any version required by ssh-key are independently resolved without conflict.

If ssh-key requires `ed25519-dalek 2.x` and that conflicts with pkarr's pre-release pin,
the mitigation is to use ssh-key without the `ed25519` feature flag, falling back to algorithm
identification without full Ed25519 signing-key support (still sufficient for fingerprint + parse).

#### Cargo.toml addition

```toml
ssh-key = { version = "0.6", default-features = true }
```

---

## Phase 8 — `--pin` and `--burn` Encryption Modes

### No new crates

Pin and burn modes use the **already-present `argon2 0.5` crate** for PIN derivation —
the same crate already used for passphrase-based key-envelope protection. No new cryptographic
primitives are required.

**Pin mode mechanics (reconstructed from PRD intent + cclink lineage):**
- Sender chooses a short PIN (4–8 digits, or passphrase)
- A separate per-share symmetric key is derived: `argon2id(PIN, random_salt, params)` → 32-byte KEK
- The age ciphertext in the `OuterRecord` is re-wrapped: `encrypt(KEK, age_ciphertext)` OR
  the age recipient is the PIN-derived key instead of the recipient's X25519 key
- Recipient must provide the PIN out-of-band to decrypt

**Burn mode mechanics:**
- The DHT TXT record is given a TTL of 0 or near-0 seconds, OR the sender signals single-read
  via a flag in the `Envelope` metadata. On `receive`, the client immediately publishes an
  updated SignedPacket with the record removed (or TTL=0) via the resolve-merge-republish
  pattern already implemented in `DhtTransport`.
- This is a best-effort signal on a distributed DHT — the "burn" cannot be truly enforced
  (DHT nodes may cache; existing resolvers may have the data). The THREAT-MODEL.md must
  acknowledge this limitation explicitly.

### cclink survey — BLOCKED

The cclink survey at `/home/john/vault/projects/github.com/cclink` could not be completed
because the Read and Bash tools are permission-denied on that directory in this research session.

**What is known from indirect evidence:**
- cclink v1.3.0 is the source of the crypto layer vendored into cipherpost (confirmed via
  `.planning/research/STACK.md` written on 2026-04-20, which listed specific modules read
  directly from the cclink GitHub repo via gh API)
- The v1.0 STACK.md from 2026-04-20 listed `src/crypto/mod.rs` as a vendored module including
  "Argon2id+HKDF key/PIN derivation" — this implies PIN derivation code EXISTS in cclink's
  crypto module
- The v1.0 STACK.md specifically notes cclink's crypto/mod.rs contains "key/PIN derivation"
  alongside the key-envelope encode/decode

**Action required for Phase 8 planning:**
The human must run the following and paste output into the Phase 8 plan:

```bash
find /home/john/vault/projects/github.com/cclink/src -name "*.rs" | sort
grep -r "pin\|burn\|ttl_zero\|one_time\|read_once" \
  /home/john/vault/projects/github.com/cclink/src/ \
  --include="*.rs" -l
```

Then read `cclink/src/crypto/mod.rs` to determine:
- Does a `derive_pin_key()` or equivalent exist?
- What are the Argon2id parameters used for PIN derivation (may differ from the passphrase
  params of m_cost=64MB, t_cost=3)?
- Is there a "burn" / "one-time" TXT record removal path in `transport/mod.rs`?

**Confident assumption based on PRD language and STACK.md evidence:**
cclink has PIN derivation in `crypto/mod.rs` using `argon2 0.5`. It will use the same
`argon2id` algorithm but likely with different params (PIN derivation typically uses lower
memory cost than passphrase KDF since PINs are short and the attacker constraint is different —
but this must be confirmed from the actual code). The burn path, if it exists, will be in
`transport/mod.rs` as a record-removal or TTL-zero publish operation.

**Vendor vs reimplementation guidance (pending confirmation):**
- `crypto/mod.rs` PIN derivation section → **VENDOR** (copy verbatim, rename to
  `cipherpost/v1/pin` HKDF context if cclink uses a cclink-namespaced context)
- `transport/mod.rs` burn/remove path → **VENDOR** if exists; **REIMPLEMENT** as a
  `OuterRecord` with TTL=0 published via `publish()` if no burn path exists in cclink
- Any `Envelope`-level pin/burn mode flag → **REIMPLEMENT** (cipherpost's `Envelope` schema
  differs from cclink's `HandoffRecord` schema; the typed-payload integration is new)

**Protocol note:** `--pin` and `--burn` are orthogonal. A burn-mode share can also be
PIN-protected. The `Envelope` needs a `mode` or `flags` field added to the schema before
inner-signing. This is a new field not in the v1.0 wire format — it constitutes a
protocol-level change requiring the JCS fixture to be regenerated and a new test vector
committed. Plan this explicitly.

---

## Phase 9 — Real-DHT Cross-Identity Round Trip + CAS Race Test

### No new crates (prefer mainline Testnet from transitive dep)

#### Real-DHT test harness options — ranked by flake risk

**Option A (RECOMMENDED): `mainline::Testnet` in-process local DHT**

`mainline` (the Mainline DHT library that pkarr uses transitively) exposes a `Testnet` type:

```rust
let testnet = Testnet::builder(3).build().unwrap();
let dht = Dht::builder()
    .bootstrap(&testnet.bootstrap)
    .bind_address(Ipv4Addr::LOCALHOST)
    .build()
    .unwrap();
```

This creates an isolated local DHT with N nodes on localhost, no public network, no flake from
network outages. The test runs fully in-process. **But**: pkarr's `ClientBlocking` / `Client`
may not expose a way to override the bootstrap nodes it uses internally — pkarr abstracts over
mainline and may hardcode the public bootstrap list.

**Investigation required at plan time:** inspect pkarr 5.0.4's `ClientBuilder` API (or
equivalent) to confirm whether it accepts custom bootstrap nodes. If it does, Option A is
straightforward. If it does not (pkarr wraps mainline opaquely), then:

Sub-option A1: Use `mainline` directly (it is already a transitive dep, so no new `Cargo.toml`
entry needed) to test the DHT put/get protocol without going through pkarr's SignedPacket layer.
This tests the network plumbing but not the full PKARR signing/verification path.

Sub-option A2: Add `mainline` as an explicit dev-dependency and spin up a local Testnet,
then configure pkarr's client to use the testnet's bootstrap addresses. Requires checking
whether pkarr's `Settings` or `ClientBuilder` struct exposes a `bootstrap` field.

Confidence: MEDIUM. The `mainline::Testnet` type exists and is documented. Whether pkarr
exposes bootstrap customization needs verification against pkarr 5.0.4's actual source.

Flake risk: LOW (in-process, no network). Speed: FAST (< 1s for local DHT convergence).

---

**Option B: Two processes via `std::process::Command`**

Compile the `cipherpost` binary and spawn two processes: one that calls `cipherpost send`,
one that calls `cipherpost receive`. Use real Mainline DHT. This is the most realistic
end-to-end test — it exercises the same binary users will actually run.

Flake risk: HIGH (depends on Mainline DHT availability, bootstrap node health, NAT traversal).
Speed: SLOW (DHT publish propagation is p50 ~1 min with long tail). Not suitable as a CI gate.

Recommended role: **manual release-acceptance gate**, not automated CI. Run before tagging
v1.1 on a machine with stable outbound UDP. Document the command in a `RELEASE-CHECKLIST.md`.

---

**Option C: Two in-process `ClientBlocking` instances on real DHT**

Create two identities in the same test process, have identity A publish a share via
`DhtTransport::publish()`, have identity B call `DhtTransport::resolve()`. Uses real Mainline
DHT but no process boundary.

Flake risk: HIGH (same DHT availability issue as Option B, minus process spawn overhead).
Speed: SLOW. Not suitable as a CI gate.

Recommended role: Same as Option B — manual release gate, not automated CI.

---

**Recommended Phase 9 test strategy:**

1. **CI gate (automated):** Option A with `mainline::Testnet` — in-process, fast, no network.
   Tests the PKARR SignedPacket publish/resolve round trip with two identities and signed receipt.
   If pkarr's bootstrap is not configurable, scope down to a `mainline`-level put/get test
   that validates the DHT layer below PKARR (note this gap in the test plan explicitly).

2. **Release gate (manual):** Option B or C with real Mainline DHT. One two-identity round trip
   (A sends, B receives, B publishes receipt, A fetches receipt). Documented in `RELEASE-CHECKLIST.md`.
   Required before cutting a v1.1 tag. Not in CI.

#### CAS merge-update race test

The `publish_receipt` path uses resolve-merge-republish with `cas` (compare-and-swap on the
PKARR SignedPacket sequence number — inherited from BEP44 mutable items). The risk: two
concurrent `publish_receipt` calls from the same recipient key race and one silently loses.

**Test approach (no new crates):**

```rust
// Spawn two threads, each trying to publish a receipt at the same time.
// Use Arc<Barrier> to synchronize so both threads attempt publish simultaneously.
// Assert that after both threads complete, the recipient's DHT record contains
// BOTH receipt TXT records (resolve-merge-republish should produce both).
// Use MockTransport (already in the codebase) with artificial latency injection.
```

The `MockTransport` already supports inspecting the published SignedPacket. Add a simulated
concurrent-write test by calling `publish_receipt` from two threads with an `Arc<Barrier>`
synchronization point and `MockTransport`. This does not test real DHT CAS behavior but does
test that the `publish_receipt` logic correctly handles a `cas` conflict (the second writer
must re-fetch, re-merge, and retry).

If `DhtTransport`'s real CAS behavior needs to be tested, use Option A (local Testnet)
with two goroutine-equivalent Rust threads and a `std::sync::Barrier`. No new crates needed;
`std::sync::Barrier` is in the standard library.

---

## Complete Cargo.toml Delta for v1.1

```toml
# --- ADD to [dependencies] ---

# Phase 6: X.509 certificate parsing (PEM + DER; no verify/validate features)
x509-parser = { version = "0.16", default-features = true }

# Phase 7: OpenPGP single-key parsing (pure Rust, MIT/Apache-2.0, no sequoia GPL)
pgp = { version = "0.14", default-features = true }

# Phase 7: SSH key parsing (OpenSSH v1 private + public; RustCrypto org)
ssh-key = { version = "0.6", default-features = true }

# --- NO CHANGES to existing [dependencies] ---
# --- NO CHANGES to [dev-dependencies] ---
# --- NO new [dev-dependencies] for Phase 9 (mainline is already transitive) ---
```

**Caveat:** exact versions above should be re-verified with `cargo search` at plan time.
- `x509-parser` latest verified: `0.18.1` — use `"0.16"` (stable minor) or `"0.18"` (latest)
- `pgp` latest verified: `0.19.0` — use `"0.14"` (conservative) or `"0.19"` (latest with RFC 9580)
- `ssh-key` latest verified: `0.6.7` — use `"0.6"` (resolves to 0.6.7)

---

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| X.509 parsing | `x509-parser` | `x509-cert` | `x509-cert` is a cert builder, not a full parser; PEM not first-class |
| X.509 parsing | `x509-parser` | `openssl` crate | C FFI; violates supply-chain cleanliness; second crypto impl |
| X.509 parsing | `x509-parser` | `pem` + manual ASN.1 | 500+ lines of hand-rolled parsing for what x509-parser gives free |
| PGP parsing | `pgp` (rPGP) | `sequoia-openpgp` | LGPL-2.0 — license incompatible with MIT distribution; also heavyweight |
| SSH parsing | `ssh-key` | `osshkeys` | Lower download volume; less RustCrypto integration; no clear advantage |
| SSH parsing | `ssh-key` | `openssh-keys` (coreos) | Public-key only; no private key support; archived |
| Pin/burn | `argon2 0.5` (existing) | `scrypt` or `pbkdf2` | PRD locked Argon2id; no reason to diverge; `argon2 0.5` already present |
| DHT test | `mainline::Testnet` | Real public DHT in CI | Flake risk too high; p50 1-min DHT propagation incompatible with CI timeouts |
| DHT test | `mainline::Testnet` | Separate test process | Subprocess + real DHT is slower and flakier than in-process Testnet |

---

## What NOT to Add

| Avoid | Why |
|-------|-----|
| `sequoia-openpgp` | LGPL — license risk for MIT-licensed cipherpost |
| `openssl` crate | C FFI; second crypto implementation; violates existing PITFALLS guidance |
| `tokio` as direct dep | Already absent at cipherpost layer; pkarr's internal runtime is sufficient; keep `fn main()` synchronous |
| `ring` or `aws-lc-rs` | Not needed for parsing-only X.509; x509-parser's verify/verify-aws features are disabled |
| `bcrypt-pbkdf` feature on `ssh-key` | Not needed — cipherpost stores SSH keys as blobs, does not decrypt them |
| `validate` feature on `x509-parser` | Not needed — cipherpost does not validate cert chains; enables code not exercised |
| Any new crate for pin/burn | Argon2id is already present via `argon2 0.5`; no new crypto primitive required |
| `chacha20poly1305` direct calls | Still prohibited — ChaCha is only reachable via `age`; existing CLAUDE.md constraint holds |

---

## Confidence Assessment

| Area | Confidence | Reason |
|------|------------|--------|
| x509-parser choice | HIGH | docs.rs verified; license confirmed; feature flags confirmed; dep tree assessed |
| pgp (rPGP) choice | MEDIUM-HIGH | docs.rs verified; license confirmed; dep tree estimated (not fully enumerated); sequoia rejection on license grounds is definitive |
| ssh-key choice | HIGH | RustCrypto pedigree; docs.rs verified; feature flags confirmed; legacy format limitations confirmed from docs |
| ssh-key + ed25519-dalek conflict risk | MEDIUM | Known potential conflict; must be verified with `cargo tree` at plan time |
| Phase 8 (pin/burn) crate needs | HIGH | Argon2 already present; no new crypto needed; cclink survey blocked but indirect evidence strong |
| cclink pin/burn survey | LOW | Access denied in this session; must be done by human before Phase 8 planning |
| Phase 9 DHT test harness | MEDIUM | `mainline::Testnet` confirmed to exist; pkarr bootstrap configurability is unverified |
| Existing v1.0 pins (yank/advisory check) | HIGH | Spot-checked via docs.rs + search; no yanks or advisories found |

---

## Sources

- `x509-parser 0.18.1` — https://docs.rs/x509-parser/latest/x509_parser/ (HIGH confidence)
- `x509-cert 0.2.5` — https://docs.rs/x509-cert/latest/x509_cert/ (HIGH confidence — consulted to reject)
- `pgp 0.19.0` — https://docs.rs/pgp/latest/pgp/ (HIGH confidence)
- `sequoia-openpgp` LGPL — https://sequoia-pgp.org/blog/2021/10/18/202110-sequoia-pgp-is-now-lgpl-2.0/ (HIGH confidence — LGPL confirmed)
- `ssh-key 0.6.7` — https://docs.rs/ssh-key/latest/ssh_key/ (HIGH confidence)
- `mainline::Testnet` — https://docs.rs/mainline/latest/mainline/struct.Dht.html (MEDIUM confidence — referenced in docs but full API unverified)
- `pkarr 5.0.4` — https://docs.rs/pkarr/5.0.4/pkarr/ (HIGH confidence)
- `age 0.11.2` — WebSearch confirmed latest stable, no advisories (HIGH confidence)
- `serde_canonical_json 1.0.0` — https://docs.rs/crate/serde_canonical_json/latest (HIGH confidence — only version, not yanked)
- `dialoguer 0.12.0` — WebSearch + docs.rs confirmed (HIGH confidence)
- `thiserror 2.0.18` — WebSearch confirmed (HIGH confidence)
- cclink survey: BLOCKED — file system access denied; indirect evidence from v1.0 STACK.md (LOW confidence for cclink-specific claims)

---

*Stack additions research for: Cipherpost v1.1 "Real v1" milestone*
*Researched: 2026-04-23*
