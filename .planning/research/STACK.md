# Stack Research

**Domain:** Rust CLI crate — self-sovereign cryptographic-material handoff over Mainline DHT
**Researched:** 2026-04-20
**Confidence:** HIGH (cclink's `Cargo.toml` + `Cargo.lock` read directly from GitHub; all versions re-verified against crates.io on the research date)

## TL;DR

Cipherpost's stack is **cclink's stack**. The crypto/DHT layer is already implemented, tested, and working in `johnzilla/cclink` v1.3.0 — cipherpost's job in the walking skeleton is to copy those modules in verbatim and build a new payload/flow layer on top. Do not substitute, reorder, or upgrade any of the crypto dependencies in the skeleton. Version bumps are a post-skeleton concern.

The skeleton uses **no async runtime** at the cipherpost layer. `pkarr::ClientBlocking` wraps the async DHT client internally. This is the single most important stack decision and is inherited from cclink — it lets the CLI stay plain `fn main()` with synchronous calls and no `#[tokio::main]` contagion.

## Recommended Stack

### Core Technologies

Every version below is the exact pin used by cclink v1.3.0 as of this research date, except where called out. Deviating from these pins in the skeleton means re-doing integration work cclink has already done.

| Crate | Version | Purpose | Why recommended |
|-------|---------|---------|-----------------|
| `pkarr` | `5.0.3` (features: `dht`, `default-features = false`) | PKARR SignedPacket publish/resolve on Mainline DHT; provides `Keypair`, `PublicKey`, `SignedPacket`, `Client`, `ClientBlocking`, and re-exports `dns` | This is the reference PKARR implementation, maintained by the Pubky org. No competing Rust PKARR client exists at production quality. The `dht` feature gives Mainline transport; `no_relays()` at build time enforces the "no servers" constraint. |
| `ed25519-dalek` | `=3.0.0-pre.5` (exact pin) | Ed25519 signing and verification; `SigningKey::to_scalar_bytes()` for Ed25519→X25519 conversion | **Hard pin required.** `pkarr 5.0.3` depends on `ed25519-dalek ^3.0.0-pre.1`. No stable 3.x exists yet. `ed25519-dalek 2.2.0` (the current stable release) is API-incompatible with pkarr 5's needs. Until pkarr ships on stable ed25519-dalek 3.x, cipherpost inherits this pre-release pin. |
| `age` | `0.11` (resolves to `0.11.2`) | X25519 age encryption and decryption | Locked by PRD ("age (X25519, derived from Ed25519)"). The `age` crate is the official Rust implementation by str4d, the same author as the reference Go `age`. Stable for the skeleton's needs (encrypt-to-recipient, decrypt-with-identity). |
| `argon2` | `0.5` (resolves to `0.5.3`) | Argon2id password hashing for key-envelope and PIN derivation | Locked by PRD (Argon2id 64MB, 3 iter). `argon2 0.5.3` is the current stable, part of the RustCrypto password-hashes org. Parameters (`Algorithm::Argon2id, Version::V0x13, Params::new(65536, 3, 1, Some(32))`) are fixed by cclink and must not change. |
| `hkdf` | `0.12` | HKDF-SHA256 expand-step for key derivation | Locked by PRD (HKDF-SHA256 with domain separation). **Stay on 0.12 to match cclink.** `hkdf 0.13.0` is out (March 2026) but cclink has not upgraded and the skeleton should not fork-and-upgrade at the same time. Treat `hkdf 0.13` as a post-skeleton item. |
| `sha2` | `0.10` | SHA-256 backing for HKDF | Same reasoning as `hkdf`: cclink pins to `0.10`. `sha2 0.11.0` (March 2026) would require a coordinated upgrade with `hkdf 0.13`. Defer. |
| `clap` | `4.5` (features: `derive`) | CLI argument parsing with derive macros | Locked by PRD shape ("CLI binary"). Clap 4.x with the `derive` feature is the 2026 standard for Rust CLIs. `clap 4.6.1` is latest; `4.5` as specified is a caret requirement so cargo will resolve to the newest 4.x anyway. No reason to drop features or switch frameworks. |
| `serde` | `1.0` (features: `derive`) | Struct serialization derive support | Universal Rust serialization primitive. Derive feature is mandatory for payload structs. |
| `serde_json` | `1.0` | JSON serialization for on-wire payload and canonical-signing form | Rust standard. **Do NOT enable the `preserve_order` feature.** Canonical JSON is achieved by declaring struct fields in alphabetical order — serde serializes in declaration order, giving deterministic output without a separate canonicalization library. This is cclink's pattern and it works. |
| `base64` | `0.22` | Base64 encoding for signatures and age ciphertext in JSON payloads | Current stable (`0.22.1`). Use `base64::engine::general_purpose::STANDARD` — the engine-based API replaced top-level `encode`/`decode` in 0.21. |
| `bech32` | `0.9` | Bech32 encoding for age-format identity/recipient strings | cclink uses `0.9` with `Variant::Bech32`. Required because age's Rust API ingests age identity and recipient strings; we encode raw X25519 bytes into the `age-secret-key-` / `age` HRP to get them into age's type system. |
| `anyhow` | `1.0` | Error propagation in application code | Standard Rust CLI error-handling choice. Latest `1.0.102`. |
| `thiserror` | `2.0` | Custom error types with derive | Latest `2.0.18`. Use `thiserror` for crate-library errors (e.g., `CipherpostError::RecordNotFound`), `anyhow` for CLI-level glue. |
| `zeroize` | `1` (resolves to `1.8.2`) | `Zeroizing<T>` wrapper for secret material in memory | Non-negotiable. Every secret scalar, derived key, and passphrase-derived KEK in cclink is `Zeroizing<[u8; 32]>`. Cipherpost must do the same. |
| `rand` | `0.8` | Random salt generation via `rand::thread_rng().gen()` | **Stay on 0.8 to match cclink.** `rand 0.10.1` is out but brings API breakage (`gen()` → `random()`, etc.). Coordinated upgrade with dependent crypto crates is a post-skeleton task. |

### Supporting Libraries (inherited from cclink, review per-use-case)

Cipherpost v1.0 scope may not need all of these in the skeleton. Include them only when the skeleton actually exercises the corresponding functionality.

| Crate | Version | Purpose | When to include in skeleton |
|-------|---------|---------|-----------------------------|
| `dirs` | `5` | Locating `~/.pubky/` or equivalent config dir | YES — needed by `init` and by `receive` to find the identity file |
| `dialoguer` | `0.12` | Interactive passphrase prompts | YES — the skeleton needs a passphrase read on unlock |
| `owo-colors` | `4` (features: `supports-colors`) | Terminal colors that auto-disable when not a TTY | OPTIONAL — nice-to-have for skeleton, can defer |
| `backon` | `1.6` | Retry-with-backoff for DHT resolve | OPTIONAL — cclink uses it; skeleton can start without retries and add later |
| `comfy-table` | `7.2.2` | Pretty tables for `list` / `receipts` output | YES for `receipts` subcommand output — receipt verification should render clearly |
| `gethostname` | `0.5` | Hostname for the encrypted payload's metadata | PROBABLY NO — cclink used this for session-handoff context; cipherpost's payload is purpose-bound, not host-bound. Leave it out of the skeleton and re-evaluate at v1.0. |
| `arboard` | `3.6` | Clipboard access | NO — out of scope for the skeleton; cclink used it to copy session IDs |
| `qr2term` | `0.3` | Terminal QR codes for pubkey sharing | NO — nice future feature, not skeleton-critical |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `cargo-nextest` | Faster parallel test runner; better flaky-test reporting | Latest `0.9.133` (April 2026). Install via `cargo install cargo-nextest --locked`. Use for both unit and integration tests. Do NOT use as the only runner — `cargo test --doc` is still required for doctests; nextest doesn't run them. |
| `proptest` | Property-based testing for protocol roundtrips and tamper resistance | Latest `1.11.0` (March 2026). Dev-dependency only. Highest-value targets: canonical-JSON determinism, envelope encode/decode roundtrip, signature verify/tamper invariants. |
| `cargo-fuzz` + `libfuzzer-sys` | Fuzzing payload parsers and envelope decoders | `cargo-fuzz` `0.13.1` (June 2025). Skeleton should land at least two fuzz targets: (1) `decrypt_key_envelope` with random bytes (must not panic), (2) payload JSON deserializer (must not panic on arbitrary bytes). Low effort, high safety ceiling for crypto code. |
| `tempfile` | Dev-dependency for integration tests that need a temporary `~/.pubky`-style dir | `3.25.0` per cclink. Standard. |
| `cargo-deny` | Supply-chain / advisory / license gate in CI | Not in cclink Cargo.toml but cclink's release notes mention running it. Recommended for a security-positioned project. Configure with a `deny.toml`. |

## Installation

Skeleton `Cargo.toml` — exactly copies cclink's dependency section, trimming items the skeleton does not need and adding `proptest` for protocol invariants.

```toml
[package]
name = "cipherpost"
version = "0.1.0"
edition = "2021"
license = "MIT"

[[bin]]
name = "cipherpost"
path = "src/main.rs"

[dependencies]
pkarr = { version = "5.0.3", default-features = false, features = ["dht"] }
# pkarr 5.0.3 requires ed25519-dalek 3.x pre-release; no stable 3.x exists yet.
# This exact pin must remain until pkarr publishes a release depending on a stable ed25519-dalek 3.x.
ed25519-dalek = "=3.0.0-pre.5"
age = "0.11"
clap = { version = "4.5", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
thiserror = "2.0"
argon2 = "0.5"
hkdf = "0.12"
sha2 = "0.10"
base64 = "0.22"
bech32 = "0.9"
zeroize = "1"
rand = "0.8"
dirs = "5"
dialoguer = "0.12"

[dev-dependencies]
tempfile = "3.25.0"
proptest = "1.11"
```

Install the dev toolchain once:

```bash
cargo install cargo-nextest --locked
cargo install cargo-fuzz --locked
cargo install cargo-deny --locked
```

## Alternatives Considered

| Recommended | Alternative | When (or whether) to use alternative |
|-------------|-------------|--------------------------------------|
| `pkarr 5.0.3` | `pkarr 6.0.0-rc.0` (Feb 2026) | Not yet. 6.0.0-rc bumps `simple-dns` (which pkarr re-exposes), introducing a breaking change for SVCB handling. Cipherpost doesn't use SVCB, so the migration is probably mechanical, but doing it inside the skeleton compounds two migrations (cclink-fork + pkarr-upgrade). Defer to post-skeleton. |
| `pkarr 5.0.3` | Direct use of `mainline 6.1.1` without PKARR | No. PKARR is the actual protocol — SignedPacket verification, key-as-identity, DNS-record semantics — and reimplementing on top of raw Mainline is reinventing the wheel and forfeiting cclink's tested code. |
| `ed25519-dalek 3.0.0-pre.5` | `ed25519-dalek 2.2.0` (stable) | No. pkarr 5 requires 3.x. Downgrading breaks pkarr. Upgrading to `3.0.0-pre.6` is the first thing to try once cclink itself upgrades. |
| `age` crate | `rage` (the CLI frontend) | No. `rage` is a binary, not a library. Cipherpost uses the `age` library crate directly, same as cclink. `rage` would be a runtime dependency spawned as a subprocess — strictly worse. |
| Synchronous `pkarr::ClientBlocking` | Async `pkarr::Client` with `tokio 1.x` | **Skeleton: use blocking.** Async gets you nothing in a one-shot CLI that publishes or resolves one packet per invocation. Async cost: `#[tokio::main]`, `.await` contagion, and `tokio` in the dependency graph. If cipherpost later adds a persistent TUI with background refreshes, revisit — but even then, running the DHT client on a separate thread is likely simpler than going async-all-the-way. |
| Alphabetical-field canonical JSON (cclink pattern) | `serde_jcs 0.2.0` (RFC 8785 JSON Canonicalization Scheme) | **Defer.** `serde_jcs` is a real implementation and may be the right long-term answer. But cclink's alphabetical-order-in-struct-declaration trick works, is zero dependencies, and is what the existing code does. Adopting `serde_jcs` is a SPEC.md-level decision (it changes the canonical form and thus the signature), not a skeleton decision. Flag as an open question for SPEC.md review. |
| `thiserror 2.0` | `thiserror 1.x` | No reason. `2.0` is the current major and cclink uses it. |
| `clap 4.5/4.6` with derive | `clap` builder API | No. Derive is clearer and is what cclink uses. |
| `clap 4` | `structopt` | Deprecated — `structopt` was folded into `clap`'s derive feature. |
| `clap 4` | `argh`, `lexopt`, `bpaf` | Viable for smaller tools but cclink uses `clap`, so cipherpost matches for consistency. No upside to switching. |
| `proptest` | `quickcheck` | `proptest` is the current community standard: better shrinking, macro-based strategies, active maintenance (1.11.0 in March 2026). `quickcheck` is still maintained but older-style. |

## What NOT to Use

| Avoid | Why | Use instead |
|-------|-----|-------------|
| `tokio` as a top-level cipherpost dependency | Drags an async runtime into a one-shot CLI; forces `#[tokio::main]` and `.await`; tokio *will* still appear transitively (e.g., via `backon`, via pkarr's internal runtime) but it is not imported at the cipherpost layer and the cipherpost code stays synchronous | `pkarr::ClientBlocking` — this is specifically why it exists |
| `async-std` | Strictly worse than tokio for this use case, and the ecosystem has consolidated on tokio. Don't pick it for a fresh project in 2026 | n/a — don't go async at all in the skeleton |
| `reqwest`, `hyper`, or any HTTP client | There is no HTTP server and no relay. The only network egress is Mainline DHT via pkarr. Adding an HTTP client signals scope creep (relay-assist) that the PRD explicitly excludes from v1.0 | pkarr's built-in DHT client |
| `openssl` or `ring` | The crypto stack is locked: Ed25519 via `ed25519-dalek`, X25519+ChaCha via `age`, SHA-256 via `sha2`, Argon2id via `argon2`. Adding `openssl` or `ring` introduces a second crypto implementation and a new attack surface | The pinned RustCrypto-ecosystem crates |
| `serde_json` with `preserve_order` feature | Breaks cclink's alphabetical-field canonicalization trick — `preserve_order` uses insertion order from the input, not struct-declaration order | Plain `serde_json`, with struct fields declared alphabetically |
| `hex` crate for base64-ish encoding | cclink and the payload spec use base64 (STANDARD alphabet) for signatures and age ciphertext in JSON. Introducing `hex` alongside is noise and invites inconsistency | `base64 0.22` with `general_purpose::STANDARD` |
| `structopt` | Deprecated, folded into `clap` derive years ago | `clap 4` with `derive` |
| `rand 0.9` / `rand 0.10` in the skeleton | cclink is on `rand 0.8`. Mixing `0.8` and `0.10` types would be a compile-time mess (traits like `Rng::gen` vs `random`). Upgrade once, post-skeleton, across the whole tree | `rand = "0.8"` to match |
| `hkdf 0.13` / `sha2 0.11` in the skeleton | Same reasoning — coordinated crypto-crate upgrade is a separate piece of work from forking cclink | `hkdf = "0.12"`, `sha2 = "0.10"` to match cclink |
| `tracing` or `log` | Not in cclink's current graph for the core paths. Adding logging to crypto code risks leaking secrets into logs and is easy to get wrong. Defer | `eprintln!` for user-facing errors; `thiserror` for structured errors in library code |
| `envelope` / `envlp` / any generic framing crate | The CCLINKEK envelope is a bespoke fixed-header format (53 bytes: magic + version + m_cost + t_cost + p_cost + salt, then age ciphertext). Don't generalize what's already simple and tested | Copy cclink's `encrypt_key_envelope` / `decrypt_key_envelope` verbatim; rename the magic to `CPOSTKEK` or similar when the time is right (flag as open question — name change may be reasonable for spec hygiene) |

## Stack Patterns by Variant

**If the skeleton keeps cclink's layout (default):**
- Single crate, binary target only, no library target exposed externally
- Modules: `src/{crypto,keys,record,transport,error}.rs` plus `src/commands/` for subcommands
- No workspace, no shared-core crate
- Rationale: matches PROJECT.md's "fork-and-diverge from cclink, no shared core crate" decision; simpler than workspace plumbing for a single binary

**If a `cipherpost-core` library is extracted later (post-skeleton):**
- Cargo workspace with `cipherpost-core/` (library) and `cipherpost/` (binary)
- `cipherpost-core` owns crypto, transport, record, error
- `cipherpost` owns CLI, commands, user I/O
- Rationale: makes the crypto/protocol code reusable by a future TUI or by third parties without forcing them to depend on `clap`/`dialoguer`. But this is premature during the skeleton — do not workspace-ify for no reason.

**If async is later required (post-skeleton, probably not needed):**
- Still do not add `#[tokio::main]` to `main.rs`
- Instead, spin up a tokio runtime inside the DHT client layer and keep the async boundary contained
- Rationale: keeps CLI logic synchronous and testable; limits async contagion to one file

## Version Compatibility

| Package A | Compatible with | Notes |
|-----------|-----------------|-------|
| `pkarr 5.0.3` | `ed25519-dalek =3.0.0-pre.5` | Hard requirement. The exact-pin is needed because pkarr's Cargo.toml specifies `^3.0.0-pre.1` and cargo's pre-release resolution won't pick a newer pre-release without an explicit pin. cclink's `Cargo.toml` comments this pin. Keep the comment. |
| `pkarr 5.0.3` | Two versions of `curve25519-dalek` in the tree (v4 via `age`, v5 via `pkarr`) | Normal. Cargo allows multiple major versions of the same crate in the dependency graph. **Critical consequence:** you cannot pass `curve25519-dalek` types across the age↔pkarr boundary — they are different types. Always convert to raw `[u8; 32]` first. This is why `crypto::mod` uses `to_bytes()` and `from_bytes()` everywhere instead of passing `MontgomeryPoint` around. Preserve that pattern. |
| `age 0.11` | `pkarr 5.0.3` (via raw bytes only) | Works exclusively through the `[u8; 32]` boundary documented in cclink's `crypto::mod`. Any attempt to share curve25519-dalek types across age and pkarr will fail to compile. |
| `hkdf 0.12` | `sha2 0.10` | Match. `hkdf 0.13` wants `sha2 0.11`. Upgrading requires both together. |
| `argon2 0.5.3` | `password-hash 0.5` / `base64ct` (transitive) | Stable. No known compatibility issues. |
| `clap 4.5` | `rustc 1.85+` | Clap 4.6.1 (and 4.5 with current minor resolver behavior) requires Rust 1.85. Confirm CI uses a recent enough toolchain. |
| `ed25519-dalek =3.0.0-pre.5` | `signature` crate (transitive) | Stable. cclink uses `Signature::from_bytes(&[u8; 64])` which is part of the pre-release API. Don't reach for anything fancier. |

## Async Runtime Decision

**Answer: synchronous skeleton. Use `pkarr::ClientBlocking`. Do NOT add `tokio` as a direct cipherpost dependency.**

Rationale:
- Cipherpost is a one-shot CLI. Each invocation does at most one DHT publish or one DHT resolve + one decrypt. There is no long-lived event loop, no concurrent I/O, no server.
- `pkarr::ClientBlocking` is explicitly designed for this — it wraps the async `Client` with its own internal runtime so callers stay synchronous.
- cclink has validated this pattern in production (v1.3.0). Copying it in means zero risk of async-related bugs.
- `tokio` will still appear in the dependency graph transitively (pkarr's internal runtime, possibly via `backon`), but it is not in cipherpost's `main.rs` and is not required for integration tests.
- Post-skeleton, if cipherpost grows a TUI that needs background DHT refresh, the boundary can be moved — but that decision is pulled out of scope for the walking skeleton.

**Flag:** confirm this decision with the user if a TUI is later prioritized. The PRD defers TUI entirely ("skeleton is CLI-only"), so this is safe for the current milestone.

## What to Vendor From cclink (Summary of cclink source layout)

cclink v1.3.0's `src/` layout (all modules are module directories with `mod.rs`, except `cli.rs`, `error.rs`, `util.rs`, `lib.rs`, `main.rs`):

```
src/
├── main.rs            -> thin wrapper, parses CLI and dispatches
├── lib.rs             -> library entry exposing public modules
├── cli.rs             -> clap derive structs and subcommand enum
├── error.rs           -> thiserror CclinkError enum
├── util.rs            -> small helpers
├── crypto/mod.rs      -> ✅ VENDOR: Ed25519↔X25519 conversion, age encrypt/decrypt, Argon2id+HKDF key/PIN derivation, CCLINKEK envelope encode/decode
├── keys/
│   ├── mod.rs         -> ✅ VENDOR: identity load/save with passphrase unwrap
│   ├── store.rs       -> ✅ VENDOR: atomic 0600 write, key_dir resolution (rename CCLINKEK→CPOSTKEK, ~/.pubky→~/.cipherpost or similar)
│   └── fingerprint.rs -> ✅ VENDOR: pubkey display helpers (z32, fingerprint truncation)
├── record/mod.rs      -> 🔶 ADAPT: HandoffRecord+HandoffRecordSignable+canonical_json+sign_record+verify_record is the right shape, but the struct's fields are cclink-specific (hostname, project, session_id). Replace with cipherpost's payload schema (generic-secret blob, purpose, terms, recipient, TTL, dual-signature setup). Keep the canonical-JSON trick (alphabetical fields, declaration-order serialization).
├── transport/mod.rs   -> ✅ VENDOR: DhtClient wrapping pkarr::ClientBlocking, publish/resolve/revoke over PKARR SignedPacket with TXT record containing JSON. Change the DNS label from `_cclink` to `_cipherpost` (or spec-decided name).
├── session/mod.rs     -> ❌ DISCARD: cclink-specific session-ID handling; cipherpost has no analog
└── commands/          -> ❌ DISCARD AND REWRITE: subcommand handlers are cclink-shaped (init/publish/pickup/revoke/list/whoami). Cipherpost subcommands are different: init, send (--self | --share <pubkey>), receive, receipts. Rewrite but keep the pattern (one file per subcommand, minimal, delegates to lib modules).
```

**Reusable tests from cclink:**
- `tests/integration_round_trip.rs` — ✅ VENDOR the patterns (self-encrypt, shared-encrypt, tamper detection). The test harness (fixed keypairs from `[42u8; 32]` and `[99u8; 32]`, fixed_keypair() helpers) transfers directly.
- `tests/plaintext_leak.rs` — ✅ VENDOR. This is exactly the kind of test cipherpost needs: a greppable invariant that encrypted payloads never appear as plaintext anywhere on the wire.

**What the skeleton adds on top (new to cipherpost):**
- Typed payload schema with `generic-secret` implemented (cert/PGP/SSH fields reserved in the enum but not parsed)
- `purpose` binding field (free-text, signed into the envelope)
- Pickup-time explicit acceptance step (CLI prompt before the inner material is revealed)
- Signed receipt: a second `HandoffRecord`-shaped object the recipient publishes back, referencing the original by some identifier (pubkey+timestamp or hash)
- `cipherpost receipts` subcommand to fetch and verify receipts the sender expects

## Sources

- **cclink source of truth** — https://github.com/johnzilla/cclink — read directly via `gh api`: `Cargo.toml`, `Cargo.lock`, `src/crypto/mod.rs`, `src/transport/mod.rs`, `src/record/mod.rs`, `src/keys/store.rs`, `tests/integration_round_trip.rs`, `README.md`. Confidence: HIGH (read the actual files).
- **pkarr crates.io metadata** — https://crates.io/api/v1/crates/pkarr — verified `5.0.4` stable, `6.0.0-rc.0` pre-release. Confidence: HIGH.
- **pkarr 5.0.4 docs** — https://docs.rs/pkarr/5.0.4/pkarr/ — verified public API: `Keypair`, `PublicKey`, `SignedPacket`, `Client`, `ClientBlocking`. Confirmed `ed25519-dalek` is a normal dependency, not re-exported. Confidence: HIGH.
- **mainline crates.io metadata** — https://crates.io/api/v1/crates/mainline — verified `6.1.1` stable. Confidence: HIGH (not a direct cipherpost dep; pkarr uses it transitively).
- **ed25519-dalek crates.io metadata** — verified `2.2.0` stable, `3.0.0-pre.6` latest pre-release (Feb 2026). Confidence: HIGH.
- **age crates.io metadata** — verified `0.11.2` latest stable. Confidence: HIGH.
- **pkarr GitHub releases** — https://github.com/pubky/pkarr/releases — summary of 5.0.4 (relay endpoint change, security advisories) and 6.0.0-rc.0 (simple-dns SVCB breaking change). Confidence: MEDIUM (release notes are terse).
- **Every other version number** (clap 4.6.1, argon2 0.5.3, hkdf 0.13.0, sha2 0.11.0, zeroize 1.8.2, rand 0.10.1, thiserror 2.0.18, anyhow 1.0.102, proptest 1.11.0, cargo-nextest 0.9.133, cargo-fuzz 0.13.1, base64 0.22.1) — crates.io API, verified on 2026-04-20. Confidence: HIGH.
- **serde_jcs** — https://crates.io/api/v1/crates/serde_jcs — verified `0.2.0` (March 2026). Confidence: MEDIUM (noted as an alternative, not adopted).

---
*Stack research for: Cipherpost Rust CLI — walking-skeleton milestone*
*Researched: 2026-04-20*
