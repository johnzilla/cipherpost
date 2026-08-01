# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

**v1.1 (full PRD v1) shipped 2026-04-26; repo is now at crate `2.0.0-alpha.1` with (a) v2 derived-key addressing — `PROTOCOL_VERSION = 2`, each share/receipt under its own key `derive(parent_pub, share_ref)` (SPEC.md §3.8) — and (b) an experimental, off-by-default `large-payload` feature.** (v1.0 walking skeleton shipped 2026-04-22.) **v2 is a clean break from v1.1:** the 1→2 bump changed every record's signed bytes and retired the "v1.0 byte-identity" lock-in; the derived-key redesign lifted the one-record-per-key packet-budget ceiling and re-enabled self-receipts. The repo is a single Rust crate (`cipherpost`) that builds a CLI binary. MIT-licensed. No shared `cipherpost-core` crate — that was considered and explicitly rejected at project kickoff (cclink is mothballed, no second consumer exists to justify the split).

Build / test / lint commands:

```bash
cargo build --release                  # release binary: ./target/release/cipherpost
cargo test                             # unit + doc tests (no DHT-touching tests)
cargo test --features mock             # + MockTransport integration tests (--all-features adds feature-gated suites)
cargo nextest run --all-features       # CI's runner (nextest); doctests run separately via `cargo test --doc`
cargo fmt --check                      # CI-enforced
cargo clippy -- -D warnings            # CI-enforced
cargo audit                            # CI-enforced (deny.toml policy)
cargo deny check                       # CI-enforced supply-chain policy
```

CI runs all of the above plus `lychee` link-check across `SPEC.md`, `THREAT-MODEL.md`, `SECURITY.md`, and `README.md`. The binary is a plain `fn main()` — there is no `tokio` dependency at the cipherpost layer (uses `pkarr::ClientBlocking`).

**Do not hardcode test counts in prose** (CLAUDE.md, FAQ, READMEs). They rot within days of every change and have been wrong three times; run the command for the current number instead of writing it down.

**MSRV: rust 1.88** (matched by `rust-toolchain.toml` and `.github/workflows/ci.yml`). Bumped from 1.85 at v1.1 close to resolve RUSTSEC-2026-0009 (`time 0.3.41` → `0.3.47` DoS-via-stack-exhaustion fix), which required rustc 1.88. Cipherpost is a binary CLI — MSRV constraints from downstream library consumers do not apply.

**Pre-push hook.** Every clone runs the full CI gauntlet locally before a push reaches GitHub via `bash scripts/setup-hooks.sh` (one-time per clone). The hook lives at `.githooks/pre-push` and mirrors `.github/workflows/ci.yml` job-for-job. GitHub Actions minutes are not free; this hook keeps them spent only on green builds. Escape hatches: `git push --no-verify` for the whole hook, or `CIPHERPOST_SKIP_NEXTEST=1 git push` for individual gates.

## What Cipherpost is

A self-sovereign, serverless, accountless CLI for handing off cryptographic material (private keys, certs, credentials, API tokens, passphrases) between parties. Positioned in the whitespace between generic secret-sharing apps (Bitwarden Send, 1Password Sharing, SendSafely) and enterprise KMS platforms. The defensible combination is: **no server + accountless + attestation primitives + purpose-built for cryptographic material**.

## Architectural lineage: fork-and-diverge from cclink

**Read this before making any design decisions.** Cipherpost is not a new protocol — it was vendored from [`cclink`](https://github.com/johnzilla/cclink) (now mothballed) and specialized for keyshare workflows. The crypto and transport primitives were reused unchanged:

- **Identity:** Ed25519/PKARR keypair, passphrase-wrapped on disk (Argon2id 64MB, 3 iter + HKDF-SHA256 with domain separation)
- **Transport:** Mainline DHT via PKARR SignedPacket — no servers, no operator
- **Encryption:** age (X25519, derived from Ed25519). `chacha20poly1305` is only reachable via `age`; no direct calls anywhere in `src/`.
- **Signing:** Dual signatures (outer PKARR packet + inner Ed25519 over canonical JSON)

The delta from cclink (v1.0 walking skeleton + v1.1 full PRD v1):

1. Typed payload schema — `Envelope { protocol_version, created_at, ttl_seconds, purpose, material }`. All four `Material` variants — `GenericSecret`, `X509Cert`, `PgpKey`, `SshKey` — are implemented (typed variants shipped v1.1). A fifth, `LargePayload`, is behind the off-by-default `large-payload` feature (v2-alpha). Realistic typed inputs often exceed the 1000-byte wire budget and surface `WireBudgetExceeded` cleanly.
2. Explicit acceptance step — recipient sees a full-fingerprint acceptance screen on stderr and must type the sender's z-base-32 pubkey to unlock decrypt.
3. Signed receipt — recipient-signed `Receipt` published (v2) under the recipient's **derived key** `derive(recipient_pub, share_ref)` at fixed DNS label `_cprcpt`, a single-writer single-record packet (no merge, no CAS). Fetched + verified by the sender via `cipherpost receipts --from <z32> --share-ref <ref>` (v2: `--share-ref` REQUIRED — receipts are addressed per-share, not enumerable). The recipient pubkey is passed to `verify_receipt` as context, not read from the slim receipt. (v1.1 used `_cprcpt-<share_ref>` on the recipient's bare key via resolve-merge-republish; superseded by §3.8.)
4. CLI surface focused on key/secret handoff (`send --self | --share`, `receive`, `receipts`, `identity generate/show`, `version`).

**Repo layout (locked):** Fully independent, fork-and-diverge. No shared `cipherpost-core` crate — will only be extracted if a second consumer appears.

## Principles that constrain design

These are hard constraints from the PRD, not suggestions. Reject approaches that violate them:

1. **No servers.** Rendezvous is Mainline DHT only. Any proposal that introduces an operator (even an optional one) is out of scope. Relay-assist is explicitly flagged as a *possible later commercial feature*, not an open-source-core option.
2. **Key is identity.** No accounts, no email verification, no logins.
3. **Ciphertext only on the wire.** Both payload and metadata are encrypted; the DHT sees only opaque blobs.
4. **Attestation first-class.** Signed receipt (shipped) and purpose binding are core features, not afterthoughts. Destruction attestation is still deferred (never implemented).
5. **Ship narrow.** Primitive first, workflows second. Enterprise features only if demand is proven.

## Shipped vs deferred

**Shipped in v1.0 (walking skeleton, 2026-04-22):**
- `cipherpost send --self` and `cipherpost send --share <pubkey>` (generic-secret payloads)
- `cipherpost receive` with dual-signature verify → TTL → typed-z32 acceptance → decrypt → state-ledger idempotency
- `cipherpost receipts --from <z32> [--share-ref | --json]`
- `cipherpost identity generate/show` (TTY double-confirm on generate; mode-0600 enforcement)
- `cipherpost version` (crate version + embedded git SHA + crypto primitives list)
- 64 KB plaintext cap, 24-hour default TTL, `-` stdin/stdout, exit-code taxonomy {0, 2, 3, 4, 5, 6, 7, 1}
- Draft `SPEC.md`, `THREAT-MODEL.md`, `SECURITY.md` at repo root; `lychee` link-check CI

**Shipped in v1.1 (full PRD v1, 2026-04-26):**
- `--pin` and `--burn` encryption modes
- All four `Material` variants: `GenericSecret`, `X509Cert`, `PgpKey`, `SshKey` (realistic typed inputs may exceed the 1000-byte wire budget → clean `WireBudgetExceeded`)
- Non-interactive passphrase automation (`CIPHERPOST_PASSPHRASE` / `--passphrase-file` / `--passphrase-fd`)
- CAS-protected receipt publication (single-retry merge-republish) — *superseded in v2 by single-writer derived-key receipts; now legacy, see below*
- Real-DHT cross-identity release-acceptance test (`tests/real_dht_e2e.rs`; manual + tag-gated, never per-commit CI)

**Shipped in v2 (derived-key addressing; `PROTOCOL_VERSION = 2`, crate `2.0.0-alpha.1`):**
- Each share and each receipt published under its own key `derive(parent_pub, share_ref)` — single-hop stealth blinding, `DERIVE_DOMAIN = "cipherpost/v2/derive-addr"`, hashing the RAW 16 bytes of the `share_ref` (SPEC.md §3.8; `src/derive.rs`, `src/transport.rs::build_derived_signed_packet`). Lifts the v1.1 one-record-per-key packet-budget ceiling: many outstanding shares/receipts per identity.
- Slim receipt schema `{accepted_at, ciphertext_hash, cleartext_hash, protocol_version, share_ref, signature}` — dropped `nonce` + both pubkeys; `verify_receipt(receipt, recipient_pub_z32)` takes the recipient pubkey as context. `receipts` now REQUIRES `--share-ref` (per-share, non-enumerable).
- Self-receipts RE-ENABLED (D-SEQ-06); the receipt no longer collides with the sender's outgoing share.

**Shipped in v2-alpha (experimental, off-by-default `large-payload` feature; crate `2.0.0-alpha.1`):**
- `send-large --self` / `receive-large` — manifest-on-DHT + ciphertext blob on a self-hosted pubky homeserver (`CIPHERPOST_HS` required, no default). `--self` only; large-payload receipts not wired.
- Hardening since v1.1: `Error::PacketBudgetExceeded` (single oversized record on the send path), receipt `purpose` removed from the DHT (privacy), `CIPHERPOST_HS` required, `--dht-timeout` wired, homeserver-client timeouts, opportunistic lock-dir GC. (The v2-alpha "self-receipts skipped" stopgap was superseded when derived-key addressing re-enabled them.)

**Deferred:**
- Cross-identity `--share` for large payloads; large-payload signed receipts
- TUI wizard; exportable audit log for compliance evidence; destruction attestation workflow; multi-recipient broadcast shares; HSM sender-side generation; identity import

**Never (per PRD non-goals):**
- Full key lifecycle management (that's a KMS) · long-term secret storage (that's a vault) · signing or crypto operations on behalf of users · incident response / CVE tracking · general file transfer · SSO / IdP federation / SIEM export · web UI

## Load-bearing lock-ins (from `research/PITFALLS.md`, enforced in code + tests)

Breaking any of these requires a protocol version bump. Don't touch without understanding why:

- Canonical JSON = **RFC 8785 (JCS) via `serde_canonical_json`** (shipped as 1.0.0 — API-compatible with the planned 0.2). `serde_json` alone is **not** canonical. Fixtures (all encode `protocol_version: 2` under v2): `tests/fixtures/outer_record_signable.bin` (192 B), `tests/fixtures/receipt_signable.bin` (**263 B** — v2 slim schema; was 389 B in v1.x after `purpose` removal, dropped further when `nonce` + both pubkeys were removed at v2). Regenerate the receipt fixture via `phase3_receipt_canonical_form --ignored regenerate_fixture` and re-run `gen_spec_test_vectors` for the SPEC §8 sigs; the `PROTOCOL_VERSION` 1→2 bump also regenerated the 5 Envelope fixtures + both outer-record fixtures (they carry the const). Property tests enforce byte-for-byte determinism.
- HKDF info strings = **`cipherpost/v1/<context>`**. Never empty, never `None`. An enumeration test walks every HKDF call-site and asserts the prefix. Phase 8 added `cipherpost/v1/pin` to the enumeration; the PIN-derived 32-byte X25519 scalar is wrapped into an `age::x25519::Identity` for nested encryption — `chacha20poly1305 only via age` invariant unchanged.
- Argon2id params live in the **identity file header (PHC string)** — never hardcoded in code.
- `chacha20poly1305` usage only via `age` — no direct calls allowed.
- Every key-holding struct uses `Zeroize` / `secrecy::SecretBox`. **No `#[derive(Debug)]` on secret holders.** A leak-scan test enumerates keyed structs and asserts `format!("{:?}", x)` never contains key bytes.
- Dual-signature verification: **outer PKARR sig before age-decrypt; inner Ed25519 sig gates every surfaced field.** No envelope field (including `purpose`) may reach stdout/stderr before inner-sig verify passes.
- Signed receipt published **only after** full verification + typed-z32 acceptance. Byte-flipping between outer verify and acceptance must publish zero receipts (SC1 integration test).
- Identity path = `~/.cipherpost/` (mode 0600). `CIPHERPOST_HOME` overrides for tests.
- Default TTL = **24 hours** (PRD's 4h was revised after DHT-latency research showed Mainline DHT p50 lookup ≈ 1 minute with a long tail).
- Async runtime: **none at the cipherpost layer.** Use `pkarr::ClientBlocking`; no direct `tokio` dep.
- `ed25519-dalek =3.0.0-pre.5` exact pin is load-bearing (pkarr 5.0.3/5.0.4 depends on `^3.0.0-pre.1`; no stable 3.x exists yet).
- `~/.cipherpost/state/accepted.jsonl` rows carry an optional `state: "accepted"|"burned"` field (Phase 8 D-P8-10); v1.0 rows missing the field deserialize via serde default to `accepted` and map CONSERVATIVELY to `LedgerState::Accepted` on read (T-08-17 — never silently classify Accepted as Burned). Burn rows write `state: "burned"`. Schema migration is wire-format-additive — v1.0 receivers parse v1.1 rows by ignoring the new field. `check_already_consumed()` returns `LedgerState { None, Accepted, Burned }`; both call sites in `src/flow.rs::run_receive` and the `main.rs` Send-dispatch idempotency check pattern-match exhaustively. Tests: `tests/state_ledger.rs` walks the schema migration paths.
- Error-oracle hygiene: all signature-verification errors (`Error::SignatureOuter`, `SignatureInner`, `SignatureCanonicalMismatch`) share one identical user-facing Display + exit code 3. A test enumerates variants and asserts identical messages.
- **Burn write order is emit-before-mark** (Phase 8 D-P8-12), inverting v1.0's accepted-then-mark ordering for burn shares ONLY. Sequence: emit decrypted bytes to stdout/file → create sentinel → append ledger row with `state: "burned"`. Crash between emit and ledger-write leaves the share re-receivable — the safer failure mode (the user keeps access to their data) compared to mark-then-emit, which would lose user data to a half-completed state write. v1.0 accepted-flow ordering is UNCHANGED (idempotent persistence; re-emit on crash is fine). Tests: `tests/burn_roundtrip.rs` + `tests/pin_burn_compose.rs` enforce; `.planning/research/PITFALLS.md` #26 carries the SUPERSEDED-by-D-P8-12 header preserving the rejected mark-then-emit alternative.
- `share_ref` = 128-bit; derived as `sha256(ciphertext || created_at_be).truncate(16)`. Hex-encoded on the wire.
- Passphrase contract: argv-inline (`--passphrase <value>`) is rejected. Use `CIPHERPOST_PASSPHRASE` env, `--passphrase-file <path>` (mode 0600/0400), or `--passphrase-fd <fd>`.
- `serial_test = "3"` + `#[serial]` on any test that mutates process env (`CIPHERPOST_HOME`, etc.) — nextest parallel runner will race otherwise.
- **v2 derived-key addressing (`PROTOCOL_VERSION = 2`).** `A' = A + t·G` where `t = reduce_mod_ℓ(SHA-512(DERIVE_DOMAIN ‖ A ‖ raw16(share_ref)))`, `DERIVE_DOMAIN = "cipherpost/v2/derive-addr"` (nonce-prefix domain `"cipherpost/v2/derive-prefix"`). **Frozen contract: hash the RAW 16 bytes decoded from the hex `share_ref`, never the 32 ASCII-hex chars** (hashing hex → valid-signing but unresolvable silent-`NotFound`). pkarr can't sign under a blinded seed-only key, so packets are hand-signed: BEP44 `signable(ts,v)` → `hazmat::raw_sign::<Sha512>({scalar: a', hash_prefix: prefix'}, .., &A')` → **self-verify** → `SignedPacket::from_relay_payload`. Inner Ed25519 sig is still by the parent IDENTITY key; only the outer BEP44 packet uses `A'`. Golden vector: `src/derive.rs::golden_vector_seed7_ref11` (seed `[7;32]`, ref `[0x11;16]` → `A' = 5af3abc0…155f5`); SPEC.md §3.8 + §8.4. Shared `src/derive.rs` code path for public + secret derivation (mock parity).
- **The v1.1 parent-key Transport surface + CAS machinery were REMOVED at v2.** Gone: `Transport::publish` / `resolve` / `publish_receipt` / `resolve_all_cprcpt`, `merge_republish`, per-key `seq` CAS, `CasConflict` (was single-retry-then-fail, no public `Error::CasConflict` per Pitfall #16). The trait is now derived-only — `publish_derived` / `resolve_derived` (single-writer, single-record, **no CAS**). Deleted with it: `tests/cas_racer.rs`, `tests/mock_transport_roundtrip.rs`, `tests/phase3_mock_publish_receipt_coexistence.rs` (they tested the removed path; v2 equivalents live in `src/transport.rs::derived_tests` + `tests/phase3_coexistence_b_self_share_and_receipt.rs`). `tests/real_dht_e2e.rs` was ported to a derived-key round trip. `MockTransport` is now a plain `HashMap<derived_z32, Vec<(label, rdata)>>`. `DHT_LABEL_RECEIPT_PREFIX` (`_cprcpt-`) stays as a documented v1.1-legacy const.
- No `CIPHERPOST_DHT_BOOTSTRAP` env var in v1.1 — pkarr defaults only (4 Mainline hosts: `router.bittorrent.com:6881`, `dht.transmissionbt.com:6881`, `dht.libtorrent.org:25401`, `relay.pkarr.org:6881`). `pkarr::ClientBuilder::bootstrap` exists (verified `pkarr-5.0.4/src/client/builder.rs:164`) but is intentionally NOT exercised; revisiting requires a future milestone gate.
- Real-DHT tests behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`; CI never runs `--features real-dht-e2e`. The test file is `tests/real_dht_e2e.rs` (single test, single file per Pitfall #29). Outer guard via `.config/nextest.toml` `slow-timeout = { period = "60s", terminate-after = 2 }` paired with an in-test `Instant::now() >= deadline` check at 120s. RELEASE-CHECKLIST.md manual invocation is the only gate (D-P9-D2). Stable cargo has no `--test-timeout` flag — use `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)'`.

## Planning workflow (GSD abandoned)

This project **no longer uses** Get Shit Done (GSD). The `.planning/` directory is
**stale** — treat it as a historical archive, not current state, and do **not** run any
`/gsd-*` commands. The `milestones/` and `.planning/research/` trees remain useful only
as reference for the v1.0/v1.1 decisions they captured (some load-bearing lock-ins above
still cite `research/PITFALLS.md`; those invariants are enforced in **code + tests**, which
are the real source of truth). Current work is tracked ad hoc — reviewer findings verified
then fixed, atomic commits straight to `main`.

**Exception — `MILESTONES.md` is a LIVING doc at repo root** (moved out of `.planning/` so
the frozen-archive rule doesn't contradict RELEASE-CHECKLIST.md's "update MILESTONES.md" gate).
It is the per-release close log and IS appended at each release. Everything else under
`.planning/` stays frozen; the older `.planning/*` docs still reference MILESTONES.md at its
former path — those are historical and not maintained.
