# Project Research Summary — Cipherpost

**Domain:** Rust CLI — self-sovereign cryptographic-material handoff (Mainline DHT + PKARR + age + Ed25519)
**Milestone:** Walking skeleton (self + share + signed receipt on generic-secret payloads, CLI only)
**Confidence:** HIGH on stack and architecture; MEDIUM-HIGH on features and pitfalls

## Executive Summary

Cipherpost's skeleton is a **fork-and-diverge from cclink** (mothballed, github.com/johnzilla/cclink). The crypto, transport, identity, and record layers are already implemented and tested in cclink v1.3.0 — they get vendored in verbatim with cosmetic renames (envelope magic `CCLINKEK` → `CIPHPOSK`, TXT label `_cclink` → `_cipherpost`, path `~/.pubky` → `~/.cipherpost`, HKDF info strings domain-separated to `cipherpost/v1/...`). The **cipherpost delta** is three new modules on top: a typed payload `Envelope` (generic-secret only for skeleton), a `Receipt` struct published under the *recipient's* PKARR key at label `_cprcpt-<share_ref>`, and a `flow/` orchestration layer that owns the explicit acceptance step and TTL enforcement. Total skeleton estimate: **~7 working days** if dep pins hold (they should — cclink validates them).

The **biggest lock-in risk** is not "which crate" — every stack decision is dictated by cclink's `Cargo.lock` (pkarr 5.0.3, ed25519-dalek =3.0.0-pre.5 exact pin, age 0.11, no direct tokio). The biggest risk is the **protocol surface landed wrong in skeleton becomes unfixable later**. PITFALLS identifies **15 of 18 pitfalls that MUST be addressed in skeleton** because they're lock-in: canonical JSON scheme, HKDF info strings, inner-timestamp for replay protection, receipt-after-verify order, share_ref derivation, Argon2 params-in-header, identity file permissions, and the dual-signature verification invariants. Every one of these changes the wire format or the signed payload; "fix it in v1.0" means every v0 share ever issued becomes unverifiable.

Two meaningful contradictions between the research files require user decision: (1) **TTL default** — PRD/PROJECT.md specify 4h, PITFALLS recommends 24h based on Mainline DHT latency (~1min median, nontrivial NAT failure rates); (2) **canonical JSON scheme** — STACK recommends cclink's alphabetical-field-declaration trick (zero-dep, works, matches vendored code), PITFALLS recommends RFC 8785 / `serde_canonical_json` (interop, cross-platform stability). Both flagged for decision before the skeleton's first signature is produced.

## Key Findings

### Recommended Stack (summary of STACK.md)

**cclink's stack, pin-for-pin** — do not substitute, upgrade, or reorder any crypto dep during skeleton. Version bumps (hkdf 0.13 / sha2 0.11 / rand 0.10 / pkarr 6.0.0-rc) are explicitly post-skeleton.

Core: `pkarr` 5.0.3, `ed25519-dalek` `=3.0.0-pre.5` (exact pin — non-negotiable), `age` 0.11, `argon2` 0.5 (64MB/3iter PRD-locked, params in file header), `hkdf` 0.12 + `sha2` 0.10 (versioned domain-separated info strings `cipherpost/v1/<context>`), `clap` 4.5 derive, `zeroize` 1 (**ban `#[derive(Debug)]` on key-holding structs**), `dialoguer` 0.12 (behind a `Prompter` trait), `serde_json` 1.0 **without `preserve_order`** (would break canonicalization), `base64` 0.22, `bech32` 0.9, `anyhow` 1.0, `thiserror` 2.0, `dirs` 5.

**Async:** None at cipherpost layer. Use `pkarr::ClientBlocking`; `main.rs` stays plain `fn main()`. No direct `tokio` dep.

**Dev tooling:** `cargo-nextest`, `proptest` (canonical-JSON / tamper invariants), `cargo-fuzz` (skeleton ships 2 targets: `decrypt_key_envelope`, payload JSON deserializer), `cargo-audit` + `cargo-deny` in CI from day one (`cargo-vet` + sigstore = v1.0).

### Expected Features (summary of FEATURES.md)

Benchmarked against Bitwarden Send, 1Password Sharing, SendSafely, Tresorit Send, crypt.fyi, FileKey, Keybase, and the real incumbent — **PGP over email**. The defensible intersection (no-server + accountless + signed receipt + purpose binding + acceptance step + typed payload + CLI-first) is hit by no competitor; every one hits at most three of those simultaneously.

**Must have (table stakes for skeleton):** T1 clear expired/invalid errors, T2 visible full sender fingerprint, T4 stdin/stdout `-` convention, T5 `-o/--output`, T6 TTY passphrase prompt, T8 meaningful exit codes, T9 `--help` with examples, T10 DHT progress to stderr, T13 expiration in local + UTC, T14 single-pickup retire, T17 accept-step shows all binding metadata, T18 fatal sig-verify failure, T19 `cipherpost version` with crypto primitives.

**Differentiators:** D1 no operator, D2 accountless, **D3 signed receipt on DHT (the cipherpost delta)**, D4 purpose binding (sender-attested), D5 explicit acceptance step, D6 ciphertext-only on wire, D7 typed payload schema.

**Defer to v1.0:** `--pin` / `--burn`, TUI, X.509/PGP/SSH payloads, non-interactive batch (T7), idempotent re-receive (T11), shell completion (T20), audit log.

### Architecture Approach (summary of ARCHITECTURE.md)

Single crate, binary target + `lib.rs` for integration-test re-exports. **Four vendored directories** (`crypto/`, `transport/`, `record/`, `identity/`) + **three greenfield** (`payload/`, `receipt/`, `flow/`). Visible boundary makes future cclink bug-syncs mechanical.

**Major components:**
1. **`crypto/`** (vendored) — Ed25519↔X25519, age, Argon2id+HKDF. Pure functions; raw `[u8;32]` at API boundary because `age` and `pkarr` pull two major versions of `curve25519-dalek`.
2. **`transport/`** (vendored + extended) — `DhtClient` wraps `pkarr::ClientBlocking`. **Only architectural delta from cclink:** a `Transport` trait so tests can inject `MockTransport`. Extension: `publish_receipt` merges TXT into recipient's existing SignedPacket.
3. **`record/`** (vendored + generalized) — `OuterRecord`/`OuterRecordSignable`. Drop cclink's `hostname`/`project`; add `share_ref`.
4. **`identity/`** (vendored) — `~/.cipherpost/secret_key`, **Argon2 params in file header** per Pitfall 8.
5. **`payload/`** (NEW) — `Envelope` + `Material` enum (only `GenericSecret` implemented). Canonical JSON + 64KB cap.
6. **`receipt/`** (NEW) — `Receipt { share_ref, sender_pubkey, recipient_pubkey, accepted_at, nonce, signature }` published under **recipient's** PKARR key at `_cprcpt-<share_ref>` (sender can't sign under recipient's key).
7. **`flow/`** (NEW) — orchestration. Owns acceptance prompt, TTL enforcement, two-tier size budget (SignedPacket ~1000 bytes encoded vs. payload 64KB plaintext).

**Critical invariant:** Material is decrypted into `Zeroizing<Vec<u8>>` before acceptance but never surfaced until user explicitly confirms. Receipt signed+published only after acceptance + post-decrypt inner-sig verify.

### Critical Pitfalls (top 7 from PITFALLS.md)

1. **Ed25519→X25519 conversion correctness** — use libsodium semantics; cross-impl byte-match fixture test.
2. **Dual-signature verification discipline** — outer before decrypt; inner gates every surfaced field; same opaque error for all failure modes.
3. **Canonical JSON scheme must be locked before first signature** — changing later invalidates every past signature. (Flagged contradiction — see Decision 2 below.)
4. **HKDF info strings versioned + domain-separated** — `cipherpost/v1/<context>`; never `None`/empty.
5. **Receipt produced only after full verify + acceptance** — binds ciphertext hash, cleartext hash, purpose, sender pubkey, timestamp, protocol version, recipient pubkey.
6. **Acceptance step = real decision, not "press Y"** — full fingerprint (not prefix), explicit multi-keystroke confirmation, no default-yes, purpose with delimiters + control-char stripping.
7. **Secrets never derive Debug / `.clone()` without review** — wrap in `secrecy::SecretBox` / `Zeroizing`; test `format!("{:?}")` on every secret type.

## Implications for Roadmap

### Reconciled Build Order for Skeleton (10 phases, ~7 working days)

STACK, ARCHITECTURE, and PITFALLS each proposed an ordering. Reconciled into one phase sequence where every phase has unambiguous predecessors and every phase carries forward the pitfalls it must not drop:

**Phase 1: Scaffold** (< half day) — Cargo.toml pin-for-pin from cclink (drop arboard/qr2term/gethostname), CI with audit+deny from PR #1. *Pitfalls addressed:* 13 (supply chain). *Research flag:* NONE.

**Phase 2: Vendor crypto + identity** (1 day) — `src/crypto/` (rename constants, HKDF info strings → `cipherpost/v1/<context>`), `src/identity/` (drop `homeserver_*`, Argon2 params in header). *Pitfalls addressed:* 1, 4, 7, 8, 9, 15. *Research flag:* NONE.

**Phase 3: Vendor transport + record** (1 day, parallelizable with Phase 2) — transport label `_cipherpost`, introduce `Transport` trait for MockTransport seam; `OuterRecord`/`OuterRecordSignable` rename, drop `hostname`/`project`, add `share_ref`. *Pitfalls addressed:* 3, 11. *Research flag:* Re-validate fit-in-1000-bytes against new field set.

**Phase 4: Payload schema** (1 day) — `Envelope` + `EnvelopeSignable` (no separate envelope signature in skeleton), `Material::GenericSecret` only, 64KB cap. *Pitfalls addressed:* 3, 12. *Research flag:* **Canonical JSON scheme must be decided before coding** (Decision 2).

**Phase 5: Self-mode round trip** (1 day) — `flow/send.rs::run_send_self`, `flow/receive.rs::run_receive` (no acceptance prompt yet), minimal CLI. MockTransport integration test. *Pitfalls addressed:* 10 (mitigated via mock), 14. *Research flag:* NONE.

**Phase 6: Share-mode** (half day) — `run_send_share`; two-identity integration test (A→B decrypts; C cannot). *Addresses:* D1, D2, D6, D7. *Pitfalls:* 2.

**Phase 7: Acceptance step** (half day) — `dialoguer::Confirm` gate, `Prompter` trait, full fingerprint display, typed confirmation. *Pitfalls addressed:* 6. *Research flag:* **UX wording + fingerprint format decision** (G1, G7, Q2).

**Phase 8: Receipt publishing** (1 day) — `src/receipt/`, `transport::publish_receipt` (resolve-merge-republish pattern). Integration tests for round-trip + coexistence. *Addresses:* D3. *Pitfalls addressed:* 5. *Research flag:* **PKARR SignedPacket merge semantics need a small prototype** (race conditions on concurrent receipts under same recipient key).

**Phase 9: Receipt fetching** (half day) — `flow/receipt_fetch.rs`, `cipherpost receipts --from <z32>`. *Research flag:* NONE.

**Phase 10: Docs drafts** (1 day, parallel with 8-9) — SPEC.md (payload schema, canonical JSON scheme, share_ref, receipt format, DHT labels, HKDF namespace, fingerprint format), THREAT-MODEL.md (identity, DHT, acceptance, receipt replay, **purpose as sender-attested**), SECURITY.md (disclosure contact). *Pitfalls addressed:* 12, abandonment resilience.

### Phase Ordering Rationale

- **Vendored-first (2-3) before greenfield (4-9):** value is in the delta, not re-derived crypto; vendored code has existing test fixtures for cheap de-risking.
- **Self before share (5 before 6):** same code path, fewer moving parts; ships first green integration test earlier.
- **Acceptance before receipt (7 before 8):** receipt is conditional on acceptance.
- **Docs parallel with receipts (10 alongside 8-9):** writing SPEC.md during code catches precision gaps (the G1-G10 list came from this analysis).
- **Parallelism:** Phases 2 and 3 share only Phase 1; can run concurrently. Phase 10 can run alongside 8-9.

### Skeleton Must Land These Correctly (Lock-in Checklist)

**15 of 18 pitfalls must be addressed in skeleton** — wire-format or signed-payload lock-in; fixing in v1.0 means v0 shares are unverifiable:

| # | Pitfall | Phase | Lock-in nature |
|---|---------|-------|----------------|
| 1 | Ed25519→X25519 conversion correctness | 2 | Wrong keys = share-mode silently broken |
| 2 | Dual-sig verify order/discipline | 6 | Changing later leaks pre-auth payload |
| 3 | Canonical JSON scheme | 4 | Any change invalidates past signatures |
| 4 | HKDF info strings versioned | 2 | Cross-context key substitution if wrong |
| 5 | Receipt only after verify+acceptance | 8 | Changes semantics = breaks cipherpost thesis |
| 6 | Real acceptance (lightweight in skeleton) | 7 | Framing must be right in v0 |
| 7 | Secrets never derive Debug | 2 | Single leak = key rotation for every user |
| 8 | Argon2 params in file header | 2 | Changing storage format = breaking change |
| 9 | `chacha20poly1305` only via `age` | 2, 5 | Nonce reuse silent+catastrophic |
| 10 | DHT unreliability budgeted | 5-6 | Informs TTL default (Decision 1) |
| 11 | Inner signed timestamp mandatory | 3, 4 | Stale packet replay defense |
| 12 | Purpose documented as sender-attested | 10 | THREAT-MODEL.md must be explicit |
| 13 | cargo-audit + cargo-deny in CI | 1 | Retrofit cost grows with deps |
| 14 | Passphrase never via argv | 5 | Trivial leak path |
| 15 | Identity file 0600 on every open | 2 | Offline crack risk |

**Deferred to v1.0:** #16 error-oracle unification, #17 MSRV pinning, #18 cross-platform CI matrix. Plus UX hardening on #6, real-DHT tuning on #10, cargo-vet + sigstore on #13.

### Decision Points — Contradictions Surfaced (NOT resolved unilaterally)

**Decision 1: Default TTL — 4h (PRD) vs. 24h (PITFALLS)**
- *PRD position:* 4 hours default (aspirational security hygiene).
- *PITFALLS position:* 24 hours default. Mainline DHT median lookup ~1 min; 90th-percentile minutes; NAT drag real. 4h combined with DHT latency distributions will routinely fail.
- *Tradeoff:* 4h = smaller exposure window; 24h = fewer "expired before I picked it up" failures. Both are client-side enforced; DHT's own record TTL is orthogonal.
- *Timing:* Decide **during requirements gathering** (before Phase 1). Constraint change in PROJECT.md.

**Decision 2: Canonical JSON scheme — cclink alphabetical vs. RFC 8785 (JCS)**
- *STACK position:* Stay on cclink's alphabetical-field-declaration trick. Zero deps, works today, matches vendored code; adopting `serde_jcs` is SPEC-level not skeleton-level.
- *PITFALLS position:* RFC 8785 (JCS) via `serde_canonical_json`. Handles Unicode and floats explicitly; cross-language interop for future reimplementation (abandonment-resilience requirement); `serde_json` alone is not canonical.
- *Tradeoff:* cclink's pattern is known-working, saves a dep. JCS is future-proof if protocol is ever reimplemented in another language. Changing schemes post-v0 is a protocol bump that invalidates every past signature.
- *Timing:* Decide **before Phase 3** (record vendor phase) — determines how to adapt cclink's `canonical_json` helper.

**Decision 3 (unilateral-safe): share_ref width — 64 vs. 128 bits**
- ARCHITECTURE proposes 64 bits (16 hex chars). Widening to 128 bits now costs 16 more bytes per receipt label and avoids a future protocol bump. Recommended: **128 bits**. Flagged for awareness only.

### Open Questions Ranked by Decision Urgency

**Before skeleton starts (Phase 1):**
1. Default TTL: 4h or 24h (Decision 1)
2. Canonical JSON scheme: cclink alphabetical or JCS (Decision 2)
3. Fingerprint canonical format — OpenSSH-style `ed25519:SHA256:<base64>`, raw hex, base58, z-base-32, or BIP39 word list (G1, FEATURES Q1)
4. Identity storage path — `~/.cipherpost/` or `$XDG_CONFIG_HOME/cipherpost/` (FEATURES Q6)
5. Envelope magic name — `CIPHPOSK` or other (STACK open question)
6. Repo layout — resolved: fully independent fork-and-diverge, single crate (PROJECT.md Key Decision)

**During skeleton (before Phase 7-8):**
7. Accept-prompt exact wording + typed-confirmation form (G7, Pitfall 6, FEATURES Q2)
8. Idempotent re-receive semantics — recommendation: lock in skeleton (state-store format has to work day one) even though v1.0 delivers full feature (G10, FEATURES Q3)
9. `cipherpost list` scope + state store location — `$XDG_STATE_HOME/cipherpost/`? (FEATURES Q4)
10. Receipt body fields exact list — per Pitfall 5: share_ref, sender_pubkey, recipient_pubkey, accepted_at, nonce, ciphertext hash, cleartext hash, purpose, protocol version
11. `cipherpost receipts --watch` polling interval + Ctrl-C behavior (FEATURES Q5)
12. Envelope-level signing — separate or rely on outer record inner-sig? (recommendation: no separate envelope signature in skeleton)

**Before v1.0:**
13. Name lock-in: "Cipherpost" vs. keyshare / dropkey / sigpost (resolved: Cipherpost per PROJECT.md)
14. Protocol governance: solo-maintain vs. donate to Pubky ecosystem
15. Commercial trajectory: decide now vs. design for flexibility
16. Encrypt-then-sign for inner layer (so inner verify happens before decrypt) — forward-look from Pitfall 2

### Gaps the PRD Missed (G1-G10 from FEATURES.md)

All CLI-UX precision issues (not protocol changes) where the PRD is silent. Should be addressed during requirements to prevent skeleton calcifying a different answer:

| G# | Gap | Fix |
|----|-----|-----|
| G1 | Fingerprint canonical format | SPEC.md — recommend `ed25519:SHA256:<base64>` (OpenSSH-compat) |
| G2 | Exit-code taxonomy | SPEC.md — {0, 2 expired, 3 sigfail, 4 decryptfail, 5 notfound, 6 network, 7 declined} |
| G3 | Stdin/stdout `-` composability | PROJECT.md Active — "all payload I/O supports `-`; status to stderr" |
| G4 | Passphrase non-interactive contract | SPEC.md — `CIPHERPOST_PASSPHRASE` env, `--passphrase-file`, `--passphrase-fd`; reject inline; TTY default |
| G5 | DHT progress/timeout UX | SPEC.md — stderr progress, 30s default `--dht-timeout`, distinguish notfound/expired/network |
| G6 | Version/build-info | Skeleton — `cipherpost version` with git hash + crypto-primitive list |
| G7 | Acceptance-screen exact content | SPEC.md — `{purpose, sender_fingerprint, ttl_remaining, payload_type, payload_size_bytes}` + typed-confirm |
| G8 | Shell-completion commitment | v1.0 — `cipherpost completion {bash,zsh,fish}` |
| G9 | Clipboard guidance | Docs-level README section |
| G10 | Idempotent re-pickup semantics | SPEC.md — second receive reports prior timestamp, does NOT republish receipt |

### Research Flags for Phase Planning

**Need deeper research during planning:**
- **Phase 4** — Canonical JSON scheme + fingerprint format (blocks first signature)
- **Phase 7** — Acceptance UX wording / fingerprint rendering (BIP39-word-list vs. Base32-grouped vs. OpenSSH-style)
- **Phase 8** — PKARR SignedPacket merge-update semantics (resolve-merge-republish race conditions, prototype needed)
- **Phase 10** — SPEC.md canonical-JSON section depends on Decision 2; THREAT-MODEL.md needs explicit adversary enumeration

**Standard patterns (skip research-phase):**
- **Phase 1** — mechanical scaffold
- **Phases 2-3** — copying from cclink; pattern in ARCHITECTURE.md §4
- **Phases 5-6** — well-specified in ARCHITECTURE.md §4.1-4.2
- **Phase 9** — inverse of Phase 8; trivial once publishing works

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Every version verified via crates.io on research date; cclink `Cargo.toml` + `Cargo.lock` read directly; pin rationale traced to pkarr-dependency constraints |
| Features | MEDIUM-HIGH | Competitor landscape HIGH; CLI ergonomics HIGH (primary sources); user-acceptance expectations MEDIUM (competitor docs, not direct research) |
| Architecture | HIGH | Every claim backed by specific file + line range in cclink source; three open design choices flagged |
| Pitfalls | MEDIUM-HIGH | Crypto/Rust practice HIGH (OWASP, RustSec, RFC 8785, libsodium); DHT empirical data MEDIUM (2011-2014 vintage; PKARR-specific limited) |

**Overall confidence: HIGH.** Research tightly scoped to a skeleton that is largely a vendoring exercise on a known-working reference (cclink) with a bounded greenfield delta. Main unknowns are the two flagged contradictions (explicitly surfaced) plus real-DHT latency (measurement task, not research gap).

### Gaps to Address During Planning

- **Real-DHT latency distribution** — cited but unmeasured; schedule a manual 20+ trial smoke test before Phase 10 to validate chosen TTL default
- **PKARR SignedPacket merge-update semantics** — Phase 8 prototype needed; race conditions on concurrent receipt publication undocumented
- **cclink `canonical_json` adaptation to JCS** — if Decision 2 picks JCS, localized change to cclink's helper needs specific implementation + test vectors
- **Fingerprint format** — needs explicit user call before Phase 4 so it lands in SPEC.md stub
- **Receipt race conditions** — two recipients simultaneously receiving different shares from same sender → publishing receipts under their own keys → no collision; but sender publishing second share before recipient's first receipt propagates → out-of-order receipts. Needs THREAT-MODEL.md treatment in Phase 10.

## Ready for Requirements

Research synthesis complete. Requirements definition can proceed with:
- A reconciled 10-phase build order (above)
- 15 pitfalls flagged as skeleton-scope lock-in
- 2 contradictions surfaced for user decision (TTL default, canonical JSON scheme) + 1 unilateral-safe recommendation (share_ref width)
- 16 open questions ranked by decision urgency
- 10 PRD gaps (G1-G10) consolidated for requirements gathering
