# Milestones

## v1.0 Walking Skeleton (Shipped: 2026-04-22)

**Phases completed:** 4 phases, 15 plans

**Stats:**
- Git range: `d16057c` → `3a7f094` (117 commits; 19 `feat(` + 12 `fix(`)
- LOC: 3,543 in `src/` (11 files) · 6,407 incl. `tests/` (46 files)
- Test suite: 86 tests green under `cargo test --features mock`
- Timeline: 2026-04-20 → 2026-04-22 (~48 hours, 3 calendar days)
- Requirements: 49/49 v1 requirements validated
- CI: `fmt`, `clippy -D warnings`, `nextest`, `audit`, `deny check`, `lychee` all green

**Key accomplishments:**

1. **Foundation with locked wire format** — Rust crate scaffold on exact cclink v1.3.0 crypto pins (`pkarr 5.0.3`, `ed25519-dalek =3.0.0-pre.5`, `age 0.11`, `argon2 0.5`, `hkdf 0.12`), plain `fn main()` (no `tokio`), CI green on `fmt/clippy -D warnings/nextest/audit/deny`; `OuterRecord`/`OuterRecordSignable` JCS fixture (`outer_record_signable.bin`) committed to freeze the byte-level wire format; domain-separated HKDF `cipherpost/v1/<context>`, Argon2id params in PHC file header, zeroize discipline across every secret-holder.

2. **Identity + encrypted send/receive round trip** — `identity generate`/`show` with TTY double-confirm passphrase (fix `2e29b74` after UAT found single-prompt footgun), OpenSSH + z-base-32 fingerprints, mode-0600 enforcement; `Envelope`/`Material::GenericSecret` payload schema with JCS round-trip and 64 KB plaintext cap; `cipherpost send --self | --share <pubkey>` publishes via PKARR, `cipherpost receive` enforces outer+inner signature verify **before** any age-decrypt, then TTL, then the full-fingerprint D-ACCEPT acceptance screen with typed-z32 confirmation.

3. **Signed receipt — the cipherpost delta** — `Receipt`/`ReceiptSignable` JCS fixture (`receipt_signable.bin`, 424 B) committed; recipient-signed Ed25519 via `verify_strict` + round-trip-reserialize guard; post-acceptance `publish_receipt` to DHT label `_cprcpt-<share_ref>` via resolve-merge-republish (coexists with outgoing shares, no clobber); sender-side `cipherpost receipts --from <z32> [--share-ref | --json]` fetches, verifies, and renders a 10-field audit-detail view. Tamper-zero-receipts invariant enforced: any byte-flip between outer verify and acceptance aborts before publication.

4. **Protocol documents drafted** — `SPEC.md` (payload schema, JCS reference vector, outer+inner signature format, share URI, DHT labels, `share_ref` derivation, TTL semantics, exit-code taxonomy, non-interactive passphrase contract), `THREAT-MODEL.md` (identity compromise, DHT adversaries incl. sybil/eclipse/replay, purpose-as-sender-attested with false-purpose example, acceptance-UX attacks, receipt replay, passphrase-prompt MITM), `SECURITY.md` (live-tested disclosure channel via GHSA, 90-day embargo, cclink lineage + `cipherpost/v1` HKDF prefix reference), `lychee` link-check CI job pinned to `0.21.0`.

5. **End-to-end verifiability** — 86 tests across 35 integration files, including Phase 3 SC1–SC4 (tamper-zero-receipts, share_ref filter, coexistence, two-identity E2E); cross-fixture byte-level determinism under JCS; mock `Transport` lets the full happy-path + every adversarial abort run without touching Mainline DHT. IDENT-01 interactive TTY passphrase prompt verified manually on a real terminal at milestone close.

**Known deferred items at close:**

- **Crate-pin drift** — `serde_canonical_json` shipped as 1.0.0 (planned 0.2; API matches), `pkarr` transitively resolved to 5.0.4 (pinned 5.0.3), PKARR wire-budget measured at 550 bytes (planned 600). All documented in `01-VERIFICATION.md`; functionally correct.
- **Real-DHT cross-identity round trip** never run — MockTransport exercises the full code path but cannot reach Mainline DHT. Documented as `reason_documented` in `v1.0-MILESTONE-AUDIT.md`.
- **PKARR merge-update race** — `publish_receipt` uses `cas` (compare-and-swap), no explicit concurrent-racer test. Not triggered by walking-skeleton usage (one sender, one recipient, one accept per share).
- **Test advisory `GHSA-36x8-r67j-hcw6`** left in draft state as a permanent reproducibility record of the disclosure-channel round-trip.
- **Local dev lychee** pinned to 0.21.0 (project rustc 1.85.1 limit); future rustc bump will allow 0.23.0+.
- **Traceability-table bookkeeping** — 29 rows in the archived `REQUIREMENTS.md` retained "Pending" labels although body checkboxes are checked and phase VERIFICATION reports confirm implementation. Archive reflects the live state at close.
- **Full milestone audit**: see `milestones/v1.0-MILESTONE-AUDIT.md` (status `tech_debt`, zero truly-unsatisfied requirements).

---
