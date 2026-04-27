# cipherpost

**Status: v1.1 Real v1 shipped (2026-04-26).** Cumulative: 9 phases · 39 plans · 311 tests green under `cargo test --features mock` · 116/116 requirements validated. Previously: v1.0 Walking Skeleton (2026-04-22).

Cipherpost is a self-sovereign, serverless, accountless CLI for cryptographic-material handoff over Mainline DHT via PKARR. Hand off a key, certificate, or secret to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.

- **No servers.** Rendezvous is Mainline DHT via PKARR. No operator, no account, no subpoena target.
- **Key is identity.** Ed25519/PKARR keypair, passphrase-wrapped on disk (Argon2id + HKDF-SHA256 + `cipherpost/v1/<context>` domain separation).
- **Ciphertext only on the wire.** Payload and metadata both encrypted; the DHT sees only opaque blobs.
- **Signed receipts.** Recipient publishes a signed receipt to the DHT on pickup; the sender can independently verify delivery without a central log.
- **Full PRD v1 scope shipped (v1.1):** typed payloads (`Material::GenericSecret`, `Material::X509Cert`, `Material::PgpKey`, `Material::SshKey`); `--pin` second-factor encryption (Argon2id+HKDF→X25519→age, no direct chacha20poly1305 calls); `--burn` single-consumption mode with emit-before-mark state ledger; non-interactive automation via `--passphrase-file` / `--passphrase-fd`; CAS-protected concurrent receipt publication with retry-and-merge contract. TUI wizard, non-interactive PIN input, and destruction attestation deferred to v1.2+.

## Quick start

### Build

```bash
cargo build --release
# binary: ./target/release/cipherpost
```

Requires Rust 1.85+ (pinned in `rust-toolchain.toml`). No `tokio` dependency at the cipherpost layer — uses `pkarr::ClientBlocking`. Bootstrap nodes are pkarr defaults (Mainline DHT — `router.bittorrent.com:6881` and three peers); no user-tunable bootstrap configuration in v1.1.

### Generate an identity

```bash
cipherpost identity generate    # prompts for passphrase twice (confirmed)
cipherpost identity show        # prints OpenSSH + z-base-32 fingerprints
```

Identity lives at `~/.cipherpost/secret_key` (mode 0600). Override with `CIPHERPOST_HOME`.

### Send to self (backup round trip)

```bash
echo "my-secret" | cipherpost send --self \
    -p "backup signing key" \
    --material-file -
# → prints a share URI on stdout
```

### Send to a recipient

```bash
cipherpost send --share <recipient-z32> \
    -p "onboarding token" \
    --material-file ./key.age
```

### Receive

```bash
cipherpost receive <share-uri>
# Prints an acceptance screen on stderr (sender fingerprints, purpose,
# TTL remaining, payload type + size). Type the sender's z-base-32
# pubkey to confirm, or anything else to decline with exit 7.
# Payload goes to stdout, or -o <path>.
```

Repeat runs on an already-accepted share report the prior acceptance timestamp and do **not** re-decrypt or publish a duplicate receipt (idempotent via state ledger).

### Verify receipts for shares you sent

```bash
cipherpost receipts --from <recipient-z32>
cipherpost receipts --from <recipient-z32> --share-ref <32-hex>
cipherpost receipts --from <recipient-z32> --json
```

Fetches the recipient's PKARR packet, filters TXT records by the `_cprcpt-` prefix, verifies each receipt's Ed25519 signature, and renders a structured summary (or a 10-field audit-detail view when filtering by `--share-ref`).

## Security model at a glance

- **Dual signatures verified before any decrypt.** Every share carries an outer PKARR-packet signature (SignedPacket) and an inner Ed25519 signature over canonical JSON (RFC 8785 / JCS). Tampering at either layer aborts `cipherpost receive` with exit 3 **before** age-decrypt runs, and no envelope field (including `purpose`) is displayed prior to that check.
- **Explicit acceptance required.** The receiver is shown a full-fingerprint acceptance screen with the sender-attested purpose and must type the sender's z-base-32 pubkey to continue. Declining returns exit 7 with no material written.
- **Tamper-zero-receipts.** A receipt is published to the DHT only after outer verify + inner verify + typed-z32 acceptance all succeed. Any byte-flip between outer verify and acceptance causes zero receipts to be published (integration-tested).
- **Passphrase contract is non-interactive-first.** `CIPHERPOST_PASSPHRASE` env var, `--passphrase-file <path>` (mode 0600/0400), or `--passphrase-fd <fd>`. Argv-inline `--passphrase <value>` is rejected — it would leak via `ps`.
- **Signature-failure errors are indistinguishable by design.** All outer/inner/canonical-mismatch verification failures share one identical user-facing message and exit 3 (defense against distinguishable-oracle attacks — see `THREAT-MODEL.md`).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic / unexpected error |
| 2 | TTL expired |
| 3 | Signature verification failed (any layer) |
| 4 | Passphrase incorrect or missing |
| 5 | Payload size cap exceeded (64 KB plaintext) |
| 6 | Network / DHT error |
| 7 | Acceptance declined |

Full taxonomy in [SPEC.md § Exit Codes](./SPEC.md#6-exit-codes).

## Documentation

- [FAQ.md](FAQ.md) for common questions and answers.
- [`SPEC.md`](./SPEC.md) — Protocol specification (wire format, JCS reference vector, share URI, DHT labels, passphrase contract)
- [`THREAT-MODEL.md`](./THREAT-MODEL.md) — Adversary model and mitigations (identity compromise, DHT adversaries, acceptance UX, receipt replay, passphrase-prompt MITM)
- [`SECURITY.md`](./SECURITY.md) — Vulnerability disclosure policy (GitHub Security Advisory, 90-day embargo)
- [`cipherpost-prd.md`](./cipherpost-prd.md) — Original product requirements document

All three protocol documents are kept current through v1.1 — wire-format decisions are stable (v1.0 fixtures byte-identical; v1.1 added pin/burn fields preserving v1.0 byte-shape via `is_false` skip-serializing-if). Editorial polish across the full v1.x scope continues.

## Architecture lineage

Cipherpost is a fork-and-diverge from mothballed [`cclink`](https://github.com/johnzilla/cclink) focused on keyshare workflows. Crypto and transport primitives (Ed25519/PKARR, age, Mainline DHT, Argon2id KDF, dual signatures) were vendored unchanged; the delta is at the payload and flow layer: typed payload schema, explicit acceptance step, signed receipt.

## Known limitations in v1.1

- **Wire-budget ceiling for typed Material.** Realistic X.509 / PGP / SSH keys exceed the 1000-byte PKARR BEP44 ceiling; `Material::GenericSecret` payloads above ~550 bytes also exceed it. Round-trip tests for realistic typed inputs are `#[ignore]`'d behind positive `Error::WireBudgetExceeded` clean-error pins. Two-tier storage / chunking / out-of-band escape hatch is targeted for v1.2+ (see [`SPEC.md` §Pitfall #22](./SPEC.md)).
- **Real-DHT cross-identity round trip is manual-only.** The cross-identity Mainline-DHT round trip exists at `tests/real_dht_e2e.rs` behind a triple-gate (`#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`). CI never enables the feature. Per-release execution via [`RELEASE-CHECKLIST.md`](./RELEASE-CHECKLIST.md) is the only gate.
- **No TUI.** CLI + non-interactive automation cover v1.x use cases.
- **Non-interactive PIN input deferred.** PIN is intentionally human-in-the-loop second factor in v1.x. `--pin-file` / `--pin-fd` deferred to v1.2+ pending concrete automation use case.
- **Destruction attestation not implemented.** Originally PRD v1.1; shifted to v1.2+ because v1.1 filled with PRD-closure scope. `--burn` is local-state-only (DHT ciphertext survives until TTL).
- **No identity import.** `cipherpost identity generate` is the only path; importing existing Ed25519 / SSH / age keys (`cipherpost identity import`) is planned for a future release.

## License

MIT — see [`LICENSE`](./LICENSE).
