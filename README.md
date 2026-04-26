# cipherpost

**Status: v1.0 Walking Skeleton shipped (2026-04-22).** 4 phases · 15 plans · 86 tests green · 49/49 requirements validated.

Cipherpost is a self-sovereign, serverless, accountless CLI for cryptographic-material handoff over Mainline DHT via PKARR. Hand off a key, certificate, or secret to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.

- **No servers.** Rendezvous is Mainline DHT via PKARR. No operator, no account, no subpoena target.
- **Key is identity.** Ed25519/PKARR keypair, passphrase-wrapped on disk (Argon2id + HKDF-SHA256 + `cipherpost/v1/<context>` domain separation).
- **Ciphertext only on the wire.** Payload and metadata both encrypted; the DHT sees only opaque blobs.
- **Signed receipts.** Recipient publishes a signed receipt to the DHT on pickup; the sender can independently verify delivery without a central log.
- **Walking skeleton scope:** generic-secret payloads over `--self` and `--share <pubkey>`. Typed payload types (X.509 / PGP / SSH), `--pin` / `--burn` modes, and the TUI are deferred to a later milestone.

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

All three protocol documents ship as **drafts** from the walking-skeleton milestone — wire-format decisions are stable, editorial polish is scheduled for a later milestone.

## Architecture lineage

Cipherpost is a fork-and-diverge from mothballed [`cclink`](https://github.com/johnzilla/cclink) focused on keyshare workflows. Crypto and transport primitives (Ed25519/PKARR, age, Mainline DHT, Argon2id KDF, dual signatures) were vendored unchanged; the delta is at the payload and flow layer: typed payload schema, explicit acceptance step, signed receipt.

## Known limitations in v1.0

- Real-DHT cross-identity round trip is documented tech debt — MockTransport exercises the full code path but the two-identity A→B→receipt flow across separate processes over Mainline DHT is pending a future release-acceptance test.
- `serde_canonical_json` transitively resolved to 1.0.0 (planned 0.2; API matches). `pkarr` resolved to 5.0.4 (pinned 5.0.3). PKARR wire-budget measured at 550 bytes (planned 600).
- Only `Material::GenericSecret` is implemented. `X509Cert`, `PgpKey`, `SshKey` variants are schema-reserved and return `unimplemented` — targeted for the next milestone.
- `--pin` and `--burn` encryption modes are not implemented — targeted for the next milestone.
- No TUI. CLI-only in this milestone.

## License

MIT — see [`LICENSE`](./LICENSE).
