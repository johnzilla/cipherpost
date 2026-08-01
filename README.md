# cipherpost

[![CI](https://img.shields.io/github/actions/workflow/status/johnzilla/cipherpost/ci.yml?branch=main&label=CI&logo=github)](https://github.com/johnzilla/cipherpost/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.88%2B-orange.svg?logo=rust)](./rust-toolchain.toml)
[![Latest release](https://img.shields.io/github/v/tag/johnzilla/cipherpost?label=release&sort=semver)](https://github.com/johnzilla/cipherpost/tags)

Cipherpost is a self-sovereign, serverless, accountless CLI for cryptographic-material handoff over Mainline DHT via PKARR. Hand off a key, certificate, or secret to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.

- **No servers.** Rendezvous is Mainline DHT via PKARR. No operator, no account, no subpoena target.
- **Key is identity.** Ed25519/PKARR keypair, passphrase-wrapped on disk (Argon2id + HKDF-SHA256 + `cipherpost/v1/<context>` domain separation).
- **Ciphertext only on the wire.** Payload and metadata both encrypted; the DHT sees only opaque blobs.
- **Signed receipts.** Recipient publishes a signed receipt to the DHT on pickup; the sender can independently verify delivery without a central log.
- Full PRD v1 scope shipped (v1.1):
    - typed payloads (`Material::GenericSecret`, `Material::X509Cert`, `Material::PgpKey`, `Material::SshKey`)
    - `--pin` second-factor encryption (Argon2id+HKDF→X25519→age, no direct chacha20poly1305 calls)
    - `--burn` single-consumption mode with emit-before-mark state ledger
    - non-interactive automation via `--passphrase-file` / `--passphrase-fd`
    - still unimplemented (deferred past v1.1): TUI wizard, non-interactive PIN input (`--pin-file`/`--pin-fd`), destruction attestation — the post-v1.1 effort went into experimental [large-payload support](#large-payloads-v2-experimental) instead
- **v2 derived-key addressing (`PROTOCOL_VERSION = 2`).** Each share and each receipt is published under its own key `derive(parent_pub, share_ref)` (SPEC.md §3.8), rather than a shared label on the parent identity key. This lifts the v1.1 one-outstanding-share/receipt-per-key ceiling (a key held ~one record), makes receipts non-enumerable from a public identity, re-enables self-share receipts, and removes the receipt-publish CAS/merge machinery (single-writer keys). A clean break: v2 invalidates v1.1 shares/receipts.

## Quick start

### Build

```bash
cargo build --release
# binary: ./target/release/cipherpost
```

Requires Rust 1.88+ (pinned in `rust-toolchain.toml`). No `tokio` dependency at the cipherpost layer — uses `pkarr::ClientBlocking`. Bootstrap nodes are pkarr defaults (Mainline DHT — `router.bittorrent.com:6881` and three peers); no user-tunable bootstrap configuration in v1.1.

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

# Slow DHT? Extend the resolve timeout (default 30s):
cipherpost receive <share-uri> --dht-timeout 90
```

Repeat runs on an already-accepted share report the prior acceptance timestamp and do **not** re-decrypt or publish a duplicate receipt (idempotent via state ledger).

### Verify receipts for shares you sent

```bash
# v2: --share-ref is REQUIRED (receipts are addressed per-share, not enumerable)
cipherpost receipts --from <recipient-z32> --share-ref <32-hex>
cipherpost receipts --from <recipient-z32> --share-ref <32-hex> --json
```

Derives the receipt's key `derive(recipient_pub, share_ref)` (SPEC.md §3.8), fetches the single receipt at that key, and verifies its Ed25519 signature (the recipient pubkey is supplied as verify context). Because receipts are addressed per-share, `--share-ref` is required — omitting it is an error; a recipient's receipts are not enumerable from their identity key (a v2 privacy property).

## Large payloads (v2, experimental)

> **Status: experimental preview, partial.** This is a **self-backup** tool today:
> `--self` only (cross-identity `--share` errors out), and a large-payload `receive`
> does **not** publish a signed receipt — so the delivery-attestation guarantee small
> shares get does **not** extend to large payloads yet. Off-by-default; the CLI surface
> and wire details may change before it graduates from `-alpha`. See the full gap list
> below.

Behind an **off-by-default** `large-payload` cargo feature, cipherpost can hand off
arbitrarily large payloads (directories, workspaces, archives) that blow past the
1000-byte DHT wire budget — without adding any operator you don't control.

```bash
cargo build --release --features large-payload
```

The model is **manifest-on-DHT, ciphertext-blob-on-homeserver**: the payload is
tar'd, age-encrypted to the recipient (same envelope crypto as small shares), and
uploaded as an **opaque ciphertext blob** to a [pubky homeserver](https://github.com/pubky/pubky-core)
(self-hostable, pkarr-addressed — the "relay" is a homeserver you run). A tiny
signed manifest carrying only `sha256(ciphertext)` + size is published to the DHT
via the normal dual-signed flow.

```bash
# CIPHERPOST_HS is REQUIRED — the pubky homeserver you control. There is no
# default: cipherpost never uploads your blobs to a host you didn't choose.
export CIPHERPOST_HS=https://hs.example.com

cipherpost send-large --self -p "vllm workspace backup" ./workspace
# → prints a share URI

cipherpost receive-large <share-uri> -o ./restored
# acceptance screen shows payload size + SHA-256; on confirm, downloads the blob,
# verifies the hash against the signed manifest, decrypts, and unpacks.
```

Talks to the homeserver over blocking HTTPS (`ureq` + OS-native TLS — **no `tokio`,
no `ring`/`aws-lc` in the default tree**; the feature adds them only when enabled).
The blob never leaves the sender's machine as plaintext: the homeserver, like the
DHT, sees only ciphertext, and a mismatched hash aborts receive with exit 3.

**v2-alpha scope — what is NOT here yet:**
- **`--self` only.** Cross-identity `--share` for large payloads is unimplemented and
  returns an error; today this is self-backup (encrypt a workspace to your own identity,
  restore it on another machine you control).
- **No delivery attestation.** Unlike small shares, a large-payload `receive` does **not**
  publish a signed receipt. The signed-receipt loop that lets a small-share sender prove
  pickup (see *Verify receipts for shares you sent* above) is **not wired** for large
  payloads — there is currently no cryptographic proof that a large blob was received.
- **Live homeserver flow is manual.** The real end-to-end homeserver round-trip is covered
  by `#[ignore]`'d tests run by hand (`tests/homeserver_live.rs`); CI exercises only the
  mock-backed round-trip, so the HTTP/auth path is not continuously regression-tested.
- **Capability-URL exposure.** Blobs live under the homeserver's world-readable `/pub/` at
  an unguessable content-addressed path (pubky-homeserver has no writable private space).
  Confidentiality rests on the age ciphertext + the unguessable path (which travels only
  inside the encrypted manifest); someone who knows your identity **and** homeserver could
  enumerate `/pub/` to see blob hashes + sizes (never content). See
  [`THREAT-MODEL.md` §10](./THREAT-MODEL.md).

## Security model at a glance

- **Dual signatures verified before any decrypt.** Every share carries an outer PKARR-packet signature (SignedPacket) and an inner Ed25519 signature over canonical JSON (RFC 8785 / JCS). Tampering at either layer aborts `cipherpost receive` with exit 3 **before** age-decrypt runs, and no envelope field (including `purpose`) is displayed prior to that check.
- **Explicit acceptance required.** The receiver is shown a full-fingerprint acceptance screen with the sender-attested purpose and must type the sender's z-base-32 pubkey to continue. Declining returns exit 7 with no material written.
- **Tamper-zero-receipts.** A receipt is published to the DHT only after outer verify + inner verify + typed-z32 acceptance all succeed. Any byte-flip between outer verify and acceptance causes zero receipts to be published (integration-tested).
- **Receipts are public but v2 shrinks what they expose.** A receipt is published *signed but not encrypted*, in v2 under the recipient's **derived key** `derive(recipient_pub, share_ref)` (SPEC.md §3.8). Its slim v2 schema is `{accepted_at, ciphertext_hash, cleartext_hash, protocol_version, share_ref, signature}` — **neither pubkey is a field** (both were dropped in v2) and there is no `nonce`. Because the key is blinded by `share_ref`, a passive observer who doesn't know the `share_ref` **cannot enumerate** a recipient's receipts from their identity key (a v2 privacy win over v1.1's `_cprcpt-*` records). The descriptive **`purpose` is deliberately not in the receipt** (it stays bound via `cleartext_hash`). Residual: a party holding both the recipient pubkey **and** the `share_ref` (the sender, or anyone with the URI) can locate and read the receipt — learning *that* a handoff was accepted and *when*. See [`THREAT-MODEL.md`](./THREAT-MODEL.md).
- **Passphrase contract is non-interactive-first.** `CIPHERPOST_PASSPHRASE` env var, `--passphrase-file <path>` (mode 0600/0400), or `--passphrase-fd <fd>`. Argv-inline `--passphrase <value>` is rejected — it would leak via `ps`.
- **Signature-failure errors are indistinguishable by design.** All outer/inner/canonical-mismatch verification failures share one identical user-facing message and exit 3 (defense against distinguishable-oracle attacks — see `THREAT-MODEL.md`).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error (incl. 64 KB payload-size cap / wire-budget exceeded) |
| 2 | TTL expired |
| 3 | Signature verification failed (any layer) |
| 4 | Passphrase incorrect or missing |
| 5 | Not found on DHT |
| 6 | Network / DHT error |
| 7 | Acceptance declined |

Full taxonomy in [SPEC.md § Exit Codes](./SPEC.md#6-exit-codes).

## Documentation

- [FAQ.md](FAQ.md) for common questions and answers.
- [`SPEC.md`](./SPEC.md) — Protocol specification (wire format, JCS reference vector, share URI, DHT labels, passphrase contract)
- [`THREAT-MODEL.md`](./THREAT-MODEL.md) — Adversary model and mitigations (identity compromise, DHT adversaries, acceptance UX, receipt replay, passphrase-prompt MITM)
- [`SECURITY.md`](./SECURITY.md) — Vulnerability disclosure policy (GitHub Security Advisory, 90-day embargo)
- [`cipherpost-prd.md`](./cipherpost-prd.md) — Original product requirements document

All three protocol documents are kept current, including v2 derived-key addressing (`SPEC.md` §3.8, §3.4, §8.4; `THREAT-MODEL.md` §1/§7) and the experimental `large-payload` additions (`SPEC.md` §Pitfall #22, `THREAT-MODEL.md` §10/§10.1). **v2 is a clean break from v1.1** — `PROTOCOL_VERSION` 1→2 changes every record's signed bytes and invalidates v1.1 shares/receipts; the "v1.0 byte-identity" lock-in is retired for v2. The `is_false` skip-serializing-if elision for pin/burn fields is preserved (those flags stay byte-absent when false), but v2 records are no longer byte-identical to v1.0.

## Architecture lineage

Cipherpost is a fork-and-diverge from mothballed [`cclink`](https://github.com/johnzilla/cclink) focused on keyshare workflows. Crypto and transport primitives (Ed25519/PKARR, age, Mainline DHT, Argon2id KDF, dual signatures) were vendored unchanged; the delta is at the payload and flow layer: typed payload schema, explicit acceptance step, signed receipt.

## Known limitations

- **Wire-budget ceiling for typed Material.** Realistic X.509 / PGP / SSH keys exceed the 1000-byte PKARR BEP44 ceiling; `Material::GenericSecret` payloads above ~550 bytes also exceed it. Round-trip tests for realistic typed inputs are `#[ignore]`'d behind positive `Error::WireBudgetExceeded` clean-error pins. An experimental two-tier escape hatch now ships behind the off-by-default `large-payload` feature (ciphertext on a Pubky homeserver, tiny signed manifest on the DHT) — see [Large payloads (v2)](#large-payloads-v2-experimental) above; chunking / out-of-band variants remain targeted for later (see [`SPEC.md` §Pitfall #22](./SPEC.md)).
- **Real-DHT cross-identity round trip is per-release, not per-commit.** The cross-identity Mainline-DHT round trip lives at `tests/real_dht_e2e.rs` behind a triple-gate (`#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`). PR + push CI stays mock-only — UDP/NAT variance + the 60-90s DHT long tail make per-commit real-DHT testing structurally unworkable (Pitfall #29). The `release-acceptance` workflow at [`.github/workflows/release-acceptance.yml`](./.github/workflows/release-acceptance.yml) runs the same gate on every `v*` tag push and uploads the output as a 90-day artifact, so each release publishes its own real-DHT evidence next to the tag. The v1.1.0 evidence run (manual demo + automated test, both PASS against pkarr-default Mainline bootstrap nodes) is checked in at [`RELEASE-EVIDENCE-v1.1.0.md`](./RELEASE-EVIDENCE-v1.1.0.md).
- **No TUI.** CLI + non-interactive automation cover v1.x use cases.
- **`receive` acceptance is interactive-only.** Passphrase (and every other input) can be scripted, but the fingerprint-acceptance step — type the sender's z-base-32 pubkey to unlock decrypt — requires an interactive TTY on stdin + stderr, and there is no `--yes`/bypass flag. So *fully unattended* receive (a cron job or CI step with no human present) is **not** supported in v1: the accept step is deliberately human-in-the-loop so a person verifies the sender out-of-band before any plaintext is written. See [FAQ.md](FAQ.md).
- **Non-interactive PIN input deferred.** PIN is intentionally a human-in-the-loop second factor. `--pin-file` / `--pin-fd` remain deferred, pending a concrete automation use case.
- **Destruction attestation not implemented.** Originally scoped for PRD v1.1; deferred when v1.1 filled with PRD-closure scope, and still unimplemented. `--burn` is local-state-only (DHT ciphertext survives until TTL).
- **One outstanding record per identity (packet budget) — LIFTED in v2.** In v1.1, PKARR's single ~1000-byte-per-key packet meant a key held effectively one large record: receiving a share (which published a receipt on your key) could make your next *send* fail with `PacketBudgetExceeded`, a recipient held at most one receipt, and self-shares skipped receipts to avoid colliding with the outgoing share. **v2 derived-key addressing removes this**: each share and each receipt is published under its own key `derive(parent_pub, share_ref)` (SPEC.md §3.8), so a key never shares a packet — a sender can have many outstanding shares, a recipient many receipts, and self-shares now publish a normal receipt. (The [FAQ.md](FAQ.md) "one outstanding receipt per identity" entry predates v2 and is superseded by this.)
- **No identity import.** `cipherpost identity generate` is the only path; importing existing Ed25519 / SSH / age keys (`cipherpost identity import`) is planned for a future release.

## License

MIT — see [`LICENSE`](./LICENSE).
