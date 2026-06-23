# Cipherpost v2-alpha — Large-Payload Handoff (grounded plan)

**Supersedes the transport choice in `cipherpost-v2-plan.md`** (the Grok draft proposed
iroh-blobs; that was rejected — see "Transport decision" below). This doc is the
source of truth for the v2-alpha slice. GSD is no longer used; `.planning/` is historical.

## Goal

Extend cipherpost to hand off arbitrarily-large payloads (directories, workspaces,
archives) while preserving every v1 invariant: dual signatures, explicit acceptance,
signed receipts, ciphertext-only-on-wire, self-sovereign / no-trusted-operator,
blocking I/O at the cipherpost layer.

## Transport decision (why not iroh)

Empirical spike (2026-06-22): `iroh-blobs` 0.103 pulls `ring` + `aws-lc-rs` + **direct**
`tokio` + `ed25519-dalek 3.0.0-rc.0` (collides with cipherpost's exact `=3.0.0-pre.5`
pkarr pin → unsatisfiable lockfile) + MSRV 1.91 — breaks four locked constraints.
`sendme` subprocess rejected too: it's a *live* P2P handoff (sender must stay online),
which defeats asynchronous handoff, and routes through n0 relays.

**Chosen:** bulk blob stored on a **pubky homeserver** (self-hostable, pkarr-addressed),
reached via cipherpost's own **blocking `ureq` client** (`--no-default-features --features
native-tls` → OS-native TLS, no ring/aws-lc, no tokio). Homeserver speaks plain HTTPS
(`PUT/GET /pub|/priv/<path>`). No `iroh`, no `pubky` client crate, no pkarr bump.

## Architecture — "manifest-on-DHT, ciphertext-blob-on-homeserver"

- **send-large `<path>`:** tar → age-encrypt to recipient (same envelope crypto) →
  `sha256(ciphertext)` → PUT ciphertext to the **sender's** homeserver → publish a tiny
  manifest via the existing dual-signed DHT flow.
- **receive-large `<share-uri>`:** existing resolve + dual-sig verify + acceptance screen
  (now shows size + hash) → GET blob → verify sha256 against the signed manifest →
  age-decrypt → untar → export.
- A curious/malicious homeserver sees only opaque age ciphertext and cannot forge
  (signed hash) — it's a dumb mirror, not a trusted operator. Principle #1 holds in spirit.

## v2-alpha scope (MVP)

- **`--self` only.** Sender == recipient == the user. Cross-identity `--share` deferred
  (needs `/pub/<128-bit-unguessable>` capability URLs or delegated read caps).
- **`/priv/` storage** (auth-gated read) — nothing world-readable; no public URL to the
  user's infrastructure. Direct URL carried in the manifest (pkarr `_pubky` discovery deferred).
- **sha256** for the content hash (reuse `sha2`; no BLAKE3 — we're not using iroh).
- Everything behind an **off-by-default `large-payload` cargo feature** so the default
  binary's dependency surface (and all current guard tests) stay unchanged.

## Workstreams

**A. Test homeserver (DigitalOcean).**
`pubky-homeserver` on a droplet (`doctl`, Ubuntu, ~2 GB / 50 GB+ disk), fronted by **Caddy
auto-HTTPS on a user-owned domain** (real Let's Encrypt cert → ureq+native-tls validates
normally, no client skip-verify path). Config: `storage = file_system`, raised
`default_quota_mb` (100 MB/request is the code ceiling), signup open or token-minted via
admin endpoint. Admin (6288) + metrics (6289) bound to localhost. Scripted in
`scripts/deploy-homeserver.sh`; documented in `docs/test-homeserver.md`. Real-homeserver
E2E is manual / off-in-CI (like `real-dht-e2e`).

**B. `BlobStore` seam.** Trait mirroring the `Transport`/`MockTransport` pattern:
`HomeserverBlobStore` (ureq + native-tls; hand-rolled pubky `AuthToken` → `/session`
handshake) + `MockBlobStore` (in-memory/tempdir) so the full flow is testable with no
live server. Local `pubky-testnet` for integration coverage.

**C. Schema.** Additive `Material::LargePayload { location, hash, size }` (+ ingest);
v1 receivers get a clean "unknown payload, upgrade cipherpost" error (backward-compatible).

**D. `send-large <path> --self`** — workstream C+D crypto/tar/PUT pipeline.

**E. `receive-large <share-uri>`** — GET + sha256-verify + decrypt + untar + export;
acceptance screen shows size + hash.

**F. Deps / docs / tests.** `ureq` (native-tls) + `tar` under the `large-payload` feature;
`deny.toml` license + ban re-verify (tokio/ring stay green); SPEC.md / THREAT-MODEL.md /
README / exit-code updates; tests: mock round-trip, sha256-mismatch rejection, oversize
handling, feature-gated wiring.

## Open items / deferred
- Cross-identity `--share` large payloads (capability URLs or delegated read).
- pkarr `_pubky` SVCB discovery (MVP uses direct URL in manifest).
- Smart `.cipherpostignore` / Claude-session presets, progress bars, resume (Grok plan Phase 2).
- Destruction-attestation interplay with `--burn` for large payloads.
