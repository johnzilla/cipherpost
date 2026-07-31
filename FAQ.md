## FAQ

<details>
  
<summary>What is Cipherpost?</summary>

Cipherpost is a self-sovereign, serverless, accountless CLI tool for securely handing off cryptographic material (keys, certificates, secrets, etc.) using the Mainline DHT via PKARR.

It requires no servers, no accounts, and no central service that can be subpoenaed or compromised. Everything is end-to-end encrypted, explicitly accepted by the recipient, and backed by signed receipts you can verify independently.

</details>

<details>
  
<summary>Why does `receive` ask me to type the sender’s full public key?</summary>

This step is not a password or secret. Public keys are meant to be public.

The real protection is `age` encryption — the payload is encrypted to *your* public key (derived from your identity). Only you can decrypt it.

The typing step serves two purposes:
- Forces explicit human confirmation that you are receiving from the exact person whose pubkey you were given out-of-band.
- Acts as a deliberate speed-bump to prevent accidental or muscle-memory acceptance of malicious payloads.

If someone else tries to receive the same record, decryption will fail because they don’t have your private key.

</details>

<details>
  
<summary>Where is my private key stored?</summary>

- Default location: `~/.cipherpost/secret_key` (permissions **0600**)
- Directory: `~/.cipherpost/` (permissions **0700**)
- You can override with the `CIPHERPOST_HOME` environment variable.

The file contains your Ed25519 seed encrypted with an Argon2id-derived key from your passphrase (PHC format, memory-hard parameters). The key never leaves the file unencrypted in memory longer than necessary and is zeroized after use.

</details>

<details>
  
<summary>Can I use an existing Ed25519 / SSH / age keypair with Cipherpost?</summary>

**Not yet** (as of v1.1).

Cipherpost currently only works with identities it generates itself (`cipherpost identity generate`). This guarantees correct passphrase wrapping, domain separation, and security parameters.

Support for importing existing keys (`cipherpost identity import`) is planned for a future release.

</details>

<details>
  
<summary>What is the maximum payload size?</summary>

As of v1.1, the practical limit is the **1000-byte PKARR BEP44 ceiling** for the full outer record (envelope + signatures + metadata). Realistic typed Material (X.509 certs ~234+ bytes DER, PGP keys, SSH keys) and PIN-protected shares routinely exceed this and surface a clean `Error::WireBudgetExceeded` at send time. v1.0-style `GenericSecret` payloads up to roughly **550 bytes** of plaintext fit cleanly.

For **small shares** this ceiling stands. For **large payloads**, v2-alpha ships the two-tier escape hatch behind the `large-payload` feature: the ciphertext lives on a Pubky homeserver and PKARR carries only a tiny signed `sha256`+size manifest (see the homeserver-integration question above and the README "Large payloads (v2)" section). Chunking-over-DHT and an out-of-band/file escape hatch remain possible future additions.

See [`SPEC.md` §Pitfall #22](./SPEC.md) and the roadmap in the README.

</details>

<details>

<summary>My send failed with "packet over budget" but my secret is tiny — why? (One outstanding receipt per identity)</summary>

PKARR gives each key **one** ~1000-byte packet, shared by *every* record published under it — your outgoing share **and** every signed receipt you accrue when you *receive* a share from someone else. Real records are big: a share is ~650 bytes and a receipt is ~570 bytes, so **any two of them exceed the 1000-byte budget**. In practice a key can hold about **one** record at a time.

The consequence: if you have **received** a share from someone (which publishes a receipt on your key), your next **send** can fail with `PacketBudgetExceeded` — "packet over budget … because of accumulated records under this key." This is **not** about your payload size (a tiny secret fails just the same); it's the accumulated receipt colliding with your outgoing share. Likewise, a recipient can hold at most **one** receipt — a second received share's receipt is dropped (logged, non-fatal).

What this means in practice:

- **Self-backup is unaffected.** `send --self → receive` deliberately does **not** publish a receipt (a receipt to yourself proves nothing), so repeated self-backup cycles never accumulate and never hit this.
- **Cross-identity receiving is capped at one outstanding receipt.** If you receive from multiple senders, only the first receipt persists on your key until it expires.
- **Workaround:** wait for the older share/receipt to age out of the DHT (it clears within hours — records aren't re-announced; see the DHT-persistence question), or use a separate identity for high-volume receiving.

This is a known ceiling of the single-packet-per-key model. A future protocol change (per-`share_ref` / derived-key packets) will lift it.

</details>

<details>
  
<summary>How does the Pubky homeserver integration work?</summary>

Shipped **experimentally** in v2-alpha behind the off-by-default `large-payload` cargo feature (`cargo build --features large-payload`), as the `send-large` / `receive-large` commands:

- The payload is tar'd and `age`-encrypted (to your own identity in this `--self`-only alpha), then uploaded as **opaque ciphertext** to a [Pubky homeserver](https://github.com/pubky/pubky-core) **you choose** (set `CIPHERPOST_HS=https://your-homeserver`). The blob lives at a content-addressed path `/pub/cipherpost/<sha256>`.
- Only a tiny **signed manifest** — the ciphertext's `sha256` and size, nothing else — is published to the DHT via the normal dual-signed flow. The blob's path is *derived* from that hash, so the manifest stays well under the 1000-byte wire budget.
- The recipient performs the same acceptance flow (now showing the payload size + hash), then downloads the blob, **verifies its hash against the signed manifest** (mismatch aborts with exit 3), decrypts, and unpacks.

The homeserver only ever sees ciphertext — it's a dumb mirror, not a trusted operator. It talks plain HTTPS via a blocking client with OS-native TLS, so the default build pulls no `tokio`/`ring`.

**This alpha is intentionally narrow** — treat it as a self-backup preview, not the full handoff story:
- **`--self` only.** Cross-identity `--share` for large payloads returns an error today.
- **No signed receipt.** `receive-large` does **not** publish the signed receipt that small shares get, so there is no delivery proof for large payloads yet.
- **Live homeserver path is manual-only** (`#[ignore]`'d tests); CI exercises only the mock round-trip.

See the README "Large payloads (v2)" section and [`THREAT-MODEL.md` §10](./THREAT-MODEL.md) for the trust model, the `/pub/` enumeration caveat, and the attestation gap.

</details>

<details>
  
<summary>Is my data stored on the DHT forever? (And can it disappear *before* the TTL?)</summary>

No — and importantly, **a share can die well before its signed 24h TTL.** Two independent clocks are at work:

- **The signed TTL** (24h default) is the sender's *promise*: the receiver's client refuses to decrypt a share older than this. It's an upper bound, not a guarantee of availability.
- **Mainline DHT retention** is separate and shorter. Nodes drop records on their own schedule (typically hours), and cipherpost publishes with **no relay and no background re-announce** — once your `send` process exits, *nothing* re-broadcasts the record. As DHT nodes churn and expire it, the share can become unresolvable long before 24h.

**Practical guidance:** treat a share as *ephemeral rendezvous*, not storage. Have the recipient receive promptly (minutes to a few hours, not "sometime tomorrow"). If a share expires before pickup, just run `send` again to republish — it's cheap and produces a fresh record. For anything that must survive longer, use the large-payload homeserver path (the ciphertext blob persists on a homeserver you control) or other content-addressed storage.

</details>

<details>
  
<summary>Who can see my payloads?</summary>

- Only the intended recipient can decrypt them.
- Anyone can see the *encrypted* blobs (or pointers) on the DHT.
- The sender’s and recipient’s public keys are visible (by design).

</details>

<details>
  
<summary>Do both parties need to be online at the same time?</summary>

Through v1.1: Not simultaneously, but the window is narrower than the 24h TTL suggests. The sender publishes, then can go offline; the recipient comes online to receive. **Caveat:** because cipherpost uses no relay and does not re-announce, the record is only kept alive by Mainline DHT nodes, which drop it on their own (typically-hours) schedule — so the recipient should receive promptly, not "within 24h" (see *Is my data stored on the DHT forever?* above). If the record has aged out, the sender just republishes with another `send`. The signed-receipt loop closes when either the sender comes back online to fetch it, or the recipient publishes it (whichever order; both work).

Future versions with homeservers or chunking will support fully asynchronous operation with longer-lived shares.

</details>

<details>
  
<summary>Can I run <code>cipherpost receive</code> fully unattended (no human, no terminal)?</summary>

**No — `receive` requires an interactive terminal (TTY), by design.** This is worth knowing up front if your use case is *unattended* credential handoff (a cron job or CI step that receives a share with no human present): that does **not** work in v1.

The *passphrase* side is fully non-interactive — `CIPHERPOST_PASSPHRASE`, `--passphrase-file`, and `--passphrase-fd` all let you supply the identity passphrase without a prompt. But `receive` also has a deliberate **human-in-the-loop acceptance step**: it prints the sender's full fingerprint + attested purpose to stderr and requires a human to type back the sender's z-base-32 pubkey to unlock decryption. That step needs a real TTY on both stdin and stderr; there is no `--yes`/`--accept-fingerprint` bypass, and none is planned for v1 — the whole point is that a person verifies *who* they're accepting material from out-of-band before any plaintext is written.

So the supported shape is **attended** receive: a person runs `cipherpost receive <uri>`, checks the fingerprint, and confirms. You can script everything *around* it (identity unlock, output path, DHT timeout), but not the acceptance itself. (`--pin` input is likewise TTY-only for the same reason — see the non-interactive-PIN note in the README's Known limitations.)

</details>

<details>
  
<summary>How do I back up my identity?</summary>

Simply copy `~/.cipherpost/secret_key` to a secure location (encrypted USB, password manager, etc.). There is no built-in backup or cloud sync — you are in control.

</details>

<details>
  
<summary>Is Cipherpost production-ready?</summary>

As of v1.1 (shipped 2026-04-26), the full PRD v1 scope ships: the core protocol, all four typed payload variants (`GenericSecret`, `X509Cert`, `PgpKey`, `SshKey`), `--pin` and `--burn` encryption modes, non-interactive automation, and CAS-protected receipt publication. 326 tests pass under `cargo nextest run --features mock` (338 under `--all-features`); the full PRD v1 requirement set is validated across v1.0 + v1.1.

Larger payloads shipped **experimentally** in v2-alpha (the off-by-default `large-payload` feature, `--self`-only — the crate is now `1.2.0-alpha.1`); full cross-identity large payloads, signed receipts for large pickup, key import, multiple identities, and destruction attestation remain deferred. The v1 core is suitable for careful use. The v1.1.0 cross-identity round trip has been validated against real Mainline DHT — both via a manual CLI demo and the automated regression test, both passing on the same network with no mocks involved. Evidence is checked in at [`RELEASE-EVIDENCE-v1.1.0.md`](./RELEASE-EVIDENCE-v1.1.0.md). Future releases automatically re-run the same gate via the tag-push workflow at [`.github/workflows/release-acceptance.yml`](./.github/workflows/release-acceptance.yml), so each public version publishes its own real-DHT evidence next to the tag.

</details>

<details>
  
<summary>What are the next planned features?</summary>

- Larger payloads via Pubky homeservers — **`--self` shipped experimentally** (`large-payload` feature); remaining: cross-identity `--share`, signed receipts for large pickup, and a DHT-only fallback
- `identity import`
- Multiple identities support
- Compression
- Direct P2P option

</details>

<details>
  
<summary>How can I help?</summary>

- Star the repo
- Try it and open issues
- Review the [SPEC.md](SPEC.md) and [THREAT-MODEL.md](THREAT-MODEL.md)
- Contribute code, documentation, or security review

</details>
