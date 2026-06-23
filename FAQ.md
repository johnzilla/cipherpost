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
  
<summary>Is my data stored on the DHT forever?</summary>

No. DHT records have natural expiration (typically hours to days). You can republish if needed. For longer-lived storage, use a homeserver or other content-addressed storage.

</details>

<details>
  
<summary>Who can see my payloads?</summary>

- Only the intended recipient can decrypt them.
- Anyone can see the *encrypted* blobs (or pointers) on the DHT.
- The sender’s and recipient’s public keys are visible (by design).

</details>

<details>
  
<summary>Do both parties need to be online at the same time?</summary>

Through v1.1: Yes (for the full send → receive → receipt flow), though the parties don't need to be online *simultaneously* — the DHT holds the share for up to its TTL (24h default). The sender publishes, then can go offline; the recipient must come online to receive within the TTL window. The signed-receipt loop closes when either the sender comes back online to fetch it, or the recipient publishes it (whichever order; both work).

Future versions with homeservers or chunking will support fully asynchronous operation with longer-lived shares.

</details>

<details>
  
<summary>How do I back up my identity?</summary>

Simply copy `~/.cipherpost/secret_key` to a secure location (encrypted USB, password manager, etc.). There is no built-in backup or cloud sync — you are in control.

</details>

<details>
  
<summary>Is Cipherpost production-ready?</summary>

As of v1.1 (shipped 2026-04-26), the full PRD v1 scope ships: the core protocol, all four typed payload variants (`GenericSecret`, `X509Cert`, `PgpKey`, `SshKey`), `--pin` and `--burn` encryption modes, non-interactive automation, and CAS-protected receipt publication. 311 tests pass under `cargo test --features mock`; 116/116 v1 requirements are validated across v1.0 + v1.1.

Some features (larger payloads via wire-budget escape hatch, key import, multiple identities, destruction attestation) are deferred to v1.2+. It is suitable for careful use. The v1.1.0 cross-identity round trip has been validated against real Mainline DHT — both via a manual CLI demo and the automated regression test, both passing on the same network with no mocks involved. Evidence is checked in at [`RELEASE-EVIDENCE-v1.1.0.md`](./RELEASE-EVIDENCE-v1.1.0.md). Future releases automatically re-run the same gate via the tag-push workflow at [`.github/workflows/release-acceptance.yml`](./.github/workflows/release-acceptance.yml), so each public version publishes its own real-DHT evidence next to the tag.

</details>

<details>
  
<summary>What are the next planned features?</summary>

- Larger payloads via Pubky homeservers — **`--self` shipped experimentally** (`large-payload` feature); remaining: cross-identity `--share`, signed receipts for large pickup, and a DHT-only fallback
- `identity import`
- Multiple identities support
- Compression
- Direct P2P option
- Typed payloads (X.509, SSH keys, etc.)

</details>

<details>
  
<summary>How can I help?</summary>

- Star the repo
- Try it and open issues
- Review the [SPEC.md](SPEC.md) and [THREAT-MODEL.md](THREAT-MODEL.md)
- Contribute code, documentation, or security review

</details>
