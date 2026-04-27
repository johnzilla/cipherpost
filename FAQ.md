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

We plan to raise this significantly in v1.2+ using a wire-budget escape hatch:
- Two-tier storage: PKARR carries a reference, ciphertext lives on a content-addressable store
- Chunking: split outer record across multiple DNS labels with reassembly
- Out-of-band payload + inline hash commit (closest to the "no servers" principle if the OOB channel is file/URI-based)

See [`SPEC.md` §Pitfall #22](./SPEC.md) and the roadmap in the README.

</details>

<details>
  
<summary>How does the Pubky homeserver integration work?</summary>

When you use the `--homeserver` flag (planned):
- The encrypted payload is uploaded to a homeserver **you choose** (self-hosted or public).
- Only a tiny pointer (URL + path + hash) is published to the DHT.
- The recipient still performs the exact same acceptance flow, then fetches the blob from the homeserver URL.

You remain responsible for the homeserver you point to. The recipient sees the URL before accepting and can decide whether to trust it. Full fallback to the current small-payload-in-DHT mode is planned.

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

Some features (larger payloads via wire-budget escape hatch, key import, multiple identities, destruction attestation) are deferred to v1.2+. It is suitable for careful use with the understanding that real-DHT cross-identity round-trip is a manual per-release gate (see [`RELEASE-CHECKLIST.md`](./RELEASE-CHECKLIST.md)).

</details>

<details>
  
<summary>What are the next planned features?</summary>

- Larger payloads via Pubky homeservers + fallback
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
