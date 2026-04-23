# Feature Research — Cipherpost v1.1 "Real v1"

**Domain:** Self-sovereign CLI tool for cryptographic-material handoff (keys, certs, credentials, passphrases)
**Milestone:** v1.1 — typed payloads (X.509/PGP/SSH), --pin/--burn modes, non-interactive passphrase flags, real-DHT release gate
**Researched:** 2026-04-23
**Confidence:** HIGH on typed-payload display conventions (primary CLI sources); MEDIUM-HIGH on pin/burn semantics (cclink inaccessible — inferred from PRD + competitor research); MEDIUM on real-DHT test shape (PKARR docs available, no empirical timing data); HIGH on passphrase-fd UX (age/gpg precedents)

---

## Context: What v1.0 Already Shipped

These are NOT in scope for this document. Listed only to prevent re-researching:

- `cipherpost send --self | --share <pubkey>` — generic-secret payloads only
- `cipherpost receive` with dual-sig verify, TTL, typed-z32 acceptance, state-ledger idempotency, signed receipt
- `cipherpost receipts --from <z32>` — receipt fetch + verify
- `cipherpost identity generate/show` — passphrase via env/file/fd/TTY; TTY double-confirm on generate
- `cipherpost version` — crate version + git SHA + primitives list
- Wire format JCS-locked; `Material` tag enum (`GenericSecret` shipped; others reserved)
- 64 KB plaintext cap; default TTL 24h; full exit-code taxonomy {0,2,3,4,5,6,7,1}
- Stdin/stdout via `-`; CLI status to stderr; typed-z32 acceptance required
- `resolve_passphrase()` already supports all four priorities (env → file → fd → TTY)

---

## Table Stakes

Features that a user of the described v1.1 capability expects. Missing = feature feels broken.

### Category A — Typed Material Receive UX

| Feature | Why Expected | Complexity | Phase |
|---------|--------------|------------|-------|
| A1: X.509 acceptance screen shows Subject, Issuer, SerialNumber, NotBefore/NotAfter, SHA-256 DER fingerprint, key algorithm | Recipients expect the same fields `openssl x509 -text` would show; anything less = no more informative than GenericSecret | M | 6 |
| A2: PGP acceptance screen shows v4/v5 fingerprint (full 40/64 hex chars), primary UID, key algorithm, subkey count + types, creation time | Recipients need the same fields `gpg --show-keys` shows; fingerprint is the ground-truth check-value | M | 7 |
| A3: SSH acceptance screen shows key type (ed25519/rsa/ecdsa-*), SHA256 fingerprint in OpenSSH format (`SHA256:<base64>`), comment field | Recipients match against `ssh-keygen -l` output; format must be byte-identical for comparison | S | 7 |
| A4: Acceptance screen identifies Material type in header (`Type: x509_cert`, `pgp_key`, `ssh_key`) | v1.0 already shows `Type: generic_secret`; typed variants must extend this, not replace it | S | 6,7 |
| A5: Decoded payload to stdout is raw bytes (DER for certs, binary PGP, OpenSSH wire format) by default; ASCII-armor on `--armor` flag | Recipients pipe to `gpg --import` or `ssh-add`; raw bytes are what tools expect | S | 6,7 |
| A6: Parse failure in Material (malformed DER, corrupt PGP packet) yields exit 1 with message naming the variant; does NOT yield exit 3 | Error-oracle hygiene: material parse failure is a content error, not a signature-verification failure | S | 6,7 |

### Category B — Non-Interactive Passphrase Flags

| Feature | Why Expected | Complexity | Phase |
|---------|--------------|------------|-------|
| B1: `--passphrase-file <path>` on `send` and `receive` sub-commands | identity subcommands already support this; users expect parity across all commands | S | 5 |
| B2: `--passphrase-fd <n>` on `send` and `receive` sub-commands | Same parity argument; CI/CD pipelines use fd-passing to avoid env leak | S | 5 |
| B3: `--passphrase-file` validates mode ≤ 0600 and rejects wider-readable files with clear error | ssh-keygen, gpg, and age all enforce this; security engineers will test it on first use | S | 5 |
| B4: Trailing newline stripped from passphrase read via file or fd | age strips trailing newlines; any tool that doesn't is broken for shell-echoed passphrases | S | 5 |
| B5: `cipherpost send - --passphrase-fd 3` combination works: payload from stdin (fd 0), passphrase from fd 3 | This is the canonical CI usage; if it doesn't work, scripted pipelines are impossible | S | 5 |
| B6: Non-TTY context with no env/file/fd passphrase source exits with `Error::Config` exit 1, never hangs | age behavior: fail fast, never block on missing TTY; subprocess consumers need a clean failure | S | 5 |

### Category C — Pin Mode

| Feature | Why Expected | Complexity | Phase |
|---------|--------------|------------|-------|
| C1: `cipherpost send --pin` prompts sender for a PIN at send time; PIN is an out-of-band second factor | Bitwarden Send "optional password," crypt.fyi "password protection" — every competitor has this concept | M | 8 |
| C2: `cipherpost receive` on a pinned share prompts for PIN before typed-z32 acceptance, not after | PIN gates the decrypt; asking after acceptance defeats the second-factor purpose | S | 8 |
| C3: PIN is never stored by cipherpost; never written to state ledger, never echoed | Same hygiene contract as passphrase — if it touches disk or stderr it leaks | S | 8 |
| C4: Wrong PIN yields same user-facing message as wrong passphrase (`passphrase failed`, exit 4) — indistinguishable from signature failure is NOT required, but PIN vs. passphrase should be unified | Distinguishable-oracle hazard (PITFALL #16): PIN and passphrase failures must not leak which layer failed. Both are exit 4 | S | 8 |

### Category D — Burn Mode

| Feature | Why Expected | Complexity | Phase |
|---------|--------------|------------|-------|
| D1: `cipherpost send --burn` marks the share as single-consumption: a second `receive` on the same share_ref returns a distinct error (not "already accepted") | Burn is semantically stronger than v1.0 idempotency; the caller expects "consumed" behavior | M | 8 |
| D2: First successful `receive` of a burn share atomically writes sentinel + ledger BEFORE receipt publish, identical to normal flow | Burn is at the state-ledger layer; the existing sentinel mechanism is the right enforcement point | S | 8 |
| D3: Burn shares display `Mode: burn-after-read` on the acceptance screen | Recipient must know they're consuming the share; not displaying it is a UX failure | S | 8 |
| D4: Burn mode does NOT attempt to delete from DHT | PKARR is append-only / republish; deletion is impossible without operator; burn = single-consumption semantics only, not physical destruction | S | 8 |

### Category E — Real-DHT Release Gate

| Feature | Why Expected | Complexity | Phase |
|---------|--------------|------------|-------|
| E1: Cross-identity send → receive round trip works over real Mainline DHT (two distinct keypairs, two invocations, no MockTransport) | This is the whole point; MockTransport exercises code paths but not the live protocol | M | 9 |
| E2: Receipt is published under recipient's real PKARR key and fetchable by sender via real DHT | Receipt is the cipherpost delta; if it doesn't propagate on real DHT the signed-receipt guarantee is untested | M | 9 |
| E3: Concurrent-racer test: two goroutines/threads simultaneously calling `publish_receipt` under the same recipient key; CAS guard prevents clobber | resolve-merge-republish uses `cas`; without a racer test the CAS invariant is untested under concurrent load | M | 9 |
| E4: PKARR merged SignedPacket with `_cipherpost` + at least one `_cprcpt-*` record survives within 1000-byte budget | Coexistence at the budget boundary is a real deployment concern; budget must be validated empirically | S | 9 |

---

## Differentiators

Capabilities beyond baseline that cipherpost uniquely offers in v1.1.

| Feature | Value Proposition | Complexity | Phase |
|---------|-------------------|------------|-------|
| DIF-1: X.509 acceptance shows both Subject AND Issuer before decrypt | Tools like `openssl x509 -text` always show both; cipherpost's acceptance screen makes this a security property — you confirm issuer before decrypting the private key | S | 6 |
| DIF-2: Material type displayed in acceptance screen before commit | No other handoff tool shows the payload type pre-accept; typed payloads make this meaningful (you know you're accepting an X.509 key, not a generic secret) | S | 6,7 |
| DIF-3: `--pin` uses age scrypt passphrase-recipient (not a separate KDF layer) | Using age's built-in scrypt recipient means the PIN is hardware-bounded like identity unlock; no separate PIN-KDF logic to audit; no nonce-reuse surface | M | 8 |
| DIF-4: Burn-mode single-consumption is enforced client-side via state ledger sentinel | DHT is immutable; cipherpost's sentinel is what makes burn meaningful — the sender's receipt confirms consumption occurred | S | 8 |
| DIF-5: Real-DHT test is a release-acceptance gate, not a CI-optional test | Other PKARR-using projects don't gate releases on real-DHT round trips; cipherpost does — this is a protocol correctness signal, not just a smoke test | M | 9 |

---

## Anti-Features

Capabilities explicitly excluded from v1.1 scope, with reasons.

| Anti-Feature | Why Users Ask | Why Excluded | Redirect |
|--------------|---------------|--------------|---------|
| AF-1: Keyring support for PgpKey (import all keys from a keyring file) | "I have a keyring with 3 keys, send them all" | 64 KB plaintext cap would be exceeded by most real keyrings; single-key semantics maps cleanly to the handoff model; keyring semantics would require selecting which key to send | Send each key individually; the single-key constraint is by design (per PROJECT.md "PgpKey = single key, not keyring") |
| AF-2: X.509 chain validation (verify chain back to a trusted root at receive time) | "Validate this cert is issued by a real CA" | Cipherpost hands off material, it doesn't validate its security properties; chain validation requires a trust store and changes the tool's role from handoff to verification | Use `openssl verify -CAfile <root>` post-receive |
| AF-3: PIN with email OTP or TOTP | "Use my authenticator app as the PIN" | Requires an operator (OTP issuer or TOTP server) — violates Principle #1 (no servers) | Use a short out-of-band code communicated via Signal/phone |
| AF-4: Auto-renew / extend TTL on receive | "The burn share should reset TTL after a failed PIN attempt" | Each share is immutable; TTL is inner-signed; extension requires a new share | Sender re-sends with new `--pin` |
| AF-5: Destruction attestation (prove recipient deleted the material) | "I need proof the private key was deleted" | Destruction attestation was deferred to v1.2; it requires recipient-side attestation infrastructure not yet built | Wait for v1.2 |
| AF-6: PGP subkey-only shares (send only the subkey, not the primary) | "I only want to share the encryption subkey" | Subkey extraction from a PGP Cert is Sequoia/rpgp internals; without full Cert semantics the key is not importable | Send the full single-primary-key Cert; recipient extracts what they need |
| AF-7: DHT deletion of a burn share after first receive | "Delete it from the DHT so nobody can see the ciphertext" | PKARR SignedPackets are republished by DHT nodes; cipherpost cannot force deletion without an operator; burn = single-consumption, not physical destruction (and DHT observers see only opaque blobs anyway) | The ciphertext on DHT is useless without the key; burn semantics are sufficient |
| AF-8: Multi-recipient pin-protected send | "Send the same pinned share to three people" | Receipt semantics are pairwise; burn-mode + pin + multi-recipient would require rethinking who "consumes" the share | Deferred to v1.2 multi-recipient scope |
| AF-9: Interactive PIN confirmation on `send` (re-prompt for PIN) | "Confirm PIN entry like passphrase confirmation on identity generate" | Short PIN entered twice provides minimal added safety; the out-of-band communication of the PIN is the security property | PIN is entered once; communication channel security is the user's responsibility |
| AF-10: TUI wizard for typed payloads | "Walk me through filling in an X.509 send" | TUI deferred to v1.2; CLI surface is sufficient for typed payloads (type is inferred from file extension / `--type` flag) | CLI with `--type x509` flag |

---

## Feature Detail — Typed Material Receive UX

### X.509 Certificate (`Material::X509Cert`) — Phase 6

**Convention source:** `openssl x509 -text -noout` output is the canonical expectation. The acceptance screen should display a subset of those fields relevant to identity verification.

**Required acceptance screen fields (stderr, before typed-z32 confirm):**

```
Type:        x509_cert
Subject:     CN=example.com, O=Example Corp, C=US
Issuer:      CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US
Serial:      04:b2:5f:...  (truncated to 12 hex bytes + "..." if > 12 bytes)
Valid from:  2025-01-01 00:00:00 UTC
Valid until: 2025-04-01 00:00:00 UTC  [EXPIRED] or [expires in 3d 14h]
Key alg:     RSA 2048-bit  (or Ed25519, ECDSA P-256, etc.)
SHA-256:     aa:bb:cc:...  (DER fingerprint, colon-separated hex, full 32 bytes)
Size:        <N> bytes (DER)
```

**Stdout output:** Raw DER bytes (binary). Pipe to `openssl x509 -in /dev/stdin -inform DER -text` for human inspection. ASCII-armored PEM via `--armor` flag (base64-encode DER, wrap with `-----BEGIN CERTIFICATE-----`).

**Parse library:** `x509-parser` (rusticata/x509-parser) — pure Rust, zero-copy, no C FFI, gives Subject/Issuer as `X509Name`, Validity as `ASN1Time`, key algorithm via `SubjectPublicKeyInfo`. SHA-256 fingerprint: `sha2::Sha256::digest(der_bytes)`. Complexity: M (parsing is straightforward; the display rendering is where care is needed).

**Wire form for Material::X509Cert:**
```json
{"type": "x509_cert", "der": "<base64-STANDARD>"}
```
Single field: raw DER bytes, base64-encoded. PEM is rejected at send time (convert to DER first). Rationale: DER is canonical; PEM is a base64 wrapper that adds ambiguity about which cert in a chain is meant.

**Edge cases:**
- Self-signed cert: Issuer == Subject — display both verbatim, no elision
- Expired cert: show `[EXPIRED]` tag in red (or `[EXPIRED]` in plain text if NO_COLOR) — do not block acceptance; the recipient may legitimately be receiving an expired cert for archival
- Multiple SANs: list up to 3 SANs in acceptance screen; truncate with `(+N more)`
- Cert chain (multiple certs in DER stream): rejected at send time; `--type x509` accepts exactly one DER cert; multi-cert chain is anti-feature AF-2

**64 KB cap interaction:** Standard X.509 certs are 1-4 KB DER; 64 KB cap is effectively unreachable for single certs. No special handling needed.

---

### PGP Key (`Material::PgpKey`) — Phase 7

**Convention source:** `gpg --show-keys` (non-import inspection) and `gpg -k --with-fingerprint --with-subkey-fingerprint` output shape the expected fields.

**Required acceptance screen fields (stderr):**

```
Type:        pgp_key
Fingerprint: AABB CCDD EEFF 0011 2233  4455 6677 8899 AABB CCDD  (v4: 40 hex, grouped)
             or AABB CCDD ... CCDD  (v5: 64 hex, grouped)
Primary UID: Alice Example <alice@example.com>
Key alg:     Ed25519 / RSA 4096-bit / ECDSA P-256  (primary key algorithm)
Created:     2024-01-15
Subkeys:     2  (ed25519/sign, cv25519/encr)  (or: "none")
Size:        <N> bytes (binary)
```

**Stdout output:** Raw binary OpenPGP packet (importable via `gpg --import`). ASCII-armor on `--armor` (`-----BEGIN PGP PUBLIC KEY BLOCK-----`).

**PgpKey vs keyring constraint (enforced at send):** Reject any input that contains more than one primary key. "Single key" means one primary key + its associated subkeys. A keyring file with two primary keys is rejected at send time with exit 1 and message: `"pgp_key payload must contain exactly one primary key; found N"`.

**v4 vs v5 fingerprint detection:** v4 fingerprints are 20 bytes (40 hex chars); v5 are 32 bytes (64 hex chars). Detection is automatic from packet format. No user-facing selection needed.

**Parse library:** `rpgp` (rpgp/rpgp) — pure Rust, permissive license (MIT/Apache), no system GPG dependency, can parse and serialize binary OpenPGP packets. Alternative: `sequoia-openpgp` (GPL-2.0 — **check license compatibility with MIT project**; sequoia-openpgp is LGPL actually). Recommendation: `rpgp` for MIT compatibility and no system deps; complexity M.

**Wire form for Material::PgpKey:**
```json
{"type": "pgp_key", "bytes": "<base64-STANDARD>"}
```
Same pattern as `GenericSecret.bytes` — raw binary OpenPGP packet, base64-encoded. The binary form is what `gpg --import` consumes directly.

**Edge cases:**
- Secret key accidentally sent: should cipherpost warn? Yes — parse primary key packet; if it's a secret key packet, prepend warning to acceptance screen: `[WARNING: this payload contains a SECRET key, not a public key]`. Do not reject; the handoff of a secret key is the primary use case.
- UID with no valid self-signature: rpgp will parse it; display raw UID string with `[no self-sig]` note
- Key with no UID: display `[no UID]`
- Revoked key: display `[REVOKED]` based on revocation certificate presence; still allow accept

---

### SSH Key (`Material::SshKey`) — Phase 7

**Convention source:** `ssh-keygen -l -f <key>` output format is the canonical fingerprint display. The output format is: `<bits> SHA256:<base64> <comment> (keytype)`.

**Required acceptance screen fields (stderr):**

```
Type:        ssh_key
Key type:    Ed25519  (or RSA 4096, ECDSA 256, etc.)
Fingerprint: SHA256:abc...def  (OpenSSH-style, base64, no trailing =)
Comment:     user@host  (or "[no comment]" if empty)
Size:        <N> bytes (wire format)
```

**Note on comment:** The SSH comment field is metadata, not part of the cryptographic identity. Two keys with the same fingerprint but different comments are the same key. The comment should be displayed but explicitly noted as non-cryptographic: `Comment: user@host  (not cryptographically verified)`.

**Stdout output:** Raw OpenSSH wire format (the `BEGIN OPENSSH PRIVATE KEY` or bare public key line format). For private keys: binary OpenSSH format importable via `ssh-add`. For public keys: the one-line `ssh-ed25519 AAAA... comment` format usable directly in `authorized_keys`.

**Parse library:** `ssh-key` crate (RustCrypto/SSH) — pure Rust, supports all key types (Ed25519, RSA, ECDSA P-256/P-384/P-521, DSA), produces OpenSSH SHA-256 fingerprints, extracts comment field. MIT/Apache licensed. Complexity: S (the crate does most of the work).

**Wire form for Material::SshKey:**
```json
{"type": "ssh_key", "bytes": "<base64-STANDARD>"}
```
Same pattern — raw OpenSSH wire bytes (binary), base64-encoded. Accept either private key format or public-key-only format; display distinguishes them (`[public key]` vs `[private key]`).

**Edge cases:**
- DSA keys: parse and display, but prepend: `[WARNING: DSA keys are deprecated; consider Ed25519]`
- RSA < 2048 bits: prepend: `[WARNING: RSA key size <N> bits is below recommended 2048]`
- Private key with passphrase: the crate detects encrypted private keys; display: `[PROTECTED: private key is passphrase-encrypted]` — do not attempt to decrypt; the recipient's passphrase for the SSH key is their own concern
- Comment with control characters: strip same as purpose field (ASCII C0+C1 strip at parse time)

---

## Feature Detail — `--pin` Mode Semantics

### Threat model role

PIN mode is a second factor for the case where the share URI leaks but the PIN does not. The adversary has the share URI (DHT is public) and the recipient's public key but not the PIN. The PIN must provide meaningful entropy above the share URI alone.

**What PIN is NOT:** authentication of the recipient's identity (that's already the pubkey). PIN is not binding to the recipient — anyone who has the share URI + PIN can decrypt. This is the same model as Bitwarden Send's password protection.

**Distinguishable-oracle hazard (PITFALL #16):** PIN verification failure must be indistinguishable from passphrase-unlock failure. Both exit with code 4 and the same message `passphrase failed`. The PIN layer is inside the age-decrypt layer, so wrong PIN = age decrypt failure = exit 4 automatically. No special handling needed IF implementation is correct.

### Recommended implementation: age scrypt passphrase-recipient as the PIN layer

**How it works:**

1. Sender runs `cipherpost send --pin --share <pubkey>`. Cipherpost prompts for PIN on TTY (no echo). PIN entropy minimum: 8 characters (enforced; shorter rejected with a warning).
2. At encryption time, the Envelope is age-encrypted with TWO recipients: the standard X25519 recipient (from recipient's Ed25519 key) AND an age scrypt passphrase-recipient derived from the PIN. age's multi-recipient mode means BOTH keys can decrypt, but in cipherpost's protocol, the X25519 recipient key is used by the legitimate recipient, and the scrypt recipient is the PIN layer — recipient must supply BOTH.
3. Actually: the correct model is **nested** — not two age recipients. Inner: encrypt Envelope to X25519 recipient as normal. Outer: wrap the age-encrypted blob in a SECOND age scrypt envelope keyed to the PIN. This means: wrong PIN = first layer fails, never reaches the X25519 decrypt. Correct PIN = outer decrypts to reveal the inner ciphertext; then identity key decrypts inner.

**Rationale for nested over multi-recipient:**
- Multi-recipient would mean the PIN alone could decrypt (without the identity key) — that violates the intent (PIN is a second factor, not an alternative factor)
- Nested: PIN AND identity key both required
- This is the only model that achieves "second factor" semantics

**Wire form change:** `OuterRecord.blob` contains a double-wrapped age ciphertext when `--pin` is active. No wire-format change needed beyond a new field in `OuterRecord` or `Envelope` to signal PIN mode. Recommendation: add `pin_protected: bool` to `OuterRecordSignable` (inner-signed, so not malleable). This bumps the wire-format test fixture — coordinate with JCS fixture update.

**Acceptance screen addition:**
```
PIN mode:    yes  (you will be prompted for a PIN before decryption)
```
PIN prompt appears on stderr BEFORE typed-z32 acceptance (C2 above), because wrong PIN should fail before the user types the z32 — saves frustration.

**UX flow for receive with --pin share:**
1. Render acceptance screen (shows `PIN mode: yes`)
2. Prompt for PIN: `Enter PIN for this share: ` (no echo)
3. Attempt outer age-decrypt with PIN — wrong PIN: `passphrase failed`, exit 4
4. If PIN correct, proceed to typed-z32 acceptance as normal
5. Decrypt inner layer with identity key; proceed to output

**Entropy floor:** 8 characters minimum, checked at send time. A 4-digit PIN (10^4 = 10,000 combos) is insufficient — even with scrypt, DHT exposure means unlimited offline tries are theoretically possible against the scrypt layer. 8 chars with alphanumeric gives ~47 bits. Document this requirement clearly.

**`--passphrase-fd` for PIN in non-interactive send:** `cipherpost send --pin --passphrase-fd 3` should read the identity passphrase from fd 3 as normal, but the PIN must come from a separate source. Options: a second `--pin-fd <n>` flag, or require TTY for PIN when `--pin` is active. Recommendation: require TTY for PIN at send time; `--pin-file <path>` for receive in scripted contexts. Defer `--pin-fd` to a later cleanup pass.

---

## Feature Detail — `--burn` Mode Semantics

### Threat model role

Burn is an ephemerality guarantee at the application layer: the share can only be successfully received once. It does NOT provide:
- Physical deletion from DHT (impossible — see AF-7)
- Deniability (the ciphertext exists on DHT regardless)
- Receiver-deletion proof (that's destruction attestation, deferred to v1.2)

Burn provides: **single-consumption enforcement at the recipient's state ledger**, plus **a receipt that signals to the sender that the one permitted receive occurred**.

### Interaction with v1.0 idempotency

v1.0 made receive idempotent: second receive on the same `share_ref` returns the prior acceptance timestamp and exits 0. Burn **inverts** this: second receive on a burned share_ref returns a distinct error.

**The distinction is signaled in the share's Envelope.** A new boolean field `burn: bool` (or `single_use: bool`) in `Envelope` (inner-signed) tells the receiver to use burn semantics. The state ledger already tracks `share_ref`; the burn flag changes how a second receive is handled.

**State machine for a burn share:**

```
First receive:
  - Sentinel file does NOT exist → proceed normally → write sentinel → publish receipt → exit 0
  
Second receive:
  - Sentinel file exists AND burn flag is true → exit N with message "share already consumed"
  - (Compare: non-burn second receive exits 0 with "already accepted on <date>")
```

**Exit code for "already consumed":** This needs a new exit code. Recommendation: exit 2 with message `"share already consumed"` — it's a form of expiry (the share's single-use TTL has elapsed). Alternatively, exit 7 with `"share consumed"` — declined semantics. Best: new exit code 8 (`consumed`) to distinguish from TTL expiry (2) and user-declined (7). Decision for requirements; flag here as an open choice.

**Wire form change:** New `burn: bool` field in `Envelope` struct (inner-signed, JCS-locked). Default `false` (non-burn). Bump `OuterRecordSignable` JCS fixture hash. Coordinate with pin wire-format bump.

**Acceptance screen addition:**
```
Mode:        burn-after-read  (this share can only be received once)
```

**`--burn` + `--pin` combination:** Supported — PIN protects the outer layer; burn protects the use count. Both can be active simultaneously. The wire form carries both `pin_protected: true` and `burn: true` fields.

**`--burn` + idempotent receive conflict:** A non-burn share's second receive is idempotent (exit 0, no receipt re-publish). A burn share's second receive is a hard error. The implementation must check the burn flag before applying the idempotency path. The existing `check_sentinel` function becomes: `check_sentinel(share_ref, is_burn)`.

---

## Feature Detail — Non-Interactive Passphrase UX

### Conventions (from age, gpg, ssh precedents)

The `resolve_passphrase()` function already exists in v1.0 `identity` subcommands. v1.1 Phase 5 wires it into `send`/`receive` clap surface.

**Error handling per source:**

| Source | Error condition | Expected behavior |
|--------|----------------|-------------------|
| `--passphrase-file <path>` | File not found | Exit 1: `passphrase file not found: <path>` |
| `--passphrase-file <path>` | Mode > 0600 | Exit 1: `passphrase file permissions too open (mode 0NNN); use chmod 600` |
| `--passphrase-file <path>` | Empty file | Exit 4: `passphrase failed` (empty passphrase is treated as wrong passphrase, not a config error) |
| `--passphrase-fd <n>` | fd not open / bad fd | Exit 1: `passphrase fd <n> not available` |
| `--passphrase-fd <n>` | fd is a regular file, not a pipe | No error — read succeeds regardless of fd type; the mode-check is only for `--passphrase-file` |
| Trailing newline | Any source | Strip `\n` and `\r\n`; no other whitespace stripping (a space-padded passphrase should be honored) |
| `CIPHERPOST_PASSPHRASE` env | Set but empty | Exit 4: `passphrase failed` — treat as wrong passphrase |
| None of the above | Non-TTY stdin | Exit 1: `Error::Config` — no passphrase source and not a TTY |

**`cipherpost send - --passphrase-fd 3` interaction:**

The risk: stdin (fd 0) carries the payload; fd 3 carries the passphrase. These must not be confused. The existing `resolve_passphrase()` reads from fd N directly (not from stdin). No conflict IF the fd argument is explicit. Implementation must open fd 3 as a `File::from_raw_fd(3)` (unsafe, but standard pattern) and read from it, not from stdin. Complexity: S.

**Python/Node subprocess gotcha:** When a subprocess spawns cipherpost with `--passphrase-fd 3`, the child process fd 3 must be explicitly kept open (not marked CLOEXEC). In Python: `pass_fds=(3,)` in `subprocess.run()`. In Node: `stdio: ['pipe', 'pipe', 'pipe', 'pipe']` (4-element array opens fd 3). Document this in `--help` for `--passphrase-fd`.

**Trailing newline stripping:** age strips trailing `\n` and `\r\n` from passphrase reads; cipherpost should match. The v1.0 `resolve_passphrase()` should be audited for this — if it doesn't strip, add it in Phase 5.

---

## Feature Detail — Real-DHT Release Gate

### What "working on Mainline DHT" means

**Minimum viable test (Phase 9):**

1. Generate two fresh cipherpost identities (keypair A, keypair B) in distinct `CIPHERPOST_HOME` directories
2. Run `cipherpost send --share <B_pubkey>` under identity A → get share URI
3. Run `cipherpost receive <URI>` under identity B → complete acceptance → get decrypted payload
4. Run `cipherpost receipts --from <B_z32>` under identity A → verify signed receipt present

All four steps must succeed over real Mainline DHT with no MockTransport.

**Propagation latency budget:** Based on Mainline DHT literature (p50 lookup ~1 minute, p90 several minutes, NAT traversal adds variance), the test should allow up to 5 minutes between publish and resolve. This is a manual release-acceptance test, not a CI test with a 30-second timeout. Recommendation: document in SPEC.md and test runner script with a `--dht-timeout 300` flag.

**Receipt coexistence test (PKARR merge-update race):**

The concurrent-racer test (E3) does the following:
1. Publish an outgoing share under identity B's PKARR key (`_cipherpost` label) via MockTransport (to set initial state)
2. Spawn two threads simultaneously, each calling `publish_receipt` under identity B for different `share_ref` values
3. Assert both receipts are present after both threads complete, and the `_cipherpost` outgoing share is not clobbered
4. The CAS mechanism in `DhtTransport::publish_receipt` is what prevents clobber; MockTransport must be updated to enforce CAS semantics (currently it may overwrite unconditionally)

**PKARR 1000-byte budget with receipts:** Each TXT record in a PKARR SignedPacket consumes label bytes + value bytes. A single Receipt JSON is approximately 400-500 bytes (per SPEC.md §8.2 fixture: 424 bytes for ReceiptSignable, slightly more for full Receipt with signature). With `_cipherpost` (OuterRecord ~500 bytes) + one `_cprcpt-<32-hex>` (Receipt ~480 bytes) = ~980 bytes + DNS packet overhead. Budget is tight. The existing `Error::WireBudgetExceeded` path handles overflow; the test should verify what happens when a second receipt would push over budget.

**DHT propagation note for receipt:** The recipient's receipt is published to the recipient's own PKARR key. For the sender to fetch it, they must resolve the recipient's key from DHT. DHT propagation for the receipt publication is subject to the same latency as the share publication — budget 5 minutes.

---

## Feature Dependencies (v1.1)

```
Phase 5: Non-interactive passphrase on send/receive
    └── prereq: resolve_passphrase() already exists (v1.0 identity subcommands)
    └── enables: scripted automation of typed-payload sends (Phase 6-7 testing)
    └── enables: CI-scriptable pin/burn test harness (Phase 8)

Phase 6: Material::X509Cert
    └── prereq: Phase 5 (passphrase automation for test scripting)
    └── establishes pattern for: Phase 7 (PgpKey, SshKey)
    └── requires: x509-parser crate addition
    └── wire-format: new Material::X509Cert variant — backwards compatible (reserved in v1.0)

Phase 7: Material::PgpKey + Material::SshKey
    └── prereq: Phase 6 (X509 pattern established)
    └── requires: rpgp crate + ssh-key crate additions
    └── PgpKey must enforce single-primary-key constraint at send time
    └── wire-format: two new Material variants — backwards compatible

Phase 8: --pin + --burn modes
    └── prereq: Phase 6-7 (typed payloads give pin/burn semantic value)
    └── wire-format changes: Envelope gains `burn: bool`; OuterRecordSignable gains `pin_protected: bool`
    └── BOTH wire-format changes require JCS fixture updates
    └── --burn inverts v1.0 idempotency: check_sentinel() must be aware of burn flag
    └── --pin uses nested age scrypt wrapping: new age encrypt/decrypt path

Phase 9: Real-DHT round trip + CAS racer test
    └── prereq: all Phase 5-8 features (full round trip exercised)
    └── requires: network access in test environment
    └── MockTransport CAS enforcement must be added for racer test
    └── This phase is a release gate, not a feature gate
```

---

## MVP / Scope Recommendation per Phase

### Phase 5 — Non-interactive passphrase (SHIP ALL)

All B-category features are table stakes. The `resolve_passphrase()` function exists; this is plumbing + clap surface. Zero reason to defer any of B1-B6.

### Phase 6 — X.509 (SHIP: A1, A4, A5, A6 for X.509; defer --armor to Phase 7 cleanup)

X.509 is the pattern-establishing phase. Ship the minimal correct implementation: DER in, acceptance screen with the 6 fields listed, raw DER out. ASCII-armor (`--armor`) can slip to Phase 7 since PGP ASCII armor is more commonly needed than X.509 PEM.

### Phase 7 — PGP + SSH (SHIP: A2, A3, A4, A5, A6 for both types)

Apply the X.509 pattern. PGP is M complexity (rpgp parsing + display rendering); SSH is S (ssh-key crate does the heavy lifting). Ship both in one phase as planned.

### Phase 8 — pin + burn (SHIP: C1-C4, D1-D4; defer --pin-fd to later)

Ship nested-age-scrypt PIN and state-ledger burn. Defer `--pin-fd` (receive-side non-interactive PIN) to a follow-up — it's a convenience for automation, not a correctness requirement. The exit code for "already consumed" (burn second-receive) needs to be decided before implementation — surface this as an open question in requirements.

### Phase 9 — Real-DHT gate (SHIP: E1-E4 as release-acceptance, not CI)

The real-DHT test is manual and release-gated. The CAS racer test (E3) is the only automated addition — it runs under MockTransport (updated to enforce CAS). Real-DHT round trip is documented as a manual pre-release checklist item.

---

## Open Questions for Requirements

1. **Exit code for burn "already consumed":** Exit 2 (expired semantics), exit 7 (declined semantics), or new exit 8 (consumed)? Impacts SPEC.md exit-code taxonomy.

2. **PIN minimum length:** 8 characters recommended; PRD is silent. Should this be a hard rejection or a stern warning?

3. **`--pin-fd` on receive:** Required for v1.1 automation or defer to later? If deferred, `--pin` receive is TTY-only (reasonable default).

4. **Envelope `burn: bool` default serialization:** `false` should be omitted from the wire (use `#[serde(skip_serializing_if = "is_false")]`) to avoid changing the JCS bytes for existing non-burn shares? Or always present? JCS compatibility with v1.0 wire format depends on this choice.

5. **Sequoia vs rpgp for PgpKey:** sequoia-openpgp is LGPL (compatible with MIT distribution); rpgp is MIT/Apache. Both are fine license-wise. Sequoia has more thorough test coverage; rpgp has fewer transitive deps. Recommendation: rpgp unless Sequoia is preferred for ecosystem alignment.

6. **Real-DHT test environment:** What's the test machine's NAT situation? If behind symmetric NAT, PKARR DHT lookups may fail at higher rates. Document expected pass rate (e.g., "3 consecutive successful round trips before release").

---

## Sources

### Typed payload display conventions (HIGH — primary sources)

- [openssl x509 manpage — Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man1/x509.1ssl.html) — canonical x509 -text field set
- [x509-parser crate docs](https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509Certificate.html) — Subject, Issuer, Validity, SubjectPublicKeyInfo accessor API
- [gpg --show-keys documentation](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html) — canonical PGP key display fields
- [sequoia-openpgp Cert struct](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/cert/struct.Cert.html) — Rust API for Cert, UID, subkeys
- [rpgp GitHub](https://github.com/rpgp/rpgp) — pure-Rust MIT/Apache OpenPGP parser
- [ssh-key crate docs](https://docs.rs/ssh-key/latest/ssh_key/) — SHA256 fingerprint, comment, key type extraction
- [ssh-keygen fingerprint format — Baeldung](https://www.baeldung.com/linux/ssh-compare-fingerprint-formats) — SHA256:<base64> canonical format confirmed

### Non-interactive passphrase UX (HIGH — age primary source + gpg comparison)

- [age non-interactive passphrase discussion #256](https://github.com/FiloSottile/age/discussions/256) — AGE_PASSPHRASE_FD behavior; trailing newline stripping
- [age passphrase + stdin discussion #685](https://github.com/FiloSottile/age/discussions/685) — stdin conflict with payload; --passphrase-fd pattern
- [gpg --passphrase-file regression T1928](https://dev.gnupg.org/T1928) — file permissions and gpg-agent loopback considerations

### Pin/burn semantics (MEDIUM — competitor research; cclink inaccessible)

- [crypt.fyi — burn-after-read implementation](https://github.com/osbytes/crypt.fyi) — password + burn combined; bot-burn protections
- [Bitwarden Send password protection](https://bitwarden.com/products/send/) — separate auth layer on top of E2E encryption
- [age authentication model](https://words.filippo.io/age-authentication/) — multi-recipient vs. nested encryption semantics
- [PINs for cryptography with Secure Elements — Filippo Valsorda](https://words.filippo.io/secure-elements/) — entropy floor discussion for short PINs

### PKARR / Mainline DHT (MEDIUM — official docs; no empirical timing data found)

- [pkarr GitHub — pubky/pkarr](https://github.com/pubky/pkarr) — 1000-byte budget, TXT records, republish semantics
- [Mainline DHT — Wikipedia](https://en.wikipedia.org/wiki/Mainline_DHT) — lookup latency characteristics
- [Mainline DHT censorship resistance — Pubky Medium](https://medium.com/pubky/mainline-dht-censorship-explained-b62763db39cb) — PKARR ecosystem context

---

*Feature research for: Cipherpost v1.1 "Real v1"*
*Researched: 2026-04-23*
