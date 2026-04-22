# Cipherpost Threat Model

> **Status: DRAFT — skeleton milestone**
>
> This document describes the walking-skeleton implementation shipped in Phases 1–3 of the
> first development milestone (2026-04).
> Wire-format decisions documented here are **stable** — changes require a protocol version bump.
> Editorial polish, completeness review, and v1.0-final sign-off are scheduled for a later phase.

**Protocol version covered:** `cipherpost/v1`
**Companion documents:** [`SPEC.md`](./SPEC.md) (protocol specification), [`SECURITY.md`](./SECURITY.md) (vulnerability disclosure policy).

## Table of Contents

1. [Trust Model](#1-trust-model)
2. [Identity Compromise](#2-identity-compromise)
3. [DHT Adversaries](#3-dht-adversaries)
   - 3.1 [Sybil](#31-sybil)
   - 3.2 [Eclipse](#32-eclipse)
   - 3.3 [Replay](#33-replay)
4. [Sender-Purpose Adversary](#4-sender-purpose-adversary)
5. [Acceptance-UX Adversary](#5-acceptance-ux-adversary)
6. [Passphrase-MITM Adversary](#6-passphrase-mitm-adversary)
7. [Receipt-Replay / Race Adversary](#7-receipt-replay--race-adversary)
8. [Out of Scope Adversaries](#8-out-of-scope-adversaries)
9. [Lineage](#9-lineage)

## 1. Trust Model

Cipherpost's security model makes a narrow set of trust assumptions. Understanding these
baseline trusts is a prerequisite for reading the adversary analysis below — every mitigation
in later sections presupposes that everything in this section holds.

**Cipherpost trusts:**

- **The sender's local environment** — disk contents at `~/.cipherpost/`, the process reading
  the passphrase, the `age` keys derived from the identity. Cipherpost cannot defend against an
  adversary who already holds the sender's disk + passphrase.
- **The recipient's local environment** — same caveat, symmetrically.
- **Cryptographic primitives** — `age 0.11` (X25519 + ChaCha20-Poly1305), Ed25519 via
  `ed25519-dalek =3.0.0-pre.5`, Argon2id via `argon2 0.5`, HKDF-SHA256 via `hkdf 0.12`, SHA-256
  via `sha2 0.10`. The security proofs for these primitives and the correctness of their
  constant-time implementations are pre-assumed.
- **RFC 8785 JCS implementation** — `serde_canonical_json 1.0.0`. Canonicalization
  non-determinism would break every inner signature; see §7 for the specific race that assumes
  this trust.

**Cipherpost does NOT trust:**

- **The Mainline DHT** — neither its confidentiality nor its integrity. DHT nodes can see every
  published packet; they can fail to deliver any packet; they can collude to hide packets from
  specific requesters. See §3.
- **The wire** — SignedPacket contents are visible to every DHT participant. All ciphertext is
  inside `OuterRecord.blob` which is age-encrypted; all metadata (`purpose`, `material`, etc.)
  is inside the encrypted blob. Only `pubkey`, `recipient`, `share_ref`, `created_at`,
  `ttl_seconds`, `signature`, and `protocol_version` leak to the DHT observer (SPEC.md#3-wire-format,
  specifically §3.3 OuterRecord).
- **The sender's claims about the material** — `purpose` is sender-attested (SPEC.md#31-envelope,
  D-WIRE-05). See §4.
- **Third-party purpose verification** — no party other than the sender attests to the purpose.
  Not the recipient's client. Not the DHT. Not a CA.

**Liveness vs. integrity:** We trust the DHT's **liveness** enough to use it as rendezvous — if
a share is published and within TTL, *some* resolver in the DHT is expected to return it. We
trust the DHT's **confidentiality not at all** and its **integrity only insofar as PKARR
SignedPacket signatures let us detect tampering on resolved records**. Eclipse attacks (§3.2)
are a liveness attack we accept.

## 2. Identity Compromise

**Capabilities:** The adversary has read access to the victim's disk (stolen laptop, malicious
process with same UID, post-exfiltration forensics, cloud backup exfiltration) or a brief
window of physical access to an unlocked machine.

**Worked example:** Carol's laptop is stolen at a conference. The thief finds
`~/.cipherpost/secret_key` and attempts to unwrap the identity by guessing her passphrase.
With Argon2id at 64 MB memory / 3 iterations (stored in the identity-file PHC header per
D-08 / CRYPTO-02), an offline guess costs roughly 0.3 seconds on commodity hardware.
A random 4-word passphrase from a ~7000-word list has ~51 bits of entropy, so exhaustive
search is infeasible in practical timeframes. The thief cannot recover the key without either
the passphrase or access to Carol's logged-in user session.

**Mitigations:**
- Argon2id KDF with parameters (64 MB, 3 iter) stored as a PHC-format string in the identity
  file header — prevents future upgrades from silently weakening the cost factor on existing
  files. [D-08, CRYPTO-02, CRYPTO-03]
- Identity file MUST be mode `0600`; wider permissions are refused at open time with a
  distinguishable error. [IDENT-03]
- `~/.cipherpost/` directory is mode `0700`. [SPEC.md#7-passphrase-contract, IDENT-01]
- Inline passphrase argv (`--passphrase <value>`) is rejected at parse time, so passphrases
  don't leak via `ps`, shell history, or CI logs. [D-13, IDENT-04]
- Every key-holding struct (identity bytes, derived KEK, decrypted material) is wrapped in
  `Zeroize` / `secrecy::SecretBox`; `Debug` derive is forbidden on such structs (enforced by
  `tests/debug_leak_scan.rs`). [CRYPTO-06]
- Wrong passphrase attempts exit with uniform message `passphrase failed` and no hint about
  which character was wrong or how far the Argon2id computation progressed. [D-16, CRYPTO-04]

**Residual risk:** A weak passphrase + a fast offline attacker breaks identity; passphrase
strength remains entirely the user's responsibility. Cipherpost does not enforce a passphrase
complexity policy in v1.0.

## 3. DHT Adversaries

All three adversary sub-classes here target the Mainline DHT transport layer, not cipherpost's
cryptographic core. The PKARR outer signature ensures that DHT adversaries cannot produce
forged shares under a victim's key; the inner Ed25519 signature ensures that a tampered
`OuterRecord` field (even one not covered by PKARR's outer signature) fails to verify. DHT
adversaries are therefore bounded to **liveness** attacks (blocking, delaying, or replaying
records), not integrity attacks.

### 3.1 Sybil

**Capabilities:** The adversary controls many DHT nodes (cheap on Mainline DHT since node IDs
are cheap to mint). Sybil nodes can respond to `get` requests with stale or absent data while
claiming responsibility for the target key's keyspace region.

**Worked example:** Eve runs 1000 Sybil nodes near the keyspace region of Alice's PKARR
public key. When Bob's `pkarr::ClientBlocking` issues a resolve for Alice's key, Bob's request
may hit Eve's Sybils first. Eve returns an empty "no record here" response, or returns a stale
SignedPacket from a week ago. Bob interprets this as "share not found" (exit code 5) or
"share expired" (exit code 2). Eve did not forge a share; she denied one.

**Mitigations:**
- PKARR resolves multiple DHT nodes and uses the most recent validly-signed SignedPacket
  (`pkarr::ClientBlocking::resolve_most_recent`). A single Sybil's stale response is
  outvoted by honest nodes. [TRANS-01, D-MRG-04]
- Inner Ed25519 signature (`verify_record` with round-trip-reserialize guard) prevents Eve
  from injecting a fabricated record even if she wins the resolve race. [D-16, SEND-04]
- `--dht-timeout` default 30s plus distinguishable exit code 6 (vs 5 NotFound) distinguishes
  transport failure from genuine not-found. [TRANS-04, D-14]
- Cipherpost does not conflate "Sybil denies" with protocol failure — the share URI remains
  valid; the sender can instruct the recipient to re-run `receive` later. [D-SEQ-02, D-URI-01]

**Residual risk:** A sufficiently resourced Sybil attacker can make a target share appear
"not found" for an extended window, effectively censoring the handoff. Cipherpost treats this
as a liveness failure, not a security failure; the material is not disclosed, but the handoff
stalls. No mitigation in cipherpost/v1 addresses a determined Sybil who can outrun honest
DHT nodes' re-publication cycles.

### 3.2 Eclipse

**Capabilities:** The adversary controls all network paths between the victim and the honest
DHT. Every DHT request the victim makes hits adversary-controlled nodes exclusively.

**Worked example:** Carol is on a captive portal network at a hotel. The portal operator
routes all UDP/DHT traffic through their own DHT view — a subset of honest nodes that omits
specific keys of interest. When Carol tries to `receive` a share Alice sent her, her DHT
resolve returns "not found" because the eclipsed view does not include Alice's key. Carol
reads "not found, exit 5" and retries later from a different network; the eclipse is
network-scoped, not identity-scoped.

**Mitigations:**
- Receive is a pure query flow — `receive` never publishes anything under the recipient's
  name until acceptance completes. An eclipse cannot cause receipt publication under a
  tainted view. [D-SEQ-01 step 13, D-RECV-01]
- Failure modes (not-found vs. timeout vs. decryption failure) are distinguishable by exit
  code so the user can react appropriately. [SPEC.md#6-exit-codes, D-14]
- The share URI is a stable identifier; retrying from a different network path retries against
  honest DHT nodes. [SPEC.md#4-share-uri, D-URI-01]

**Residual risk:** A persistent network-level eclipse can indefinitely prevent a share from
being retrieved by a specific victim. This is a confidentiality-preserving denial (material
is not disclosed), but a complete liveness attack for that victim on that network. Defending
against a network-level eclipse is out of cipherpost's scope; users on adversarial networks
should prefer out-of-band trust channels.

### 3.3 Replay

**Capabilities:** The adversary holds a previously-published, validly-signed `OuterRecord`
(e.g., harvested from DHT observation while the share was live) and attempts to cause a
recipient to re-process it as if it were a new share.

**Worked example:** Alice published a share for Bob at `t=0` with a 24-hour TTL (inner-signed
`created_at + ttl_seconds`). The share was successfully delivered and Bob's local state
recorded a sentinel. Mallory harvested the entire SignedPacket during its live window. At
`t = 1 week`, Mallory injects the old SignedPacket back into the DHT. Bob's scheduled
monitoring script runs `cipherpost receive <old_uri>`.

**Mitigations:**
- Idempotent re-receive check is the FIRST step of `receive`, before any network call. The
  sentinel file at `~/.cipherpost/state/accepted/<share_ref>` short-circuits to "already
  accepted at `<timestamp>`; not re-decrypting" and exits 0 without decrypt or receipt
  publish. [D-RECV-02, D-STATE-01, RECV-06]
- TTL check is enforced against the inner-signed `created_at + ttl_seconds`. An old record
  replayed past its TTL exits with code `2` (Expired), distinct from signature failures and
  distinct from "never accepted before". [RECV-02, SPEC.md#5-flows step 5]
- Receipt replay is handled separately in §7.

**Residual risk:** The very first receive of a replayed share (no sentinel yet AND replayed
while still in TTL) would be indistinguishable from a first legitimate receipt — the sender
can republish the same SignedPacket during a TTL window without any local state consequence
for the recipient (both publishes would decrypt to the same material). This is a degenerate
case with no adversarial impact: the material is what the sender intended; the recipient
accepts once. If the sender's intent was to republish, they'd have done so legitimately.

## 4. Sender-Purpose Adversary

**Capabilities:** The adversary is a legitimate cipherpost user with a valid identity (their
own passphrase-protected Ed25519 key). They can send shares signed by their own key. The
adversary cannot forge shares under another sender's key.

**Worked example:** Mallory publishes a share to Alice with `purpose = "emergency key rotation
for the prod deploy key; see incident #4421"` when there is no incident #4421 and Mallory is
attempting to get Alice to accept and use a key she shouldn't. The acceptance screen displays
Mallory's full 52-char z-base-32 pubkey, and Alice correctly types Mallory's own pubkey to
confirm (since it matches the sender pubkey). The purpose string is signed — Mallory cannot
repudiate having written it — but **cipherpost does not verify the truth value of the
purpose**. Alice's full-z32 confirmation (D-ACCEPT-01) does not prevent this; she accepted
the correct sender, just with a misleading purpose.

**Mitigations:**
- Purpose is Ed25519-signed by the sender (inner signature over JCS(`OuterRecordSignable`)
  whose `blob` commits to JCS(`Envelope`) which includes `purpose`). Non-repudiation: Mallory
  cannot deny having authored the purpose. [D-WIRE-05, SEND-04]
- Purpose is control-stripped at send time (C0/C1/DEL) before canonicalization, preventing
  terminal-injection or invisible-character lookalike attacks in the acceptance screen.
  [D-WIRE-05, D-ACCEPT-02]
- Acceptance screen displays `purpose` inside ASCII double quotes with control chars already
  stripped — Alice sees the purpose exactly as Mallory signed it, with no interpretation.
  [D-ACCEPT-02, PAYL-04]
- `SPEC.md` §3.1 explicitly documents purpose as sender-attested and NOT independently
  verified. [D-WIRE-05, SPEC.md#31-envelope]
- Out-of-band verification is the canonical mitigation: the recipient is expected to confirm
  a nontrivial purpose claim via a separate channel (voice call, in-person, a signed message
  tied to Mallory's identity elsewhere) before using the material. [Documented in SPEC.md#1-introduction
  security note and SPEC.md#31-envelope security note]

**Residual risk:** Cipherpost cannot mechanically prevent this attack. The entire defense is
**user vigilance + out-of-band corroboration**. A recipient who habitually accepts any share
from any correctly-fingerprinted sender without corroborating the purpose is vulnerable. This
residual risk is the single strongest argument for the full-z32 confirmation token (§5) — the
friction itself is a small cognitive speed-bump that resists acceptance-by-muscle-memory.

## 5. Acceptance-UX Adversary

**Capabilities:** The adversary exploits the cognitive limits of the user at the acceptance
step — prompt-fatigue attacks, lookalike-fingerprint attacks, clipboard-injection attacks on
the confirmation token, terminal-rendering attacks against the acceptance screen.

**Worked example:** Mallory sends Alice a barrage of shares with purposes that all claim to be
"routine key renewals," hoping that Alice develops acceptance-by-reflex and stops verifying
the full z-base-32 pubkey each time. On the 20th share, Mallory slips in a share under a
different pubkey — one that visually resembles a known-legitimate sender in the first 8 chars
but diverges in the middle. If Alice pastes from her clipboard without re-reading the full 52
chars, she may confirm the wrong pubkey. Alternatively, Mallory sends a `purpose` containing
control characters (newlines, ANSI escapes) hoping to inject fake "Sender:" lines above the
real one — mitigated at send time by D-WIRE-05 stripping, defense-in-depth at display.

**Mitigations:**
- Confirmation token is the sender's **full 52-char z-base-32 pubkey**, not `y`/`n` or a
  short hash. Constant-length, high-entropy, no default. Alice must type or paste all 52
  chars exactly. [D-ACCEPT-01, RECV-04]
- No `--yes` flag, no `--no-confirm`, no batch mode. The acceptance step has no bypass.
  Scripted use requires an injected `Prompter` trait implementation, which is
  `#[cfg(any(test, feature = "mock"))]`-only in production builds. [D-ACCEPT-03, RECV-05]
- TTY requirement — both stdin and stderr MUST be TTYs. If either is a pipe or file,
  `receive` aborts before decrypt with `Error::Config`. Prevents automated injection of a
  stored confirmation answer. [D-ACCEPT-03, RECV-05]
- Acceptance screen is ANSI-free by default, renders plain ASCII with a bordered box layout.
  Logs and screenshots reproduce the screen legibly. [D-ACCEPT-02, CLI-04]
- Purpose is displayed in ASCII double quotes with control chars already stripped at send
  time. No ANSI-escape injection possible. [D-WIRE-05, D-ACCEPT-02, PAYL-04]
- Sender's OpenSSH-style fingerprint and z-base-32 are displayed on **separate lines** so
  both forms are visually comparable; the user can verify via either channel their
  out-of-band record uses. [D-ACCEPT-02, IDENT-05, SPEC.md#5-flows]

**Residual risk:** Mallory can still engineer prompt fatigue by sending many legitimate-looking
shares to prime Alice's reflex. The mitigation against this is again out-of-band: Alice should
not accept a key she didn't specifically expect to receive. No mechanical defense exists in
the protocol itself against a user who chooses to paste without reading.

## 6. Passphrase-MITM Adversary

**Capabilities:** The adversary can intercept or observe the passphrase at the moment the user
enters it — shoulder surfing, keylogger malware, malicious environment-variable injection in
shell startup files, malicious shims wrapping the `cipherpost` binary.

**Worked example:** Bob runs `cipherpost send` inside a compromised shell that has been
persistently altered. The shell wrapper has replaced `/usr/local/bin/cipherpost` with a script
that reads stdin (where the passphrase prompt response goes), records it to
`/tmp/.exfil`, and then invokes the real binary. Bob types his passphrase; the malicious
wrapper captures it; the binary proceeds normally. Bob has no indication of compromise.

**Mitigations:**
- Passphrase prompting requires a TTY (`rpassword`-style stdin check). Pipe-based passphrase
  injection is refused — the non-interactive sources (`CIPHERPOST_PASSPHRASE`,
  `--passphrase-file`, `--passphrase-fd`) are the explicit opt-in for automated contexts.
  [D-13, IDENT-04, SPEC.md#7-passphrase-contract]
- Inline argv passphrase (`--passphrase <value>`) is refused at parse time. Prevents
  historical `ps` disclosure and shell-history leaks. [D-13, IDENT-04]
- Wrong passphrase surfaces a uniform `passphrase failed` message with exit code 4, no
  timing disclosure, no partial-match hint. [D-16, SPEC.md#6-exit-codes]
- Passphrase bytes are held only in `secrecy::SecretBox<Vec<u8>>` / `Zeroizing<Vec<u8>>`
  buffers; `Debug` derive on wrapping structs is forbidden (enforced by
  `tests/debug_leak_scan.rs`). Error source chains never Display (D-15). [CRYPTO-06, D-15]
- Error stderr is fuzz-scanned for passphrase-byte leakage in CI
  (`tests/stderr_scan.rs`-like coverage). No known leak paths. [CLI-05, D-15]

**Residual risk:** Cipherpost cannot defend against compromise of the local execution
environment (malicious wrapper, keylogger, rootkit). "Trusts the local environment" is
explicit in §1 Trust Model. Users on untrusted systems MUST regenerate their identity on a
clean system; no remediation is possible otherwise.

## 7. Receipt-Replay / Race Adversary

**Capabilities:** The adversary replays a harvested receipt, or races legitimate concurrent
publications, or tampers with a stored receipt on the recipient's PKARR key before the sender
fetches it.

**Worked example A (replay):** Mallory observes a live receipt TXT record under Bob's PKARR
key at label `_cprcpt-<abc...>` (D-06). Days later, Mallory injects the same TXT record back
into the DHT (possible if Mallory runs DHT nodes). Alice runs `cipherpost receipts --from
<b-z32>` and sees the replayed receipt. Unlike share replay, a replayed receipt is still
validly signed by Bob — the signature does not expire.

**Worked example B (race):** Bob accepts two shares from different senders at nearly the same
time. Both `publish_receipt` calls race: each resolves Bob's current SignedPacket, builds a
new one with their new receipt, and publishes. Whichever wins the publish drops the other's
receipt — a classic lost-update race. D-MRG-02 explicitly documents this as known-but-not-
mitigated.

**Worked example C (receipt tamper):** Mallory flips a byte in a stored receipt TXT record
in the DHT (possible if running a malicious DHT node + successfully racing the recipient's
re-publication). Alice's `cipherpost receipts` fetches the mutated record and attempts to
verify it.

**Mitigations:**
- `verify_receipt` uses `verify_strict` + round-trip-reserialize guard (canonicalization-
  bypass defense). A tampered-byte receipt fails both Ed25519 verification and the JCS
  re-serialize equality check; `Error::SignatureInner` (D-16 unified) is surfaced, the
  specific receipt is skipped, and the rest of the listing continues. [D-RS-07, D-OUT-03]
- `cipherpost receipts` counts and displays `fetched N receipt(s); M valid, K malformed,
  L invalid-signature`; exit 0 if any receipt verifies; exit 3 if all present receipts fail
  signature verification; exit 1 if only malformed; exit 5 if no receipts under `_cprcpt-`.
  The warn-and-skip contract means one tampered receipt doesn't poison the entire listing.
  [D-OUT-03, D-OUT-04, SPEC.md#5-flows]
- Replay is contextually detectable because the Receipt's `accepted_at` field and `nonce`
  (128-bit random, D-RS-03) make honest duplicates highly unlikely to collide; a re-published
  receipt with identical `accepted_at` and `nonce` IS the same receipt. Multiple receipts for
  the same `share_ref` from the same recipient public key are a policy signal to the sender
  (unusual) but not a hard failure — the sender may inspect via `--share-ref <ref>`
  audit-detail view. [D-RS-03, D-OUT-02, SPEC.md#34-receipt]
- Concurrent-publish race (example B) is documented, not mitigated in code. Per the PITFALLS
  traffic estimate (1–100 shares/week/user), concurrent receipts under the same identity are
  vanishingly rare in skeleton use. Future `cipherpost republish-receipt` command (deferred
  to v1.0+) would allow the sender to ask the recipient to retry. [D-MRG-02, D-SEQ-02]
- Publish failure on the recipient side is degraded to a stderr warning + exit 0 (material
  delivered successfully; receipt loss is sender-visible degradation only). The recipient's
  local ledger stays at `receipt_published_at: null`, recording the state for future retry.
  [D-SEQ-02, D-SEQ-04, D-STATE-01]

**Residual risk:** The concurrent-publish race (example B) means that under genuinely
concurrent acceptance on the same recipient's machine, one receipt may be lost from the DHT
even though the recipient's local ledger records both acceptances. At skeleton scale this is
rare enough to defer; if telemetry shows otherwise, the mitigation is a per-identity
publish-lock or an optimistic-concurrency retry loop (tracked in 03-CONTEXT.md deferred).

## 8. Out of Scope Adversaries

This threat model does **not** cover the following adversary classes. Defense against these
is either provided by other layers (OS, hardware, cryptographic primitives' own security
proofs) or is an explicit non-goal of cipherpost/v1.

- **Cryptographically-relevant quantum adversary.** Ed25519, X25519, ChaCha20-Poly1305, and
  SHA-256 are all pre-quantum primitives. A sufficiently large quantum computer breaks all
  cipherpost guarantees. No post-quantum migration in v1.0; tracked as a v2+ consideration.
- **Nation-state forensic access to physical devices.** Cold-boot attacks, RAM extraction,
  evil-maid attacks on unlocked machines. Cipherpost cannot defend against an adversary who
  can physically manipulate a powered-on machine; `Zeroize` only reduces, not eliminates,
  residual-memory exposure. [CRYPTO-06]
- **Supply-chain compromise of `rustc`, `cargo`, or pinned dependencies.** Cipherpost's
  builds trust the published crates (enforced by `cargo audit` + `cargo deny check` in CI
  per SCAF-03), but do not use `cargo-vet` or reproducible-build verification in
  cipherpost/v1. Deferred to v1.0 per `.planning/research/PITFALLS.md` §13.
- **Malicious libraries on `crates.io`.** If `pkarr`, `age`, `ed25519-dalek`, `argon2`,
  `hkdf`, `sha2`, or `serde_canonical_json` ship with a backdoor, cipherpost has no
  independent defense. Mitigation at the ecosystem layer: pin exact versions, audit changelogs
  at upgrade time, subscribe to RustSec advisories. [SCAF-03, SCAF-04]
- **Destruction attestation.** PRD lists destruction attestation as a v1.1 feature; not
  shipped in the skeleton. A compromised recipient who lies about having destroyed material
  cannot be detected by cipherpost/v1.
- **Long-term storage security** of the material after delivery. Once material leaves
  cipherpost's decrypt buffer, its lifecycle is the recipient's responsibility. Cipherpost is
  not a vault.
- **Accountability across multiple devices under the same identity.** If Alice runs
  cipherpost on two machines with the same identity, there's no cross-device sync of the
  local state ledger. Receipts published from one machine are discoverable from the other,
  but acceptance sentinels are not shared. This is a v1.0+ operational concern. [D-STATE-01]
- **Timing side-channel attacks on `ed25519-dalek`, `age`, or Argon2id.** Cipherpost assumes
  the underlying crates are constant-time where necessary; independent verification is
  out of scope for this threat model. [CRYPTO-01]
- **Receipt rotation / garbage collection under wire-budget pressure.** If a recipient
  accumulates enough receipts under one identity to exceed the ~1000-byte SignedPacket
  budget, `publish_receipt` surfaces `Error::WireBudgetExceeded`. Automatic pruning /
  rotation is a v1.0+ operational feature. [D-MRG-06, D-ERR-01]

## 9. Lineage

Cipherpost is a fork-and-diverge of [cclink](https://github.com/johnzilla/cclink) — a prior
project that applied the same PKARR + age + Ed25519 + Mainline DHT primitives to Claude Code
session-ID handoff. cclink is **mothballed**; no further development is planned upstream.

The crypto, identity, record, and transport layers ported from cclink are reused without
protocol-level modification — `age 0.11` for payload encryption; `ed25519-dalek =3.0.0-pre.5`
for signatures; `argon2 0.5` with (64 MB, 3 iter) parameters; `hkdf 0.12` with SHA-256;
`pkarr 5.0.3` for DHT rendezvous. The threat-model implications of these choices (Argon2id
brute-force cost factor §2, Ed25519 signature forgery §4, age AEAD §7, HKDF domain
separation) are shared with cclink.

Cipherpost domain-separates from cclink via the HKDF info-string prefix `cipherpost/v1/`
(D-08; enforced by `tests/hkdf_info_enumeration.rs`). Keys produced by cipherpost and keys
produced by cclink are not interoperable despite sharing primitive implementations — attempts
to cross-decrypt fail at the HKDF step. This domain separation means a cclink compromise does
NOT directly compromise cipherpost identities (and vice versa); the two systems share
library surface but not key material. [D-08, CRYPTO-03, TRANS-05]

**Fork point:** cclink v1.3.0 (the last release before cclink was mothballed). Any cclink
CVE that surfaces post-fork is evaluated on a case-by-case basis for cipherpost applicability
— cipherpost inherits cclink's *code patterns* but is an independently maintained codebase
with its own release cadence. [SCAF-01]

The cipherpost-specific delta from cclink (typed payload schema, explicit acceptance, signed
receipt) is the subject of the threat-model sections above; cclink's threat model does not
cover these because cclink has no such mechanisms. [PAYL-01, RECV-04, RCPT-01]
