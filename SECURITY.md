# Security Policy

> **Status: DRAFT — current through v1.1 Real v1 (shipped 2026-04-26)**
>
> This document describes the security policy as shipped through v1.0 Walking Skeleton
> (Phases 1–4) and v1.1 Real v1 (Phases 5–9). The disclosure channel below was live-tested
> during v1.0 close and remains the canonical reporting path.
> Editorial polish across the full v1.x scope continues.

Cipherpost is a self-sovereign, serverless tool for handing off cryptographic material over
Mainline DHT (see [`SPEC.md`](./SPEC.md) for the protocol, [`THREAT-MODEL.md`](./THREAT-MODEL.md)
for the adversary model).

## Reporting a Vulnerability

To report a security vulnerability in Cipherpost, please use GitHub's private Security
Advisory system:

**→ [Report a vulnerability](https://github.com/johnzilla/cipherpost/security/advisories/new)**

This opens a private, encrypted channel between you and the maintainer. No email address,
PGP key, or additional infrastructure is required; GitHub encrypts the report in transit
and at rest, and the advisory thread is visible only to you and the repo maintainer until
coordinated publication.

**Alternative for reporters without a GitHub account:** open a public issue requesting a
private contact method. This is discouraged because the request itself may reveal that a
vulnerability exists before mitigation is ready. If you have the option, use the Security
Advisory flow instead.

### What to include in a report

If possible, include:

- A short description of the vulnerability and its potential impact
- Steps to reproduce (minimal test case, affected cipherpost version, commit SHA, OS, Rust
  toolchain version)
- Whether you have already validated the issue reproduces in a clean environment
- Any suggested mitigation (optional)

We do not require a CVSS score, proof-of-concept exploit code, or a patch — a clear
reproduction is sufficient. Please do NOT include exploitation payloads that could be
harmful if the advisory thread is inadvertently leaked.

## Disclosure Policy

- **Embargo period:** Up to 90 days from first report, with negotiation available for complex fixes (e.g., coordinated disclosure with upstream `age`, `pkarr`, or `ed25519-dalek`).
- If no fix is released within 90 days and no extension has been negotiated, the reporter
  is free to disclose publicly.
- We target **acknowledgment within 48 hours** and a **severity assessment within 5
  business days**. If you do not receive an acknowledgment within 5 days, please escalate
  by mentioning `@johnzilla` in the advisory thread.
- Reporters are credited in the published advisory and in release notes unless they request
  anonymity.
- Cipherpost is a one-maintainer open-source project. Coordination will be informal but
  timely; we do not promise the same SLA as commercial vendors.

## Scope

**In scope:**

- The `cipherpost` binary and library (everything under `src/`)
- The wire-format protocol as documented in [`SPEC.md`](./SPEC.md) — vulnerabilities that
  would let an attacker forge, replay, or leak material despite correctly-followed protocol
  semantics
- Identity-file handling (`~/.cipherpost/`) including passphrase, Argon2id params, zeroize
  discipline
- CLI argument parsing — any way to leak passphrase bytes, key bytes, or raw payload bytes
  via argv, env, stderr, logs, or shell history
- Integration with `age 0.11`, `ed25519-dalek =3.0.0-pre.5`, `argon2 0.5`, `hkdf 0.12`,
  `sha2 0.10`, `pkarr 5.0.3`, `serde_canonical_json 1.0.0` — cipherpost's usage patterns
  that misuse these crates
- The CI pipeline (`.github/workflows/ci.yml`) if a vulnerability causes cipherpost to ship
  compromised artifacts

**Out of scope** (see [`THREAT-MODEL.md`](./THREAT-MODEL.md) §8 for the complete adversary
out-of-scope list):

- Upstream CVEs in dependencies — report those to the upstream project. If the vulnerability
  is cipherpost-specific *because of how we use* an upstream crate, that IS in scope.
- The Mainline DHT infrastructure itself (Sybil / Eclipse censorship attacks — documented as
  liveness-only limitations in THREAT-MODEL.md §3)
- The reporter's own operating system, terminal emulator, or keyboard (keyloggers, shoulder
  surfing)
- Quantum cryptanalysis — cipherpost/v1 is pre-quantum; post-quantum migration is a v2+
  consideration
- Third-party key stores (OS keychains, HSMs) — not integrated through v1.1
- Destruction attestation — deferred to v1.2+ per [`PROJECT.md`](./.planning/PROJECT.md)
  (originally PRD v1.1, shifted because v1.1 filled with PRD-closure scope);
  cipherpost/v1 has no such mechanism, so there is nothing to attack yet

## Safe Harbor

We support security research conducted in good faith. If you report a vulnerability in
accordance with this policy:

- We will not pursue legal action against you for the research, provided it stayed within
  the scope defined above.
- We will not ask you to sign an NDA or pay for CVE registration.
- Research conducted against your own test identities on your own machines (i.e., not
  exploiting other users' live shares) is unambiguously in bounds.

Research that exfiltrates material belonging to other users, publishes unredacted live
share URIs, or otherwise harms third parties is NOT covered by safe harbor.

## Lineage

Cipherpost is a fork-and-diverge of [cclink](https://github.com/johnzilla/cclink) — a prior
project by the same author that applied PKARR + age + Ed25519 + Mainline DHT primitives to
Claude Code session-ID handoff. **cclink is mothballed:** no further upstream development.
Cipherpost was seeded in 2026-04 by vendoring cclink's crypto, identity, record, and
transport layers essentially unchanged and adding a new payload and flow layer on top.

The primitive stack is identical to cclink v1.3.0 (the fork point): `age 0.11`,
`ed25519-dalek =3.0.0-pre.5`, `argon2 0.5`, `hkdf 0.12`, `sha2 0.10`, `pkarr 5.0.3`.
CVEs in this stack apply equally to cipherpost. Upstream-reported vulnerabilities in these
crates MUST be evaluated for cipherpost applicability on a per-CVE basis.

Domain separation from cclink is via the HKDF info prefix `cipherpost/v1/` (enforced by
`tests/hkdf_info_enumeration.rs`). Cipherpost identities and cclink identities are
cryptographically distinct despite sharing primitive implementations; a cclink key-material
compromise does not directly compromise cipherpost, and vice versa.

## Verification

_Disclosure channel verified round-trip 2026-04-22 — see
[`.planning/security-disclosure-test.md`](./.planning/security-disclosure-test.md) for the
test Advisory ID, filing timestamp, and a note on self-filing behavior (single-maintainer
repos do not produce separate notification events)._

---

*This policy applies to `cipherpost` v1.0 (walking-skeleton, 2026-04-22) and v1.1
(Real v1, 2026-04-26) and later releases until superseded. For the exact version of
this file that applies to a given release, consult the git tag.*
