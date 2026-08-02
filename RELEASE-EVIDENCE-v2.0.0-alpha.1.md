# cipherpost v2.0.0-alpha.1 — Real-DHT Release Acceptance Evidence

This file is the audience-facing record that cipherpost's **v2 derived-key
addressing** wire protocol works end-to-end against the real Mainline DHT — no
mocks, no test doubles, no placeholders. Unlike the v1.1.0 evidence (which paired
a manually-driven CLI demo with the automated test), this record captures the
**automated release-acceptance run triggered by the `v2.0.0-alpha.1` tag push**.
A separate manual CLI demo was not re-run for this alpha; the automated run
exercises the identical production code path (`DhtTransport` against Mainline).

## Environment

| Field | Value |
|-------|-------|
| Date (UTC) | 2026-08-02 |
| Git SHA (tag commit) | `144a9ce95214bf89f37a015a7ada2de507059630` |
| Tag | `v2.0.0-alpha.1` |
| Crate version | `2.0.0-alpha.1` (`PROTOCOL_VERSION = 2`) |
| `rustc` | `1.88.0 (6b00bc388 2025-06-23)` (pinned via `rust-toolchain.toml`) |
| Runner | GitHub Actions `ubuntu-24.04` (Azure `westus2`) |
| Workflow | `.github/workflows/release-acceptance.yml` (triggered on `v*` tag push) |
| Nextest run ID | `b1abbcff-9703-4db6-9667-7c7a348fbdbe` |
| Bootstrap nodes | pkarr defaults (`router.bittorrent.com:6881`, `dht.transmissionbt.com:6881`, `dht.libtorrent.org:25401`, `relay.pkarr.org:6881`) |
| Evidence artifact | `real-dht-evidence-v2.0.0-alpha.1` — run [30725213381](https://github.com/johnzilla/cipherpost/actions/runs/30725213381) (retained 90 days) |

## What is real, what is not

| Layer | Real or mocked | Note |
|-------|----------------|------|
| Identity (Ed25519/PKARR keypair, Argon2id+HKDF passphrase wrap) | **Real** | Fresh `cipherpost identity generate` for Alice and Bob in separate `CIPHERPOST_HOME` dirs. |
| **v2 derived-key addressing** — `A' = A + t·G`, `t = reduce_mod_ℓ(SHA-512("cipherpost/v2/derive-addr" ‖ A ‖ raw16(share_ref)))` | **Real** | Share published under `derive(alice_pub, share_ref)`; receipt under `derive(bob_pub, share_ref)`. |
| Hand-signed BEP44 packets under blinded keys (`ed25519-dalek::hazmat::raw_sign` → self-verify → `SignedPacket::from_relay_payload`) | **Real** | pkarr's seed-only `Keypair` cannot sign under a blinded key; the production `transport::build_derived_signed_packet` path published **and** resolved on real Mainline nodes. |
| Wire format (PKARR SignedPacket, JCS canonical JSON, dual signatures) | **Real** | Production encode/decode + verify path. |
| Transport (Mainline DHT publish/resolve via `pkarr::ClientBlocking`) | **Real** | `DhtTransport::new` against pkarr-default bootstrap; UDP to Mainline. `MockTransport` is **not** used in this run. |
| Crypto (age, X25519, Ed25519, ChaCha20-Poly1305 via age) | **Real** | Production `age` path. |
| Acceptance UX (typed-z32 confirmation prompt) | Bypassed by `AutoConfirmPrompter` — this run validates network round-trip viability, not the acceptance gate (which is covered by the mock-feature suite). |

## Run — automated cross-identity round trip (v2 derived keys)

Alice generates an identity and `run_send`s a share to Bob published under
`derive(alice_pub, share_ref)`; Bob resolves that derived key with 7-step
exponential backoff (in-test deadline 900s), runs the full receive flow
(dual-signature verify → age-decrypt), and publishes a receipt under
`derive(bob_pub, share_ref)` at label `_cprcpt`; Alice then resolves that derived
receipt key. Every hop is `DhtTransport` against Mainline — no mock.

```
   Compiling cipherpost v2.0.0-alpha.1 (/home/runner/work/cipherpost/cipherpost)
 Nextest run ID b1abbcff-9703-4db6-9667-7c7a348fbdbe with nextest profile: default
    Starting 1 test across 1 binary (43 binaries skipped)
        SLOW [> 60.000s] (───) cipherpost::real_dht_e2e real_dht_cross_identity_round_trip_with_receipt
        SLOW [>120.000s] (───) cipherpost::real_dht_e2e real_dht_cross_identity_round_trip_with_receipt
        SLOW [>180.000s] (───) cipherpost::real_dht_e2e real_dht_cross_identity_round_trip_with_receipt
        ...  (SLOW markers every 60s)  ...
        SLOW [>720.000s] (───) cipherpost::real_dht_e2e real_dht_cross_identity_round_trip_with_receipt
        PASS [ 739.054s] (1/1) cipherpost::real_dht_e2e real_dht_cross_identity_round_trip_with_receipt
     Summary [ 739.054s] 1 test run: 1 passed (1 slow), 0 skipped
```

**Result: PASS.** The full v2 derived-key round trip (share publish → resolve →
decrypt → receipt publish → receipt resolve) completed against live Mainline DHT
in **739.054s**, within the 900s in-test deadline. The test asserts the recovered
plaintext matches Alice's input byte-for-byte and that Bob's receipt is resolvable
at its derived key `derive(bob_pub, share_ref)` (the BURN-04 one-receipt invariant,
which under v2 is "one record present at the derived key").

## Reproduce

From a network with outbound UDP egress to Mainline DHT:

```
cargo nextest run --features real-dht-e2e --run-ignored only \
  --filter-expr 'binary(real_dht_e2e)' --no-fail-fast
```

The test triple-gates as `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` +
`#[serial]`; day-to-day CI never enables the feature. It runs only via the
tag-push release-acceptance workflow, or manually per `RELEASE-CHECKLIST.md`
§Manual real-DHT gate. On a restrictive network the test skips cleanly with
`real-dht-e2e: UDP unreachable; test skipped (not counted as pass)` — a skip is
not a release blocker; re-run from a permissive network.
