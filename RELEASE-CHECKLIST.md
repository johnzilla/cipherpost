# Cipherpost Release Checklist (template)

> **Status: living template — copied per release into `RELEASE-CHECKLIST-vX.Y.md`**
>
> This template is the source-of-truth for every v1.1+ release. At ship
> time, `cp RELEASE-CHECKLIST.md RELEASE-CHECKLIST-v<version>.md`, fill in
> the release-specific fields, and tick each box as the gate is verified.
> The ticked snapshot ships in the release commit; the template stays
> unticked.

**Release date:** YYYY-MM-DD
**Releaser:** @<github-username>
**Tag:** v<version>

---

## Pre-flight

- [ ] All Phase VERIFICATION.md files for this milestone signed off (pass)
- [ ] PROJECT.md §Validated reflects shipped scope; §Active is empty for the closing milestone
- [ ] Cargo.toml `version =` matches the release tag
- [ ] CHANGELOG entry drafted (if a CHANGELOG exists; not required for v1.1)

## Code gates (run from repo root)

- [ ] `cargo fmt --check` — no diff
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — clean
- [ ] `cargo audit` — no advisories OR documented exceptions in `deny.toml`
- [ ] `cargo deny check` — clean
- [ ] `cargo test` (no features) — all green
- [ ] `cargo test --features mock` — all green (>=311 tests for v1.1; bumps with each milestone)
- [ ] `cargo test --doc` — doctests green
- [ ] `lychee --offline SPEC.md THREAT-MODEL.md SECURITY.md README.md CLAUDE.md RELEASE-CHECKLIST.md` — no broken links

## Wire-format byte-count regression guard

These fixtures are JCS-canonical bytes — any drift is a protocol-version-bump
event. Run `wc -c tests/fixtures/<name>.bin` for each:

- [ ] `tests/fixtures/outer_record_signable.bin` — **192 bytes** (Phase 1; OuterRecord)
- [ ] `tests/fixtures/receipt_signable.bin` — **424 bytes** (Phase 3; Receipt)
- [ ] `tests/fixtures/envelope_jcs_generic_secret.bin` — **119 bytes** (Phase 1/2; Envelope generic-secret)
- [ ] `tests/fixtures/outer_record_pin_required_signable.bin` — **212 bytes** (Phase 8 Plan 02; OuterRecord with pin_required=true)
- [ ] `tests/fixtures/envelope_burn_signable.bin` — **142 bytes** (Phase 8 Plan 04; Envelope with burn_after_read=true)

## Manual real-DHT gate (DHT-03/04/05)

This is the cipherpost-specific release-acceptance step that does NOT run in
day-to-day CI (D-P9-D2 + Pitfall #29). A separate tag-push workflow
(`.github/workflows/release-acceptance.yml`) runs the same gate on every
`v*` tag push, so manual + CI evidence agree per release. Allow ~10s
between consecutive local runs for socket teardown (09-RESEARCH.md
Pitfall C).

- [ ] Confirm running on a network with normal outbound UDP egress (corporate
      / restrictive firewalls block Mainline DHT bootstrap; the test will
      skip with `real-dht-e2e: UDP unreachable; test skipped (not counted as pass)`
      — re-run from a permissive network if observed)
- [ ] Run: `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'binary(real_dht_e2e)' --no-fail-fast`
      (the `slow-timeout = { period = "60s", terminate-after = 16 }` profile
      override in `.config/nextest.toml` enforces a 960s wall-clock cap;
      paired with the in-test 900s deadline. Filter is `binary()` not
      `test()` because the function name doesn't contain `real_dht_e2e`,
      so `test()` would silently match zero tests — corrected 2026-04-28
      after the v1.1.0 evidence run, see RELEASE-EVIDENCE-v1.1.0.md.)
- [ ] Test passes within 900s OR skips with the canonical UDP-unreachable
      message (skip is not a release blocker; rerun on a permissive network)
- [ ] Output observation: round trip completes; receipt count == 1 under
      bob's z32 (BURN-04 invariant)
- [ ] Capture the run output as `RELEASE-EVIDENCE-v<X.Y.Z>.md` next to
      `RELEASE-EVIDENCE-v1.1.0.md` for audience-facing release records

## Security review

- [ ] Review RUSTSEC advisory list for any new advisories against current
      crate deps since the previous release; document any new acceptances
      in `deny.toml`
- [ ] Confirm SECURITY.md disclosure channel is live (link to GitHub Security
      Advisory page resolves)
- [ ] Verify `chacha20poly1305` does NOT appear as a direct dep:
      `cargo tree | grep -E "^chacha20poly1305" || echo "PASS: chacha20poly1305 only via age"`
- [ ] HKDF info-enumeration test green:
      `cargo test --features mock --test hkdf_info_enumeration` — every call-site uses
      `cipherpost/v1/<context>` prefix (CLAUDE.md load-bearing)
- [ ] Debug-leak scan green:
      `cargo test --features mock --test leak_scan` — no `format!("{:?}", x)` on key
      bytes contains the seed material

## Release artifacts

- [ ] Create git tag `v<version>` on the release commit
- [ ] Update MILESTONES.md with the milestone close summary (one paragraph
      per milestone; cite VERIFICATION.md for the proof)
- [ ] Snapshot this file as `RELEASE-CHECKLIST-v<version>.md` (ticked) at
      the release commit. The template stays unticked at `RELEASE-CHECKLIST.md`.

---

*Template lifecycle: living document. Versioned snapshots are committed at
release time per D-P9-C4.*
