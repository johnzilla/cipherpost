# Cipherpost v1.1 Release Checklist

**Release date:** YYYY-MM-DD (filled at v1.1 release tag time)
**Releaser:** @<github-username>
**Tag:** v1.1.0

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
CI (D-P9-D2 + Pitfall #29). Allow ~10s between consecutive runs for socket
teardown (09-RESEARCH.md Pitfall C).

- [ ] Confirm running on a network with normal outbound UDP egress (corporate
      / restrictive firewalls block Mainline DHT bootstrap; the test will
      skip with `real-dht-e2e: UDP unreachable; test skipped (not counted as pass)`
      — re-run from a permissive network if observed)
- [ ] Run: `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast`
      (the `slow-timeout = { period = "60s", terminate-after = 2 }` profile
      override in `.config/nextest.toml` enforces a 120s wall-clock cap)
- [ ] Test passes within 120s OR skips with the canonical UDP-unreachable
      message (skip is not a release blocker; rerun on a permissive network)
- [ ] Output observation: round trip completes; receipt count == 1 under
      bob's z32 (BURN-04 invariant)

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

*Snapshot of `RELEASE-CHECKLIST.md` at v1.1 close (committed unticked at
Phase 9 close per D-P9-C4 + Discretion recommendation). Ticking happens
at v1.1 release tag time.*
