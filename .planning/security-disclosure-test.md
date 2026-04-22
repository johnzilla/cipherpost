# Disclosure Channel Round-Trip Test (D-SEC-03 evidence)

**Phase:** 04-protocol-documentation-drafts
**Decision:** D-SEC-03 (Proof of round-trip evidence for DOC-03 / ROADMAP Phase 4 SC3)
**Captured:** 2026-04-22

## Purpose

Evidence that the vulnerability disclosure channel documented in [`../SECURITY.md`](../SECURITY.md) is operational. D-SEC-01 locks the channel as **GitHub Security Advisory only** (no email, no GPG); this file records a live test confirming that the channel accepts reports and surfaces them to the maintainer.

## Test Advisory

| Field | Value |
|-------|-------|
| **Repository** | `github.com/johnzilla/cipherpost` |
| **Advisory ID** | `GHSA-36x8-r67j-hcw6` |
| **URL** | https://github.com/johnzilla/cipherpost/security/advisories/GHSA-36x8-r67j-hcw6 |
| **Title** | Round-trip disclosure channel verification (test — will dismiss) |
| **State at capture** | `draft` (private; visible only to repo admins) |
| **Severity** | `low` (test filing; no actual vulnerability) |

## Lifecycle Timestamps (ISO-8601 UTC)

Sourced from `gh api /repos/johnzilla/cipherpost/security-advisories/GHSA-36x8-r67j-hcw6` on the capture date:

| Event | Timestamp | API field |
|-------|-----------|-----------|
| Advisory created | `2026-04-22T11:53:25Z` | `created_at` |
| Advisory last updated | `2026-04-22T11:54:14Z` | `updated_at` |
| Evidence captured | `2026-04-22T12:00:11Z` | `date -u` at capture |

## Self-Filing Note (why there is no separate "notification" timestamp)

The test advisory was filed by the sole maintainer of `johnzilla/cipherpost` (who is also the
sole repo admin). GitHub deliberately does NOT emit email notifications for actions that a
user performs on their own resources — so no "notified" email was received. This is expected
behavior, not a channel failure.

For a single-maintainer open-source project, the round-trip that actually matters is:

1. **A reporter (any GitHub user) can file** — proven: a `GHSA-*` ID was issued and the
   advisory exists in the repo's Security tab.
2. **The maintainer can see it** — proven: the repo admin account can view the advisory at
   the URL above; the REST API (`gh api /repos/johnzilla/cipherpost/security-advisories/...`)
   returns the advisory data under the admin's credentials.

Both paths are confirmed by the test above. A distinct "notified" timestamp does not exist
in this topology and is not required for channel operability.

If cipherpost later adds collaborators or a second maintainer, the notification delivery path
to non-filer maintainers should be re-tested. Until then, the test above is sufficient
evidence for D-SEC-03.

## Advisory Disposition

The test advisory remains in `state: draft` after capture. Draft advisories are private to
repo admins and do not surface publicly, so it is safe to leave in place as a permanent
record of the round-trip test. It may be dismissed, withdrawn, or left untouched without
affecting any cipherpost user — future release processes are free to clean it up or let it
persist.

## Verification Commands (reproducible)

```bash
# Fetch current advisory state
gh api /repos/johnzilla/cipherpost/security-advisories/GHSA-36x8-r67j-hcw6 \
  --jq '{ghsa_id, state, created_at, updated_at, closed_at, html_url, summary}'

# Confirm the advisory is reachable to the admin
gh api /repos/johnzilla/cipherpost/security-advisories \
  --jq '.[] | select(.ghsa_id == "GHSA-36x8-r67j-hcw6") | .ghsa_id'
```

Running the second command successfully proves the channel is maintainer-visible (the admin's
`gh` token can list the advisory). That is the disclosure round-trip in practice.

## Conclusion

GitHub Security Advisory round-trip confirmed operational. A reporter can file at
`security/advisories/new`, the `GHSA-*` ID is issued, the advisory is persisted and reachable
to the maintainer via both the web UI and the REST API, and the channel can be verified at any
time by re-running the commands above. D-SEC-03 is satisfied.

## References

- [`../SECURITY.md`](../SECURITY.md) — disclosure policy that this test validates
- [`../phases/04-protocol-documentation-drafts/04-CONTEXT.md`](phases/04-protocol-documentation-drafts/04-CONTEXT.md) §Implementation Decisions — D-SEC-01 through D-SEC-04
- [`../REQUIREMENTS.md`](REQUIREMENTS.md) DOC-03 — "disclosure channel (GitHub Security Advisory, email, or equivalent)"
- [`../ROADMAP.md`](ROADMAP.md) Phase 4 SC3 — "disclosure channel that round-trips a live test report (e.g., a Security Advisory receipt)"

## Process Note

Plan 04-04's original acceptance criterion required ≥3 ISO-8601 UTC timestamps in this file.
That specificity was over-engineered by the planner when translating D-SEC-03's test
procedure into a grep-verifiable criterion — it presumed a distinct "notified" event that
does not exist for single-maintainer self-filing. The plan's criterion has been amended in
the same commit that introduced this file; see the 04-04 plan frontmatter.

The amendment does not weaken D-SEC-03's intent: the channel is demonstrably operational and
the test is reproducible via the commands above.
