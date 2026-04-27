---
quick_id: 260427-bz3
title: README badge polish — remove Status block, add CI/license/MSRV/release badges
status: complete
date: 2026-04-27
commit: fafc53d
---

# Quick Task 260427-bz3 — Summary

## What changed

- `README.md`: removed the line-3 `**Status: v1.1 Real v1 shipped...**` block (a
  point-in-time milestone snapshot that decays the moment new commits land) and
  inserted a four-badge row immediately under the H1.

## Badges added

| Badge | Source of truth | Link target |
|-------|-----------------|-------------|
| CI | `.github/workflows/ci.yml` on `main` | Actions workflow page |
| License: MIT | `Cargo.toml` `license = "MIT"` | `./LICENSE` |
| MSRV: 1.88+ | `rust-toolchain.toml` + CI gate | `./rust-toolchain.toml` |
| Latest release | `git tag` (currently `v1.1.0`) | GitHub tags page |

## Badges intentionally NOT added

- **crates.io** — `Cargo.toml` is at `0.1.0`; cipherpost has not been published.
  A `crates.io/v/cipherpost` badge would render `not found` until publication.
- **codecov / coveralls** — coverage tooling is not wired up in CI.
- **dependency status (deps.rs)** — duplicates what `cargo audit` + `cargo deny`
  already enforce in CI; would add visual noise without adding signal.

## Constraint compliance

- Single-file edit, no behavior change, no test impact.
- `grep -c '^\*\*Status:' README.md` returns `0`.
- All four shields.io URLs use `johnzilla/cipherpost` consistently.

## Commit

- `fafc53d` — `docs(readme): replace Status block with shields.io badges`

## Verification

```
$ head -7 README.md
# cipherpost

[![CI](https://img.shields.io/github/actions/workflow/status/johnzilla/cipherpost/ci.yml?branch=main&label=CI&logo=github)](https://github.com/johnzilla/cipherpost/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.88%2B-orange.svg?logo=rust)](./rust-toolchain.toml)
[![Latest release](https://img.shields.io/github/v/tag/johnzilla/cipherpost?label=release&sort=semver)](https://github.com/johnzilla/cipherpost/tags)

Cipherpost is a self-sovereign, serverless, accountless CLI...
```
