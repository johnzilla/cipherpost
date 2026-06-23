# Cipherpost test homeserver (pubky-homeserver on DigitalOcean)

Live test target for the v2 large-payload flow. Deployed 2026-06-22. This is a
**test box** — not production; treat data as ephemeral.

## Coordinates

| | |
|---|---|
| Public endpoint (use this) | `https://hs.trustedgelabs.com` (Caddy → Let's Encrypt cert) |
| Homeserver pubkey (z32) | `9sagw7nf8xei96trohzmhr7mdi5nedq893xwus5mz4mjuhjrgjry` |
| Droplet | `cipherpost-hs` · DO id `579556370` · nyc1 · `s-1vcpu-2gb` · shared VPC `d59b6cdd-…` |
| Public IP | `157.230.216.146` |
| DNS | `hs.trustedgelabs.com A 157.230.216.146` (managed at external DNS provider, not DO) |
| SSH | `ssh -i ~/.ssh/id_ed25519 root@157.230.216.146` (DO key `DarterPro`) |
| pubky-homeserver version | `v0.9.1` (built from source at `/root/pubky-core`) |

## How cipherpost talks to it

- Connect to `https://hs.trustedgelabs.com` (normal publicly-trusted TLS → `ureq` + native-tls validates with no special handling).
- Set header **`pubky-host: <tenant-z32>`** on every request. Host resolution order in
  the homeserver (`pubky_host.rs`): `host` header → `pubky-host` header (overrides) →
  `pubky-host` query param. Since Caddy forwards `Host: hs.trustedgelabs.com` (not a
  pubkey), the `pubky-host` header is required.
- **`signup_mode = "open"`** on this box — cipherpost signs up with just its keypair
  (sign a pubky `AuthToken` → `POST /session` or `/signup` → session cookie → `PUT`/`GET`).
  No signup token needed. (Public/production homeservers use `token_required`.)
- Paths: `/pub/<path>` is world-readable; `/priv/<path>` requires a session to read.
  v2-alpha `--self` uses `/priv/cipherpost/<share_ref>` so nothing is world-readable.
- Limits: **100 MB / request** (homeserver code cap), **5120 MB / user** quota (configured).

### Verified (2026-06-22)
- `GET /` → 200 through Caddy. `GET /pub/... -H 'pubky-host: <z32>'` → 404 (routing OK).
- Let's Encrypt cert valid (`ssl_verify_result=0`).
- Not yet exercised end-to-end: authenticated signup + PUT + GET (lands with the
  `HomeserverBlobStore` client).

## Operations

```bash
ssh -i ~/.ssh/id_ed25519 root@157.230.216.146

# services
systemctl status pubky-homeserver caddy
systemctl restart pubky-homeserver
journalctl -u pubky-homeserver -n 50 --no-pager

# config + data
/root/.pubky/config.toml          # homeserver config (signup_mode, quota, ports, db url)
/root/cipherpost-hs-secrets.txt   # PG_PASSWORD + ADMIN_PASSWORD (NOT committed to repo)
/etc/caddy/Caddyfile              # reverse proxy hs.trustedgelabs.com -> 127.0.0.1:6286

# admin API (localhost-only; reach via SSH tunnel)
ssh -i ~/.ssh/id_ed25519 -L 6288:127.0.0.1:6288 root@157.230.216.146
#   then, if signup_mode is switched to token_required:
curl "http://127.0.0.1:6288/generate_signup_token" -H "X-Admin-Password: <ADMIN_PASSWORD>"
```

Internal ports (all bound to 127.0.0.1, never public): 6286 icann-http (Caddy upstream),
6287 pubky-tls, 6288 admin, 6289 metrics. Public firewall (ufw): 22/80/443 only.

## Lifecycle / cost

`s-1vcpu-2gb` ≈ \$12/mo. The 2 GB was for the one-time compile; the running homeserver
is light. Reversible resize (CPU/RAM only — disk can't shrink):

```bash
doctl compute droplet-action resize 579556370 --size s-1vcpu-1gb   # then power back on
doctl compute droplet delete 579556370                              # tear down entirely
```

Rebuild homeserver after a `pubky-core` update: `cd /root/pubky-core && git fetch &&
git checkout <tag> && ~/.cargo/bin/cargo build --release -p pubky-homeserver &&
systemctl restart pubky-homeserver`.
