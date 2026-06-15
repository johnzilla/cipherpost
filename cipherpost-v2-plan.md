**Cipherpost v2 Milestone Plan / PRD**  
**“Universal Sovereign Handoff”** — Adding Large-Payload Support via Iroh Blobs

**Version**: Draft v0.1 (for Claude Code + your review)  
**Author**: Grok (assisting John Turner / johnzilla)  
**Date**: 2026-06-14  
**Status**: Proposed for v2.0

---

### 1. Vision & Goals
Extend **cipherpost** from a cryptographic-material handoff tool (keys, certs, small secrets) into a **universal secure handoff primitive** on the Mainline DHT / PKARR.

**Core new capability**: `cipherpost send-large` (and friends) lets users publish a tiny, encrypted **manifest/ticket** via your existing sovereign flow, while the actual bulk payload (directories, session files, workspaces, tars — any size) is transferred P2P via **iroh-blobs** (BLAKE3 content-addressed, resumable, verified streaming).

This directly solves the wire-budget and “stuff of substance” limitations you hit, while preserving:
- Self-sovereign identity (Ed25519/PKARR)
- E2EE, explicit acceptance, signed receipts, --pin/--burn/--share
- No servers, no accounts, delayed/async handoffs, unknown environments

**Non-goals**:
- Full general-purpose file sync daemon (use Syncthing/Tailscale/rsync for that)
- Replacing sendme (we embed the libs, not fork the CLI)
- Breaking v1.x wire format or threat model

---

### 2. Key Features (v2.0)

#### Phase 1: Core Large Payload Support (MVP)
- New subcommand family: `send-large`, `receive-large` (aliases or flags on existing `send`/`receive`)
- Smart directory handling:
  - Tar/zip on-the-fly with configurable ignores (`.cipherpostignore`, parcels/agentbeam-style, Claude/vLLM defaults)
  - BLAKE3 hashing via `iroh_blobs`
  - Generate Iroh `BlobTicket`
- Manifest published via existing PKARR flow (encrypted Envelope now includes `large_payload: { ticket: String, hash: String, size: u64, ... }`)
- Receiver: Pull manifest → decrypt → Iroh download (resumable, progress, verification) → export to path
- Preserve all v1 security: dual signatures, acceptance screen (now shows payload size/hash), receipts
- `--self` support for large backups

#### Phase 2: Polish & UX
- Non-interactive automation (`--large --manifest-only`, ticket export/import)
- Background lightweight Iroh router/daemon mode for serving blobs
- Progress bars, resume support, partial downloads
- Extended `receipts` command to attest large payload pickup
- Smart defaults for Claude sessions, agent workspaces, etc.

#### Phase 3: Advanced (v2.1+)
- Chunking fallback for pure-DHT (if Iroh unavailable)
- Collection support (multi-blob dirs)
- TUI enhancements for large transfers
- Integration hooks for cclink/parcels (share Iroh ticket via cclink reference)

---

### 3. Technical Approach
- **Deps**: `iroh`, `iroh-blobs`, `tokio` (minimal/async layer; keep blocking where possible for consistency)
- **Manifest extension**: Backward-compatible (v1 receivers see unknown large field and graceful error)
- **Security**: Iroh’s QUIC E2EE + your outer/inner signatures on manifest. Optional inner age layer on blob if desired.
- **Storage**: Use `FsStore` or `MemStore`; integrate with `~/.cipherpost/blobs` cache
- **Testing**: Mock + real-DHT extension of existing release-acceptance pipeline; cross-tool interop with `sendme`

---

### 4. Phased Milestone Plan

**v2.0-alpha** (2-3 weeks)
- Integrate iroh-blobs basics
- `send-large <path>` → manifest publish
- `receive-large <share-uri>` end-to-end
- Basic ignore rules + progress
- Update SPEC.md, THREAT-MODEL.md, README, exit codes

**v2.0-beta**
- Non-interactive, --self, receipts for large
- Smart ignores + Claude session presets
- Docs, examples, release checklist

**v2.0**
- Polish, CI updates, real-DHT evidence
- Announcement / blog post synergy with bugbountybrief + your other tools

**Post-v2.0**
- cclink convergence
- parcels/agentbeam hybrid commands
- TUI wizard for large transfers

---

### 5. Success Criteria
- Can securely hand off a full Claude project directory or vLLM workspace asynchronously across unknown devices.
- Wire size for manifest stays << 1KB.
- Receipts/auditability preserved.
- No regression on v1 small-payload flows.
- Passes existing + new real-DHT tests.

---

### 6. Risks & Mitigations
- Async/Tokio complexity → Start small, isolate in new modules.
- Dep bloat/supply chain → `deny.toml` updates, careful pinning.
- NAT/relay reliability → Iroh handles it; document fallback expectations.
- User confusion (small vs large) → Clear CLI separation + helpful errors.

---
