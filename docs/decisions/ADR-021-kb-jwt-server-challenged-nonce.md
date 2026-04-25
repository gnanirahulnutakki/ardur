# ADR-021: KB-JWT server-challenged nonce protocol (proposed)

Date: 2026-04-21

## Status

Proposed. Addresses finding #8 from the 2026-04-21 review.

## Context

Proof-of-Possession on VIBAP passports requires the presenter to
supply a KB-JWT (key-bound JWT) signed with the holder's private
key. The KB-JWT carries a `nonce` claim that must not have been
seen before within the freshness window. Today the nonce is
PRESENTER-CHOSEN: the KB-JWT is minted by the holder with whatever
nonce they like, and the proxy simply checks the nonce hasn't
appeared in `_seen_kb_nonces` within the window.

Consequences:

- A captured passport + KB-JWT pair stays replayable to any proxy
  that hasn't observed that specific nonce yet (cold proxies,
  different replicas, restarted state).
- Cross-proxy replay isn't defended by nonce checks because
  `_seen_kb_nonces` is in-process.
- The time-based iat freshness (default max_age_s=300) provides a
  5-minute window of replay against any previously-unseen proxy.

The SD-JWT-VC spec and typical OAuth DPoP bindings use
SERVER-CHALLENGED nonces: the server supplies a `nonce` at
session-request time, the holder echoes it in the KB-JWT, and the
server verifies the echoed nonce equals the one it issued. This
binds each KB-JWT to a specific server + timestamp, eliminating
cross-proxy replay.

## Decision

Introduce a two-phase `start_session` handshake:

**Phase 1** — `POST /session/challenge` with the passport token as
a bearer. Response: `{"nonce": "<server-generated>",
"expires_at": <ts>}`. The nonce is stored server-side with a short
TTL (e.g., 60s) under `_session_challenge_lock`.

**Phase 2** — `POST /session/start` with passport + KB-JWT +
holder_public_key. KB-JWT must carry the echoed nonce. Server
verifies the echoed nonce matches a live challenge, consumes the
challenge entry (one-use), and proceeds with PoP verification.

Backwards compatibility: callers that don't supply `cnf` (bearer
mode) skip the handshake entirely. Callers presenting a `cnf` token
that don't do Phase 1 first receive `400 challenge_required` —
breaking change for clients, documented in release notes.

## Consequences

- Replay window shrinks from 5 minutes to ~60 seconds, and only
  against the SPECIFIC proxy replica that issued the challenge.
- Multi-replica deployments must share challenge state (Redis or
  shared file) for the handshake to work across the cluster;
  sticky-session routing is a simpler fallback.
- Clients (install_hook.sh, demo scripts) need a Phase-1 round
  trip added. Minor.
- Test surface: challenge→consume happy path, replay attempt on a
  consumed challenge, cross-proxy challenge attempt, expired
  challenge.

## Out of scope

- Distributed challenge store — treat as an operator concern;
  single-proxy demo keeps in-process storage.
- Challenge-tied-to-client-IP for extra defense — future ADR if
  audit reveals proxy-handle replay across different presenter
  networks.
- Moving entirely to DPoP (RFC 9449) — deliberate divergence
  given the existing SD-JWT-VC-style KB-JWT format; revisit if we
  need standards interop.
