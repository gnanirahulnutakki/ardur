# ADR-020: Persisted session re-verification on load (proposed)

Date: 2026-04-21

## Status

Proposed. Addresses finding #4 from the 2026-04-21 review.

## Context

`GovernanceSession.from_dict` reconstructs a session from its
persisted JSON by reading `passport_token` and `passport_claims`
verbatim. The claims dict is trusted as-is; no re-verification
against the current lineage index, revocation list, or tightened
verifier logic happens on load.

Consequence: a session persisted BEFORE a tightening lands (e.g.,
before the orphan-child fail-closed rules in PR #10) stays live
afterward via a cold proxy restart, bypassing the new invariants.
An attacker who obtained a persisted session file at a permissive
version keeps that authority after the fix lands.

The proxy's revocation flow partially mitigates this — every
`evaluate_tool_call` consults the revocation list — but does NOT
re-walk lineage, does NOT re-verify signatures, does NOT re-apply
the current verifier's chain-integrity checks.

## Decision

Introduce a proxy-level session loader
`GovernanceProxy._load_verified_session(path)` that:

1. Reads the persisted JSON.
2. Calls `GovernanceSession.from_dict(data)` to unmarshal.
3. Re-runs `verify_passport_token(session.passport_token)` against
   the current public key and lineage index.
4. If re-verification fails, the session is ejected: disk file
   deleted, in-memory registry skipped, `_log` writes a
   "stale_session_evicted" entry with the jti and reason.
5. If it succeeds, the reconstructed `claims` REPLACES
   `session.passport_claims` so any claim-drift (e.g., derived
   fields that verify_passport adds) is picked up.

All existing callers of `GovernanceSession.from_dict` go through
the new loader. Direct `from_dict` stays available for tests that
deliberately want to bypass re-verification.

## Consequences

- Tightening the verifier now retroactively invalidates sessions
  that would fail under the new rules — the intended property.
- Cold proxy restart cost grows by one signature verify per
  session on disk. Benchmarks: typically <10ms per session;
  mitigable via a per-session sentinel (skip re-verify when the
  persisted sentinel matches the current public-key fingerprint).
- Tests must add two cases:
  (a) a session persisted with the old orphan-child permissive shape is
      evicted on load under the new rules;
  (b) a session persisted AT the current version loads unchanged.

## Out of scope

- Migrating pre-ADR-016 session files to include lineage hints —
  covered by the migration path in proxy.py's
  `_reconstruct_lineage_from_sessions`.
- Attested receipts on disk — ADR-016 already requires receipt
  re-verification on chain walk; this ADR is about the live session
  object, not the evidence ledger.
