# ADR-016: Delegation Lineage Hash Index

Date: 2026-04-21

## Status

Accepted.

## Context

Delegated JWT passports carry a signed `delegation_chain` so a cold verifier
can walk ancestry without loading every ancestor session blob from disk. Shape
checks alone are not enough: a signer could mint a self-consistent child token
that references a fabricated `parent_jti`, or re-parent a real ancestor JTI to
a different ancestor and make revocation checks walk the wrong lineage.

The stricter alternative of requiring the raw `parent_token` for every
delegated verification closes that gap, but it breaks the cold revocation
walk that the signed-chain design was meant to support.

## Decision

Delegated verification now requires one of two anchors:

- The raw `parent_token`, which is hashed and matched against
  `parent_token_hash`, then used to reconstruct the exact expected parent
  chain. The child token's `delegation_chain` must match that reconstructed
  lineage.
- A trusted proxy-maintained lineage index mapping ancestor `jti` to both the
  token hash and the recorded parent edge (`parent_jti`,
  `parent_token_hash`) captured when that ancestor session was started.

The proxy persists this index in `lineage_hashes.json` under the existing
passport-state lock. Cold verifiers use the index, not ancestor session JSON,
so revocation checks remain bounded while fabricated or re-parented ancestry
fails closed.

## Consequences

- A delegated token with only a self-consistent signed chain is rejected by the
  generic verifier unless the caller supplies `parent_token` or
  both `trusted_parent_token_hashes` and `trusted_parent_lineage`.
- Existing cold proxy verification remains supported when the parent lineage
  was previously started and recorded by the proxy.
- If `lineage_hashes.json` is missing or corrupt in a state directory that
  already has sessions, delegated verification fails closed until an operator
  rebuilds or rotates state. The pre-lineage migration path rebuilds the index
  from on-disk session JSONs so pre-migration intermediate sessions keep their
  real `(parent_jti, parent_token_hash)` edge — an empty backfill would mark
  every intermediate as a root and silently break grandchild re-parenting
  detection for chains that straddle the migration boundary (2026-04-21 audit).

## Known limitation: Biscuit-origin lineage is intra-token, not whole-token

The JWT anchor design above compares `sha256(whole_jwt_bytes)` on both sides:
`trusted_parent_token_hashes` stores `_passport_token_hash(stored_token)` and
child tokens carry the same hash in `parent_token_hash`. For Biscuit-origin
delegated sessions, `biscuit_passport._context_from_blocks` emits each chain
link's `token_hash` as `sha256(block_source)` — the Datalog text of one block
inside a nested Biscuit — not `sha256(biscuit_bytes)`. Two consequences:

1. Cold verification of a Biscuit-derived chain across proxy process
   boundaries compares hashes from different domains and will not match the
   proxy's whole-token `trusted_parent_token_hashes`. In-process flows avoid
   the mismatch only because the proxy holds the live session.
2. The "preserves revocation lineage" claim in the 2026-04-21 session doc
   for nested Biscuit children currently holds only through live session
   state, not through the lineage index alone.

Follow-up work (tracked for a separate ADR) must land one canonical
hash domain across JWT and Biscuit paths — either by extending
`_context_from_blocks` to carry `sha256(accumulator_bytes)` per block, or
by routing Biscuit verification through a Biscuit-native revocation check
that bypasses `trusted_parent_token_hashes` entirely. Neither is attempted
in this ADR.
