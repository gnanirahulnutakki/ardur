# ADR-019: JWT parent_token path must also anchor against trusted_lineage (proposed)

Date: 2026-04-21

## Status

Proposed. Addresses finding #3 from the 2026-04-21 review.

## Context

`passport.verify_passport(token, public_key, parent_token=...)`
supports two anchor modes for a delegated child:

1. **`parent_token` supplied:** verifier decodes the parent, checks
   `parent_jti` + `parent_token_hash` match, reconstructs the
   expected chain via `_expected_chain_for_parent`, compares against
   the child's signed chain.

2. **`parent_token` omitted, `trusted_parent_token_hashes` +
   `trusted_parent_lineage` supplied:** verifier walks the chain and
   checks each ancestor's hash + parent edge against the trusted
   index.

Path 1 does NOT consult `trusted_parent_lineage` at all. A caller
who holds a validly-signed parent token whose OWN ancestry was
itself forged upstream (e.g., a malicious intermediate issuer that
signed a fake grandparent claim) bypasses the lineage anchor —
path 1's checks all pass, even though the intermediate parent is
impostor.

This is the same class of attack the signed-chain-only check
already protects against in path 2, but path 1 trusts the caller
to have done ancestral diligence.

## Decision

When BOTH `parent_token` and `trusted_parent_lineage` are supplied,
verify_passport shall perform the parent_token check AS WELL AS
the trusted_lineage walk. The two anchors compose; the verifier
rejects on ANY mismatch from either path. When only one is
supplied, current behavior is unchanged.

Concretely: after the existing `expected_chain` equality check at
the end of the `parent_token is not None` branch, add the same
`trusted_parent_lineage.get(link["jti"])` loop that path 2
already performs.

## Consequences

- Strengthens the parent_token path for callers who CAN provide
  trusted lineage (the proxy always can). Legacy callers who supply
  only parent_token keep working.
- Test surface: add a test where the parent_token is signed-valid
  but references a `parent_jti` not present in `trusted_parent_lineage`.
  Must raise `PermissionError("... lineage edge is not trusted")`.
- Performance: O(chain_depth) extra dict lookups per verify —
  negligible.

## Out of scope

- Making `trusted_parent_lineage` mandatory for all delegated verify
  calls (would break offline verify use cases) — future ADR if
  we ever decide offline verify without registry is obsolete.
- Finding #9b (live-observation backfill) — the verifier records
  observed parents back into the trusted index. Covered separately
  because it changes caller responsibility rather than verifier
  semantics.
