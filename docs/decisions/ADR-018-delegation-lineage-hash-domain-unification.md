# ADR-018: Delegation Lineage Hash-Domain Unification (proposed)

Date: 2026-04-21

## Status

Proposed. Addresses the "Known Limitation" in ADR-016 and the
Biscuit-origin hash-mismatch finding from the 2026-04-21 review.

## Context

The delegation lineage index (`lineage_hashes.json`) stores per-jti
`token_hash = sha256(stored_credential_bytes)` where the stored
credential is either a JWT string or the base64-encoded Biscuit
token. Cold verify uses that hash to anchor ancestors.

Biscuit's `_context_from_blocks` builds each chain link's
`token_hash` as `sha256(block_source_text)` — the Datalog text of
one block inside a nested Biscuit, not the whole token bytes. When
the proxy converts a Biscuit session to JWT-shape claims for
uniform consumption, it propagates these per-block hashes as
`parent_token_hash` in the synthesized claims.

Cold verification then compares `lineage_hashes.json`'s whole-token
hash against the chain's per-block-source hash. These are from
different hash domains and NEVER match. The bug is currently
latent because in-process flows bypass cold verify, and the test
suite never exercises cross-process Biscuit cold verify.

## Decision

Adopt ONE canonical hash domain across JWT and Biscuit paths:

**Option A (preferred) — whole-credential hash everywhere.**
`_context_from_blocks` stops emitting per-block-source hashes.
Instead, `derive_child_biscuit` embeds a first-party fact
`parent_token_sha256("<hex>")` in each appended block at issuance
time, where `<hex>` is `sha256(parent_biscuit_bytes)` computed from
the parent bytes the caller holds. Legacy biscuits without the
fact are rejected on cold verify (fail-closed); live verify with
`parent_token` supplied still works by direct hashing.

**Option A mandatory verification step (review comment #13):**
Biscuit first-party append is keyless — any holder can add a block,
and the Datalog in that block is adversary-controlled. The
`parent_token_sha256` fact therefore CANNOT be trusted on face
value; reading it into the chain without verification would let an
attacker declare any hash they like and re-parent their token onto
a non-revoked ancestor.

The verifier MUST recompute `sha256(accumulator_bytes_up_to_this_block)`
— i.e., a canonical serialization of every block up to but
excluding the block carrying the fact — and compare the recomputed
hash against the fact's value. Any mismatch raises
`BiscuitVerifyError` ("declared parent_token_sha256 does not match
recomputed ancestor bytes"). Only verified facts populate chain
links; the fact is an *assertion* the block author must be able to
prove against the actual token bytes, not a *declaration* the
verifier accepts at face value.

**Option B (rejected) — Biscuit-native revocation.**
Route Biscuit verification through the upstream `biscuit_auth`
revocation-identifier mechanism, bypassing `lineage_hashes.json`
for Biscuit tokens. Rejected because it forks the operational
control plane (JWT revocation via lineage index; Biscuit revocation
via Biscuit revocation identifiers) — two independent systems to
keep consistent for cross-org delegation is worse than one canonical
hash.

## Consequences

- Legacy biscuits issued before this ADR will fail cold verify —
  acceptable, they were never cross-process verifiable anyway.
- `derive_child_biscuit` grows a small parent-hash computation step.
- The "Known Limitation" section added to ADR-016 is removed once
  this lands.
- Biscuit tests must add cross-process verification coverage that
  ADR-016 explicitly flagged as missing.

## Out of scope

- Hash function agility (SHA-256 → SHA-3 or BLAKE3) — future ADR.
- Revocation of still-live ancestors — covered by existing revoked
  list + lineage walk; unchanged.
