# ADR-017: Biscuit Attenuation Narrowing Semantics (proposed)

Date: 2026-04-21

## Status

Proposed. Blocks: the "Biscuit-side fact-merge widening" finding from the
2026-04-21 adversarial re-review of PR #10.

## Context

`biscuit_passport._context_from_blocks` reconstructs the effective
`PassportContext` by reading facts from the root authority block and
then iterating appended blocks. For list-valued attenuation families
(`allowed_tool`, `forbidden_tool`, `resource_scope`,
`allowed_side_effect_class`, `max_tool_calls_per_class`), the current
logic is:

- If the block contains ANY fact of that family, REPLACE the running
  effective list with the block's facts for that family.
- If the block is silent on that family, INHERIT the parent's value.

Biscuit first-party attenuation (`Biscuit.append`) requires **no**
issuer private key — any holder can append a block. The block's
Datalog is therefore fully adversary-controlled. A holder who never
touches `derive_child_biscuit` can append a block with, for example,
one benign `forbidden_tool("non_existent_tool")` fact; the
REPLACE-on-presence rule then drops the parent's real denylist
entirely. The same attack widens `allowed_side_effect_class` and
`max_tool_calls_per_class`.

`derive_child_biscuit` enforces narrowing in Python at the issuance
path, but the VERIFIER (`_context_from_blocks`) is the authoritative
source of truth on presentation and it does not re-check narrowing
against the parent's baseline.

Tests currently pass because they never exercise a hand-crafted
Biscuit with an attenuation-violating block.

## Decision

Replace wholesale with strictly narrowing semantics in
`_context_from_blocks`:

| Family | Parent → Child rule |
|---|---|
| `allowed_tool` | Child = Child ∩ Parent (intersection) |
| `forbidden_tool` | Child = Child ∪ Parent (union) |
| `resource_scope` | Each child entry must be subpath of SOME parent entry |
| `allowed_side_effect_class` | Child ⊆ Parent |
| `max_tool_calls_per_class[k]` | Child[k] = min(Child[k], Parent[k]) |
| `max_tool_calls` | Child = min(Child, Parent) |
| `max_duration_s` | Child = min(Child, Parent) |
| `max_delegation_depth` | Child ≤ Parent − 1 |
| `delegation_allowed` | Child ⇒ Parent (child can only turn it off) |
| `cwd` | Child is subpath of Parent (same rule as JWT path) |

`_context_from_blocks` will raise `BiscuitVerifyError` on any widening
observed. The Python helper `derive_child_biscuit` stays as an
ergonomic issuance entrypoint; its invariants become redundant
defence-in-depth rather than the only anchor.

## Consequences

- Biscuit first-party attenuation via `Biscuit.append` becomes safe
  regardless of holder intent: widening blocks fail verification
  instead of silently succeeding.
- A handful of existing tests that rely on the current
  "omit-to-inherit, one-entry-to-replace" shape will need updating.
- `_context_from_blocks` grows ~60 LOC of narrowing logic. Budget:
  one focused PR with unit + property-based tests.
- Callers that want to GRANT authority must go through a key-holding
  issuer (`issue_biscuit_passport` or third-party attenuation with a
  signed block), not through `append`.

## Out of scope (separate ADRs)

- Hash-domain unification between JWT and Biscuit lineage — ADR-018.
- Policy DSL invariants in the Mission compiler — future ADR.
