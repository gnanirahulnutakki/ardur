# MCEP Specifications (v0.1)

This directory carries the v0.1 specification documents for Ardur's protocol layer, MCEP (Mission-bound Cryptographic Evidence Protocol). v0.1 is a pre-release series — the specs describe the intended protocol shape; the public code that implements them is being curated in phases per [docs/public-import-plan.md](../public-import-plan.md).

**Public-surface import caveat.** The migrated specs were authored in a private context and may reference implementation source paths (e.g. `vibap-prototype/vibap/passport.py`), private session artifacts (e.g. `docs/session-2026-04-XX/...`), or internal review trails that have not yet landed in this public repo. Treat such references as pointers to future work — the underlying code lands alongside the Phase 1 import per the [public import plan](../public-import-plan.md). Contributors cannot verify those referenced artifacts from the public tree today. Same caveat as the [decisions index](../decisions/README.md).

## Migration status

| Spec | Status | Notes |
|------|--------|-------|
| [Conformance Profiles](./conformance-profiles-v0.1.md) | **migrated** | Clean verbatim copy |
| [Delegation Grant (DG) Profile of AAT](./delegation-grant-profile-v0.1.md) | **migrated** | Clean verbatim copy |
| [Verifier Contract](./verifier-contract-v0.1.md) | **migrated** | Clean verbatim copy |
| Mission Declaration (MD) | _pending_ | Requires protocol-level rename decision (JWT media types + URL identifiers); see below |
| Execution Receipt (ER) | _pending_ | Same as above |
| Execution Receipt EAT/CWT Profile | _pending_ | Same as above |
| IDM Extension Profile | _pending_ | Same as above |
| Revocation Model | _pending_ | Same as above |

## Why some specs are pending

The migrated specs above carry no references to historical internal codenames. The specs still under review reference protocol-level identifiers (JWT media types like `application/<name>.er+jwt`, `$id` URIs like `https://<name>.io/...`) that embed a legacy name. Renaming these identifiers is a protocol-versioning decision, not just a text substitution: any receipt, passport, or attestation that was produced under the v0.1-as-written identifiers would no longer verify under a rewritten spec.

The decision — rename identifiers in v0.1 (clean break, assume no published artifacts), or bump to v0.2 with dual-type support for backward compatibility — is tracked in the private Phase 1 execution hand-off. The pending specs migrate once that decision lands.

## Reading order for first-timers

Pending specs are listed by name only — they're not yet linkable from this repo. They land once the protocol-rename decision is made.

1. **Mission Declaration (MD)** _(pending)_ — the signed scope envelope the agent starts with
2. [Delegation Grant (DG) Profile](./delegation-grant-profile-v0.1.md) — how child agents get strictly narrower authority
3. **Execution Receipt (ER)** _(pending)_ — the signed per-tool-call decision record
4. **Execution Receipt EAT/CWT Profile** _(pending)_ — RFC 9711 binding for ER carriage
5. [Verifier Contract](./verifier-contract-v0.1.md) — what a conforming verifier must do
6. [Conformance Profiles](./conformance-profiles-v0.1.md) — tiered conformance matrix (Delegation-Core, MIC-State, MIC-Evidence, IDM Extension)
7. **Revocation Model** _(pending)_ — layered revocation across delegation, session, credential, and transparency-log layers
8. **IDM Extension Profile** _(pending)_ — Intent-Declaration-Manifest experimental profile

## Relationship to adjacent standards

- **AAT (Attenuating Authorization Tokens)** — IETF OAuth WG draft; MCEP's Delegation Grant is an AAT profile.
- **EAT (Entity Attestation Token, RFC 9711)** — used by the ER EAT/CWT profile to carry Execution Receipts.
- **SPIFFE** — workload identity substrate; MCEP binds mission credentials to SVIDs.
- **Biscuit** — first-party-attenuation credential format; the DG profile's narrowing semantics rely on Biscuit's append-only block model (see [ADR-017](../decisions/ADR-017-biscuit-attenuation-narrowing-semantics.md)).

These are real artifacts, not codenames. Their names stay in the specs as technical lineage.

## Conventions

- **Versioning:** v0.1 is the pre-release. The next revision (v0.2 or later) lands after the protocol-level rename decision + one round of adversarial review against the migrated public specs.
- **Normative language:** MUST / SHOULD / MAY usage follows RFC 2119 / RFC 8174.
- **Updates:** specs don't mutate in place; a material change opens a new version file and leaves the prior version immutable for citation stability.
