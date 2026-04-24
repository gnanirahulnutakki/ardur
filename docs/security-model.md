# Security Model

Ardur security is based on least privilege, explicit declaration, runtime
enforcement, and verifiable evidence.

## Core security gates

- tool calls must match declared tools
- resource access must match declared scopes
- delegated child authority must be a subset of parent authority
- receipt chains must verify
- attestations must verify
- missing evidence must become `unknown`, not a false allow

## Threats in scope

- prompt injection causing out-of-scope tool use
- resource-scope abuse
- delegation scope widening
- budget double-spend
- receipt tampering, stripping, replay, and forking
- metadata forgery or laundering
- partial observation causing unsafe overclaims
- authorized tools used for unauthorized purpose

## Hardening direction

The wider hardening roadmap includes:

- deterministic behavioral templates
- streaming reconciliation and active revocation
- manual reconciliation for unresolved `unknown` states
- TEE-bound attestation profiles
- nested multi-agent attestation
- tiered governance with downgrade rejection

Important boundary: those hardening directions must not be marketed as fully
proven protections until their proof entries reach L5 for the claimed scope.

## Network and secrets posture

- SSRF-sensitive destinations should be denied by policy where the capability
  is claimed as release-gated.
- Official artifacts and recordings should be reviewed for secrets before being
  treated as publishable evidence.

## Governance tiers

| Tier | Boundary |
|---|---|
| `fast_hmac` | internal low-risk actions only |
| `standard_jws` | default receipt path for ordinary governed actions |
| `strong_eat_tee` | required for high-risk delegated or side-effecting actions |

## Required posture

When Ardur lacks evidence, it must deny or return `unknown` rather than
claim safe success.
