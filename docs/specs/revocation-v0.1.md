# Revocation Model v0.1

> **Public-import note.** This document was authored against the private research repo's `docs/spec/` layout. In the public ardur tree, migrated specs live under `docs/specs/`. Any `docs/spec/...` path reference in the body refers to the original private layout; the public-tree mapping is in [`docs/specs/README.md`](./README.md).

## Status

This document defines version `v0.1` of the revocation model for the
Ardur runtime-governance protocol.
This document is written in an RFC-style normative form.
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## 1. Scope

This document defines how Ardur composes four revocation and audit
mechanisms:

1. short credential lifetimes
2. Token Status List (TSL)
3. OpenID Shared Signals Framework (SSF) event delivery carrying Security
   Event Tokens (SETs), with CAEP event types when used
4. optional SCITT transparency logging

This document does not redefine:

1. the TSL token format, status encodings, caching primitives, or referenced
   token status structure
2. the SET syntax or claim model
3. the SSF event-stream management model or delivery methods
4. the CAEP event-type payloads
5. the SCITT signed-statement, receipt, or transparency-service formats

Those primitives are defined by their referenced specifications.
This document only defines how Ardur composes them.

## 2. Design Model

Ardur uses a layered revocation model rather than a single revocation
primitive.

The layers have different jobs:

1. short TTL limits residual authority if no online signal is available
2. TSL provides the authoritative machine-readable status check
3. SSF/CAEP/SET provides near-real-time propagation that tells receivers to
   refresh or invalidate cached state sooner
4. SCITT provides optional third-party auditability for issuance events

TSL is the authoritative revocation signal for mission status in this
version.
SSF event delivery accelerates freshness.
SCITT improves auditability.
None of those optional layers replace TSL.

## 3. Required Mission-Level Status Binding

### 3.1. `revocation_ref`

The Mission Declaration (MD) `revocation_ref` claim MUST identify the Token
Status List Token URI used to determine the MD's status, as defined by
`draft-ietf-oauth-status-list`.

This document does not define a new Ardur-specific status primitive.
The referenced-token status model remains the one defined by
`draft-ietf-oauth-status-list`, including the binding between a referenced
token and its list position.
Any profile-specific encoding of that binding into local claims is out of
scope for this document.

Mission-level status is the primary interoperable revocation mechanism in
this version.
A separate per-DG revocation pointer is OPTIONAL and out of scope for the
base profile.

### 3.2. Authoritative Check

Before using an MD for authorization, a verifier MUST evaluate the MD's
status using the Token Status List identified by `revocation_ref`.

If the TSL status for the MD is:

1. `VALID`, the verifier MAY continue with normal MD and DG processing
2. `INVALID`, the verifier MUST treat the MD as revoked
3. `SUSPENDED`, the verifier MUST treat the MD as temporarily unusable until
   a subsequent status check returns `VALID`

This document does not define a new local status vocabulary.
It reuses the status meanings from `draft-ietf-oauth-status-list`.

### 3.3. Caching and Freshness

TSL caching and refresh behavior MUST follow the TSL issuer's freshness
signals, especially `ttl` and `exp`, as defined by
`draft-ietf-oauth-status-list`.

Deployments MAY impose stricter local freshness policy.
If required freshness cannot be established, the verifier MUST follow the
selected local fail-closed policy.

## 4. Cascading Revocation Semantics

### 4.1. Mission Root

Every Delegation Grant (DG) in the Ardur profile is rooted in exactly
one MD via `mission_ref`.
Mission revocation therefore operates at the mission root.

### 4.2. Cascade Rule

If an MD is revoked, every DG or descendant DG carrying that MD's
`mission_ref` MUST be treated as revoked for authorization purposes,
regardless of whether the DG itself has expired yet.

This cascade is transitive.
The verifier MUST NOT require a separate descendant-by-descendant revocation
enumeration step.

### 4.3. Verifier Effect

When a verifier observes that the governing MD is `INVALID` or `SUSPENDED`
in TSL, it MUST reject authorization under every DG in that mission lineage.

In particular:

1. a locally cached but otherwise signature-valid DG MUST NOT survive a
   revoked governing MD
2. a freshly derived child DG MUST NOT become usable if its governing MD is
   revoked
3. a verifier MUST apply the cascade rule before emitting a `compliant`
   result

This document does not require a separate cryptographic walk over every DG in
order to express mission-level revocation.
The mission root is sufficient.

## 5. Short-TTL Baseline

Short lifetimes are REQUIRED as a baseline containment measure even when TSL
and event signaling are available.

By default:

1. MD TTL SHOULD be less than or equal to 1 hour
2. DG TTL SHOULD be less than or equal to 5 minutes

These defaults are RECOMMENDED, not hard-coded protocol constants.
Deployments MAY choose shorter or longer values.

Any deployment that increases those defaults SHOULD document why the longer
window is necessary, because a longer TTL increases:

1. the usable lifetime of stale delegated authority
2. dependence on online freshness checks
3. the blast radius of cache staleness or propagation delay

## 6. Optional Event Propagation with SSF / CAEP / SET

### 6.1. Role of Eventing

A deployment MAY subscribe to OpenID Shared Signals Framework event streams
to reduce revocation latency.
When used, the event payload is a Security Event Token as defined by
RFC 8417.

SETs are statements of fact, not commands.
Receipt of a SET therefore MUST NOT by itself redefine token status.
Instead, a relevant SET SHOULD trigger immediate refresh or invalidation of
cached mission status so that the verifier re-checks the authoritative TSL.

### 6.2. SSF Stream Management

If SSF is used, the deployment SHOULD use the SSF 1.0 transmitter discovery
metadata and Event Stream Management API.

SSF 1.0 defines:

1. transmitter metadata such as `issuer`, `jwks_uri`,
   `delivery_methods_supported`, `configuration_endpoint`, and
   `status_endpoint`
2. creation and management of event streams via the configuration endpoint
3. push delivery using RFC 8935 and poll delivery using RFC 8936

If an SSF stream is created without an explicit delivery method, SSF 1.0
defaults to poll delivery.

### 6.3. Relevant CAEP Event Types

At minimum, deployments using this optional layer SHOULD understand the CAEP
event type:

`https://schemas.openid.net/secevent/caep/event-type/credential-change`

CAEP defines `credential-change` to signal that a credential associated with
the identified subject has been created, revoked, updated, or deleted.

Ardur does not redefine the event payload.
When used, the deployment MUST interpret the event according to CAEP and then
map it to local cache-refresh or quarantine behavior.

### 6.4. Recommended Local Reaction

Upon receiving a relevant SET, a deployment SHOULD:

1. authenticate and validate the SET according to RFC 8417 and SSF
2. identify the affected local subject, mission, or cached authorization
   material using deployment policy
3. refresh the authoritative TSL as soon as practical
4. invalidate or quarantine matching cached MD / DG state until the refreshed
   TSL is evaluated

This document does not define a universal subject-to-mission correlation
algorithm.
That mapping is deployment-specific.

## 7. Optional Transparency Logging with SCITT

### 7.1. Logging Model

MD issuance MAY be logged to a SCITT transparency service.
If this is done, the MD or an MD issuance statement MAY be registered as a
SCITT signed statement.

If registration succeeds, the transparency service returns a receipt that can
be retained as audit evidence, as described by
`draft-ietf-scitt-architecture`.

### 7.2. Purpose

SCITT is OPTIONAL in this version.
Its purpose is auditability and third-party verifiability of issuance events.
It is not the primary revocation signal.

A verifier MUST NOT treat the absence of a SCITT entry as equivalent to
revocation unless a higher-level profile explicitly says so.

### 7.3. Deployment Guidance

A deployment considering SCITT SHOULD evaluate:

1. metadata disclosure from publishing mission issuance cadence
2. operational cost of registering many short-lived mission artifacts
3. whether to log only MD issuance, rather than every descendant DG

This version only standardizes the statement that MD issuance MAY be logged.

## 8. Processing Summary

### 8.1. Issuer

An issuer conforming to this version SHOULD:

1. issue MDs with short TTLs
2. publish or arrange access to the authoritative TSL referenced by
   `revocation_ref`
3. issue DGs with shorter TTLs than MDs
4. optionally publish SSF metadata and event streams if near-real-time
   signaling is required
5. optionally log MD issuance to SCITT

### 8.2. Verifier

Before authorizing under a DG, a verifier conforming to this version MUST:

1. verify the MD and DG according to their own specifications
2. resolve the governing MD via `mission_ref`
3. evaluate the MD's authoritative TSL status via `revocation_ref`
4. apply mission-level cascade semantics to the DG lineage

If the deployment uses SSF/CAEP/SET, the verifier or its surrounding control
plane SHOULD use those events to shorten cache staleness, not to replace the
TSL check.

## 9. Security and Privacy Considerations

### 9.1. Shared Status Lists

TSL is intentionally suited to shared lists.
Deployments SHOULD prefer shared status-list resources over unique
per-mission resources when operationally feasible, because shared lists
reduce avoidable observability and correlation.

### 9.2. Event Minimization

If SSF / CAEP is used, deployments SHOULD subscribe only to the event types
and subject scope they actually need.
Over-broad subscriptions increase disclosure of security-sensitive state
changes.

### 9.3. Transparency Metadata

If SCITT is used, deployments SHOULD assume that issuance metadata may become
observable to auditors or transparency participants even when the full
mission payload is not disclosed.

## 10. References

### 10.1. Normative References

1. `draft-ietf-oauth-status-list-19`, *Token Status List (TSL)*,
   20 March 2026, https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
2. RFC 8417, *Security Event Token (SET)*, July 2018,
   https://www.rfc-editor.org/rfc/rfc8417.html
3. OpenID Shared Signals Framework Specification 1.0, 29 August 2025,
   https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
4. OpenID Continuous Access Evaluation Profile 1.0, 29 August 2025,
   https://openid.net/specs/openid-caep-1_0-final.html

### 10.2. Informative References

1. `draft-ietf-scitt-architecture`, *An Architecture for Trustworthy and
   Transparent Digital Supply Chains*,
   https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
2. `docs/spec/mission-declaration-v0.1.md`