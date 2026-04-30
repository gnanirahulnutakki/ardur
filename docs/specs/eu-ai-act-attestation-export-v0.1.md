# EU AI Act Article 12 Attestation Export v0.1

> **Status:** Draft evidence profile. This document is not legal advice and does
> not determine whether any specific system is a high-risk AI system under
> Regulation (EU) 2024/1689.

## 1. Scope

This profile defines a portable Ardur evidence export for EU AI Act Article 12
record-keeping workflows. It packages signed Ardur Execution Receipts, a
regulator-readable manifest, retention metadata, redaction metadata, and trust
anchor references so an auditor can verify the exported evidence offline.

The export profile is an evidence format. It does not:

1. classify a system as high-risk;
2. replace a conformity assessment;
3. certify compliance with EU law;
4. require disclosure of raw personal data; or
5. assert that Article 12 mandates signed receipts.

Article 12 requires automatic event logging capabilities for high-risk AI
systems. Article 19 and Article 26 add retention obligations for logs under
provider or deployer control. Article 72 links those logs to post-market
monitoring. Ardur's role is to make the resulting evidence tamper-evident and
offline-verifiable.

Primary official source:

- Regulation (EU) 2024/1689, Publications Office:
  <https://op.europa.eu/en/publication-detail/-/publication/dc8116a1-3fe6-11ef-865a-01aa75ed71a1/language-en>

## 2. Relationship to Ardur ER

The source of truth for each governed event is the signed Execution Receipt
defined in [`execution-receipt-v0.1.md`](./execution-receipt-v0.1.md). The
Article 12 export manifest is a projection over those receipts. A verifier MUST
trust the original ER and its signature over the projection when they disagree.

An export MAY contain redacted or digest-only evidence. Redaction does not make
an event invalid by itself. The verification result MUST distinguish:

- `verified`: all manifest projections and referenced receipts verify;
- `verified_with_redactions`: signatures and digests verify, but raw evidence is
  intentionally withheld;
- `incomplete_evidence`: required receipts or detached evidence are missing; and
- `invalid`: signatures, hashes, chains, or schema checks fail.

## 3. Package Layout

An export bundle SHOULD use this layout:

```text
article12-export/
  manifest.json
  manifest.jws
  trust-anchor.json
  receipts/
    <receipt_id>.jwt
  detached-evidence/
    <evidence_id>.json
  redactions/
    redaction-profile.json
  verification/
    verification-report-template.json
```

`manifest.json`, `manifest.jws`, `trust-anchor.json`, and `receipts/` are the
minimum package members for a full Ardur evidence export. Detached evidence is
optional because privacy, security, and local law may require digest-only
disclosure.

## 4. Manifest Object

`manifest.json` MUST validate against
[`eu-ai-act-attestation-export-v0.1.schema.json`](./eu-ai-act-attestation-export-v0.1.schema.json).

The manifest contains:

- `schema_version`: this profile version.
- `export_id`: stable export identifier.
- `generated_at`: time the export was produced.
- `export_period`: covered event interval.
- `regulatory_scope`: declared Article 12 scope and operator role.
- `system`: system/deployment identifiers and intended purpose.
- `retention`: retention policy metadata.
- `integrity`: canonicalization, digest, signature format, and trust anchor
  metadata.
- `events`: regulator-readable projections derived from signed receipts.
- `attachments`: optional detached-evidence and redaction references.

The manifest digest MUST be computed over the canonical manifest object with
`integrity.manifest_digest` set to the empty string. The digest value is then
stored as `sha-256:<hex>`. This avoids self-referential hashing while preserving
a deterministic verification procedure.

## 5. Event Projection

Each event projection MUST be derived from a signed ER unless the event is
explicitly marked as incomplete evidence. The projection SHOULD include only the
minimum regulator-readable fields needed for traceability:

- receipt reference;
- trace and run identifiers;
- actor and verifier identifiers;
- observed time and optional start/end time;
- tool, action class, target, resource family, and side-effect class;
- invocation and argument digests;
- result digest when available;
- ER verdict and evidence level;
- Article 12 tags; and
- privacy/redaction metadata.

The projection MUST NOT introduce a stronger claim than the ER supports. If the
ER verdict is `insufficient_evidence`, the export MUST preserve that verdict.

## 6. Article 12 Tags

The `article12_tags` object maps each event to the Article 12 purposes that the
exporter believes it supports:

- `risk_or_substantial_modification_signal`
- `post_market_monitoring_relevant`
- `deployer_operation_monitoring_relevant`

These are audit-routing tags, not legal conclusions. They MUST be supported by
the referenced ER, detached evidence, or deployment documentation.

## 7. Annex III Point 1(a) Extension

If the deployment declares that the relevant high-risk AI system is covered by
Annex III point 1(a), events corresponding to a system use SHOULD populate
`annex_iii_1a_fields`.

That object carries:

- use-period start/end timestamps;
- reference database identity, version, and digest;
- matched-input digest or redaction reason; and
- natural-person verification records, represented by pseudonymous references
  unless raw identity disclosure is legally required.

Deployments outside Annex III point 1(a) SHOULD omit this object rather than
emit empty or misleading placeholders.

## 8. Retention

`retention.minimum_retention_days` SHOULD be at least 183 unless
`retention.exception_ref` identifies a stricter or different applicable-law rule
that governs the export. The profile uses days for schema validation, but
operators SHOULD map the policy to the exact calendar-month language applicable
to their deployment.

An offline verifier SHOULD report a policy warning when
`minimum_retention_days < 183` and `exception_ref` is absent. The JSON Schema
keeps this field structurally valid for deployments that must document a
different applicable-law retention rule.

Retention controls MUST be paired with data minimization. Where raw evidence is
deleted or redacted, the export SHOULD preserve enough digest evidence to verify
that an ER existed and that the redaction was intentional.

## 9. Offline Verification

An offline verifier MUST:

1. validate `manifest.json` against the schema;
2. verify `manifest.jws` against the declared trust anchor;
3. recompute the manifest digest using the canonicalization rule in Section 4;
4. load every referenced ER;
5. verify ER signatures and issuer/verifier bindings;
6. verify ER `iat`, `exp`, and `jti` according to the ER profile;
7. rebuild the parent receipt chain;
8. compare each event projection with the verified ER claims;
9. verify detached-evidence digests where detached evidence is provided;
10. preserve `insufficient_evidence` outcomes; and
11. emit one of the verification result values in Section 2.

The verifier MUST NOT call an export `verified` if any required receipt is
missing, any signature fails, or any projection conflicts with the signed ER.

The packaged `ardur article12-verify` command implements the reference offline
slice for this profile: JSON Schema validation, manifest digest recomputation,
attachment path containment, attachment digest checks, `manifest.jws`
verification, ER signature verification, receipt-chain checks,
receipt-projection comparison, and result classification.

The reference verifier accepts a `trust-anchor.json` object with this minimum
shape:

```json
{
  "schema_version": "ardur.trust_anchor.v0.1",
  "manifest": {
    "kid": "manifest-key",
    "alg": "ES256",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----..."
  },
  "receipts": [
    {
      "kid": "receipt-key",
      "alg": "ES256",
      "issuer": "verifier:example-local",
      "verifier_id": "verifier:example-local",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----..."
    }
  ]
}
```

## 10. Example

A minimal non-normative manifest is provided at:

```text
examples/article12-attestation-export/minimal-export.json
```

The example is schema-valid and has a self-consistent manifest digest, but it is
not a cryptographically complete bundle because the referenced JWS, trust
anchor, and receipt files are not included. The reference verifier therefore
returns `incomplete_evidence`:

```bash
PYTHONPATH=python python3 -m vibap.cli article12-verify \
  --manifest examples/article12-attestation-export/minimal-export.json
```

## 11. Safe Public Claim

Acceptable wording:

> Ardur can package signed, offline-verifiable evidence bundles that help
> providers and deployers operationalize EU AI Act Article 12 logging workflows.

Avoid wording:

> Ardur makes deployments EU AI Act compliant.

Avoid wording:

> Article 12 requires signed receipts.
