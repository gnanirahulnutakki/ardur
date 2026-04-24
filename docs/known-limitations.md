# Known Limitations

This page distinguishes honest product boundaries from implementation bugs.

## Research and foundation surfaces not yet broad runtime claims

- semantic judging is advisory unless a specific runtime policy path consumes
  its verdict
- behavioral templates are the intended deterministic direction, but broad
  marketing claims still require template coverage and L5 evidence
- streaming reconciliation and active revocation primitives exist, but broader
  framework-live proof remains a follow-on for some surfaces
- manual reconciliation is implemented at an API-first foundation layer; richer
  operator UX is follow-on work
- TEE support is not yet a general hardware-rooted production claim until real
  vendor quote verification and proof-of-possession artifacts exist
- nested attestation primitives exist, but framework-level end-to-end evidence
  still needs expansion
- fast HMAC is intentionally not a cross-organization non-repudiation tier

## Evidence limits

If a delegated tool or gateway can hide all relevant side effects and emits no
evidence, Ardur must classify the result as `unknown` rather than safe.

## Product limits

Ardur is not:

- a sandbox by itself
- a universal semantic-safety engine
- a replacement for identity, workload isolation, or network controls

Those controls still matter around Ardur.
