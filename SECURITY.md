# Security Policy

This file is the public reporting policy for Ardur.

## Supported versions

Until Ardur has tagged releases, only the latest default branch is treated
as supported for security fixes.

## Reporting a vulnerability

Do not open a public issue for an active vulnerability.

Report security issues privately to:

- `gnani.nutakki@gmail.com`

Include:

- affected version or commit
- reproduction steps
- expected impact
- whether the issue can cause out-of-scope action, forged evidence, or unsafe
  overclaiming

## What counts as a security issue

Examples include:

- out-of-scope tool or resource execution
- delegation scope widening
- forged, replayed, stripped, or tampered receipts
- verifier bypasses that turn missing evidence into false success
- downgrade attacks on governance tiers
- secret leakage through official artifacts or evidence bundles

## Scope reminders

Ardur is a runtime governance and evidence layer. Some gaps are documented
openly in `docs/known-limitations.md`. Those documented boundaries may still be
important product risks even when they are not implementation bugs.

## Security posture

For the actual product security model, see:

- `docs/security-model.md`
- `docs/known-limitations.md`
