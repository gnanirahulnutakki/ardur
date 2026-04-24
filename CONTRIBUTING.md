# Contributing To Ardur

Ardur is an engineering-first open source project. Contributions should
make the runtime, verifier, deployment posture, or framework support clearer
and more trustworthy.

## Before you open a pull request

1. Make sure the change fits the public product surface.
2. Update docs when behavior or support boundaries change.
3. Keep claims aligned with the proof registry and verifier outputs.
4. Avoid introducing internal-only language, session mechanics, or private
   planning material into the public surface.

## Contribution priorities

We especially welcome contributions that improve:

- public docs and positioning clarity
- verifier and artifact quality
- runtime governance correctness
- framework adapters with honest support boundaries
- documentation clarity
- deployment and self-hosting guidance
- security hardening that stays proofable

## Proof and honesty rules

- Do not call a capability proven unless the verifier and public artifacts back
  that claim.
- If a surface is design-only or foundation-scope, label it explicitly.
- Do not land docs that market a capability more strongly than the evidence
  allows.

## Current public repo note

This repo is opening in phases. Until the curated runtime code lands here, many
contributions will be docs, media, packaging, or launch-surface changes rather
than direct runtime edits. When code-bearing surfaces arrive, local check
guidance should be updated to match the real public commands.

## Pull request expectations

- Keep changes scoped and reviewable.
- Explain user-facing behavior changes clearly.
- Mention any security, compatibility, or proof-boundary impact.
- Link to the relevant verifier, artifacts, or limitation note when a claim is
  affected.

## Security reports

For active vulnerabilities, use the process in `SECURITY.md` instead of opening
a public issue.
