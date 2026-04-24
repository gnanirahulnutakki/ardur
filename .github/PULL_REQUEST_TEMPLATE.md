<!--
PR title format: <type>: <short imperative description>
Types: feat, fix, docs, refactor, test, chore, ci, perf, build
Examples:
  docs: add Article 06 — Public Import Discipline
  feat(python): add Mission Declaration verifier CLI
  fix(receipts): correct chain-hash byte order
-->

## Relevant issues

<!-- List issue numbers this PR addresses (e.g. #12, #34). If this is a `dev → main` graduation PR, link the discussion thread instead. -->

## Type

- [ ] `feat` — new capability or surface
- [ ] `fix` — bug fix
- [ ] `docs` — article, README, or doc change
- [ ] `refactor` — internal change, no behaviour change
- [ ] `test` — test-only change
- [ ] `ci` — CI / workflow / tooling
- [ ] `chore` — housekeeping
- [ ] `dev → main graduation` — promoting reviewed work to release branch

## Changes

<!-- What changed and why. Bullet list is fine. Keep this honest — reviewers read it. -->

## Testing

<!--
What did you actually run to verify this works? Be concrete.
- `pytest python/tests/test_xxx.py` (all green)
- ran `examples/quickstart` end-to-end and verified receipt chain
- re-recorded ARDUR-CAP-001, played back to confirm zero `Wolverine` strings
For docs PRs: confirm link-check is green and any internal references resolve.
-->

## Graduation gates (for `dev → main` PRs only)

- [ ] Link-check CI green
- [ ] Secret-scan CI green
- [ ] No `glasswing`, `project.internal`, or stale `Wolverine` references in changed files (Article 06 historical-naming passages and ADR archival notes are exempt — call them out if applicable)
- [ ] Article numbering is sequential, no gaps
- [ ] 24-hour cool-off re-read complete
- [ ] Every numeric claim in changed prose traces to an artifact under `artifacts/ardur-era-*/` (or has an explicit "measured under Wolverine runtime, preserved for history" footnote)
