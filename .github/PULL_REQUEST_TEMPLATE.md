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
- re-recorded ARDUR-CAP-001, played back to confirm zero historical-codename strings in terminal output
For docs PRs: confirm link-check is green and any internal references resolve.
-->

## Graduation gates (for `dev → main` PRs only)

- [ ] **Link-check CI green.**
- [ ] **Secret-scan CI green (gitleaks).**
- [ ] **Forbidden-term gate green.** No `glasswing` or `project.internal` in changed files. If a changed file carries a historical internal codename in an unavoidable archival context (a preserved artifact that would lose provenance if rewritten), call it out in the PR body under "Changes" and get explicit maintainer approval below before merging — the blanket "exceptions" carve-out has been retired.
- [ ] **Article numbering sequential on `main`.** Outline-only entries on `dev` don't count as gaps.
- [ ] **24-hour cool-off re-read complete.**
- [ ] **Numeric claims trace to artifacts.** Every cited number in changed prose resolves to a path under `artifacts/ardur-era-*/`. Archival exception: an explicit "measured under the historical legacy runtime, preserved for lineage" footnote pointing at `artifacts/legacy-era-*/`.
