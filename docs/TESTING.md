# Testing — what runs against this repo

The runtime code that produces signed receipts hasn't been imported into the public ardur tree yet. Until [Phase 1 of the public-import plan](public-import-plan.md) lands the Python runtime under `python/vibap/`, the only "tests" this repo has are CI workflows that catch the mistakes that a content-mostly repo can actually make. This page documents what runs today and what will run after each public-import phase.

The structure mirrors how testing works in the private research repo: structured CI for what's safely automatable, plus an explicit "before claiming tests pass" discipline for what isn't.

## What runs today (Phase 0 — content-mostly repo)

Three GitHub Actions workflows, all gated on push to `dev`/`main` and on every pull request.

### `secret-scan` — gitleaks + forbidden-term gate

[`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml)

- **gitleaks** scans the full git history (`fetch-depth: 0`) for secrets — API keys, tokens, private key material. Pinned to commit SHA `ff98106e...`.
- **forbidden-terms** is a custom `grep -RInE` job. The configured pattern is defined inline in [`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml) — read the workflow file for the authoritative regex (this page deliberately doesn't reproduce the pattern, because doing so would self-trip the gate). The pattern targets a small set of historical-internal references the repo cannot leak. Excludes `.github/`, `.git/`, `artifacts/`. Includes Markdown, YAML, JSON, asciinema casts, TOML, Python, Go, shell, `.gitignore`, `.env*`, `Dockerfile*`, `Makefile*`.

### `link-check` — lychee on Markdown links

[`/.github/workflows/link-check.yml`](../.github/workflows/link-check.yml)

- Runs on PRs touching `**/*.md` and weekly via cron. Uses `lycheeverse/lychee-action@v2.8.0` (commit-pinned).
- Excludes two URL patterns that are known to 404 for an unauthenticated checker: the GitHub Discussions tab (404 until Discussions is enabled in repo settings) and `security/advisories/new` (requires sign-in). Both are part of our intended feedback surface; the excludes are temporary and documented inline in the workflow.

### `validate-formats` — JSON, YAML, Markdown-table parsers

[`/.github/workflows/validate-formats.yml`](../.github/workflows/validate-formats.yml)

- **JSON job**: every `.json` file (excluding `.git`, `.claude`, `artifacts/`) parses with `python3 -c "import json; json.load(...)"`.
- **YAML job**: every `.yml`/`.yaml` file parses with PyYAML's `safe_load_all` (handles multi-document YAML).
- **Markdown-tables job**: every Markdown table where the header row's pipe count differs from the separator row's pipe count fails. Catches the most common table-typo bug.

This workflow exists because a misplaced comma in `media/selected-assets.json` or a stray indent in an issue-template YAML would otherwise sit broken silently.

### What's NOT enforced by CI today

Honest list, so the gap is visible:

- No content-fact verification (article claims, ADR cross-references) — caught only by review rounds and the cool-off re-read in the `dev → main` PR template.
- No Markdown lint beyond table-pipe counts — `markdownlint` adds noise we don't want yet.
- No YAML link-check (the issue-template `config.yml` URLs are not under `**/*.md`).
- No spelling.
- No external link-check on YAML or `.cast` files.

## What runs after Phase 1 (Python runtime imported)

Phase 1 imports `vibap-prototype/vibap/` → `python/vibap/` per the [public-import plan](public-import-plan.md). When that lands:

### Python suite

A new `python-ci.yml` workflow will join the set:

```yaml
# Phase 1 sketch — actual file lands with the code
on:
  push:
    branches: [main, dev]
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
      - uses: actions/setup-python@<sha>  # v5, sha-pinned
        with:
          python-version: '3.13'    # NOT 3.14 — biscuit-python 0.4.0
                                    # fails on PyO3 ABI 3.14
      - run: |
          python -m pip install --upgrade pip
          pip install -e 'python/[dev]'
          pip install 'biscuit-python==0.4.0' 'spiffe>=0.2,<0.3'
      - name: Show environment
        run: |
          python --version
          pip show biscuit_auth | head -3
          pip show spiffe | head -3
          pip show cedarpy | head -3
      - name: pytest
        run: pytest python/tests/ -q
      - name: Z3 composition proofs (if applicable)
        run: |
          python python/verification/composition_smt.py | tee /tmp/z3-output.txt
          grep -q "ALL PROPERTIES HOLD" /tmp/z3-output.txt
      - name: make reproduce
        working-directory: python
        run: make reproduce
```

### Local development setup (Phase 1 onwards)

The discipline lifts directly from the private research repo's `TESTING.md`:

```bash
# First-run setup — Python 3.13 required
cd /path/to/ardur/python
python3.13 -m venv .venv
.venv/bin/pip install -e '.[dev]'

# Run the curated test suite
.venv/bin/pytest tests/ -q

# Run a specific module
.venv/bin/pytest tests/test_passport.py -v

# End-to-end reproduce (Z3 proofs, signed proof bundle, corpus consistency)
make reproduce
```

### Module-specific gotchas (carry-over from private research)

- **`test_mission_binding.py`**: one xfail (`test_tampered_md_returns_chain_invalid`) due to module-level `urllib.request.urlopen` state leak — runs green in isolation. CI invokes it as a separate `pytest` call.
- **`test_biscuit_passport.py`**: requires `biscuit-python==0.4.0`. ABI breaks on 0.5+ and on Python 3.14.
- **Live LLM tests**: tests under the semantic-judge / behavioral-fingerprint lanes need API access. Default test runs use null-judge stubs; live runs require explicit env vars (`ARDUR_SEMANTIC_JUDGE=anthropic` + `ANTHROPIC_API_KEY`).
- **Mark `pytest.mark.<name>`**: every custom mark must be registered in `conftest.py` so `pytest -W error` doesn't blow up. The private repo had unregistered `spiffe_mock` warnings; we don't carry that forward.

### Coverage targets (Phase 1 onwards)

| Surface | Minimum coverage | Source of bar |
|---------|------------------|---------------|
| `python/vibap/` | 80% | matches private research repo's bar for `pkg/` |
| `python/cli/` | 60% | matches private research repo's bar for `cmd/` |
| `python/integrations/<framework>/` | 70% | new bar for public adapters |

Coverage runs against the renamed Ardur runtime only; legacy-era results are archived under `artifacts/legacy-era-*/` for lineage but never count for gates.

## What runs after Phase 5 (Go runtime imported)

A `go-ci.yml` mirrors the radiantic pattern:

- `go mod verify`
- `go build ./...`
- `go test -race -v ./...`
- `go tool cover -func=coverage.out` with 80% pkg/ + 60% cmd/ enforcement
- `gofmt -l .` clean
- `golangci-lint`

Same SHA-pinning discipline as the rest of the workflows. Annotated tags get peeled to commit SHAs (verified via `git ls-remote refs/tags/<tag>^{}`).

## Test-authoring rules (carry-over from private research, applies to all phases)

- **No rigged adapters.** Labels come from a separate file derived from public dataset labels. Adapters never see the ground truth. Violations are the single fastest way to get a benchmark retracted — see [Article 11 (Public Import Discipline)](articles/06-public-import-discipline.md) on the rigged-tests audit story.
- **Regression tests for every bug fix.** If you fix bug X, write a test that fails on the pre-fix code and passes on the fixed code. The test goes in the same PR as the fix.
- **Name tests after what they prove, not what they exercise.** `test_passport_with_invalid_sig_is_rejected` beats `test_verify_passport_case_3`.
- **Avoid live-LLM tests by default.** Unit suites run with null-judge / null-challenger stubs; live-LLM paths are explicit opt-in via env var. CI doesn't burn API budget on every push.

## Before claiming "tests pass"

For Phase 0 (today): a pre-commit local sweep is enough — `python3 -c 'import json; json.load(...)'` over `media/selected-assets.json`, `python3 -c 'import yaml; yaml.safe_load_all(...)'` over the workflow YAMLs, plus the forbidden-term grep. The exact `grep` invocation lives in [`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml); copy the include list, exclude list, and pattern string from there to run it locally:

```bash
# substitute <PATTERN> with the literal regex from secret-scan.yml's
# `PATTERN='...'` line; if you embed the pattern in this file the
# forbidden-term gate self-trips.
grep -RInE \
  --include='*.md' --include='*.yml' --include='*.yaml' \
  --include='*.json' --include='*.cast' --include='*.toml' \
  --include='*.py' --include='*.go' --include='*.sh' \
  --include='.gitignore' --include='.env*' \
  --include='Dockerfile*' --include='Makefile*' \
  --exclude-dir='.git' --exclude-dir='artifacts' \
  --exclude-dir='.github' \
  '<PATTERN>' .
```

For Phase 1 onwards (after Python runtime lands):
- Exit code 0 on the full pytest suite
- Known-failing / known-collecting-error count has not grown
- No `xfail` flipped to pass-or-fail without an explicit reason
- The pytest summary line (`N passed, M skipped, K xfailed`) pasted into the commit body so a reviewer can see the delta vs the known baseline without re-running

## Why this page exists

Public security-software repos that fail their own CI on the first PR every time train contributors not to trust the gates. The current state — three workflows, three useful checks, no-ops nowhere — is intentional. New CI jobs join the set when the corresponding code does, not as placeholders.
