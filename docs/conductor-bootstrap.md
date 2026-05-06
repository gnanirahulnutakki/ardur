# Conductor Bootstrap

Ardur workspaces in Conductor should start with a repo-local bootstrap pass.
The goal is to give every new chat session one trustworthy pickup point before
it starts changing code.

For normal development, target `dev`. `main` is release-only and receives work
only after `dev` has been tested, reviewed, and verified for the public repo.

## First command

```bash
./scripts/conductor-bootstrap.sh
```

The command writes local, ignored files under `.context/`:

- `.context/ARDUR_CONTEXT.md` - human-readable session context.
- `.context/ardur-graph.json` - machine-readable graph of files, modules,
  symbols, docs, workflows, tests, and references.
- `.context/ardur-graph.md` - compact graph summary for agents.
- `.context/ardur-graph.mmd` - Mermaid overview of the main repo areas.
- `.context/skills/README.md` - local-only guidance for private skills.

These files are generated from the current checkout. Do not commit them.

## Local-only skills

Private skills, imported agent instructions, and scratch context must stay in
ignored paths:

- `.context/skills/`
- `.agents/`
- `.local-skills/`
- `.ai-context/`
- `.agent-context/`
- `.codex/`
- `.claude/`
- `HANDOFF.md`
- `workdone-so-far.md`

The committed repo only carries public-safe instructions such as `AGENTS.md`
and `docs/agent-instructions/`. Local private instructions can contain
machine-specific paths, agent preferences, or unpublished project context, so
they are blocked from tracking by `.gitignore`, `scripts/check-local.sh`, and
the `secret-scan` workflow.

## Script surface

- `scripts/conductor-bootstrap.sh` gathers branch state, tool versions, CI
  workflow names, key docs, and graph output into `.context/ARDUR_CONTEXT.md`.
- `scripts/build-knowledge-graph.py` builds the repo graph without external AI
  calls, API keys, or embedding services.
- `scripts/setup-dev.sh` creates `python/.venv` with Python 3.13 dev
  dependencies and checks whether local Go matches `go/go.mod`.
- `scripts/check-local.sh` runs quick or full local validation using the same
  source-of-truth files as CI where practical.

## Graph model

The graph is intentionally structural, not semantic. It records:

- root subsystems: `python`, `go`, `docs`, `examples`, `deploy`, `.github`
- tracked files from `git ls-files`
- Python modules, imports, classes, and functions via `ast`
- Go packages, imports, functions, and types via `go list` when available, with
  a regex fallback
- docs, ADRs, specs, workflows, tests, and Markdown references
- edges such as `contains`, `defines`, `imports`, `tests`, `documents`,
  `references`, `validates`, and `workflow-runs`

This gives agents a single navigable map without indexing private `.context`
content or introducing model/API cost. A semantic index can be layered on top
later if the project needs it.

## Validation

Use quick checks for docs and small script changes:

```bash
./scripts/check-local.sh --quick
```

Use full checks after local setup succeeds:

```bash
./scripts/setup-dev.sh
./scripts/check-local.sh --full
```

If docs disagree with `.github/workflows/`, treat the live workflow files as the
current CI truth and update the stale docs in the same change when possible.

## Branch flow

- Feature and hardening work starts on a short-lived branch or Conductor
  workspace.
- The first merge target is `dev`.
- `dev` carries the current integration state and may be ahead of `main`.
- `main` is promoted from `dev` only for tested, verified, public-facing drops.
- Dependabot or emergency public fixes may open against `main`, but larger
  product work should land on `dev` first.
