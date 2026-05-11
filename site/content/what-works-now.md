---
title: "What Works Now"
description: "Current public Ardur capability, separated from roadmap ambition."
weight: 20
maturity: ["public-now", "in-progress"]
claim_types: ["status", "runtime-boundary", "integration", "protocol-spec"]
surfaces: ["docs", "python", "go", "examples", "media", "github"]
frameworks: ["framework-agnostic", "claude-code", "langchain", "langgraph", "autogen"]
evidence_levels: ["code-and-doc", "spec", "archival-media"]
---

Ardur is pre-release, but the public repo is code-bearing today.

## Public Now

| Surface | Current state | Primary source |
|---|---|---|
| Runtime governance | Python and Go runtime imports, mission passport issuance, verification, receipt paths, governance checks | {{< repo-link "python/README.md" "Python" >}}, {{< repo-link "go/README.md" "Go" >}} |
| CLI | `issue`, `verify`, `attest`, `start`, `hub`, `setup`, `status`, `doctor`, `protect claude-code`, `cc-hook`, `cc-report` | {{< repo-link "docs/reference/cli.md" "CLI reference" >}} |
| Ardur Personal | Local Hub service, browser extension, desktop observe adapter, native messaging host | {{< repo-link "docs/guides/ardur-personal-hub.md" "Personal Hub guide" >}} |
| Claude Code | Plugin and hooks for `PreToolUse`, `PostToolUse`, `SubagentStart`, `SubagentStop`; source-checkout MVP quickstart with no-key harness and live-Claude path | {{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "MVP quickstart" >}}, {{< repo-link "plugins/claude-code/README.md" "Plugin README" >}} |
| Runnable examples | Mission JSON, LangChain, LangGraph, AutoGen, browser extension, desktop observe, native host | {{< repo-link "examples/README.md" "Examples index" >}} |
| Protocol docs | Mission Declaration, Delegation Grant, Execution Receipt, EAT profile, Verifier Contract, conformance profiles, IDM extension, revocation | {{< repo-link "docs/specs/README.md" "Specs index" >}} |
| CI and public hygiene | Python 3.10 and 3.13, Go, CodeQL, link-check, secret-scan, format validation, Hugo build | {{< repo-link ".github/workflows/tests.yml" "Tests workflow" >}} |

## Bounded Or In Progress

{{< proof-status state="archival" label="Archival media only" source="MEDIA.md" >}}
The current recordings are asciinema `.cast` files. They are useful proof
media, but they are not rerunnable public proof until stable verifier commands
and artifact paths land.
{{< /proof-status >}}

{{< proof-status state="hold" label="Not a packaged production release" source="STATUS.md" >}}
PyPI/Homebrew/OCI distribution, broader cluster deployment material, and
rerunnable public proof media are still being hardened.
{{< /proof-status >}}

Primary status source: {{< repo-link "STATUS.md" >}}.
