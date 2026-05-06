---
title: "Use And Troubleshooting"
description: "Hosted entry points for using Ardur, checking current limits, and debugging integrations without leaving the site."
weight: 41
maturity: ["public-now", "in-progress"]
claim_types: ["orientation", "runtime-boundary", "limitation", "deployment", "integration"]
surfaces: ["docs", "python", "go", "examples", "deploy", "github"]
frameworks: ["framework-agnostic", "langchain", "langgraph", "autogen", "google-adk", "openai-agents-sdk", "claude-code", "kubernetes", "spire"]
evidence_levels: ["code-and-doc", "doc-and-manifest", "limitation-backed"]
---

This page is the hosted documentation map. Readers should be able to understand
the current repo, usage path, known limits, and troubleshooting surface here
without using GitHub as the documentation browser.

## Start

- {{< repo-link "README.md" "Project README" >}} — thesis, current public scope, and first-wave artifacts.
- {{< repo-link "STATUS.md" "Status" >}} — what is public now, what is still being hardened, and what changed most recently.
- {{< repo-link "ROADMAP.md" "Roadmap" >}} — staged publication plan and next hardening work.
- {{< repo-link "docs/known-limitations.md" "Known limitations" >}} — caveats around not-yet-runnable proof paths and public media.

## Use

- {{< repo-link "python/README.md" "Python package" >}} — current Python surface and runtime boundary.
- {{< repo-link "go/README.md" "Go module" >}} — current Go surface and protocol support.
- {{< repo-link "examples/README.md" "Examples index" >}} — framework examples and their maturity labels.
- {{< repo-link "examples/langchain-quickstart/README.md" "LangChain quickstart" >}}
- {{< repo-link "examples/langgraph-quickstart/README.md" "LangGraph quickstart" >}}
- {{< repo-link "examples/autogen-quickstart/README.md" "AutoGen quickstart" >}}
- {{< repo-link "examples/google-adk/README.md" "Google ADK quickstart" >}}
- {{< repo-link "examples/openai-agents-sdk/README.md" "OpenAI Agents SDK quickstart" >}}
- {{< repo-link "examples/claude-code-hook/README.md" "Claude Code hook example" >}}

## Troubleshoot

- {{< repo-link "docs/TESTING.md" "Testing guide" >}} — local and CI validation commands.
- {{< repo-link "docs/security-model.md" "Security model" >}} — trust boundaries and security assumptions.
- {{< repo-link "SECURITY.md" "Security policy" >}} — vulnerability reporting and supported surfaces.
- {{< repo-link "MEDIA.md" "Media proof notes" >}} — archival media caveats and proof-status labels.
- {{< repo-link "docs/audit/" "Audit records" >}} — hosted audit notes and code-scanning dismissal rationale.

## Deploy

- {{< repo-link "deploy/README.md" "Deployment overview" >}}
- {{< repo-link "deploy/helm/ardur/README.md" "Helm chart" >}}
- {{< repo-link "deploy/k8s/spire/README.md" "SPIRE deployment notes" >}}

## Protocol And Reference

- {{< repo-link "docs/specs/README.md" "Specs index" >}}
- {{< repo-link "docs/decisions/README.md" "ADR index" >}}
- {{< repo-link "docs/protocol-roots.md" "Protocol roots" >}}
- {{< repo-link "docs/comparisons/README.md" "Comparisons" >}}
- {{< repo-link "go/spec/mission-governance/v0alpha1/README.md" "Go mission-governance spec" >}}

## Articles And Contributor Docs

- {{< repo-link "docs/articles/README.md" "Article index" >}}
- {{< repo-link "docs/articles/05-proof-media-that-actually-means-something.md" "Proof Media That Actually Means Something" >}}
- {{< repo-link "docs/articles/06-public-import-discipline.md" "Public Import Discipline" >}}
- {{< repo-link "CONTRIBUTING.md" "Contributing" >}}
- {{< repo-link "CODE_OF_CONDUCT.md" "Code of conduct" >}}
- {{< repo-link ".github/PULL_REQUEST_TEMPLATE.md" "Pull request template" >}}
