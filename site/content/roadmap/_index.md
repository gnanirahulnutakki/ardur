---
title: "Roadmap"
description: "A staged view of public-now, in-progress, planned, and not-public-yet work."
weight: 70
maturity: ["public-now", "in-progress"]
claim_types: ["status", "roadmap", "deployment", "integration", "proof-media"]
surfaces: ["docs", "examples", "media", "deploy"]
frameworks: ["framework-agnostic", "kubernetes", "spire", "openai-agents-sdk", "google-adk"]
evidence_levels: ["code-and-doc", "doc-and-manifest", "archival-media", "limitation-backed"]
---

## Public Now

- Runtime governance core in Python and Go.
- Ardur Personal Hub, CLI, Claude Code plugin, and local adapter surfaces.
- Runnable LangChain, LangGraph, AutoGen, browser extension, desktop observe,
  and native-host examples.
- Public v0.1 specs, ADRs, CI workflows, agent instructions, articles, and
  source-backed Hugo site.

## In Progress

- Runnable OpenAI Agents SDK and Google ADK adapter lifts.
- Codex hooks and Claude Desktop MCP packaging.
- Rerunnable proof media from the public runtime.
- Conformance test vectors under `docs/specs/conformance/`.
- Tagged release and regenerated Homebrew formula.
- Broader deployment material beyond the current SPIRE design surface.

## Not Public Yet

- PyPI, Homebrew, or OCI distribution suitable for non-technical users.
- Production-complete cluster, identity, and receipt-storage walkthroughs.
- Hardware-rooted TEE production claims.
- Benchmark-heavy material and internal session artifacts.

Primary source: {{< repo-link "ROADMAP.md" >}}.
