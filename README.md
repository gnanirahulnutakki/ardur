# Ardur

Ardur is the runtime governance and evidence layer for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-blue)](STATUS.md)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/gnanirahulnutakki/ardur/discussions)

This public repo is opening in phases. It now contains the product intent,
research-informed positioning, public specs, curated Python and Go runtime
imports, mission examples, runnable framework adapters (LangChain, LangGraph,
AutoGen), the Ardur Personal Hub service, the Claude Code plugin and hook,
and the public Hugo evidence site. Re-runnable proof media, full packaging,
and production deployment material are still being tightened before they are
presented as release-ready.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Coverage Map](docs/coverage-map.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Articles](docs/articles/README.md) · [Docs](docs/README.md) · [Reference](docs/reference/README.md) · [Read the Phase 1 Evidence Bundle](docs/guides/read-phase1-evidence-bundle.md) · [Evidence Site Source](site/README.md)

## Fastest MVP Path: Claude Code

Start with the source-checkout walkthrough in
[`docs/guides/claude-code-mvp-quickstart.md`](docs/guides/claude-code-mvp-quickstart.md).
It gives two bounded paths:

- a **no-key confidence check** that runs the fresh-user evidence harness,
  simulated Claude Code hook allow/deny receipts, and redacted bundle checks
  without contacting an LLM provider; and
- a **live Claude Code demo** for users who already have the `claude` binary
  installed and authenticated.

That guide also separates **Works now**, **Not claimed**, and **Coming soon** so
Ardur stays honest about package-manager release status, provider-hidden
behavior, and subprocess/kernel/network side-effect gaps.

> **Capture boundary today (v0.1):** Ardur signs every Claude Code tool-call
> invocation. Side effects below the tool boundary — subprocess trees,
> kernel events, network connections initiated by tool-spawned processes —
> are not yet captured; the roadmap closes that gap in v0.2 (filesystem
> snapshots), v0.5 (Linux eBPF), and v1.0 (macOS Endpoint Security
> Framework). See [`docs/coverage-map.md`](docs/coverage-map.md) for the
> precise per-tool audit.

## Why Ardur

Many agent stacks can log what happened. Fewer can stop an out-of-scope action
before it executes. Fewer still can prove later, with verifier-backed evidence,
what the runtime allowed, denied, or left unknown.

Ardur is being built to do all three:

- bind agents to a declared mission
- enforce runtime boundaries over tools, resources, budgets, and delegation
- emit evidence that can be checked instead of argued about

Concretely — these are the design principles the repo is being built to meet, not guarantees that every checked-in surface is already production-ready:

- **Public-by-default as a working principle.** The aim is that every public claim ties to a verifier path, an artifact, a re-runnable test, or an explicit limitation note. The code-bearing runtime is landing in phases per the [public import plan](docs/public-import-plan.md); claims that depend on not-yet-verified runtime behavior still need explicit caveats.
- **Composable with what already exists.** Designed around SPIFFE for workload identity, Biscuit for first-party-attenuation credentials, Cedar for policy, and on the AAT and EAT IETF drafts for token semantics. We didn't reinvent the substrate.
- **Cryptographically bound by design.** Mission credentials are designed to be signed by an issuer key, holder-bound to a SPIFFE SVID, and produce signed receipts chain-hashed to the previous one. The design is documented in the [ADRs](docs/decisions/README.md); the public code that implements it is being curated in phases.
- **Delegation that narrows, never widens.** Child sessions get strictly narrower authority than their parent — fewer tools, smaller resource scope, smaller budget. The narrowing discipline is formalised in [ADR-017](docs/decisions/ADR-017-biscuit-attenuation-narrowing-semantics.md).
- **Honest about what it doesn't do.** Scope-level governance can't catch semantic misuse — if an allowed tool is used on an allowed resource for the wrong reason, that's a different layer's job. We say so out loud.
- **MIT licensed.** The research foundation (the Silence Theorem, the protocol formalism, the benchmark methodology) will be linked from this repo when the paper's public identifier is assigned. Articles in this repo paraphrase the research in original prose; they do not reproduce paper content.

## What Is Public Today

This repo currently includes:

- the product thesis and launch direction
- a short research-informed positioning summary
- current status and what is still being resolved
- public v0.1 specs for mission declarations, execution receipts, verifier contracts, conformance profiles, and related protocol surfaces
- curated Python and Go runtime imports under `python/` and `go/`
- the Ardur Personal Hub service and CLI under `python/vibap/` (`ardur hub`, `ardur setup`, `ardur status`, `ardur protect claude-code`, `ardur profile init`, `ardur doctor-claude-code`)
- the Claude Code plugin under `plugins/claude-code/` with `PreToolUse`, `PostToolUse`, `SubagentStart`, and `SubagentStop` hooks emitting signed receipts
- runnable framework adapters under `examples/`: LangChain, LangGraph, AutoGen, browser extension, desktop-observe, and native-host. JSON mission examples remain in `examples/missions/`. OpenAI Agents SDK and Google ADK directories remain deferred adapter specs
- dedicated Python (3.10 + 3.13) and Go CI under `.github/workflows/tests.yml`, plus CodeQL, link-check, secret-scan, format validation, and the Hugo build
- the Hugo public evidence site source under `site/`, with each public claim linkable to its backing source file
- bootstrap and verification scripts under `scripts/` (`conductor-bootstrap.sh`, `setup-dev.sh`, `check-local.sh`)
- agent-specific public guides under [`docs/agent-instructions/`](docs/agent-instructions/) (Conductor, Codex, Claude)
- new technical reference pages under [`docs/reference/`](docs/reference/) — CLI, Personal Hub HTTP API, and the `ARDUR.md` profile format
- selected archival terminal recordings, plus a separate re-runnable no-key
  Phase 1 evidence harness for the Claude Code MVP path — see
  [MEDIA.md](MEDIA.md) and the
  [evidence-bundle guide](docs/guides/read-phase1-evidence-bundle.md)
- a journey-log [article series](docs/articles/README.md) — Article 06 (Public Import Discipline) and Article 05 (Proof Media That Actually Means Something) are the first-wave shippers
- a public audit trail at [`docs/audit/`](docs/audit/) mirroring the GitHub Code Scanning dismissal record so triage decisions are auditable from the repo tree without GitHub credentials

## What Is Coming Next

The next repo drops will add:

- runnable OpenAI Agents SDK and Google ADK adapter lifts to replace the current deferred-spec README directories
- Codex hooks and Claude Desktop MCP packaging as separate next-cycle integrations
- re-runnable proof media — recordings made against the public runtime with stable verifier commands and artifact paths, replacing the current archival walkthrough casts
- a tagged release with a regenerated Homebrew formula carrying Python resource stanzas, so non-technical users can install Ardur Personal without a source checkout
- broader deployment material (cluster, identity, receipt storage) past the current SPIRE design surface

## Integrations

Ardur sits between an AI agent and the tools it calls — so the integration story is which agent frameworks, model providers, policy engines, and identity systems Ardur plugs into.

| Layer                | In repo now | Still pending public validation |
|----------------------|-------------|---------------------------------|
| **Agent framework**  | JSON mission examples; Claude Code plugin; runnable LangChain, LangGraph, AutoGen, browser, desktop-observe, and native-host examples; deferred README-only OpenAI Agents SDK and Google ADK directories | more runnable framework adapters |
| **Model provider**   | provider-agnostic tool boundary in the runtime design | local Ollama quickstarts and live-provider examples |
| **Policy engine**    | native checks, forbid-rules, Cedar-facing surfaces | OPA and broader Biscuit datalog examples |
| **Identity**         | SPIFFE / SPIRE-oriented code and docs | full cluster deployment walkthrough |
| **Receipts sink**    | local JSON / stdout-oriented receipt surfaces | OTel emitters and durable storage examples |

If you'd use an integration that isn't listed, file an [integration request](https://github.com/gnanirahulnutakki/ardur/issues/new?template=integration_request.yml) — it's the strongest signal we have for prioritisation.

## Naming Note

`Ardur` is the public product name.

Some implementation and protocol surfaces still use `VIBAP`, `MCEP`, and
related protocol names. Those names are part of the technical lineage and are
kept where they describe actual artifacts, specifications, or protocol roots.

## Honest Note

This is not yet the full Ardur product repo.

We are publishing the public surface in phases so the repo starts clear,
credible, and truthful instead of dumping a private monorepo or making claims
ahead of the exported code.
