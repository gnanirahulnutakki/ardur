# Ardur

Ardur is the runtime governance and evidence layer for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-blue)](STATUS.md)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/gnanirahulnutakki/ardur/discussions)

This public repo is opening in phases. It now contains the product intent,
research-informed positioning, public specs, curated Python and Go runtime
imports, mission examples, and framework example stubs. Broader proof surfaces,
packaging, and production deployment material are still being tightened before
they are presented as release-ready.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Docs](docs/README.md)

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
- JSON-only mission examples plus framework example stubs under `examples/`
- selected archival terminal recordings (the rerunnable proof path lands with the next public drop — see [MEDIA.md](MEDIA.md))

## What Is Coming Next

The next repo drops will add:

- dedicated Python and Go CI workflows once the imported runtime surfaces finish their public verification pass
- first runnable framework examples beyond JSON mission files
- public verifier and proof commands with stable artifact paths
- a tighter quickstart and framework story

## Integrations

Ardur sits between an AI agent and the tools it calls — so the integration story is which agent frameworks, model providers, policy engines, and identity systems Ardur plugs into.

| Layer                | In repo now | Still pending public validation |
|----------------------|-------------|---------------------------------|
| **Agent framework**  | JSON mission examples; framework stubs (README-only) for Claude Code, OpenAI Agents SDK, Google ADK, LangChain, LangGraph, AutoGen | runnable framework adapters |
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
