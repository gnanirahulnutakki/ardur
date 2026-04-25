# Ardur

Ardur is the runtime governance and evidence layer for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Phase](https://img.shields.io/badge/phase-0%20%E2%80%94%20public%20shell-blue)](STATUS.md)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/gnanirahulnutakki/ardur/discussions)
[![Articles](https://img.shields.io/badge/docs-articles-9cf)](docs/articles/README.md)

This public repo is opening in phases. It starts with the product intent,
research-informed positioning, current status, and selected example recordings.
Curated code, runnable examples, and broader proof surfaces are landing next.
More is coming soon, but the repo starts narrow on purpose.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Articles](docs/articles/README.md) · [Docs](docs/README.md)

## Why Ardur

Many agent stacks can log what happened. Fewer can stop an out-of-scope action
before it executes. Fewer still can prove later, with verifier-backed evidence,
what the runtime allowed, denied, or left unknown.

Ardur is being built to do all three:

- bind agents to a declared mission
- enforce runtime boundaries over tools, resources, budgets, and delegation
- emit evidence that can be checked instead of argued about

Concretely — these are the design principles the repo is being built to meet, not guarantees the Phase 0 shell already delivers:

- **Public-by-default as a working principle.** The aim is that every public claim ties to a verifier path, an artifact, a re-runnable test, or an explicit limitation note. The code-bearing runtime lands in phases per the [public import plan](docs/public-import-plan.md) — until it does, claims that depend on the runtime say so explicitly.
- **Composable with what already exists.** Designed around SPIFFE for workload identity, Biscuit for first-party-attenuation credentials, Cedar for policy, and on the AAT and EAT IETF drafts for token semantics. We didn't reinvent the substrate.
- **Cryptographically bound by design.** Mission credentials are designed to be signed by an issuer key, holder-bound to a SPIFFE SVID, and produce signed receipts chain-hashed to the previous one. The design is documented in the [ADRs](docs/decisions/README.md); the public code that implements it is being curated in phases.
- **Delegation that narrows, never widens.** Child sessions get strictly narrower authority than their parent — fewer tools, smaller resource scope, smaller budget. The narrowing discipline is formalised in [ADR-017](docs/decisions/ADR-017-biscuit-attenuation-narrowing-semantics.md).
- **Honest about what it doesn't do.** Scope-level governance can't catch semantic misuse — if an allowed tool is used on an allowed resource for the wrong reason, that's a different layer's job. We say so out loud.
- **MIT licensed.** The research foundation (the Silence Theorem, the protocol formalism, the benchmark methodology) will be linked from this repo when the paper's public identifier is assigned. Articles in this repo paraphrase the research in original prose; they do not reproduce paper content.

## What Is Public Today

This Phase 0 repo shell includes:

- the product thesis and launch direction
- a short research-informed positioning summary
- current status and what is still being resolved
- selected terminal recordings from canonical proof paths

## What Is Coming Next

The next repo drops will add:

- curated code from the fresh-history export
- first runnable public examples
- public verifier and proof commands
- a tighter quickstart and framework story

## Integrations

Ardur sits between an AI agent and the tools it calls — so the integration story is which agent frameworks, model providers, policy engines, and identity systems Ardur plugs into.

| Layer                | Today (publicly installable) | Phase 1 (curated lift in progress) | Phase 2 (validated privately, public SDK pending) |
|----------------------|------------------------------|-------------------------------------|---------------------------------------------------|
| **Agent framework**  | none yet                     | Claude Code hook · OpenAI Agents SDK · Google ADK | LangChain · LangGraph · AutoGen                   |
| **Model provider**   | n/a                          | provider-agnostic via tool boundary | local Ollama tested in private demos              |
| **Policy engine**    | none yet                     | Cedar (built-in) · forbid-rules     | OPA · Biscuit datalog                             |
| **Identity**         | none yet                     | SPIFFE / SPIRE                      | OIDC bridges                                      |
| **Receipts sink**    | none yet                     | local JSON · stdout                 | OTel emitters · S3 / WORM offload                 |

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
