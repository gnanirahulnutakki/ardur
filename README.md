# Ardur

Ardur is the runtime governance and evidence layer for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-blue)](STATUS.md)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/gnanirahulnutakki/ardur/discussions)

Ardur sits between an agent and the tools it wants to call. A session gets a
signed mission passport describing mission intent, tool permissions, resource
scope, budget, and delegation limits. The runtime enforces those boundaries at
execution time and emits signed receipts so reviewers can verify what was
allowed, denied, or left unknown.

This public repo is pre-release and opening in phases. It includes public
specs, curated Python and Go reference runtime code, tests, examples, selected
deployment material, and a claim/evidence/limitation posture. It is not yet a
production-ready distribution, and full public replay media is still being
tightened.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Articles](docs/articles/README.md) · [Docs](docs/README.md) · [Reference](docs/reference/README.md) · [Evidence Site Source](site/README.md)

## Try the no-key passport proof

This path does not call an LLM or require provider credentials.

```bash
# from the repo root (Python 3.10+)
cd python
python3 -m pip install -e .

TOKEN="$(
  ardur issue \
    --agent-id example-agent \
    --mission "read sales data and write a summary" \
    --allowed-tools read_file write_report \
    --resource-scope 'sales/*' 'reports/*' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
)"

ardur verify --token "$TOKEN"
```

Expected result: `"valid": true`, with mission, tool, resource-scope, and
budget claims visible in the decoded passport.

This is a narrow local proof: passport issue/verify works. It is not yet a full
public replay proof for every runtime session.

## What you can verify today

| Claim | How to check | Limit |
|---|---|---|
| Python mission-passport issue/verify works locally | Run the no-key block above and `python/tests/test_passport.py` | Narrow proof, not full runtime replay |
| Python and Go runtime surfaces are present in this repo | `python/vibap/`, `go/pkg/`, `go/cmd/` | Pre-release APIs may still change |
| CI and hygiene gates are defined | `.github/workflows/tests.yml`, `docs/TESTING.md` | A defined workflow is not the same as a linked green run |
| Runnable framework quickstarts are present | `examples/langchain-quickstart/`, `examples/langgraph-quickstart/`, `examples/autogen-quickstart/` | Optional dependencies and provider setup are still needed for full live demos |
| Conformance boundaries are explicit | `STATUS.md` (`In Progress`), `docs/specs/verifier-contract-v0.1.md` | Conformance test vectors are not fully imported yet |

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
- selected archival terminal recordings (the rerunnable proof path lands with the next public drop — see [MEDIA.md](MEDIA.md))
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

If you care about agent accountability, star the repo and run the no-key proof above. If you'd use an integration that isn't listed, file an [integration request](https://github.com/gnanirahulnutakki/ardur/issues/new?template=integration_request.yml) so we can prioritize the right adapter work.

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
