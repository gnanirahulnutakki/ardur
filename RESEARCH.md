# Research Notes

This public repo shape is based on a scan of strong public AI infrastructure
repos, including Guardrails AI, Langfuse, Portkey, Letta, AgentScope,
Invariant, LLM Guard, Tencent AI-Infra-Guard, and Prompt Injector.

## What Strong Repos Do

- lead with a category claim, not a theory claim
- make time-to-value obvious
- put product and operator value before proof
- use the repo itself as marketing, onboarding, and trust surface
- own one wedge instead of explaining five products at once

## What That Means For Ardur

Ardur should not open as:

- a paper repo
- a benchmark repo
- a protocol archive
- a dump of internal history

Ardur should open as:

- a runtime governance layer
- an evidence layer
- a proof-backed engineering project

## Chosen Wedge

The public wedge is narrower than the internal monorepo story:

- govern agent actions against a declared mission
- emit verifiable runtime evidence
- prove claims with reproducible artifacts

That is more distinctive than competing on "guardrails" alone.

## Naming Boundary

`Ardur` is the public product and repo name.

`VIBAP`, `MCEP`, and related protocol names remain useful where they identify
the implementation lineage, evidence model, or protocol research roots. The
public repo should preserve those names when they are technically meaningful
and avoid obsolete product codenames in public-facing copy.

## Why This Repo Opens In Phases

This repo opens in phases so the public surface stays understandable and
truthful while code, deployment material, proof artifacts, and examples are
curated into the public layout.

The repo now includes:

- intent
- status
- roadmap
- public v0.1 specs
- curated Python and Go runtime imports
- mission examples and framework example stubs
- selected recordings

The remaining work is packaging, end-to-end proof paths, runnable framework
examples, and deployment validation.
