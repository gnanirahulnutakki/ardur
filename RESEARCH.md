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

## Naming Transition

For this Phase 0 public shell, `Ardur` is the public name.

The current implementation lineage still uses `Wolverine` in parts of the code,
CLI, capability IDs, and recordings. That transition is operational, not
conceptual.

## Why This Repo Starts Thin

This Phase 0 shell exists so the public repo can start now without pretending
the full exported codebase has already landed.

The repo opens with:

- intent
- status
- roadmap
- selected recordings

Then it grows into the fuller code-bearing product repo in later drops.
