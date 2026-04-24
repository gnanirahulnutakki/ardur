# Ardur

Ardur is the runtime governance and evidence layer for AI agents.

This public repo is opening in phases. It starts with the product intent,
research-informed positioning, current status, and selected example recordings.
Curated code, runnable examples, and broader proof surfaces are landing next.
More is coming soon, but the repo starts narrow on purpose.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Docs](docs/README.md)

## Why Ardur

Many agent stacks can log what happened. Fewer can stop an out-of-scope action
before it executes. Fewer still can prove later, with verifier-backed evidence,
what the runtime allowed, denied, or left unknown.

Ardur is being built to do all three:

- bind agents to a declared mission
- enforce runtime boundaries over tools, resources, budgets, and delegation
- emit evidence that can be checked instead of argued about

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

## Transition Note

`Ardur` is the public product name.

Some current implementation surfaces still use the `Wolverine` codename in
CLIs, capability IDs, env vars, and example recordings. That is intentional for
now. The public brand is moving first; the deeper code and namespace rename can
follow once the exported repo shape is stable.

## Honest Note

This is not yet the full Ardur product repo.

We are publishing the public surface in phases so the repo starts clear,
credible, and truthful instead of dumping a private monorepo or making claims
ahead of the exported code.
