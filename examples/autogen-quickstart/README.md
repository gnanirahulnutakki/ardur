# AutoGen + Ardur quickstart

Placeholder. The adapter code lives in the private research repo and is being imported with the public-name cleanup applied; this directory describes what lands when that import finishes.

## What this example will demonstrate

An AutoGen agent (v0.4+ architecture, `autogen-agentchat`) making tool calls through Ardur's governance proxy. The agent runs under an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

AutoGen 0.4 is a ground-up rewrite from 0.2, so this adapter only targets the new event-driven runtime. The proxy attaches at the `FunctionTool` boundary inside `AssistantAgent`, before the tool's own pydantic validation runs — that ordering matters because mission violations should short-circuit before argument parsing reports a different error.

## Dependencies

- `python/` editable install (this repo, `pip install -e ../python`; CLI is `ardur`, module imports are `vibap`)
- `autogen-agentchat ^0.4.0`
- `autogen-core` (transitive, but worth pinning if you hit version skew)
- LLM access: local Ollama or OpenAI
- Optional: Docker for the recorded asciinema flow

A heads-up for whoever lifts this: AutoGen's `protobuf` dependency has historically conflicted with other Google libraries (notably `google-cloud-*`) by pinning incompatible majors. If you're testing in a venv that already has GCP libs installed, use a fresh venv or expect to pin `protobuf>=4.25,<5` manually.

## File layout (when imported)

```
autogen-quickstart/
├── README.md              # this file
├── run.sh                 # one-line runner
├── src/
│   ├── agent.py           # AssistantAgent + tool registration
│   └── tools.py           # tool stubs (read, write, summarize)
├── mission.json           # the Mission Declaration the agent runs under
└── expected-receipt.json  # what a clean run produces, for diff-testing
```

## Run (when available)

```bash
cd autogen-quickstart
./run.sh
# Output:
#   - mission compiled
#   - agent started with passport
#   - tool calls + per-call verdicts
#   - session attestation printed at exit
```

## Out of scope for this example

- Multi-agent group chat (`SelectorGroupChat`, `RoundRobinGroupChat`) — single-agent flow only. Group chat receipts need turn-attribution semantics that aren't settled yet.
- Real-cluster SPIRE deployment — the example uses local file-based identity.
- Live LLM provider failover — single provider per run.
- Multi-tenant key isolation — single issuer key.

The protocol-only flow is in `examples/missions/`.
