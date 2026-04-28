# LangGraph + Ardur quickstart

Placeholder. The adapter code lives in the private research repo and is being imported with the public-name cleanup applied; this directory describes what lands when that import finishes.

## What this example will demonstrate

A LangGraph agent making tool calls through Ardur's governance proxy. The agent runs under an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

LangGraph's integration point is different from LangChain's: the verifier hooks into node transitions on the `StateGraph`, not the tool wrapper directly. That means cycles and conditional edges need receipts that carry the source/target node so the attestation stays linkable to the graph topology — receipts emit in node order, not call order.

## Dependencies

- `python/` editable install (this repo, `pip install -e ../python`; CLI is `ardur`, module imports are `vibap`)
- `langgraph ^0.2.0`
- LLM access: local Ollama via `OllamaChat`
- Optional: Docker for the recorded asciinema flow

## File layout (when imported)

```
langgraph-quickstart/
├── README.md              # this file
├── run.sh                 # one-line runner
├── src/
│   ├── agent.py           # the StateGraph definition
│   └── tools.py           # tool stubs (read, write, summarize)
├── mission.json           # the Mission Declaration the agent runs under
└── expected-receipt.json  # what a clean run produces, for diff-testing
```

## Run (when available)

```bash
cd langgraph-quickstart
./run.sh
# Output:
#   - mission compiled
#   - agent started with passport
#   - per-node tool calls + verdicts
#   - session attestation printed at exit
```

## Out of scope for this example

- Real-cluster SPIRE deployment — the example uses local file-based identity.
- Live LLM provider failover — single provider per run.
- Multi-tenant key isolation — single issuer key.
- Persistent checkpointing across runs (LangGraph supports it, but the example resets state each run for reproducible receipts).

For pure protocol exercising without the framework on top, see `examples/missions/`.
