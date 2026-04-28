# LangChain + Ardur quickstart

Placeholder. The adapter code lives in the private research repo and is being imported with the public-name cleanup applied; this directory describes what lands when that import finishes.

## What this example will demonstrate

A LangChain agent making tool calls through Ardur's governance proxy. The agent runs under an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

The integration point is the LangChain tool callback layer — the proxy wraps `BaseTool.invoke` so verification runs before the underlying tool body, and receipts emit on both success and exception paths.

## Dependencies

- `python/` editable install (this repo, `pip install -e ../python`; CLI is `ardur`, module imports are `vibap`)
- `langchain ^0.3.0`
- LLM access: local Ollama via `OllamaChat`
- Optional: Docker for the recorded asciinema flow

LangChain 0.3 split out `langchain-core`; the adapter pins `langchain-core ^0.3` directly to avoid surprises when a future `langchain` minor pulls in something incompatible.

## File layout (when imported)

```
langchain-quickstart/
├── README.md              # this file
├── run.sh                 # one-line runner
├── src/
│   ├── agent.py           # the agent definition
│   └── tools.py           # tool stubs (read, write, summarize)
├── mission.json           # the Mission Declaration the agent runs under
└── expected-receipt.json  # what a clean run produces, for diff-testing
```

## Run (when available)

```bash
cd langchain-quickstart
./run.sh
# Output:
#   - mission compiled
#   - agent started with passport
#   - tool calls + per-call verdicts
#   - session attestation printed at exit
```

`expected-receipt.json` is byte-comparable against the real receipt minus the timestamp and signature fields, which makes it cheap to regression-test the adapter with `diff` in CI.

## Out of scope for this example

- Real-cluster SPIRE deployment — the example uses local file-based identity. Cluster identity comes later.
- Live LLM provider failover — single provider per run.
- Multi-tenant key isolation — single issuer key.

If you want any of the above, look at `examples/missions/` for the protocol-only flow and combine it with your own deployment patterns.
