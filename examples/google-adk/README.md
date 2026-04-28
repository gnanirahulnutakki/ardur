# Google ADK + Ardur quickstart

**Status: stub — Phase 3 lift target.** This README documents the intended shape; the runnable code lands in a follow-up commit.

## What this example will demonstrate

A Google ADK agent making tool calls through Ardur's governance proxy. The agent receives an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

## Dependencies

- `python/vibap` (this repo, `pip install -e ../python`)
- `google-adk ^0.1.0`
- LLM access: Google AI Studio API key
- Optional: Docker for the recorded asciinema flow

## Expected files (when lifted)

```
google-adk/
├── README.md           # this file
├── run.sh              # one-line runner
├── src/
│   ├── agent.py        # the agent definition
│   └── tools.py        # tool stubs (read, write, summarize)
├── mission.json        # the Mission Declaration the agent runs under
└── expected-receipt.json   # what a clean run produces, for diff-testing
```

## Run (when available)

```bash
cd google-adk
./run.sh
# Output:
#   - mission compiled
#   - agent started with passport
#   - tool calls + per-call verdicts
#   - session attestation printed at exit
```

## Source for the lift

Adapter code lives in the private research repo at `vibap-prototype/demos/Google ADK/`. The lift requires the same Wolverine/Radiantic → Ardur rename pass as the rest of the runtime (clean break, no backward-compat dual-type — see `docs/specs/README.md` "Protocol identifier rename" section).

## What this example does NOT cover

- Real-cluster SPIRE deployment (separate Phase 6 work; this example uses local file-based identity)
- Live LLM provider failover (single-provider per run)
- Multi-tenant key isolation (single issuer key)
