# Claude Code + Ardur quickstart

Placeholder. The adapter code lives in the private research repo and is being imported with the public-name cleanup applied; this directory describes what lands when that import finishes.

## What this example will demonstrate

Claude Code running under Ardur governance via the hook system. Unlike the framework adapters that wrap a Python tool layer, this one plugs into Claude Code's `PreToolUse` and `PostToolUse` hooks — the agent itself isn't modified, the hook is the integration point. Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. On every `PreToolUse`, verifies the about-to-run tool call against the mission's allowed tools, resource scope, and budget; non-zero exit blocks the call
3. On every `PostToolUse`, emits an Execution Receipt (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

The hook-based model is a different shape from the SDK adapters: the verifier is a separate process that Claude Code execs with tool-call JSON on stdin, and the hook's exit code is what gates execution. That means the verifier has to be fast — startup time directly inflates per-tool-call latency. The adapter ships a small daemon mode to amortize startup across a session.

## Dependencies

- `python/` editable install (this repo, `pip install -e ../python`; CLI is `ardur`, module imports are `vibap`)
- `claude-code` CLI installed and on `PATH`
- LLM access: handled by Claude Code itself
- Optional: Docker for the recorded asciinema flow

The hook configuration goes in `.claude/settings.json` — the example writes one for you, scoped to its directory, so it doesn't pollute global settings.

## File layout (when imported)

```
claude-code-hook/
├── README.md              # this file
├── run.sh                 # one-line runner
├── .claude/
│   └── settings.json      # hook config (PreToolUse + PostToolUse)
├── src/
│   ├── verifier.py        # the hook entrypoint (reads JSON on stdin)
│   └── daemon.py          # optional persistent verifier
├── mission.json           # the Mission Declaration the agent runs under
└── expected-receipt.json  # what a clean run produces, for diff-testing
```

## Run (when available)

```bash
cd claude-code-hook
./run.sh
# Spawns Claude Code with the hook installed and a fixed prompt;
# prints per-tool-call verdicts inline and the session attestation at exit.
```

## Out of scope for this example

- Hook timeout tuning — the example assumes Claude Code's default 60s ceiling is fine for local verification. Real deployments may need to drop it.
- Stop / SubagentStop hooks — only PreToolUse and PostToolUse are wired. Stop-hook integration for terminal attestation is a separate piece.
- Multi-tenant key isolation — single issuer key.
- Real-cluster SPIRE deployment — the example uses local file-based identity.

If you want to exercise the protocol without Claude Code in the loop, see `examples/missions/`.
