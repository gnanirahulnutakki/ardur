# Ardur Claude Code Hook Plugin

## What it does

This plugin governs every Claude Code tool call against the active Mission
Passport. `PreToolUse` runs before the tool executes: the adapter loads the
passport, maps the tool input to declared telemetry, and runs the native policy
backend. On Permit it emits a chained, tamper-evident receipt and returns
`continue: true`. On Deny it emits a non-compliant receipt and returns
`continue: false` with a `stopReason`. `PostToolUse` runs after the tool
returns: the adapter loads the response, computes its SHA-256 digest, and emits
a chained receipt with `result_hash` populated. All receipts are ES256-signed
and linked by SHA-256 parent-hashes so the chain can be verified offline.

## Prerequisites

- Python 3.11+
- `pip install -e python/` from the repo root (makes `vibap` importable)
- `python3` on PATH in Claude Code's spawn environment
- A Mission Passport issued via `ardur issue --mission "..."`, with the
  resulting JWT exported as `ARDUR_MISSION_PASSPORT`

## Install

```bash
# Issue a mission passport
cd <ardur-repo>
pip install -e python/
ardur issue --agent-id me --mission "review my code without running it" \
  --allowed-tools Read,Glob,Grep --forbidden-tools Bash,Write,Edit \
  --resource-scope '/Users/me/work/*' > active_mission.jwt
export ARDUR_MISSION_PASSPORT="$(cat active_mission.jwt)"

# Install the plugin into Claude Code
claude plugin add path/to/plugins/claude-code
```

Note: `claude plugin add` is the conventional Claude Code plugin install
command. Verify against current Claude Code documentation if the exact
subcommand differs for your installed version.

## What happens when a tool is called

1. **PreToolUse fires.** The hook script invokes
   `vibap.claude_code_hook.pre_tool_use_handler` with the tool name and input
   JSON from Claude Code.
2. The adapter calls `vibap.claude_code_telemetry.map_tool_call` to translate
   the Claude Code tool input into Ardur declared telemetry (tool name,
   arguments, resource targets).
3. The native policy backend evaluates the telemetry against the active
   passport's `allowed_tools`, `forbidden_tools`, and `resource_scope`.
4. **On Permit**: a chained receipt is emitted (parent-hash set to the previous
   receipt's digest, or the passport `jti` for the first call). The hook exits
   with `continue: true`.
5. **On Deny**: a non-compliant receipt is emitted. The hook exits with
   `continue: false` and a `stopReason` describing which policy clause was
   violated.
6. **PostToolUse fires** after the tool runs. The adapter receives the tool
   response, computes `sha256(response_bytes)`, and emits a chained receipt with
   `result_hash` set. No policy decision is made at this stage — PostToolUse is
   evidence collection only.

## Where receipts live

Receipts are written to:

```
$ARDUR_CC_HOOK_DIR/<trace_id>/receipts.jsonl
```

Default when `ARDUR_CC_HOOK_DIR` is not set:

```
~/.vibap/claude-code-hook/<trace_id>/receipts.jsonl
```

Each line is one signed receipt JWT. The `trace_id` is derived from the
passport's `jti` claim. Override it with `ARDUR_TRACE_ID`.

## Verifying the chain

```bash
PYTHONPATH=python python3 -c "
from pathlib import Path
from vibap.receipt import verify_chain
from vibap.passport import load_public_key
jwts = Path('~/.vibap/claude-code-hook/<trace>/receipts.jsonl').expanduser().read_text().splitlines()
jwts = [j.strip() for j in jwts if j.strip()]
pk = load_public_key()
verify_chain(jwts, pk)
print('chain ok:', len(jwts), 'receipts')
"
```

Replace `<trace>` with the `jti` from the passport (or the value of
`ARDUR_TRACE_ID` if you set that override).

## What this plugin does NOT do

- Does not validate tool-response content — only digests it (SHA-256 hash of
  the raw response bytes).
- Does not catch tools that bypass the hook system, for example tools invoked by
  sub-shells started inside a `Bash` tool call.
- Does not gate non-tool agent actions: model output, system prompts, sampling
  decisions, and memory writes are outside the hook surface.
- Does not enforce budgets across sessions — `max_tool_calls` is mission-scoped,
  but the hook adapter does not re-check budget on every call. Cross-session
  budget accounting is handled by the proxy session state (Tasks 6-8), not this
  plugin.

## Troubleshooting

**"ardur: no active mission passport found"**
The `ARDUR_MISSION_PASSPORT` environment variable is not set in the shell where
Claude Code is running. Export it before launching Claude Code, or add it to a
`.env` file that Claude Code loads on startup.

**"all candidate passports failed verification"**
The passport was signed by a keypair that does not match the public key resolved
from `keys_dir`. Either re-issue the passport with the correct key (run
`ardur issue` again) or point `ARDUR_KEYS_DIR` at the directory containing the
matching public key.

**Hook crashes silently / receipts not appearing**
Check that `ARDUR_CC_HOOK_DIR` (or `~/.vibap/claude-code-hook/`) is writable by
the process running Claude Code. Also confirm `python3` is on PATH in Claude
Code's environment — the hook scripts invoke `python3` directly.

**Hook fires but every call is denied unexpectedly**
Inspect the non-compliant receipt: `jq -r '. | @base64d' receipts.jsonl` (after
splitting on `.`) shows the payload. The `policy_result.reason` field identifies
which clause triggered the deny.

## Filing integration requests

Open an issue at:
https://github.com/gnanirahulnutakki/ardur/issues/new?template=integration_request.yml
