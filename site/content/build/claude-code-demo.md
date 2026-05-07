---
title: "Claude Code + Ardur — Live Session Demo"
description: "Real Claude Code session under Ardur supervision: hooks fire, signed receipts chain, scope violation caught."
weight: 42
maturity: ["public-now"]
claim_types: ["demo", "evidence"]
surfaces: ["python", "examples"]
frameworks: ["claude-code"]
evidence_levels: ["code-and-doc"]
---

This page demonstrates the Ardur Claude Code plugin guarding a real,
non-synthetic Claude Code session against the production Anthropic API. The
recording below is replay of artifacts captured on **2026-05-06** — the
receipt chain is bit-for-bit verifiable against the locally-generated ES256
public key.

{{< asciinema src="/casts/ardur-claude-code.cast"
              poster="/casts/ardur-claude-code.gif"
              cols="80" rows="24"
              idle-time-limit="1" >}}

## What the recording shows

1. **Profile.** A plain-Markdown `ARDUR.md` declares `read only` mode
   scoped to `/private/tmp/ardur-bench` with Read + Search allowed and
   Bash/Edit/Write blocked.
2. **Activation.** `ardur protect claude-code --profile ARDUR.md` compiles
   the profile into a Mission Passport and prints the exact `claude` command
   that pairs the plugin with the active passport.
3. **Live session.** A real `claude --plugin-dir plugins/claude-code …`
   invocation against the Anthropic API. The model uses Glob and Read to
   solve the task.
4. **Receipt report.** `ardur claude-code-report` summarises the chain: 9
   receipts, 3 Glob, 6 Read, 8 compliant verdicts, **1 violation**.
5. **Per-receipt decode.** Each receipt is decoded; signatures verify
   against the public key; `parent_receipt_hash` of receipt N matches
   `receipt_hash` of receipt N–1, so the chain is unforgeable without the
   private key.

## The violation

Receipt #1 carried a `violation` verdict. The model's first Glob targeted
`/tmp/ardur-bench/**/*.txt`, but the active scope was `/private/tmp/ardur-bench`
(macOS resolves `/tmp` to `/private/tmp`, but the scope check matches the
canonical absolute path). Ardur denied the call, recorded the violation
receipt, and Claude Code retried with the in-scope path. The second Glob
landed `compliant`, and the rest of the session completed normally.

This is a real-world demonstration that the plugin enforces what the
profile declares — not a synthetic deny that the test harness was rigged
to produce.

## Reproducing it locally

The demo script and saved artifacts live under `.context/claude-bench/`
(workspace-local, gitignored). To run a fresh session yourself:

```bash
# from the ardur repo root
pip install -e python/

mkdir -p /tmp/ardur-bench
cd /tmp/ardur-bench
seq 1 30 | sed 's/^/file1 line /' > file1.txt
seq 1 50 | sed 's/^/file2 line /' > file2.txt
seq 1 70 | sed 's/^/file3 line /' > file3.txt

ardur profile init --template read-only --path ARDUR.md
ardur protect claude-code --profile ARDUR.md
# Run the exact `VIBAP_HOME=… claude --plugin-dir … …` command Ardur prints,
# adding -p "Use Glob and Read to count total lines across all .txt files"

# Inspect the chain
ardur claude-code-report \
  --chain-dir "$VIBAP_HOME/claude-code-hook" \
  --keys-dir "$VIBAP_HOME/keys"
```

Receipts land at `$VIBAP_HOME/claude-code-hook/<trace_id>/receipts.jsonl`.
Each line is an ES256-signed JWT; `verify_chain()` in `vibap.receipt`
walks the chain backwards to confirm no entry was inserted, removed, or
reordered.

## Cost and timing

Both runs used the same Claude Code session against the Anthropic API,
with the same default model (CLI default at the time of capture; specific
model identifiers are elided per the repo convention in
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md)). Two single-shot runs of
the same prompt:

| Run | Wall | API ms | Cost | Tool calls | Result |
|---|---|---|---|---|---|
| Without Ardur | 76.19 s | 59,100 ms | $0.418 | 4 | 153 (off by 3) |
| With Ardur | 44.18 s | 22,970 ms | $0.397 | 5 (1 deny + retry) | **150** (correct) |

The wall-clock delta is **not a causal claim about Ardur** — the second run
hit a warm prompt cache that the first run created. For a clean overhead
measurement, run with-Ardur and without-Ardur 5× each, interleaved, and
compare medians. Hook-overhead per call is 150–250 ms (Python startup +
JWT signing + JSONL append + flock); on this run that's ~1.5–2.5 s
cumulative — well below the API-side variance.

The headline isn't speed — it's that **the model completed the task with
the correct answer under Ardur supervision**, the **scope violation was
caught**, and the **9-receipt chain verifies**.

## Where the code lives

- Hook entrypoints: {{< repo-link "plugins/claude-code/hooks/" "plugins/claude-code/hooks/" >}}
- Hook adapter: {{< repo-link "python/vibap/claude_code_hook.py" "python/vibap/claude_code_hook.py" >}}
- Telemetry mapper (covers all Claude Code built-ins + MCP fallback): {{< repo-link "python/vibap/claude_code_telemetry.py" "python/vibap/claude_code_telemetry.py" >}}
- Receipt chain primitives: {{< repo-link "python/vibap/receipt.py" "python/vibap/receipt.py" >}}
- Plugin README with full setup: {{< repo-link "plugins/claude-code/README.md" "Claude Code plugin README" >}}
