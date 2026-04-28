# Ardur Examples

Working examples of Ardur governing AI agents across the major frameworks. Some directories are runnable today; the rest are placeholders waiting on adapter code that's still being imported from the private research tree.

## Status

| Example | Status | Runtime dependency |
|---------|--------|-------------------|
| [missions/](missions/) | runnable | None — JSON files only |
| [langchain-quickstart/](langchain-quickstart/) | placeholder | `python/` editable install + LangChain + Ollama |
| [langgraph-quickstart/](langgraph-quickstart/) | placeholder | `python/` editable install + LangGraph + Ollama |
| [autogen-quickstart/](autogen-quickstart/) | placeholder | `python/` editable install + AutoGen v0.4+ + Ollama |
| [claude-code-hook/](claude-code-hook/) | placeholder | `python/` editable install + Claude Code CLI |
| [openai-agents-sdk/](openai-agents-sdk/) | placeholder | `python/` editable install + OpenAI Agents SDK + OpenAI API key |
| [google-adk/](google-adk/) | placeholder | `python/` editable install + Google ADK + Google AI API key |

Each placeholder directory carries a README that lays out the dependency footprint, the file layout the import will produce, and the framework-specific gotchas a contributor should know going in. The adapter code lives in the private research repo and is being imported with the public-name cleanup applied; whoever picks up an adapter can finish the import in isolation without coordinating with the others.

## Running the mission examples (today, no agent required)

```bash
cd ../python
pip install -e .

# Issue and verify a passport using one of the example mission files
ardur issue --from-file ../examples/missions/minimal-mission.json
ardur verify <token-from-issue-output>
```

That exercises the core protocol surface end-to-end — mission compilation, passport issuance, signature, verification — without an LLM or framework in the loop. It's the fastest way to confirm a local install actually works.

## Why placeholders instead of one big drop

Each framework has its own tool-call interface, its own session-state model, and its own integration point where Ardur's governance proxy attaches. LangChain tool callbacks look nothing like AutoGen's `FunctionTool` registration; LangGraph's state graph wants the verifier wrapped around node transitions; Claude Code wires in via the hook lifecycle, not a Python import. Lifting these as one monolithic commit would conflate unrelated breakage. Per-framework directories let each adapter land, get reviewed, and run CI on its own.

## CI for examples

Once at least one quickstart has runnable code, an `examples-smoke.yml` workflow will exercise it end-to-end on every PR — `langchain-quickstart` is the likely first because it has the lightest dependency surface (no extra system packages, Ollama already in the image). CodeQL handles static analysis automatically once Python files appear under `examples/*/src/`.
