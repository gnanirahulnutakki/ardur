# Ardur Examples

Working examples of Ardur governing AI agents across major frameworks. Each subdirectory either has a runnable example (today) or a structured stub describing what the example will do once the per-framework adapter lands (Phase 3 of the lift wave continuation).

## Status

| Example | Status | Runtime dependency |
|---------|--------|-------------------|
| [missions/](missions/) | ✅ runnable | None — JSON files only |
| [langchain-quickstart/](langchain-quickstart/) | 🚧 stub | `python/vibap` + LangChain + Ollama |
| [langgraph-quickstart/](langgraph-quickstart/) | 🚧 stub | `python/vibap` + LangGraph + Ollama |
| [autogen-quickstart/](autogen-quickstart/) | 🚧 stub | `python/vibap` + AutoGen v0.4+ + Ollama |
| [claude-code-hook/](claude-code-hook/) | 🚧 stub | `python/vibap` + Claude Code CLI |
| [openai-agents-sdk/](openai-agents-sdk/) | 🚧 stub | `python/vibap` + OpenAI Agents SDK + OpenAI API key |
| [google-adk/](google-adk/) | 🚧 stub | `python/vibap` + Google ADK + Google AI API key |

A "🚧 stub" means: the directory has a README that describes what the example covers, what the user will need to install, and what the expected output is. The actual adapter code lands as the per-framework Phase 3 work — those commits each ship one runnable example with a documented run-script.

## Running the mission examples (today, no agent required)

```bash
cd ../python
pip install -e .

# Issue and verify a passport using one of the example mission files
ardur issue --from-file ../examples/missions/minimal-mission.json
ardur verify <token-from-issue-output>
```

This exercises the core protocol surface — mission compilation, passport issuance, signature, verification — without any LLM or framework dependency.

## Why stubs

Per-framework adapter work is real engineering: each framework has its own tool-call interface, its own session-state model, and its own integration points where Ardur's governance proxy attaches. Lifting the adapters from the private working tree into the public Ardur repository needs a careful pass per framework, including public-name cleanup and the protocol-identifier clean break. The stub READMEs document the intended shape so a contributor can pick up any one of them and complete the lift in isolation.

## Testing the examples (after Phase 3 lift completes)

A new CI workflow `examples-smoke.yml` will run at least one quickstart end-to-end on every PR (likely `langchain-quickstart` since it has the simplest dependency footprint). The CodeQL workflow already handles static analysis once Python files land under `examples/*/src/`.
