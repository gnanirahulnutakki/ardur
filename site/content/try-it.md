---
title: "Try It"
description: "The shortest source-backed local path through Ardur today."
weight: 30
maturity: ["public-now"]
claim_types: ["orientation", "runtime-boundary"]
surfaces: ["python", "examples", "docs"]
frameworks: ["framework-agnostic", "claude-code"]
evidence_levels: ["code-and-doc"]
---

The fastest current path does not require an LLM provider. It exercises the
core protocol surface with a checked-in mission file.

```bash
cd python
pip install -e .
ardur issue --from-file ../examples/missions/minimal-mission.json
ardur verify --token '<token-from-issue-output>'
```

That path covers mission compilation, passport issuance, signing, and
verification. For local product usage, start with the Personal Hub and Claude
Code plugin docs.

## Next Paths

- {{< repo-link "docs/reference/cli.md" "CLI reference" >}}
- {{< repo-link "docs/guides/ardur-personal-hub.md" "Ardur Personal Hub guide" >}}
- {{< repo-link "plugins/claude-code/README.md" "Claude Code plugin" >}}
- {{< repo-link "examples/langchain-quickstart/README.md" "LangChain quickstart" >}}
- {{< repo-link "examples/langgraph-quickstart/README.md" "LangGraph quickstart" >}}
- {{< repo-link "examples/autogen-quickstart/README.md" "AutoGen quickstart" >}}

## Keep In Mind

OpenAI Agents SDK and Google ADK are currently deferred adapter specs, not
runnable examples. Rerunnable proof media is also not public yet.
