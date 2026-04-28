"""Ardur live-governance demo — LangChain flavor.

Uses the shared scene structure from demo_scenes.py. Only the
framework-specific bits are here: how the LangChain agent is built and
how scenarios are invoked.

Scope note: the governance layer (SPIRE, Biscuit, Cedar, native,
forbid-rules, signed receipts, attestation) is exercised with real
tools. The demo's tool IMPLEMENTATIONS (`send_email`, `delete_file`)
are stubs — they return placeholder strings if permitted. That's
deliberate: the point of the demo is to show governance stopping the
call BEFORE the side-effect would fire; whether the side-effect
implementation is real or stubbed doesn't change anything governance
does.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, "/app/ardur")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from demo_scenes import (
    DIM,
    RESET,
    fetch_svid_via_spiffe_python,
    make_langchain_governed_tools,
    make_langchain_llm,
    make_langchain_multiagent_tools,
    provider_label,
    run_demo,
)


FRAMEWORK = "LangChain"


def build_agent(proxy, session, workspace):
    """Framework-specific agent construction. Returns:
      (agent, session_ref, invoke_benign, invoke_attack)
    session_ref is a mutable list so Scene 10 can swap to a child
    session without rewrapping tools.
    """
    session_ref = [session]
    tools = make_langchain_governed_tools(proxy, session_ref, workspace)
    llm = make_langchain_llm()
    code = f'''
      llm = make_langchain_llm()   # provider = {provider_label()}
      agent = create_react_agent(llm, tools)
    '''
    print(f"{DIM}{code}{RESET}")
    agent = create_react_agent(llm, tools)

    def invoke(agent, prompt):
        response = agent.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"recursion_limit": 12},
        )
        print(f"\n      (agent produced {len(response.get('messages', []))} "
              f"messages total)")

    return agent, session_ref, invoke, invoke


def build_multiagent_agent(engine):
    tools = make_langchain_multiagent_tools(engine)
    llm = make_langchain_llm()
    code = f'''
      llm = make_langchain_llm()   # provider = {provider_label()}
      tools = [spawn_subagent, run_subagent, close_subagent]
      agent = create_react_agent(llm, tools)
    '''
    print(f"{DIM}{code}{RESET}")
    agent = create_react_agent(llm, tools)

    def invoke(agent, prompt):
        response = agent.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"recursion_limit": 40},
        )
        print(f"\n      (multiagent parent produced "
              f"{len(response.get('messages', []))} messages total)")

    return agent, invoke


def main():
    return run_demo(
        framework=FRAMEWORK,
        ollama_model=provider_label(),
        svid_fetch=fetch_svid_via_spiffe_python,
        build_agent=build_agent,
        build_multiagent_agent=build_multiagent_agent,
    )


if __name__ == "__main__":
    sys.exit(main())
