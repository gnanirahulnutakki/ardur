"""Ardur live-governance demo — LangGraph (native StateGraph) flavor.

Shares the scene structure from demo_scenes.py. Only the agent
construction uses LangGraph's native StateGraph primitives instead of
LangChain's prebuilt create_react_agent — so the recording shows the
same governance story against a different agent runtime.
"""

from __future__ import annotations

import os
import sys
from typing import Annotated, TypedDict

sys.path.insert(0, "/app/ardur")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langchain_core.messages import AnyMessage, HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

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


FRAMEWORK = "LangGraph (native StateGraph)"


class GraphState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


def build_agent(proxy, session, workspace):
    session_ref = [session]
    tools = make_langchain_governed_tools(proxy, session_ref, workspace)
    llm = make_langchain_llm().bind_tools(tools)

    code = '''
      class GraphState(TypedDict):
          messages: Annotated[list[AnyMessage], add_messages]

      llm_with_tools = ChatOllama(...).bind_tools(tools)
      tool_node = ToolNode(tools)

      def agent_node(state): return {"messages": [llm_with_tools.invoke(state["messages"])]}
      def should_continue(state):
          return "tools" if state["messages"][-1].tool_calls else END

      graph = StateGraph(GraphState)
      graph.add_node("agent", agent_node)
      graph.add_node("tools", tool_node)
      graph.add_edge(START, "agent")
      graph.add_conditional_edges("agent", should_continue,
                                   {"tools": "tools", END: END})
      graph.add_edge("tools", "agent")
      compiled = graph.compile()
    '''
    print(f"{DIM}{code}{RESET}")

    tool_node = ToolNode(tools)

    def agent_node(state: GraphState) -> dict:
        return {"messages": [llm.invoke(state["messages"])]}

    def should_continue(state: GraphState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        return END

    graph = StateGraph(GraphState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges(
        "agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")
    compiled = graph.compile()

    def invoke(compiled, prompt):
        result = compiled.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"recursion_limit": 12},
        )
        print(f"\n      (graph emitted {len(result.get('messages', []))} "
              f"messages total)")

    return compiled, session_ref, invoke, invoke


def _build_graph(tools):
    llm = make_langchain_llm().bind_tools(tools)
    tool_node = ToolNode(tools)

    def agent_node(state: GraphState) -> dict:
        return {"messages": [llm.invoke(state["messages"])]}

    def should_continue(state: GraphState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        return END

    graph = StateGraph(GraphState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges(
        "agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")
    return graph.compile()


def build_multiagent_agent(engine):
    tools = make_langchain_multiagent_tools(engine)
    code = f'''
      llm_with_tools = make_langchain_llm().bind_tools(multiagent_tools)
      tool_node = ToolNode([spawn_subagent, run_subagent, close_subagent])
      compiled = StateGraph(...).compile()
      # provider = {provider_label()}
    '''
    print(f"{DIM}{code}{RESET}")
    compiled = _build_graph(tools)

    def invoke(compiled, prompt):
        result = compiled.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"recursion_limit": 40},
        )
        print(f"\n      (multiagent graph emitted "
              f"{len(result.get('messages', []))} messages total)")

    return compiled, invoke


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
