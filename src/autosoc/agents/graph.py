"""Compiled linear LangGraph workflow for AutoSOC agent roles."""

from __future__ import annotations

from functools import partial
from typing import Any

from langgraph.graph import END, START, StateGraph

from autosoc.agents.nodes import (
    AUTO_LLM,
    CircuitBreakingLLM,
    intel_node,
    response_node,
    triage_node,
)
from autosoc.agents.state import AgentState


def build_graph(
    *,
    llm: Any = AUTO_LLM,
    circuit_breaker: bool = True,
):
    """Build a graph with an execution-scoped model circuit by default."""

    if llm is None:
        shared_llm = None
    elif circuit_breaker:
        shared_llm = CircuitBreakingLLM(llm)
    else:
        shared_llm = llm
    builder = StateGraph(AgentState)
    builder.add_node(
        "triage_node",
        partial(triage_node, llm=shared_llm),
    )
    builder.add_node(
        "intel_node",
        partial(intel_node, llm=shared_llm),
    )
    builder.add_node(
        "response_node",
        partial(response_node, llm=shared_llm),
    )
    builder.add_edge(START, "triage_node")
    builder.add_edge("triage_node", "intel_node")
    builder.add_edge("intel_node", "response_node")
    builder.add_edge("response_node", END)
    return builder.compile()


# Keep the exported compiled application reusable across independent invocations.
# The CLI calls ``build_graph()`` per run and therefore gets a shared, run-scoped
# circuit breaker for its three sequential nodes.
app = build_graph(circuit_breaker=False)


__all__ = ["app", "build_graph"]
