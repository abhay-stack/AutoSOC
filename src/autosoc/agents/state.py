"""State contract shared by the AutoSOC LangGraph nodes."""

from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages

from autosoc.models import IncidentReport


class AgentState(TypedDict):
    """Portable state for the deterministic-report orchestration graph."""

    incident_report: IncidentReport
    playbook: str
    messages: Annotated[list[AnyMessage], add_messages]


__all__ = ["AgentState"]
