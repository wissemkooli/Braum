"""Tekmor observability component: the event schema and the append-only JSONL log.

The security timeline and provenance graph are rendered from that log by `viewer.py`,
which reads the JSONL and nothing else — anything it can show is in the trace.
"""

from tekmor.observability.events import (
    SCHEMA_VERSION,
    DecisionEvent,
    EventLog,
    Outcome,
    decision_event,
    read,
)
from tekmor.observability.viewer import render

__all__ = [
    "SCHEMA_VERSION",
    "DecisionEvent",
    "EventLog",
    "Outcome",
    "decision_event",
    "read",
    "render",
]
