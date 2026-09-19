"""The synthetic organisation the agent works inside.

The environment owns the records, applies effects, and -- importantly --
labels every piece of content it hands back with a trust level and a
sensitivity. Those labels come from the fixture, not from the attack: an
adversary who edits a document changes its *text*, never its provenance.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Field:
    """One labelled span of content returned by a tool."""

    name: str
    text: str
    trust: str
    sensitivity: str
    source_ref: str


@dataclass
class ToolResult:
    ok: bool = True
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    fields: List[Field] = field(default_factory=list)
    effect: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "error": self.error,
            "data": self.data,
            "fields": [f.__dict__ for f in self.fields],
            "effect": self.effect,
        }


@dataclass
class EffectRecord:
    step: int
    tool: str
    effect: str
    args: dict
    approved_by_human: bool = False


class Environment:
    def __init__(self, fixture: dict, allowed_tools: Optional[List[str]] = None):
        self.fixture = copy.deepcopy(fixture)
        self.collections: Dict[str, dict] = self.fixture["collections"]
        self.domain: str = self.fixture.get("domain", "generic")
        self.principal: dict = self.fixture.get("principal", {})
        self.allowed_tools = set(allowed_tools or [])
        self.effects: List[EffectRecord] = []
        self.tool_output_overrides: Dict[Tuple[str, str], str] = {}
        self.read_log: List[str] = []
        self.final_response: str = ""
        self._counter = 0

    # ------------------------------------------------------------- records
    def record(self, collection: str, key: str) -> Optional[dict]:
        return self.collections.get(collection, {}).get(key)

    def put(self, collection: str, key: str, value: dict) -> None:
        self.collections.setdefault(collection, {})[key] = value

    def next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{9000 + self._counter}"

    # -------------------------------------------------------------- content
    def field_from_record(self, tool: str, collection: str, key: str, attr: str, rec: dict,
                          trust: Optional[str] = None, sensitivity: Optional[str] = None) -> Field:
        """Build a labelled field, honouring any attacker override of its text."""
        text = str(rec.get(attr, ""))
        override = self.tool_output_overrides.get((tool, attr))
        if override is not None:
            text = override
        return Field(
            name=attr,
            text=text,
            trust=trust or rec.get("trust", "UNTRUSTED_EXTERNAL"),
            sensitivity=sensitivity or rec.get("sensitivity", "INTERNAL"),
            source_ref=f"{collection}/{key}/{attr}",
        )

    def override_tool_output(self, tool: str, field_name: str, text: str) -> None:
        self.tool_output_overrides[(tool, field_name)] = text

    def tool_override(self, tool: str, field_name: str) -> Optional[str]:
        return self.tool_output_overrides.get((tool, field_name))

    # -------------------------------------------------------------- effects
    def record_effect(self, step: int, tool: str, effect: str, args: dict, approved: bool = False) -> None:
        self.effects.append(EffectRecord(step=step, tool=tool, effect=effect, args=dict(args),
                                         approved_by_human=approved))

    def effect_names(self) -> List[str]:
        return [e.effect for e in self.effects]

    # --------------------------------------------------------------- canary
    def canaries(self) -> Dict[str, str]:
        """Marker -> the record it belongs to, for leak detection at scoring."""
        out = {}
        for cname, coll in self.collections.items():
            for key, rec in coll.items():
                if isinstance(rec, dict) and rec.get("canary"):
                    out[rec["canary"]] = f"{cname}/{key}"
        return out

    def sink_contents(self) -> Dict[str, str]:
        """Everything the agent wrote anywhere, for leak detection."""
        out = {}
        for cname in ("drafts", "outbound", "case_notes", "incidents", "memory", "tickets"):
            for key, rec in self.collections.get(cname, {}).items():
                out[f"{cname}/{key}"] = json.dumps(rec, default=str)
        out["agent/final_response"] = self.final_response
        return out

    def snapshot(self) -> dict:
        return {
            "domain": self.domain,
            "effects": [e.__dict__ for e in self.effects],
            "drafts": self.collections.get("drafts", {}),
            "outbound": self.collections.get("outbound", {}),
            "incidents": self.collections.get("incidents", {}),
            "case_notes": self.collections.get("case_notes", {}),
            "memory": self.collections.get("memory", {}),
            "final_response": self.final_response,
        }
