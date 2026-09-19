"""The capability model: what the defense knows about the tools it guards.

Loaded from `tool_model.yaml`. Everything here describes *tools*, never
scenarios. A tool the catalogue has never heard of is not waved through --
it is treated as maximally consequential, because an unknown capability is
exactly what a novel attack reaches for.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL = os.path.join(_HERE, "tool_model.yaml")


class Consequence(IntEnum):
    """Severity of a call if it turns out to be attacker-induced."""

    READ_ONLY = 0
    LOCAL_WRITE = 1
    PERSISTENT_WRITE = 2
    EXTERNAL_EFFECT = 3
    IRREVERSIBLE = 4


ROLES = ("target", "control", "content")


@dataclass(frozen=True)
class ArgSpec:
    name: str
    role: str = "content"


@dataclass(frozen=True)
class Downgrade:
    tool: str
    keep: tuple


@dataclass
class ToolSpec:
    name: str
    capability: str
    consequence: Consequence
    args: Dict[str, ArgSpec] = field(default_factory=dict)
    required_args: tuple = ()
    sink: Optional[str] = None
    oversight_impact: bool = False
    always_authorized: bool = False
    requires: tuple = ()
    safer_alternative: Optional[Downgrade] = None
    effects: tuple = ()
    intent_verbs: tuple = ()
    intent_objects: tuple = ()
    known: bool = True

    @property
    def family(self) -> str:
        return self.capability.split(".", 1)[0]

    def role_of(self, arg: str) -> str:
        spec = self.args.get(arg)
        return spec.role if spec else "control"  # unmodelled args: assume control

    def args_with_role(self, role: str) -> List[str]:
        return [a for a, s in self.args.items() if s.role == role]

    def effect_for(self, args: dict) -> str:
        """Which effect the environment will record for this argument set.

        One tool can produce several effects: `ticket_update(status=closed)`
        closes a ticket. Tool-name allowlisting cannot see that; the defense
        must reason at argument granularity.
        """
        for rule in self.effects:
            when = rule.get("when", {})
            if all(str(args.get(k, "")).strip().lower() == str(v).strip().lower() for k, v in when.items()):
                return rule["effect"]
        return self.name


def unknown_tool(name: str) -> ToolSpec:
    """Fail-closed default for a tool outside the catalogue."""
    return ToolSpec(
        name=name,
        capability=f"unknown.{name}",
        consequence=Consequence.IRREVERSIBLE,
        args={},
        required_args=(),
        known=False,
    )


class ToolCatalogue:
    def __init__(self, specs: Dict[str, ToolSpec]):
        self.specs = specs

    @classmethod
    def load(cls, path: str = DEFAULT_MODEL) -> "ToolCatalogue":
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        specs = {}
        for name, body in (raw.get("tools") or {}).items():
            body = body or {}
            downgrade = None
            if body.get("safer_alternative"):
                sa = body["safer_alternative"]
                downgrade = Downgrade(tool=sa["tool"], keep=tuple(sa.get("keep", ())))
            intent = body.get("intent") or {}
            specs[name] = ToolSpec(
                name=name,
                capability=body.get("capability", f"unknown.{name}"),
                consequence=Consequence[body.get("consequence", "IRREVERSIBLE")],
                args={a: ArgSpec(a, (v or {}).get("role", "content")) for a, v in (body.get("args") or {}).items()},
                required_args=tuple(body.get("required_args", ())),
                sink=body.get("sink"),
                oversight_impact=bool(body.get("oversight_impact", False)),
                always_authorized=bool(body.get("always_authorized", False)),
                requires=tuple(body.get("requires", ())),
                safer_alternative=downgrade,
                effects=tuple(body.get("effects", ())),
                intent_verbs=tuple(intent.get("verbs", ())),
                intent_objects=tuple(intent.get("objects", ())),
            )
        return cls(specs)

    def get(self, name: str) -> ToolSpec:
        return self.specs.get(name) or unknown_tool(name)

    def __contains__(self, name: str) -> bool:
        return name in self.specs

    def names(self) -> List[str]:
        return sorted(self.specs)

    def capability_of(self, name: str) -> str:
        return self.get(name).capability

    def family_members(self, family: str) -> List[ToolSpec]:
        return [s for s in self.specs.values() if s.family == family]
