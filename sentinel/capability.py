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
    requires_confirmation: bool = False
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
    inferred: bool = False

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


# --------------------------------------------------------------------------
# Inference for tools this catalogue has never seen.
#
# A defense that only works against a tool list it was shipped with is a
# defense that fails on the day someone adds a tool. Tool names are not
# arbitrary -- `payment_execute`, `document_search`, `ticket_update` are all
# object_verb -- so a useful specification can be derived from the name plus
# whatever the operator's policy context declares.

VERB_SYNONYMS = {
    "read": ("read", "open", "review", "check", "view", "inspect", "examine", "summarize", "summarise"),
    "search": ("search", "find", "look", "locate", "list", "browse", "query"),
    "lookup": ("lookup", "look", "find", "check", "pull", "retrieve", "fetch"),
    "summary": ("summarize", "summarise", "summary", "review", "check", "look", "status"),
    "draft": ("draft", "compose", "write", "prepare"),
    "send": ("send", "forward", "dispatch", "transmit", "notify", "share"),
    "notify": ("notify", "inform", "contact", "tell", "alert"),
    "create": ("create", "open", "raise", "file", "add", "log", "record", "declare"),
    "update": ("update", "change", "modify", "edit", "annotate", "comment", "add", "log", "append"),
    "prepare": ("prepare", "stage", "set", "draft", "raise"),
    "confirm": ("confirm", "approve", "verify", "authorize", "authorise"),
    "execute": ("execute", "run", "perform", "release", "disburse", "apply", "settle", "pay"),
    "close": ("close", "resolve", "complete", "finish", "dismiss"),
    "note": ("note", "record", "document", "write", "log"),
    "delete": ("delete", "remove", "purge", "drop"),
    "disable": ("disable", "silence", "mute", "suppress", "stop", "off"),
    "reset": ("reset", "rotate", "revoke", "change"),
    "isolate": ("isolate", "quarantine", "contain", "segment"),
}

VERB_SEVERITY = {
    "read": Consequence.READ_ONLY, "search": Consequence.READ_ONLY,
    "lookup": Consequence.READ_ONLY, "summary": Consequence.READ_ONLY,
    "get": Consequence.READ_ONLY, "list": Consequence.READ_ONLY,
    "draft": Consequence.LOCAL_WRITE, "prepare": Consequence.LOCAL_WRITE,
    "create": Consequence.PERSISTENT_WRITE, "update": Consequence.PERSISTENT_WRITE,
    "note": Consequence.PERSISTENT_WRITE, "write": Consequence.PERSISTENT_WRITE,
    "comment": Consequence.PERSISTENT_WRITE, "close": Consequence.PERSISTENT_WRITE,
    "confirm": Consequence.PERSISTENT_WRITE,
    "send": Consequence.EXTERNAL_EFFECT, "notify": Consequence.EXTERNAL_EFFECT,
    "publish": Consequence.EXTERNAL_EFFECT, "isolate": Consequence.EXTERNAL_EFFECT,
    "execute": Consequence.IRREVERSIBLE, "delete": Consequence.IRREVERSIBLE,
    "disable": Consequence.IRREVERSIBLE, "reset": Consequence.IRREVERSIBLE,
    "revoke": Consequence.IRREVERSIBLE, "transfer": Consequence.IRREVERSIBLE,
}

OVERSIGHT_VERBS = ("disable", "suppress", "silence", "mute", "purge", "delete")
OVERSIGHT_OBJECTS = ("monitoring", "logging", "audit", "telemetry", "alerting", "edr", "log")

CONTENT_ARGS = frozenset({
    "body", "content", "note", "notes", "comment", "message", "summary", "text",
    "description", "reference", "subject", "title", "resolution", "memo", "details",
})
# Never dropped by the quarantine rewrite: removing them would produce a call
# the tool cannot honour, which is a worse outcome than escalating.
STRUCTURAL_ARGS = frozenset({"to", "recipient", "beneficiary", "amount", "target", "destination"})

# A status that retires or disables a record is consequential whatever the
# tool is called; this mirrors how operators actually reason about state.
TERMINAL_STATUS = frozenset({"closed", "resolved", "cancelled", "canceled", "disabled", "deleted", "archived"})

# Some tools carry the dangerous verb in an argument rather than in their name:
# `remediation_prepare(action="disable_monitoring")` reduces oversight exactly
# as much as a tool called `monitoring_disable` would. Reading only tool names
# misses it.
OVERSIGHT_ARG_VALUES = (
    "disable_monitoring", "disable_logging", "disable_alerting", "disable_audit",
    "stop_monitoring", "stop_logging", "silence_alerts", "suppress_alerts",
    "mute_alerts", "pause_monitoring", "turn_off_monitoring", "delete_logs",
    "purge_logs", "clear_audit",
)


def touches_oversight(arguments: dict) -> bool:
    """True when an argument value asks to reduce monitoring, logging or audit."""
    for value in (arguments or {}).values():
        if not isinstance(value, str):
            continue
        normalised = value.strip().lower().replace(" ", "_").replace("-", "_")
        if any(marker in normalised for marker in OVERSIGHT_ARG_VALUES):
            return True
    return False


def infer_spec(name: str, consequential: bool = False, known_tools: tuple = ()) -> ToolSpec:
    """Derive a usable specification from a tool's name and the operator's policy."""
    tokens = [t for t in name.split("_") if t]
    verb = tokens[-1] if tokens else name
    objects = tuple(tokens[:-1]) or (name,)

    severity = VERB_SEVERITY.get(verb, Consequence.PERSISTENT_WRITE)
    oversight = verb in OVERSIGHT_VERBS and any(o in objects for o in OVERSIGHT_OBJECTS)
    if consequential:
        severity = max(severity, Consequence.EXTERNAL_EFFECT)

    # send -> draft within the same family, when such a tool exists.
    safer = None
    if verb in ("send", "notify", "publish"):
        for alternative in (f"{objects[0]}_draft", f"{objects[0]}_prepare", f"{objects[0]}_note"):
            if alternative in known_tools:
                safer = Downgrade(tool=alternative, keep=("subject", "body", "content", "message", "note"))
                break

    return ToolSpec(
        name=name,
        capability=f"{objects[0]}.{verb}",
        consequence=severity,
        requires_confirmation=consequential,
        oversight_impact=oversight,
        safer_alternative=safer,
        intent_verbs=VERB_SYNONYMS.get(verb, (verb,)),
        intent_objects=objects,
        known=True,
        inferred=True,
    )


def infer_arg_roles(spec: ToolSpec, arguments: dict) -> ToolSpec:
    """Attach roles for arguments this specification does not already describe."""
    if not spec.inferred and all(a in spec.args for a in arguments):
        return spec
    args = dict(spec.args)
    required = set(spec.required_args)
    for name in arguments:
        if name in args:
            continue
        lowered = name.lower()
        if lowered.endswith("_id") or lowered == "id":
            role = "target"
            required.add(name)
        elif lowered in CONTENT_ARGS:
            role = "content"
        else:
            role = "control"
            if lowered in STRUCTURAL_ARGS:
                required.add(name)
        args[name] = ArgSpec(name, role)
    spec.args = args
    spec.required_args = tuple(sorted(required))
    return spec


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
