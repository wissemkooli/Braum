"""A deliberately susceptible tool-using agent.

This is the thing being defended, and it is modelled as the worst realistic
case: an agent that reads its observations, finds text shaped like an
instruction, and does what it says -- including after base64 decoding, because
real models decode helpfully. It also substitutes hijacked content into
whatever it writes next, which is how indirect exfiltration actually happens.

Making the agent credulous is the point. The spec's own threat model says to
assume the base model is fallible; a defense evaluated against a sceptical
agent is measuring the agent, not the defense. Every attack in this repository
therefore reaches the guard as a real, fully-formed tool call.

`--agent compliant` disables injection-following, which is how the benign
utility baseline is measured.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sentinel.normalize import views
from sentinel.signals import CandidateAction

CALL_WITH_JSON = re.compile(
    r"\b(?:call|invoke|use|run|execute|trigger|perform|issue)\s+[`'\"]?([a-z][a-z0-9_]{2,40})[`'\"]?"
    r"\s*(?:with|:|=)?\s*(\{.{0,400}?\})",
    re.IGNORECASE | re.DOTALL,
)
CALL_PARENS = re.compile(r"\b([a-z][a-z0-9_]{2,40})\s*\(\s*(\{.{0,400}?\})\s*\)", re.DOTALL)
TEMPLATE = re.compile(r"\{\{\s*([a-z0-9_]+)\.([a-z0-9_]+)\s*\}\}", re.IGNORECASE)
# "{{resolve.TICK}}" models how a model answers "the corresponding ticket":
# it takes the most recent identifier of that shape in what it has just read.
RESOLVE = re.compile(r"\{\{\s*resolve\.([A-Z]{2,6})\s*\}\}")


@dataclass
class PlanStep:
    id: str
    action: str                 # tool_call | respond
    tool: Optional[str] = None
    args: Dict[str, Any] = field(default_factory=dict)
    content: str = ""
    final: bool = False
    origin: str = "plan"        # plan | injected


@dataclass
class AgentConfig:
    follow_injected_instructions: bool = True
    substitute_hijacked_content: bool = True
    label: str = "susceptible"


class SusceptibleAgent:
    def __init__(self, reference_plan: List[dict], tool_names: List[str],
                 config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.tool_names = set(tool_names)
        self.queue: List[PlanStep] = [
            PlanStep(
                id=str(s.get("id", f"step{i}")),
                action=s.get("action", "tool_call"),
                tool=s.get("tool"),
                args=dict(s.get("args") or {}),
                content=s.get("content", ""),
                final=bool(s.get("final", False)),
            )
            for i, s in enumerate(reference_plan)
        ]
        self.results: Dict[str, Dict[str, Any]] = {}
        self.hijacked_content: Optional[str] = None
        self.seen_payloads: set = set()
        self.notes: List[str] = []
        self._pending: Optional[PlanStep] = None

    # ------------------------------------------------------------ planning
    def next_action(self, step: int) -> Optional[CandidateAction]:
        while self.queue:
            plan_step = self.queue.pop(0)
            self._pending = plan_step
            if plan_step.action == "respond":
                content = self._resolve(plan_step.content or "Done.")
                return CandidateAction("respond", {"content": content}, step,
                                       rationale=f"plan:{plan_step.id}")
            args = {k: self._resolve(v) for k, v in plan_step.args.items()}
            return CandidateAction(plan_step.tool or "unknown", args, step,
                                   rationale=f"{plan_step.origin}:{plan_step.id}")
        return None

    @property
    def pending_is_injected(self) -> bool:
        return bool(self._pending and self._pending.origin == "injected")

    def _resolve(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        match = RESOLVE.search(value)
        if match:
            prefix = match.group(1)
            found = []
            for bucket in self.results.values():
                for text in bucket.values():
                    found += re.findall(rf"\b{prefix}-\d{{2,6}}\b", str(text))
            return RESOLVE.sub(found[-1] if found else "", value)
        def repl(match):
            step_id, field_name = match.group(1), match.group(2)
            # A credulous agent writes whatever it was last told to write.
            if self.config.substitute_hijacked_content and self.hijacked_content:
                return self.hijacked_content
            return str(self.results.get(step_id, {}).get(field_name, ""))
        return TEMPLATE.sub(repl, value)

    # --------------------------------------------------------- observation
    def observe(self, fields: List[Any], data: Dict[str, Any]) -> List[PlanStep]:
        """Record a tool result and follow anything instruction-shaped in it."""
        step_id = self._pending.id if self._pending else "unknown"
        bucket = self.results.setdefault(step_id, {})
        bucket.update(data or {})
        for f in fields or []:
            bucket[f.name] = f.text

        if self._pending and self._pending.origin == "injected" and fields:
            # The injection told the agent to use this content; it now will.
            self.hijacked_content = fields[0].text

        if not self.config.follow_injected_instructions:
            return []
        injected: List[PlanStep] = []
        for f in fields or []:
            injected += self._extract_calls(f.text)
        # Injected work jumps the queue, exactly as an obedient model would.
        self.queue = injected + self.queue
        return injected

    # A real model decodes base64 helpfully; it does not act on rot13 or
    # leetspeak noise. The *defense* inspects every view, the agent only these.
    AGENT_READABLE = ("identity", "strip_invisible", "despace", "urldecode", "base64", "hex")

    def _extract_calls(self, text: str) -> List[PlanStep]:
        found: List[PlanStep] = []
        for view in views(text or ""):
            if view.transform not in self.AGENT_READABLE:
                continue
            for pattern in (CALL_WITH_JSON, CALL_PARENS):
                for tool_name, blob in pattern.findall(view.text):
                    tool_name = tool_name.lower()
                    if tool_name not in self.tool_names:
                        continue
                    args = _parse_args(blob)
                    if args is None:
                        continue
                    key = (tool_name, json.dumps(args, sort_keys=True))
                    if key in self.seen_payloads:
                        continue
                    self.seen_payloads.add(key)
                    found.append(PlanStep(
                        id=f"injected-{len(self.seen_payloads)}",
                        action="tool_call", tool=tool_name, args=args, origin="injected",
                    ))
                    self.notes.append(
                        f"followed instruction found in observed content: {tool_name}"
                        + (f" (after {view.transform} decoding)" if view.covert else "")
                    )
        return found

    def note_refusal(self, reason: str) -> None:
        self.notes.append(f"guard refused: {reason}")


def _parse_args(blob: str) -> Optional[dict]:
    try:
        value = json.loads(blob)
    except json.JSONDecodeError:
        try:
            value = json.loads(blob.replace("'", '"'))
        except json.JSONDecodeError:
            return None
    return value if isinstance(value, dict) else None
