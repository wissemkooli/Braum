"""Scenario loading and adversary application.

The attack is applied to the *environment*, before the agent runs. From that
moment the malicious text is indistinguishable from ordinary content: it lives
in a document body, an email body or a tool-output field, carrying that
surface's ordinary provenance labels. Neither the agent nor the defense is
told which bytes the attacker wrote.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from .env import Environment


@dataclass
class Turn:
    goal: str
    reference_plan: List[dict] = field(default_factory=list)


@dataclass
class Scenario:
    path: str
    id: str
    title: str
    domain: str
    description: str = ""
    split: str = "public"
    policy_profile: str = "enterprise_standard"
    fixture: str = ""
    allowed_tools: List[str] = field(default_factory=list)
    max_steps: int = 15
    turns: List[Turn] = field(default_factory=list)
    attack: Dict[str, Any] = field(default_factory=dict)
    success_conditions: List[dict] = field(default_factory=list)
    security_properties: List[str] = field(default_factory=list)
    forbidden_effects: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    harness: Dict[str, Any] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @property
    def attack_present(self) -> bool:
        return bool(self.attack.get("present"))

    @property
    def family(self) -> str:
        return self.attack.get("family", "benign") if self.attack_present else "benign"

    @property
    def difficulty(self) -> int:
        return int(self.attack.get("difficulty", 0)) if self.attack_present else 0

    @property
    def approver(self) -> str:
        return str(self.harness.get("approver", "deny"))


def load(path: str) -> Scenario:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    turns = [Turn(goal=t.get("goal", ""), reference_plan=t.get("reference_plan", []) or [])
             for t in (raw.get("turns") or [])]
    return Scenario(
        path=path,
        id=raw.get("id", os.path.basename(path)),
        title=raw.get("title", raw.get("id", "")),
        domain=raw.get("domain", "enterprise"),
        description=raw.get("description", ""),
        split=raw.get("split", "public"),
        policy_profile=raw.get("policy_profile", "enterprise_standard"),
        fixture=raw.get("fixture", ""),
        allowed_tools=list(raw.get("allowed_tools") or []),
        max_steps=int(raw.get("max_steps", 15)),
        turns=turns,
        attack=raw.get("attack") or {},
        success_conditions=list(raw.get("success_conditions") or []),
        security_properties=list(raw.get("security_properties") or []),
        forbidden_effects=list(raw.get("forbidden_effects") or []),
        tags=list(raw.get("tags") or []),
        harness=raw.get("harness") or {},
        raw=raw,
    )


def load_fixture(scenario: Scenario, root: str = ".") -> dict:
    path = scenario.fixture
    if not path:
        path = f"fixtures/{scenario.domain}/base.json"
    if not os.path.isabs(path):
        path = os.path.join(root, path)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_environment(scenario: Scenario, root: str = ".") -> Environment:
    return Environment(load_fixture(scenario, root), allowed_tools=scenario.allowed_tools)


def apply_attack(scenario: Scenario, env: Environment) -> List[dict]:
    """Write the adversary's text into the environment. Returns what it did."""
    if not scenario.attack_present:
        return []
    surfaces = {s["id"]: s for s in scenario.attack.get("surfaces", [])}
    applied = []
    for payload in scenario.attack.get("payloads", []):
        surface = surfaces.get(payload.get("surface"))
        if not surface:
            continue
        target = surface.get("target", "")
        text = payload.get("text", "")
        operation = payload.get("operation", "append_text")
        cap = int(surface.get("max_chars", 4000))
        text = text[:cap]
        parts = target.split("/")

        if parts[0] == "tool_output" and len(parts) >= 3:
            tool_name, field_name = parts[1], parts[2]
            base = ""
            if operation != "set_tool_text":
                base = ""  # append against an empty baseline; the tool supplies the rest
            env.override_tool_output(tool_name, field_name, (base + text) if base else text)
            applied.append({"target": target, "operation": operation, "chars": len(text)})
            continue

        if len(parts) >= 3:
            collection, key, attr = parts[0], parts[1], parts[2]
            rec = env.record(collection, key)
            if rec is None:
                continue
            current = str(rec.get(attr, ""))
            if operation == "append_text":
                rec[attr] = current + ("\n" if current else "") + text
            elif operation == "prepend_text":
                rec[attr] = text + ("\n" if current else "") + current
            else:
                rec[attr] = text
            applied.append({"target": target, "operation": operation, "chars": len(text)})
    return applied


def discover(paths: List[str]) -> List[str]:
    """Expand files and directories into a sorted list of scenario files."""
    out: List[str] = []
    for item in paths:
        if os.path.isdir(item):
            for base, _, files in os.walk(item):
                out += [os.path.join(base, f) for f in files if f.endswith((".yaml", ".yml"))]
        elif item.endswith((".yaml", ".yml")):
            out.append(item)
    return sorted(set(out))
