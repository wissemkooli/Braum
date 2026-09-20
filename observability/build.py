"""Turn recorded traces into the self-contained HTML dashboard.

The dashboard embeds the trace data rather than fetching it, so the file opens
from disk with no server and no network -- which is also what makes it safe to
hand to a judge on a USB stick.
"""

from __future__ import annotations

import html
import json
import os
from typing import Dict, List

from sentinel.trace import load

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "template.html")


def structure(events: List[dict]) -> dict:
    """Fold a flat event log into the shape the UI renders."""
    run: Dict = {
        "run_id": "", "scenario": "", "title": "", "domain": "", "defense": "",
        "policy_profile": "", "agent": "", "approver": "", "description": "",
        "attack": {}, "allowed_tools": [], "turns": [], "observations": {},
        "verdict": None, "steps": [],
    }
    current = None
    turn_goals: Dict[int, dict] = {}

    for e in events:
        kind = e["kind"]
        if kind == "run_start":
            run.update({k: e.get(k, run.get(k)) for k in
                        ("run_id", "scenario", "title", "domain", "defense", "policy_profile",
                         "agent", "approver", "description", "attack", "allowed_tools")})
        elif kind == "turn_start":
            turn_goals.setdefault(e["turn"], {})["goal"] = e["goal"]
        elif kind == "mandate_sealed":
            turn_goals.setdefault(e["turn"], {})["mandate"] = e["mandate"]
            turn_goals[e["turn"]]["exposed"] = e.get("context_already_exposed", False)
            turn_goals[e["turn"]]["guard_config"] = e.get("guard_config", {})
        elif kind == "agent_intent":
            current = {
                "turn": e["turn"], "step": e["step"], "tool": e["tool"], "args": e["args"],
                "harness_label": e["harness_label"], "decision": None, "human_review": None,
                "effects": [], "observations": [], "blocked": False, "response": None,
                "error": None,
            }
            run["steps"].append(current)
        elif kind == "decision" and current is not None:
            current["decision"] = e
        elif kind == "human_review" and current is not None:
            current["human_review"] = e
        elif kind == "blocked" and current is not None:
            current["blocked"] = True
        elif kind == "effect" and current is not None:
            current["effects"].append(e)
        elif kind == "tool_error" and current is not None:
            current["error"] = e.get("error")
        elif kind == "observation":
            run["observations"][e["obs_id"]] = e
            if current is not None:
                current["observations"].append(e["obs_id"])
        elif kind == "final_response" and current is not None:
            current["response"] = e["content"]
        elif kind == "verdict":
            run["verdict"] = e

    run["turns"] = [{"turn": k, **v} for k, v in sorted(turn_goals.items())]
    return run


def build(trace_paths: List[str], out_path: str) -> str:
    runs = []
    for path in trace_paths:
        try:
            events = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not events:
            continue
        run = structure(events)
        run["source"] = os.path.basename(path)
        runs.append(run)

    runs.sort(key=lambda r: (r.get("scenario", ""), r.get("defense", "")))
    with open(TEMPLATE, "r", encoding="utf-8") as fh:
        template = fh.read()
    payload = json.dumps(runs, default=str).replace("</", "<\\/")
    page = template.replace("/*__RUNS__*/[]", payload)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out_path
