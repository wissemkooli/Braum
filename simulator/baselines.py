"""Baseline defenses, for comparison.

Each one is a real position someone has argued for. Running them on the same
scenarios, through the same trace format, is what makes the claim "SENTINEL
does better" falsifiable rather than decorative.
"""

from __future__ import annotations

import re
from typing import List

from sentinel.capability import Consequence
from sentinel.guard import Decision, Sentinel
from sentinel.policy import Intervention
from sentinel.risk import RiskScore
from sentinel.signals import CandidateAction

FLAT = RiskScore(risk=0.0, logit=0.0, confidence=0.0)


def _decision(action: CandidateAction, intervention: Intervention, reason: str,
              severity: Consequence, capability: str, risk: float = 0.0) -> Decision:
    return Decision(
        action_in=action,
        intervention=intervention,
        action_out=action if intervention == Intervention.ALLOW else None,
        risk=RiskScore(risk=risk, logit=0.0, confidence=0.0),
        severity=severity,
        capability=capability,
        reason=reason,
    )


class AllowAll(Sentinel):
    """No defense. The control condition."""

    def review(self, action: CandidateAction) -> Decision:
        spec = self.catalogue.get(action.tool)
        d = _decision(action, Intervention.ALLOW, "baseline allow_all: no safety layer",
                      spec.consequence, spec.capability)
        if self.tracer:
            self.tracer.emit("decision", step=action.step, turn=self.session["turn"],
                             **d.as_dict(), context=self.ledger.snapshot())
        return d


class BlockAll(Sentinel):
    """Maximum safety, zero utility. The spec calls this unacceptable; here is why."""

    def review(self, action: CandidateAction) -> Decision:
        spec = self.catalogue.get(action.tool)
        allow = action.tool == "respond"
        d = _decision(action, Intervention.ALLOW if allow else Intervention.BLOCK,
                      "baseline block_all: refuses every tool call",
                      spec.consequence, spec.capability, risk=0.0 if allow else 1.0)
        if self.tracer:
            self.tracer.emit("decision", step=action.step, turn=self.session["turn"],
                             **d.as_dict(), context=self.ledger.snapshot())
        return d


class KeywordFilter(Sentinel):
    """The obvious defense: scan for injection phrases and refuse.

    Fails in both directions -- it misses anything encoded, and it fires on
    legitimate documents that merely discuss attacks.
    """

    PATTERNS = (
        "ignore previous", "ignore the", "ignore all", "disregard", "override",
        "you must", "critical directive", "new instructions", "system:",
        "do not tell", "urgent action required", "guardrails",
    )

    def review(self, action: CandidateAction) -> Decision:
        spec = self.catalogue.get(action.tool)
        haystack = " ".join(
            [str(v) for v in action.args.values()]
            + [o.text for o in self.ledger.observations]
        ).lower()
        hit = next((p for p in self.PATTERNS if p in haystack), None)
        intervention = Intervention.BLOCK if hit and action.tool != "respond" else Intervention.ALLOW
        d = _decision(action, intervention,
                      f"baseline keyword: matched {hit!r}" if hit else "baseline keyword: no match",
                      spec.consequence, spec.capability, risk=1.0 if hit else 0.0)
        if self.tracer:
            self.tracer.emit("decision", step=action.step, turn=self.session["turn"],
                             **d.as_dict(), context=self.ledger.snapshot())
        return d


class ToolAllowlist(Sentinel):
    """Least privilege at tool granularity -- necessary, and not sufficient.

    Every attack in the public library uses only tools the task legitimately
    needs, so this baseline waves all of them through.
    """

    def __init__(self, *args, allowed_tools=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed = set(allowed_tools or []) | {"respond"}

    def review(self, action: CandidateAction) -> Decision:
        spec = self.catalogue.get(action.tool)
        ok = action.tool in self.allowed
        d = _decision(action, Intervention.ALLOW if ok else Intervention.BLOCK,
                      f"baseline allowlist: {action.tool} "
                      + ("is enabled for this task" if ok else "is not enabled"),
                      spec.consequence, spec.capability, risk=0.0 if ok else 1.0)
        if self.tracer:
            self.tracer.emit("decision", step=action.step, turn=self.session["turn"],
                             **d.as_dict(), context=self.ledger.snapshot())
        return d


BASELINES = {
    "allow_all": AllowAll,
    "block_all": BlockAll,
    "keyword": KeywordFilter,
    "tool_allowlist": ToolAllowlist,
}
