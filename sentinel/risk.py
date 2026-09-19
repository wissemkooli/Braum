"""Turning evidence into a calibrated likelihood.

The number this module produces is deliberately *not* "how bad would this be".
It is:

    risk = P(this action was induced by something other than the user)

Severity is a separate axis, declared per tool in the capability model, and
the two are combined only at decision time (`policy.py`). Keeping them apart
is what lets the same 0.93 mean "escalate" on a read and "block" on a wire
transfer, and it is what makes the score legible on camera.

Aggregation is a log-odds sum: each evidence code contributes
`weight x strength` to a logit, which a logistic squashes back to [0,1].
Weights are hand-specified priors, not learned -- with a scenario library this
small, a fitted model would be memorising the library. `calibrate.py` reports
the separation those priors actually achieve, and the ablation study reports
what each one is worth.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .signals import Evidence

BIAS = -3.2

WEIGHTS: Dict[str, float] = {
    # mandate -- is this inside the authority sealed before exposure?
    "MANDATE_PROHIBITED_CAPABILITY": 3.0,
    "MANDATE_CAPABILITY_EXPANSION": 2.6,
    "TARGET_OUTSIDE_MANDATE": 2.4,
    "IN_MANDATE": -2.2,
    "MANDATE_UNPARSED": -0.5,
    # origin -- who authored the arguments?
    "ARG_UNTRUSTED_ORIGIN": 2.8,
    "ARG_COVERT_ORIGIN": 2.2,
    "ARG_UNRESOLVED_ORIGIN": 0.8,
    "UNTRUSTED_ACTION_DICTATION": 2.5,
    "TRUSTED_ORIGIN": -2.0,
    # context -- what is the untrusted text doing? (capped family)
    "IMPERATIVE_IN_UNTRUSTED": 0.8,
    "OBFUSCATED_INSTRUCTION": 1.6,
    "GOAL_REDIRECTION": 1.2,
    "AUTHORITY_FORGERY": 1.4,
    # flow -- where is sensitive content going?
    "EXFIL_SENSITIVE_TO_SINK": 2.8,
    "FLOW_UNAUTHORIZED_SOURCE": 1.5,
    # history
    "CONTAMINATION_PRESSURE": 0.7,
    "NO_UNTRUSTED_EXPOSURE": -3.0,
    "LIFECYCLE_VIOLATION": 1.5,
    "UNKNOWN_TOOL": 1.8,
}

# A contaminated context must not, on its own, stop unrelated legitimate work.
# The textual-heuristic family is therefore capped; the structural families
# (mandate, origin, flow) are not.
FAMILY_CAPS: Dict[str, float] = {"context": 2.2}

ABLATABLE_FAMILIES = ("mandate", "origin", "context", "flow", "history")


@dataclass
class Contribution:
    code: str
    family: str
    strength: float
    weight: float
    logit: float

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "family": self.family,
            "strength": round(self.strength, 3),
            "weight": self.weight,
            "logit": round(self.logit, 3),
        }


@dataclass
class RiskScore:
    risk: float
    logit: float
    confidence: float
    contributions: List[Contribution] = field(default_factory=list)
    capped: Dict[str, float] = field(default_factory=dict)

    @property
    def reason_codes(self) -> List[str]:
        return [c.code for c in sorted(self.contributions, key=lambda c: -abs(c.logit))]

    def top_codes(self, n: int = 4) -> List[str]:
        return [c.code for c in sorted(self.contributions, key=lambda c: -c.logit)[:n] if c.logit > 0]

    def as_dict(self) -> dict:
        return {
            "risk": round(self.risk, 4),
            "logit": round(self.logit, 3),
            "bias": BIAS,
            "confidence": round(self.confidence, 3),
            "reason_codes": self.reason_codes,
            "contributions": [c.as_dict() for c in self.contributions],
            "family_caps_applied": {k: round(v, 2) for k, v in self.capped.items()},
        }


def _sigmoid(x: float) -> float:
    if x < -30:
        return 0.0
    if x > 30:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


def dedupe(evidence: Iterable[Evidence]) -> List[Evidence]:
    """Keep the strongest instance of each code, so repetition cannot stack."""
    best: Dict[str, Evidence] = {}
    for item in evidence:
        current = best.get(item.code)
        if current is None or item.strength > current.strength:
            best[item.code] = item
    return list(best.values())


def score(
    evidence: Iterable[Evidence],
    provenance_completeness: float = 1.0,
    tool_known: bool = True,
    disabled_families: Iterable[str] = (),
) -> RiskScore:
    disabled = set(disabled_families)
    items = [e for e in dedupe(evidence) if e.family not in disabled]

    contributions: List[Contribution] = []
    family_positive: Dict[str, float] = {}
    total = BIAS

    for item in items:
        weight = WEIGHTS.get(item.code, 0.0)
        logit = weight * item.strength
        contributions.append(Contribution(item.code, item.family, item.strength, weight, logit))
        if logit > 0:
            family_positive[item.family] = family_positive.get(item.family, 0.0) + logit
        else:
            total += logit

    capped: Dict[str, float] = {}
    for family, positive in family_positive.items():
        limit = FAMILY_CAPS.get(family)
        if limit is not None and positive > limit:
            capped[family] = positive - limit
            positive = limit
        total += positive

    families_fired = len({c.family for c in contributions if c.strength > 0})
    confidence = 0.30 + 0.14 * families_fired + 0.25 * provenance_completeness
    if not tool_known:
        confidence *= 0.5
    confidence = max(0.05, min(0.98, confidence))

    return RiskScore(
        risk=_sigmoid(total),
        logit=total,
        confidence=confidence,
        contributions=sorted(contributions, key=lambda c: -abs(c.logit)),
        capped=capped,
    )
