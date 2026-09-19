"""From risk to one of four actions.

Two ideas do the work here.

**Hard constraints are not probabilistic.** Some things are decided by policy,
not by evidence: an irreversible action needs a human, information classified
above the mandate does not leave through a sink, a capability the user
explicitly refused is refused. These set a *floor* on the intervention. Risk
can raise that floor; it can never lower it.

**Least restrictive sufficient intervention.** Above the floor, the defense
picks the *weakest* intervention that brings residual risk inside tolerance
for that severity tier. Blocking is what happens when nothing weaker works --
which is why a poisoned ticket update gets its malicious argument stripped and
still updates the ticket, rather than being refused outright.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional

from .capability import Consequence


class Intervention(IntEnum):
    ALLOW = 0
    REWRITE = 1
    ESCALATE = 2
    BLOCK = 3

    @property
    def label(self) -> str:
        return self.name


# Maximum P(induced) tolerated for an unassisted ALLOW, by severity.
TOLERANCE: Dict[Consequence, float] = {
    Consequence.READ_ONLY: 0.75,
    Consequence.LOCAL_WRITE: 0.60,
    Consequence.PERSISTENT_WRITE: 0.40,
    Consequence.EXTERNAL_EFFECT: 0.25,
    Consequence.IRREVERSIBLE: 0.15,
}

# At or above this, asking a human is alarm fatigue: the evidence is decisive.
BLOCK_AT: Dict[Consequence, float] = {
    Consequence.READ_ONLY: 0.90,
    Consequence.LOCAL_WRITE: 0.85,
    Consequence.PERSISTENT_WRITE: 0.80,
    Consequence.EXTERNAL_EFFECT: 0.75,
    Consequence.IRREVERSIBLE: 0.70,
}

# Below this confidence we prefer a human over a unilateral refusal.
CONFIDENT_BLOCK = 0.50


@dataclass
class HardRule:
    code: str
    floor: Intervention
    rationale: str

    def as_dict(self) -> dict:
        return {"code": self.code, "floor": self.floor.label, "why": self.rationale}


@dataclass
class PolicyProfile:
    name: str
    tolerance: Dict[Consequence, float] = field(default_factory=lambda: dict(TOLERANCE))
    block_at: Dict[Consequence, float] = field(default_factory=lambda: dict(BLOCK_AT))
    confirm_irreversible: bool = True
    confirm_oversight_changes: bool = True
    enforce_lifecycle: bool = True
    enforce_information_flow: bool = True
    allow_rewrites: bool = True
    description: str = ""

    def tolerance_for(self, consequence: Consequence) -> float:
        return self.tolerance[consequence]

    def block_threshold(self, consequence: Consequence) -> float:
        return self.block_at[consequence]

    def risk_intervention(self, risk: float, consequence: Consequence, confidence: float) -> Intervention:
        if risk <= self.tolerance_for(consequence):
            return Intervention.ALLOW
        if risk >= self.block_threshold(consequence):
            # Confident enough to refuse on our own? Otherwise ask a human.
            return Intervention.BLOCK if confidence >= CONFIDENT_BLOCK else Intervention.ESCALATE
        return Intervention.ESCALATE


PROFILES: Dict[str, PolicyProfile] = {
    "enterprise_standard": PolicyProfile(
        name="enterprise_standard",
        description="Knowledge work. Drafts are cheap, outbound mail and record "
                    "state changes are not.",
    ),
    "finance_standard": PolicyProfile(
        name="finance_standard",
        description="Money movement. Strict prepare -> confirm -> execute lifecycle "
                    "and a lower tolerance on every write.",
        tolerance={
            Consequence.READ_ONLY: 0.70,
            Consequence.LOCAL_WRITE: 0.45,
            Consequence.PERSISTENT_WRITE: 0.30,
            Consequence.EXTERNAL_EFFECT: 0.20,
            Consequence.IRREVERSIBLE: 0.10,
        },
        block_at={
            Consequence.READ_ONLY: 0.88,
            Consequence.LOCAL_WRITE: 0.80,
            Consequence.PERSISTENT_WRITE: 0.72,
            Consequence.EXTERNAL_EFFECT: 0.68,
            Consequence.IRREVERSIBLE: 0.60,
        },
    ),
    "soc_standard": PolicyProfile(
        name="soc_standard",
        description="Incident response. Reading and note-taking stay cheap so triage "
                    "is not slowed; remediation and anything touching monitoring is gated.",
        tolerance={
            Consequence.READ_ONLY: 0.80,
            Consequence.LOCAL_WRITE: 0.65,
            Consequence.PERSISTENT_WRITE: 0.45,
            Consequence.EXTERNAL_EFFECT: 0.25,
            Consequence.IRREVERSIBLE: 0.12,
        },
    ),
}

DEFAULT_PROFILE = "enterprise_standard"


def get_profile(name: Optional[str]) -> PolicyProfile:
    """Return a *copy*.

    Profiles are mutable (a caller may relax `confirm_irreversible` for one
    decision, e.g. when a human has already approved that exact action). If the
    shared instance were handed out, that relaxation would silently apply to
    every later decision in the process -- including other runs. A guard owns
    its policy; the registry owns the template.
    """
    return copy.deepcopy(PROFILES.get(name or DEFAULT_PROFILE, PROFILES[DEFAULT_PROFILE]))
