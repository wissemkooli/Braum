"""Plan attestation: sealing the user's authority before exposure.

The core asymmetry this defense exploits is temporal. At the start of a turn
the only instruction in the context is the user's. Whatever the agent is
allowed to do, it is allowed to do *then* -- before a single byte of document,
email, log line or tool output has been read.

So we derive the authority envelope at that moment and seal it with a hash.
Every later candidate action is measured against the seal. An injection can
make the agent *want* to do something new; it cannot retroactively make the
user have asked for it.

Nothing in here looks at anything but the trusted goal text and the operator's
tool catalogue.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .capability import Consequence, ToolCatalogue

# Structural identifier shape: two-to-six capitals, a dash, digits.
ID_PATTERN = re.compile(r"\b[A-Z]{2,6}-\d{2,6}\b")

NEGATION_CUES = (
    "do not", "don't", "dont", "never", "must not", "should not", "no need to",
    "without", "avoid", "refrain from", "under no circumstances", "not to",
)

# Markers that tell us the user referred to a record they did not name, so the
# agent is *expected* to resolve the identifier out of observed content.
# Strong cues open a family on their own; weak possessives only do so when the
# user named no identifier at all, otherwise "summarize their status" would
# loosen a goal that already said which customer.
INDIRECTION_STRONG = (
    "corresponding", "associated", "related", "linked", "relevant", "matching",
    "referenced", "appropriate", "the one",
)
INDIRECTION_WEAK = ("their", "its", "the same")

CLAUSE_SPLIT = re.compile(r"[.;\n]|,\s+(?=then\b)|\bthen\b|\band\b")


def _phrase_in(term: str, text: str) -> bool:
    if " " in term:
        return term in text
    return re.search(rf"\b{re.escape(term)}\w{{0,3}}\b", text) is not None


@dataclass(frozen=True)
class Mandate:
    """The sealed authority envelope for one turn."""

    goal_text: str
    principal: str
    capabilities: frozenset          # capability strings the user asked for
    prohibited: frozenset            # capabilities the user explicitly refused
    tools: frozenset                 # tools whose intent matched the goal
    resources: frozenset             # identifiers named in the goal
    open_families: frozenset         # families where the user used indirection
    seal: str = ""

    def authorizes(self, capability: str) -> bool:
        return capability in self.capabilities

    def forbids(self, capability: str) -> bool:
        return capability in self.prohibited

    def resource_open(self, family: str) -> bool:
        return family in self.open_families

    def as_dict(self) -> dict:
        return {
            "goal": self.goal_text,
            "principal": self.principal,
            "capabilities": sorted(self.capabilities),
            "prohibited": sorted(self.prohibited),
            "tools": sorted(self.tools),
            "resources": sorted(self.resources),
            "open_resolution_families": sorted(self.open_families),
            "seal": self.seal,
        }


def _clauses(goal: str) -> List[str]:
    parts = [c.strip() for c in CLAUSE_SPLIT.split(goal) if c and c.strip()]
    return parts or [goal.strip()]


def _negated(clause_lower: str) -> Tuple[bool, str]:
    """Return (is_negated, the span the negation governs)."""
    for cue in NEGATION_CUES:
        idx = clause_lower.find(cue)
        if idx != -1:
            return True, clause_lower[idx + len(cue) :]
    return False, clause_lower


def _tools_matching(span: str, catalogue: ToolCatalogue) -> Set[str]:
    """Tools whose declared intent vocabulary is satisfied by this span.

    A match needs both a verb and an object: "review the account" authorizes
    account.read, "review" alone authorizes nothing.
    """
    matched = set()
    for name, spec in catalogue.specs.items():
        if re.search(rf"\b{re.escape(name)}\b", span):
            matched.add(name)
            continue
        if not spec.intent_verbs or not spec.intent_objects:
            continue
        if any(_phrase_in(v, span) for v in spec.intent_verbs) and any(
            _phrase_in(o, span) for o in spec.intent_objects
        ):
            matched.add(name)
    return matched


def _upward_closure(tools: Set[str], catalogue: ToolCatalogue) -> Set[str]:
    """Prohibition is upward-closed in severity within a capability family.

    If the user says "do not prepare any payments", executing one is not a
    loophole -- it is strictly worse than the thing they refused.
    """
    out = set()
    for name in tools:
        spec = catalogue.get(name)
        out.add(spec.capability)
        for sibling in catalogue.family_members(spec.family):
            if sibling.consequence >= spec.consequence:
                out.add(sibling.capability)
    return out


def derive_mandate(goal: str, catalogue: ToolCatalogue, principal: str = "AUTHENTICATED_USER") -> Mandate:
    """Read the user's goal and nothing else."""
    goal = (goal or "").strip()
    authorized_tools: Set[str] = set()
    prohibited_tools: Set[str] = set()
    open_families: Set[str] = set()

    for clause in _clauses(goal):
        lower = clause.lower()
        negated, span = _negated(lower)
        matched = _tools_matching(span, catalogue)
        if negated:
            prohibited_tools |= matched
            continue
        authorized_tools |= matched
        named_ids = bool(ID_PATTERN.findall(goal))
        if any(cue in lower for cue in INDIRECTION_STRONG) or (
            not named_ids and any(cue in lower for cue in INDIRECTION_WEAK)
        ):
            open_families |= {catalogue.get(t).family for t in matched}

    capabilities = {catalogue.get(t).capability for t in authorized_tools}
    prohibited = _upward_closure(prohibited_tools, catalogue)
    capabilities -= prohibited
    authorized_tools = {t for t in authorized_tools if catalogue.get(t).capability not in prohibited}

    mandate = Mandate(
        goal_text=goal,
        principal=principal,
        capabilities=frozenset(capabilities),
        prohibited=frozenset(prohibited),
        tools=frozenset(authorized_tools),
        resources=frozenset(ID_PATTERN.findall(goal)),
        open_families=frozenset(open_families),
    )
    canonical_form = json.dumps(mandate.as_dict(), sort_keys=True).encode("utf-8")
    seal = hashlib.sha256(canonical_form).hexdigest()[:16]
    return Mandate(**{**mandate.__dict__, "seal": seal})
