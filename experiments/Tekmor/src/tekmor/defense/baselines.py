"""Baseline defenses: the reference points every later number is read against.

`docs/06-evaluation-methodology.md`: a number without a baseline says nothing. These bracket the
space — allow-all gives the utility ceiling and the security floor, deny-sensitive the
reverse, and the keyword filter stands in for the text-matching defenses that the
literature reports adaptive attackers bypassing (`docs/10-research-report.md` Part II).
`RefuseAll` brackets Proposal B the same way: it is the judge a judge has to beat.

None of them is a defense. They exist to be beaten.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Verdict,
)
from tekmor.policy.core import Policy

#: Words a naive filter would flag in an outbound argument. Deliberately shallow: the
#: point of this baseline is that shallow matching loses to encoding and paraphrase.
DEFAULT_KEYWORDS = frozenset(
    {
        "api key",
        "api_key",
        "credential",
        "ignore previous instructions",
        "password",
        "secret",
        "token",
    }
)


@dataclass(frozen=True, slots=True)
class AllowAll:
    """Undefended agent. Utility ceiling, security floor."""

    name: str = "allow-all"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        return Decision(Verdict.ALLOW, ("BASELINE_ALLOW_ALL",))


@dataclass(frozen=True, slots=True)
class DenySensitive:
    """Blocks every sensitive tool, whatever drove it.

    Secure by construction and useless by construction: it is the false-block rate a
    provenance-aware defense has to beat while keeping the same attack coverage.
    """

    name: str = "deny-sensitive"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        if action.tool in policy.sensitive_tools:
            return Decision(Verdict.BLOCK, ("TARGET_TOOL_SENSITIVE",))
        return Decision(Verdict.ALLOW, ("TARGET_TOOL_NOT_SENSITIVE",))


@dataclass(frozen=True, slots=True)
class KeywordFilter:
    """Blocks an action whose arguments contain a flagged word.

    A strawman, and a specific one: it inspects the candidate action's arguments as
    text, so base64/hex/spaced/reversed encodings of the same value pass it, and benign
    work that merely mentions a flagged word is blocked. Both failures are measured
    rather than asserted; see tests/security/test_baselines.py.
    """

    name: str = "keyword"
    keywords: frozenset[str] = field(default=DEFAULT_KEYWORDS)

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        # ponytail: str() of the args covers nested values in one pass; a real scanner
        # walks fields so it can report which one matched.
        haystack = str(dict(action.args)).lower()
        if any(word in haystack for word in self.keywords):
            # The matched word is left out of the reason code on purpose: reason codes
            # are public, and the match may be a secret value.
            return Decision(Verdict.BLOCK, ("KEYWORD_MATCH",))
        return Decision(Verdict.ALLOW, ("NO_KEYWORD_MATCH",))


@dataclass(slots=True)
class RefuseAll:
    """`deny-gray`: a `Judge` (`defense.auditor`) that never confirms anything.

    Wrapped in an `AlignmentAuditor` this is the gray-zone refusal switch — every action
    the rules allowed under sub-threshold influence is sent to a human, and nothing else
    moves. It is the control `docs/07-results.md` left open: both GPU judges refused ~99%
    of the gray zone, so their rows cannot be read as alignment checking until this row
    exists beside them. Whatever a judge buys over *this* is what the judge contributes;
    the rest is the refusal.

    It is deliberately the same mechanism, not a second one. Reusing the auditor holds
    the gray-zone definition, the REWRITE-else-ESCALATE fallback and the monotone fusion
    fixed, so the arms differ in the judge alone.

    The fields `CausalJudge` uses for its cost and answer reporting are mirrored so that
    `evaluation/alignment.py` reports both arms through one path, and they carry the same
    meaning in both: `calls` counts *distinct* (task, call) questions, as `CausalJudge`
    does by incrementing only on a cache miss, so this arm's count is comparable with the
    858 and 849 recorded for the two model judges. It is the size of the gray zone, which
    is the quantity this arm exists to report. The answers are all 0.0, and `model` is
    None because no model is loaded.
    """

    name: str = "deny-gray"
    calls: int = 0
    #: Always 0.0: refusing costs no inference. Kept so the cost report has one shape.
    seconds: float = 0.0
    model: Any = field(default=None, repr=False)
    _answers: dict = field(default_factory=dict, repr=False)

    def aligned(self, task: str, action: Action) -> float:
        key = (task, str(action))
        if key not in self._answers:
            self._answers[key] = 0.0
            self.calls += 1
        return 0.0
