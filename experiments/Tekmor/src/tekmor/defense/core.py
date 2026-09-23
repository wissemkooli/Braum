"""The decision contract every defense implements, and the mediation entry point.

`docs/10-research-report.md` Part IV: every candidate action passes through
`Defense.decide(state, action, provenance, policy) -> Decision`. Routing all actions
through `mediate()` is what makes the defense a reference monitor with complete
mediation; failing closed there is what keeps an internal error from becoming an ALLOW.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from tekmor.policy.core import Policy
from tekmor.provenance.taint import ArgumentOrigin
from tekmor.provenance.trust import Source, TrustLevel, least_trusted

logger = logging.getLogger(__name__)


class Verdict(Enum):
    """What the monitor does with a candidate action."""

    ALLOW = "allow"
    REWRITE = "rewrite"
    ESCALATE = "escalate"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class Action:
    """A candidate tool call, before it reaches the world."""

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ActionProvenance:
    """The observations that influenced a candidate action.

    How the set is computed is `tekmor.provenance.taint`'s business, not the decision
    core's: what the decision needs is the set and its meet. Field-level provenance
    within one observation is the remaining granularity gap; see
    `docs/04-provenance-and-trust.md`.
    """

    sources: tuple[Source, ...] = ()
    #: Where each argument's values came from (`TaintTracker.origins`). Empty when the
    #: driver did not trace them, and then every argument is judged at call level.
    arguments: tuple[ArgumentOrigin, ...] = ()

    @property
    def confidential(self) -> bool:
        """Whether anything confidential influenced the action.

        Confidentiality joins the other way from integrity: one confidential influence
        makes the action confidential, where one untrusted influence makes it untrusted.
        Both are the pessimistic direction of their own lattice.
        """
        return any(s.confidential for s in self.sources)

    @property
    def integrity(self) -> TrustLevel:
        """Biba integrity of the action: the minimum integrity of its influences.

        Each influence counts at `Source.integrity`, which is its label, or `ENDORSED`
        when the user endorsed it (`provenance.taint.endorse`). That is the one place a
        label is raised, and the source records that it was.
        """
        return least_trusted(s.integrity for s in self.sources)

    def argument_integrity(self, name: str, *, endorsed: bool = True) -> TrustLevel:
        """The integrity of one argument: the minimum over its values.

        A traced value counts at the *highest* label among the observations that contain
        it. A value a trusted source supplied is vouched for even if an attacker echoes
        it, because the echo adds no authority the trusted copy lacked. An untraced
        value, or an argument nobody traced, counts at call level. A value is never
        raised above the label of an observation that actually contained it, and
        untraceability never raises anything.

        `endorsed=False` judges on the raw `trust` labels, for arguments an endorsement
        may not raise (`Policy.target_args`).
        """
        label = (lambda s: s.integrity) if endorsed else (lambda s: s.trust)  # noqa: E731
        call = least_trusted(label(s) for s in self.sources)
        origin = next((a for a in self.arguments if a.name == name), None)
        if origin is None:
            return call
        return min(
            (max(map(label, vouchers)) if vouchers else call for vouchers in origin.values),
            default=call,
        )

    @classmethod
    def of(
        cls, sources: Iterable[Source], arguments: Iterable[ArgumentOrigin] = ()
    ) -> ActionProvenance:
        return cls(tuple(sources), tuple(arguments))


@dataclass(frozen=True, slots=True)
class AgentState:
    """What the defense may see about the run besides the action itself.

    Deliberately thin. It must never carry scenario identifiers or expected outcomes —
    a defense that can recognise a test case is not evidence of security.
    """

    task: str = ""
    step: int = 0


@dataclass(frozen=True, slots=True)
class Decision:
    """The monitor's answer, with the reason codes the answer was computed from.

    `reason_codes` are coarse and public (the adaptive attacker sees them); fine-grained
    sub-scores belong in the private trace. They are faithful only as long as they name
    the predicates that actually fired, so never add one the decision did not use.

    `risk` is how bad the action looked on the severity scale in `defense/risk.py`, and
    it is optional because it is honest for a defense not to have one: the baselines
    emit verdicts and no score, and a metric computed over scores must be able to say
    "undefined here" rather than read a missing score as zero risk.
    """

    verdict: Verdict
    reason_codes: tuple[str, ...]
    rewritten: Action | None = None
    risk: float | None = None

    def __post_init__(self) -> None:
        if (self.verdict is Verdict.REWRITE) != (self.rewritten is not None):
            raise ValueError("a rewritten action is required by REWRITE and only by REWRITE")
        if not self.reason_codes:
            raise ValueError("a decision must name the reasons it was computed from")
        if self.risk is not None and not 0.0 <= self.risk <= 1.0:
            raise ValueError(f"risk must be a fraction in [0, 1], got {self.risk!r}")


@runtime_checkable
class Defense(Protocol):
    """Anything that can decide on a candidate action."""

    name: str

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision: ...


def mediate(
    defense: Defense,
    state: AgentState,
    action: Action,
    provenance: ActionProvenance,
    policy: Policy,
) -> Decision:
    """Call `defense`, failing closed.

    A monitor that crashes must not let the action through, and neither must one that
    returns something that is not a `Decision`. Every caller of a defense goes through
    here so that this property holds for all of them.
    """
    try:
        decision = defense.decide(state, action, provenance, policy)
    except Exception:
        logger.exception("defense %r raised; failing closed", getattr(defense, "name", defense))
        # Risk 1.0 on both fail-closed paths: a monitor that could not answer is the
        # worst case the scale has, and a trace sorted by risk must not hide it below
        # the actions the monitor did manage to judge.
        return Decision(Verdict.BLOCK, ("INTERNAL_ERROR",), risk=1.0)
    if not isinstance(decision, Decision):
        logger.error(
            "defense %r returned %r; failing closed",
            getattr(defense, "name", defense),
            type(decision),
        )
        return Decision(Verdict.BLOCK, ("MALFORMED_DECISION",), risk=1.0)
    return decision
