"""Trust levels as integrity labels.

The six levels of `docs/10-research-report.md` Part I form a lattice:

    SYSTEM_POLICY > AUTHENTICATED_USER > TRUSTED_INTERNAL >
    UNTRUSTED_INTERNAL > UNTRUSTED_EXTERNAL > ADVERSARY_CONTROLLED

Read as Biba integrity labels: the integrity of anything influenced by several inputs is
the *minimum* integrity of those inputs. The enum is ordered so that the usual
comparison operators are the lattice order and `min()` is the meet.

This module is the lattice itself and the labelled source it applies to. Accumulating
those labels over a run is `taint.py`.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum


class TrustLevel(IntEnum):
    """Integrity of a source. Higher is more trusted; the order is the lattice order."""

    ADVERSARY_CONTROLLED = 0
    UNTRUSTED_EXTERNAL = 1
    UNTRUSTED_INTERNAL = 2
    TRUSTED_INTERNAL = 3
    AUTHENTICATED_USER = 4
    SYSTEM_POLICY = 5


#: The integrity an endorsement raises content to: the default Trusted-Action threshold,
#: and no higher. An endorsed document is one the user vouched for acting on, not one the
#: user wrote.
ENDORSED = TrustLevel.TRUSTED_INTERNAL


def least_trusted(levels: Iterable[TrustLevel]) -> TrustLevel:
    """Meet of the lattice: the integrity of something influenced by all of `levels`.

    No levels means nothing is known about the influences. Unknown provenance must not
    read as trusted, so the meet of the empty set is the bottom of the lattice rather
    than the top.
    """
    return min(levels, default=TrustLevel.ADVERSARY_CONTROLLED)


@dataclass(frozen=True, slots=True)
class Source:
    """One labelled observation that can influence an action.

    `origin` is free text naming where the content came from (a tool name, a document
    id, the user). It is kept because provenance must never be silently reduced to a
    bare trust level.

    `confidential` is the second label, kept separate from integrity on purpose:
    integrity says who may *drive* an action, confidentiality says what may *leave*. A
    secret read by the authenticated user has high integrity and is still confidential,
    and collapsing the two would lose one of the two rules the policy engine enforces.
    It defaults to False, which is the safe default for this label — marking everything
    confidential would block every outbound call, and the label is only ever set by
    whatever produced the observation.

    It lives here rather than beside the decision contract so that anything producing
    observations — the simulator, the runtime — can label them without importing the
    defense.
    """

    id: str
    trust: TrustLevel
    origin: str = ""
    confidential: bool = False
    #: The id of the authenticated source that endorsed this content, or None. Set only
    #: by `taint.endorse`, and it never rewrites `trust`: the trace keeps the label the
    #: content arrived with *and* the fact that someone vouched for it.
    endorsed_by: str | None = None

    @property
    def integrity(self) -> TrustLevel:
        """The label a decision is judged against: `trust`, raised to `ENDORSED` if endorsed."""
        return max(self.trust, ENDORSED) if self.endorsed_by else self.trust
