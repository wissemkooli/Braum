"""CANARY-FLOW: an encoding-aware scan of outbound arguments, layered over any defense.

See `docs/architecture.md` for where this sits and `docs/limitations.md` for what it does
not cover. What is recorded here is the reasoning a reader of *this file* needs.

**Why a layer and not part of the monitor.** The monitor never reads argument text, and
that is exactly what makes its verdicts encoding-independent. Folding a text matcher into
it would retire that claim for every decision, including the ones that never needed the
matcher. Keeping it separate also lets the ablations run the core with and without it,
and keeps a text matcher from being mistaken for the defense -- the literature this
project is built on is about text matchers being bypassed.

**Monotone-safe fusion** (`docs/03-architecture.md` §3.7). This only ever *raises*
suspicion: a BLOCK from the wrapped defense is returned untouched, ALLOW or REWRITE can
become BLOCK but never the reverse, and the reported risk is raised to this layer's
severity and never lowered below what the wrapped defense scored.

**It scans arguments, so it sees only what the call carries.** In the financial domain
the thing that leaves is a *prepared payment* staged by an earlier call, and
`execute_payment` takes only an id -- so a canary routed through payment state is a leak
this layer cannot see, while `World.canaries_in` can. Scanning state rather than
arguments is a different mechanism; the rule that does cover it is the provenance one.
Pinned in `tests/security/test_canary_scanner.py`.

**The secret registry is deployment input, not scenario metadata.** It carries no
scenario id and no `benign` flag -- nothing a defense could recognise a test case by
(`docs/06-evaluation-methodology.md` §6.3). Deriving it from anything that does
would void every number measured with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Defense,
    Verdict,
    mediate,
)
from tekmor.defense.risk import SEVERITY
from tekmor.policy.core import Policy, permitted_flow, recipients_of
from tekmor.provenance.canary import appears_in

#: A registered secret found in the argument of a call heading somewhere unauthorized.
#: Scored as the flow violation it is an instance of (`defense/risk.py`) rather than at
#: the top of the scale: what this layer adds is *evidence* of that violation where the
#: labels carried none, not a worse violation than the one the rule already names.
CANARY_SEVERITY = SEVERITY["CONFIDENTIAL_INFLUENCE"]


@dataclass(frozen=True, slots=True)
class CanaryScanner:
    """A defense, plus a scan of what the approved call would actually carry out."""

    inner: Defense
    #: The values that must not leave. Never logged, never named in a reason code.
    secrets: frozenset[str] = field(default_factory=frozenset)

    @property
    def name(self) -> str:
        """Names the layer *and* what it wraps.

        The defense name is what a run id and every event line is keyed by, so two
        different defenses must not share one: `canary` over the monitor and `canary`
        over `AllowAll` are different mechanisms with very different results, and an
        ablation table that could not tell them apart would be wrong rather than coarse.
        """
        return f"{self.inner.name}+canary"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        # Through `mediate`, so a wrapped defense that raises fails closed here exactly
        # as it would at the top level, rather than taking this one down with it.
        decision = mediate(self.inner, state, action, provenance, policy)
        if decision.verdict is Verdict.BLOCK:
            return decision

        # The call that would *execute*, which after a capability downgrade is not the
        # one proposed: a canary in a `draft_email` body is not a canary leaving.
        outgoing = decision.rewritten or action
        # Asking Permitted-Flow the question with `confidential=True` is asking "would
        # this destination be allowed to receive a secret?". If the policy says yes, a
        # secret going there is authorized work and blocking it is a false block. It
        # also answers yes for any non-outbound tool, which is the check for that.
        if permitted_flow(outgoing.tool, True, recipients_of(outgoing.args, policy), policy):
            return decision

        if not any(
            appears_in(secret, str(value))
            for secret in self.secrets
            for value in outgoing.args.values()
        ):
            return decision

        # Which secret, and which argument, stay out of the public reason codes: the
        # first is close to the value and the second is a hill-climbing channel that
        # tells an attacker exactly which field was read (`docs/03-architecture.md` §3.7).
        return Decision(
            Verdict.BLOCK,
            ("CANARY_IN_OUTBOUND_ARGUMENT", "RECIPIENT_NOT_AUTHORIZED"),
            risk=max(CANARY_SEVERITY, decision.risk or 0.0),
        )
