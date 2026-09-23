"""The reference monitor: the policy predicates turned into a verdict.

`docs/architecture.md` explains the design; this note records what matters when editing
the file. The policy engine (`tekmor.policy.core`) answers yes/no about a candidate
action, and this module decides what to *do* about a no.

**The ordering is the design, and it is fixed.**

1. **Least privilege** -- a tool the policy does not permit is blocked before anything
   else is considered.
2. **Permitted-Flow** -- there is no safe downgrade of an exfiltration. A
   lower-capability variant still carrying the value has only moved it, and escalating
   hands a human a decision they cannot check, because the value is not in the argument
   in a form they would recognise. So this blocks rather than rewrites.
3. **Trusted-Action** -- downgraded where the policy declares a variant, escalated where
   it does not. This is the branch that exists so the answer to an injection is not
   always "stop working": the analyst still gets a ticket, the drafted mail is still
   there for a human to send.

The predicates are evaluated once into `signals.Signals`, and both the verdict and the
reported risk are read off that one object -- a score derived from a second evaluation
could drift from the decision it is printed beside.

Everything here is computed from the four inputs it is handed. It never sees the
scenario, the world, the file it came from, or whether the run is meant to be an attack.
"""

from __future__ import annotations

from dataclasses import dataclass

from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Verdict,
)
from tekmor.defense.risk import score as risk_score
from tekmor.defense.signals import Signals, extract
from tekmor.policy.core import Policy


@dataclass(frozen=True, slots=True)
class ReferenceMonitor:
    """Tekmor's deterministic core: provenance and policy, no text matching, no model.

    It reads the *provenance* of the action rather than its arguments, so the encodings
    and paraphrases that defeat `baselines.KeywordFilter` change nothing here: a base64
    copy of a secret was still influenced by the read that produced it.

    The reverse is the honest limitation, and it is the one to measure: the monitor sees
    only the sources it is handed, and taint propagation hands it call-level influence.
    A value that reached an argument without passing through a labelled observation is
    invisible here, and an action taken after reading hostile content is labelled by it
    whether or not that content had anything to do with the action.
    """

    name: str = "tekmor"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        return self.judge(extract(state, action, provenance, policy), action)

    def judge(self, signals: Signals, action: Action) -> Decision:
        """The rules themselves, over already-extracted signals.

        Separate from `decide` so that the rule ordering can be tested, and a risk
        contribution explained, against a `Signals` value written by hand — without
        assembling a policy and a provenance set to reach one branch.
        """
        risk = risk_score(signals)

        if not signals.tool_permitted:
            return Decision(Verdict.BLOCK, ("TOOL_NOT_PERMITTED",), risk=risk)

        if not signals.flow_permitted:
            # The recipient itself is left out of the reason codes: they are public, and
            # a destination is part of what the run is trying to keep in.
            return Decision(
                Verdict.BLOCK,
                ("CONFIDENTIAL_INFLUENCE", "OUTBOUND_TOOL", "RECIPIENT_NOT_AUTHORIZED"),
                risk=risk,
            )

        if not signals.integrity_sufficient:
            violation = ("TARGET_TOOL_SENSITIVE", "ACTION_INTEGRITY_BELOW_THRESHOLD")
            if signals.argument_integrity is not None:
                violation += ("AUTHORITY_ARGUMENTS",)
            if signals.downgrade is None:
                return Decision(
                    Verdict.ESCALATE, (*violation, "NO_CAPABILITY_DOWNGRADE"), risk=risk
                )
            # Arguments travel unchanged: the downgrade is of the *capability*, and the
            # variant is chosen to accept the same call. Argument redaction is a separate
            # rewrite that does not exist yet.
            return Decision(
                Verdict.REWRITE,
                (*violation, "CAPABILITY_DOWNGRADE"),
                Action(signals.downgrade, action.args),
                risk=risk,
            )

        allowed = ("TOOL_PERMITTED", "PERMITTED_FLOW_SATISFIED", "TRUSTED_ACTION_SATISFIED")
        if signals.argument_integrity is not None:
            allowed += ("AUTHORITY_ARGUMENTS",)
        return Decision(Verdict.ALLOW, allowed, risk=risk)
