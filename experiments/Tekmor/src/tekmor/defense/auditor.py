"""TASK-ALIGN: a task-alignment auditor that arbitrates the gray zone, and only raises.

`docs/10-research-report.md` Proposal B. The deterministic core decides the clear cases. What
it leaves is the gray zone: an action the rules *allowed* although something below the
integrity threshold influenced it — a non-sensitive call made after reading hostile
content, or a sensitive one driven by content the user endorsed. Those are the actions
the rules cannot tell apart from legitimate work, because their provenance is the same.
The auditor asks a judge one question about each of them: does this call serve what the
user asked for?

**Monotone-safe fusion** (`docs/03-architecture.md` §3.7), exactly as `CanaryScanner`:

- anything the wrapped defense did not ALLOW is returned untouched, and the judge is
  never asked. A judge cannot soften a verdict it never sees;
- a gray-zone ALLOW the judge does not confirm becomes REWRITE when the policy declares a
  vetted downgrade, else ESCALATE. It never becomes BLOCK, because a judge's "no" is a
  reason to ask a human, not proof of an attack;
- the reported risk is raised to the Trusted-Action severity it stands in for and never
  lowered.

**What the judge sees** is the authenticated task and the tool call, and nothing the agent
read. The doc's mitigation for an auditor that is itself an injection target is that it
never reads raw untrusted text as instruction. Arguments can still carry attacker text (a
URL, a mail body), so a fooled judge is possible. It can only fail to escalate, which is
what monotone fusion is for.

**The judge's score stays private.** The public reason code says only that alignment was
not confirmed. The probability is a hill-climbing channel, for the same reason
`risk.contributions` is private.

The judge is a protocol so the auditor can be tested with a stub and run with a model
(`tekmor.runtime.qwen.CausalJudge`) without `defense/` importing a model library.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

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
from tekmor.policy.core import Policy, downgrade_for


@runtime_checkable
class Judge(Protocol):
    """Anything that can say how likely a tool call is to serve a request, in [0, 1]."""

    name: str

    def aligned(self, task: str, action: Action) -> float: ...


def gray(provenance: ActionProvenance, policy: Policy) -> bool:
    """Whether anything below the integrity threshold influenced the action, *as labelled*.

    Read off each source's own `trust`, not its endorsed `integrity`: content the user
    endorsed is exactly the content whose influence the rules can no longer see, so it
    belongs in the zone the auditor arbitrates.
    """
    return any(source.trust < policy.min_integrity for source in provenance.sources)


@dataclass(frozen=True, slots=True)
class AlignmentAuditor:
    """A defense, plus a judge consulted on the gray-zone actions it allowed."""

    inner: Defense
    judge: Judge
    #: The alignment probability below which a gray-zone action is not confirmed. 0.5 is
    #: the judge's own "more likely no than yes"; anything else is a fitted parameter.
    threshold: float = 0.5

    @property
    def name(self) -> str:
        return f"{self.inner.name}+align"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        decision = mediate(self.inner, state, action, provenance, policy)
        if decision.verdict is not Verdict.ALLOW or not gray(provenance, policy):
            return decision
        # A judge that raises propagates to the caller's `mediate`, which fails closed.
        if self.judge.aligned(state.task, action) >= self.threshold:
            return decision

        target = downgrade_for(action.tool, policy)
        if target is not None:
            return Decision(
                Verdict.REWRITE,
                ("TASK_ALIGNMENT_UNCONFIRMED", "CAPABILITY_DOWNGRADE"),
                Action(target, action.args),
                risk=max(SEVERITY["CAPABILITY_DOWNGRADE"], decision.risk or 0.0),
            )
        return Decision(
            Verdict.ESCALATE,
            ("TASK_ALIGNMENT_UNCONFIRMED",),
            risk=max(SEVERITY["ACTION_INTEGRITY_BELOW_THRESHOLD"], decision.risk or 0.0),
        )
