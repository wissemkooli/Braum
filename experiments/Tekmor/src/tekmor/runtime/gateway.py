"""The tool gateway: the world's only door.

`docs/10-research-report.md` Part I: approved actions go to the tool gateway, which updates
world state. The gateway owns the *last* check before execution — it turns a `Decision`
into "this exact action runs" or "nothing runs" — so complete mediation is a property of
one small class rather than of every caller that drives an agent.

It is deliberately a separate object from the run loop: the evaluation harness and any
future driver (an AgentDojo pipeline element, a live server) get the same chokepoint
without re-implementing the verdict handling, and `world.invoke` keeps exactly one call
site in the package.

The gateway does not decide. It is handed the decision `mediate()` produced and refuses
anything it does not recognise.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tekmor.defense import Action, Decision, Verdict
from tekmor.provenance.trust import Source
from tekmor.simulator.world import World

#: The simulated human an ESCALATE goes to. Denying is the safe default, and a run that
#: needs approvals says so by passing its own.
Approver = Callable[[Action], bool]


def deny(action: Action) -> bool:
    return False


def permitted(action: Action, decision: Decision, approver: Approver = deny) -> Action | None:
    """The action a decision lets execute, or `None`. Anything unrecognised executes nothing.

    A verdict added later therefore fails closed here until it is handled on purpose,
    which is the same rule as `mediate()` failing closed on an error. A function rather
    than only a method so a driver with its own tool runtime (the AgentDojo pipeline
    element) applies the same mapping instead of a copy of it.
    """
    if decision.verdict is Verdict.ALLOW:
        return action
    if decision.verdict is Verdict.REWRITE:
        return decision.rewritten
    if decision.verdict is Verdict.ESCALATE and approver(action):
        return action
    return None


@dataclass(frozen=True, slots=True)
class Execution:
    """What the gateway did with one decided action.

    `source` is the provenance of `result`, carried out of the world so the caller can
    add it to the run's taint. It is `None` when nothing executed or the call failed:
    there is no observation to have been influenced by.
    """

    executed: Action | None
    result: str | None = None
    error: str | None = None
    source: Source | None = None


@dataclass(frozen=True, slots=True)
class ToolGateway:
    """Executes decided actions against one world, and nothing else against it."""

    world: World
    approver: Approver = deny

    def permitted(self, action: Action, decision: Decision) -> Action | None:
        return permitted(action, decision, self.approver)

    def execute(self, action: Action, decision: Decision) -> Execution:
        allowed = self.permitted(action, decision)
        if allowed is None:
            return Execution(None)
        try:
            observation = self.world.invoke(allowed.tool, allowed.args)
            return Execution(allowed, result=observation.text, source=observation.source)
        except Exception as exc:  # a bad call is an outcome, not a crashed run
            return Execution(allowed, error=f"{type(exc).__name__}: {exc}")
