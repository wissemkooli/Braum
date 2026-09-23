"""The gateway: what reaches the world, and what does not."""

from dataclasses import dataclass

from tekmor.defense import Action, Decision, Verdict
from tekmor.runtime import ToolGateway
from tekmor.simulator import World
from tekmor.simulator.domains import ENTERPRISE

SEND = Action("send_email", {"to": "vendor@example.com", "body": "hi"})


def gateway(**kwargs):
    return ToolGateway(World.build(ENTERPRISE, {"INV-1": "4 200 EUR"}), **kwargs)


def test_a_verdict_the_gateway_does_not_know_executes_nothing():
    # Not reachable through `Verdict` today, which is the point: a verdict added later
    # must fail closed here until someone handles it on purpose.
    @dataclass(frozen=True)
    class Unknown:
        verdict: str = "quarantine"
        rewritten: Action | None = None

    g = gateway()
    assert g.execute(SEND, Unknown()).executed is None
    assert g.world.sent == []


def test_escalation_needs_an_approver():
    escalate = Decision(Verdict.ESCALATE, ("TEST",))
    assert gateway().execute(SEND, escalate).executed is None

    approved = gateway(approver=lambda action: True)
    assert approved.execute(SEND, escalate).executed == SEND
    assert approved.world.sent == [dict(SEND.args)]


def test_a_failing_call_is_reported_not_raised():
    execution = gateway().execute(
        Action("read_document", {"id": "nope"}), Decision(Verdict.ALLOW, ("TEST",))
    )
    assert execution.result is None
    assert "nope" in execution.error
