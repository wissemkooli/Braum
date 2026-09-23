"""The monitor's verdict mapping, on actions built here rather than run through a world.

The scenario-level behaviour lives in `tests/security/test_monitor.py`. What is here is
the order of the checks and the cases a scenario does not reach.
"""

from dataclasses import replace

from tekmor.defense import (
    Action,
    ActionProvenance,
    AgentState,
    ReferenceMonitor,
    Source,
    Verdict,
    mediate,
)
from tekmor.policy import Policy
from tekmor.provenance import TrustLevel

POLICY = Policy(
    name="enterprise",
    sensitive_tools=frozenset({"send_email"}),
    allowed_tools=frozenset({"read_document", "send_email", "draft_email"}),
    outbound_tools=frozenset({"send_email"}),
    authorized_recipients=frozenset({"legal@internal.example"}),
    rewrites={"send_email": "draft_email"},
)
MAIL = Action("send_email", {"to": "ap@contoso.example", "body": "..."})
USER = Source("user:request", TrustLevel.AUTHENTICATED_USER, origin="user")
HOSTILE = Source("doc:INV-91", TrustLevel.ADVERSARY_CONTROLLED, origin="read_document")
SECRET = Source("tool:read_secret", TrustLevel.TRUSTED_INTERNAL, "read_secret", confidential=True)


def decide(action, *sources, policy=POLICY):
    return ReferenceMonitor().decide(
        AgentState(task="t", step=0), action, ActionProvenance.of(sources), policy
    )


def test_an_unpermitted_tool_is_blocked_before_anything_else_is_considered():
    # Even driven by the user, and even with nothing confidential in it.
    decision = decide(Action("wire_transfer", {"to": "legal@internal.example"}), USER)
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_codes == ("TOOL_NOT_PERMITTED",)


def test_a_permitted_action_with_clean_provenance_is_allowed():
    assert decide(MAIL, USER).verdict is Verdict.ALLOW


def test_an_untrusted_driver_of_a_sensitive_tool_is_downgraded():
    decision = decide(MAIL, HOSTILE)
    assert decision.verdict is Verdict.REWRITE
    assert decision.rewritten == Action("draft_email", MAIL.args)
    assert decision.reason_codes == (
        "TARGET_TOOL_SENSITIVE",
        "ACTION_INTEGRITY_BELOW_THRESHOLD",
        "CAPABILITY_DOWNGRADE",
    )


def test_without_a_declared_downgrade_the_same_action_escalates():
    decision = decide(MAIL, HOSTILE, policy=replace(POLICY, rewrites={}))
    assert decision.verdict is Verdict.ESCALATE
    assert decision.reason_codes[-1] == "NO_CAPABILITY_DOWNGRADE"


def test_a_flow_violation_blocks_rather_than_downgrading():
    # Both rules are violated here, and the order matters: drafting an email that still
    # carries the secret has moved the value, not stopped it, and the downgrade target
    # is chosen for capability, not for what it carries.
    decision = decide(MAIL, HOSTILE, SECRET)
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_codes[0] == "CONFIDENTIAL_INFLUENCE"


def test_a_confidential_action_the_user_drove_is_still_stopped():
    # Integrity and confidentiality are separate labels: high integrity says the user
    # asked for it, which is not permission for the secret to leave.
    assert decide(MAIL, USER, SECRET).verdict is Verdict.BLOCK


def test_the_authorized_recipient_is_the_way_the_secret_may_leave():
    authorized = Action("send_email", {**MAIL.args, "to": "legal@internal.example"})
    assert decide(authorized, USER, SECRET).verdict is Verdict.ALLOW


def test_an_action_with_no_declared_provenance_is_not_trusted():
    # An empty source set is the Qwen adapter's honest answer, and the lattice reads it
    # as ADVERSARY_CONTROLLED. It must not come out as ALLOW on a sensitive tool.
    assert decide(MAIL).verdict is Verdict.REWRITE


def test_the_monitor_still_fails_closed_through_mediate():
    broken = replace(POLICY, rewrites=None)  # a policy the monitor cannot evaluate
    decision = mediate(
        ReferenceMonitor(), AgentState(), MAIL, ActionProvenance.of([HOSTILE]), broken
    )
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_codes == ("INTERNAL_ERROR",)
