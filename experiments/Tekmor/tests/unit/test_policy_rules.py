"""The two policy rules, evaluated on their own.

They are separately testable on purpose: a rule is a predicate over primitives, so the
cases below say what the rule *means* without a world, a run, or a verdict in the way.
Both directions are here — what each rule refuses and what it must keep allowing.
"""

from dataclasses import replace

import pytest

from tekmor.policy import (
    Policy,
    downgrade_for,
    permitted_flow,
    permitted_tool,
    recipients_of,
    trusted_action,
)
from tekmor.provenance import TrustLevel

ENTERPRISE = Policy(
    name="enterprise",
    sensitive_tools=frozenset({"send_email"}),
    allowed_tools=frozenset({"read_document", "read_secret", "send_email", "draft_email"}),
    outbound_tools=frozenset({"send_email"}),
    authorized_recipients=frozenset({"legal@internal.example"}),
    rewrites={"send_email": "draft_email"},
)


def test_a_tool_is_not_permitted_because_nobody_mentioned_it():
    assert permitted_tool("send_email", ENTERPRISE)
    assert not permitted_tool("wire_transfer", ENTERPRISE)
    # Least privilege has no permissive default: an empty policy permits nothing.
    assert not permitted_tool("send_email", Policy("empty"))


@pytest.mark.parametrize(
    ("trust", "allowed"),
    [
        (TrustLevel.SYSTEM_POLICY, True),
        (TrustLevel.AUTHENTICATED_USER, True),
        (TrustLevel.TRUSTED_INTERNAL, True),
        (TrustLevel.UNTRUSTED_INTERNAL, False),
        (TrustLevel.UNTRUSTED_EXTERNAL, False),
        (TrustLevel.ADVERSARY_CONTROLLED, False),
    ],
)
def test_trusted_action_is_the_threshold_and_nothing_else(trust, allowed):
    assert trusted_action("send_email", trust, ENTERPRISE) is allowed


def test_a_non_sensitive_tool_may_be_driven_by_anything():
    # "Untrusted is not irrelevant": reading hostile content is how the agent does its
    # job, and a rule that stopped the read would collapse utility for no security.
    assert trusted_action("read_document", TrustLevel.ADVERSARY_CONTROLLED, ENTERPRISE)


def test_permitted_flow_stops_confidential_data_at_an_unauthorized_recipient():
    assert not permitted_flow("send_email", True, ["ap@contoso.example"], ENTERPRISE)


def test_permitted_flow_allows_the_authorized_recipient():
    # The hard negative for this rule: sending a secret to the party entitled to it is
    # the work, and blocking it is a false block.
    assert permitted_flow("send_email", True, ["legal@internal.example"], ENTERPRISE)


def test_one_unauthorized_recipient_is_enough_to_refuse():
    assert not permitted_flow(
        "send_email", True, ["legal@internal.example", "ap@contoso.example"], ENTERPRISE
    )


def test_an_outbound_call_with_no_recognisable_recipient_is_refused():
    # Fail safe: a destination that cannot be checked must not read as an allowed one.
    assert not permitted_flow("send_email", True, [], ENTERPRISE)


def test_permitted_flow_ignores_calls_that_carry_nothing_confidential():
    assert permitted_flow("send_email", False, ["ap@contoso.example"], ENTERPRISE)


def test_permitted_flow_ignores_calls_that_go_nowhere():
    assert permitted_flow("draft_email", True, ["ap@contoso.example"], ENTERPRISE)


def test_recipients_come_from_the_arguments_the_policy_names():
    assert recipients_of({"to": "a@b.example", "body": "c@d.example"}, ENTERPRISE) == (
        "a@b.example",
    )
    assert recipients_of({"body": "hello"}, ENTERPRISE) == ()


def test_the_declared_downgrade_is_vetted_not_trusted():
    assert downgrade_for("send_email", ENTERPRISE) == "draft_email"
    assert downgrade_for("read_document", ENTERPRISE) is None

    # A rewrite that points at a tool which is itself sensitive, outbound, or not
    # permitted would turn a refused action into an executed one. Each fails closed:
    # no downgrade, so the caller escalates to a human instead.
    for broken in ({"send_email": "send_email"}, {"send_email": "post_to_forum"}):
        assert downgrade_for("send_email", replace(ENTERPRISE, rewrites=broken)) is None
