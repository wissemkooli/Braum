"""The risk score: what it is computed from, and what it is not allowed to do.

The score describes a decision, it does not make one (`src/tekmor/defense/risk.py`). So
the assertions here are about two properties: the ordering of the severities, and the
agreement between the bands and the rules. A weight that moves without the band moving
with it is the failure this file exists to catch.
"""

import pytest

from tekmor.defense import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    ReferenceMonitor,
    Source,
    Verdict,
    band,
    contributions,
    extract,
    mediate,
    risk_score,
)
from tekmor.defense.risk import SEVERITY
from tekmor.policy import Policy
from tekmor.provenance import TrustLevel

POLICY = Policy(
    name="enterprise",
    sensitive_tools=frozenset({"send_email", "wire_transfer"}),
    allowed_tools=frozenset({"read_document", "send_email", "draft_email", "wire_transfer"}),
    outbound_tools=frozenset({"send_email"}),
    authorized_recipients=frozenset({"legal@internal.example"}),
    rewrites={"send_email": "draft_email"},
)
MAIL = Action("send_email", {"to": "ap@contoso.example", "body": "..."})
INTERNAL_MAIL = Action("send_email", {"to": "legal@internal.example", "body": "..."})
USER = Source("user:request", TrustLevel.AUTHENTICATED_USER, origin="user")
HOSTILE = Source("doc:INV-91", TrustLevel.ADVERSARY_CONTROLLED, origin="read_document")
SECRET = Source("tool:read_secret", TrustLevel.TRUSTED_INTERNAL, "read_secret", confidential=True)


def signals(action, *sources, policy=POLICY):
    return extract(AgentState(task="t", step=0), action, ActionProvenance.of(sources), policy)


def test_a_clean_action_scores_zero_and_fires_nothing():
    clean = signals(INTERNAL_MAIL, USER)

    assert contributions(clean) == ()
    assert risk_score(clean) == 0.0
    assert band(0.0) is Verdict.ALLOW


def test_the_score_is_the_worst_signal_that_fired_not_their_sum():
    # Hostile influence *and* a confidential read heading somewhere unauthorized. Summed
    # weights would leave the scale, and two violations are not twice one violation.
    both = signals(MAIL, HOSTILE, SECRET)

    assert risk_score(both) == SEVERITY["CONFIDENTIAL_INFLUENCE"]
    assert [code for code, _ in contributions(both)] == [
        "CONFIDENTIAL_INFLUENCE",
        "CAPABILITY_DOWNGRADE",
    ]


def test_reading_hostile_content_is_a_gray_zone_signal_not_a_violation():
    # A non-sensitive tool driven by an adversary-controlled read. The monitor allows it
    # — "untrusted is not irrelevant" — and the score says the influence was there.
    read = signals(Action("read_document", {"id": "INV-91"}), HOSTILE)

    assert contributions(read) == (("UNTRUSTED_INFLUENCE", SEVERITY["UNTRUSTED_INFLUENCE"]),)
    assert band(risk_score(read)) is Verdict.ALLOW


def test_an_authorized_confidential_flow_stays_in_the_allow_band():
    authorized = signals(INTERNAL_MAIL, USER, SECRET)

    assert [code for code, _ in contributions(authorized)] == ["CONFIDENTIAL_INFLUENCE_PERMITTED"]
    assert band(risk_score(authorized)) is Verdict.ALLOW


def test_a_bounded_downgrade_scores_below_one_that_needs_a_human():
    downgradable = signals(MAIL, HOSTILE)
    # Same violation, no vetted variant to fall back to, so a person has to decide.
    unbounded = signals(Action("wire_transfer", {"amount": 1}), HOSTILE)

    assert risk_score(downgradable) < risk_score(unbounded)
    assert band(risk_score(downgradable)) is Verdict.REWRITE
    assert band(risk_score(unbounded)) is Verdict.ESCALATE


def test_an_unpermitted_tool_tops_the_scale():
    unpermitted = signals(Action("delete_everything", {}), USER)

    assert risk_score(unpermitted) == 1.0
    assert band(1.0) is Verdict.BLOCK


@pytest.mark.parametrize("action", [MAIL, INTERNAL_MAIL, Action("wire_transfer", {"amount": 1})])
@pytest.mark.parametrize(
    "sources", [(USER,), (HOSTILE,), (SECRET,), (USER, SECRET), (HOSTILE, SECRET)]
)
def test_the_band_of_the_score_is_the_verdict_the_rules_reached(action, sources):
    # The threshold table of docs/10-research-report.md Part XIII, stated as a claim about the
    # rules rather than as a second decision procedure. If a severity and a rule ever
    # disagree, this is where it surfaces instead of in a dashboard.
    monitor = ReferenceMonitor()
    decision = monitor.decide(
        AgentState(task="t", step=0), action, ActionProvenance.of(sources), POLICY
    )

    assert decision.risk is not None
    assert band(decision.risk) is decision.verdict


def test_a_decision_may_carry_no_score_but_never_an_impossible_one():
    # The baselines report no score, and that is not the same claim as risk 0.0.
    assert Decision(Verdict.ALLOW, ("BASELINE_ALLOW_ALL",)).risk is None
    with pytest.raises(ValueError, match="fraction"):
        Decision(Verdict.BLOCK, ("TOOL_NOT_PERMITTED",), risk=1.5)


def test_a_defense_that_cannot_answer_reports_the_top_of_the_scale():
    class Broken:
        name = "broken"

        def decide(self, state, action, provenance, policy):
            raise RuntimeError("no")

    decision = mediate(
        Broken(), AgentState(task="t", step=0), MAIL, ActionProvenance.of((USER,)), POLICY
    )

    # Fail-closed, and visibly so: a trace sorted by risk must not file the action the
    # monitor could not judge below the ones it could.
    assert decision.verdict is Verdict.BLOCK
    assert decision.risk == 1.0
