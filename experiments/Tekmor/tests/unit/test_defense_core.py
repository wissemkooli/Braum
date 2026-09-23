"""The decision contract and the fail-closed mediation point."""

import pytest

from tekmor.defense import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Defense,
    Source,
    Verdict,
    mediate,
)
from tekmor.defense.baselines import AllowAll
from tekmor.policy import Policy
from tekmor.provenance import TrustLevel

STATE = AgentState(task="summarise the vendor thread", step=3)
ACTION = Action(tool="send_email", args={"to": "vendor@example.com", "body": "thanks"})
POLICY = Policy(name="enterprise", sensitive_tools=frozenset({"send_email"}))
NO_PROVENANCE = ActionProvenance()


def test_action_integrity_is_the_minimum_of_its_sources():
    provenance = ActionProvenance.of(
        [
            Source("req-1", TrustLevel.AUTHENTICATED_USER, origin="user"),
            Source("doc-7", TrustLevel.UNTRUSTED_EXTERNAL, origin="read_attachment"),
        ]
    )
    assert provenance.integrity == TrustLevel.UNTRUSTED_EXTERNAL


def test_rewrite_requires_a_rewritten_action():
    with pytest.raises(ValueError):
        Decision(Verdict.REWRITE, ("X",))
    with pytest.raises(ValueError):
        Decision(Verdict.ALLOW, ("X",), rewritten=Action(tool="draft_email"))


def test_a_decision_must_carry_its_reason_codes():
    with pytest.raises(ValueError):
        Decision(Verdict.ALLOW, ())


def test_baselines_satisfy_the_defense_protocol():
    assert isinstance(AllowAll(), Defense)


def test_a_crashing_defense_blocks_rather_than_falling_through_to_allow():
    class Broken:
        name = "broken"

        def decide(self, state, action, provenance, policy):
            raise RuntimeError("signal extractor exploded")

    decision = mediate(Broken(), STATE, ACTION, NO_PROVENANCE, POLICY)
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_codes == ("INTERNAL_ERROR",)


def test_a_defense_returning_a_non_decision_blocks():
    class Confused:
        name = "confused"

        def decide(self, state, action, provenance, policy):
            return "allow"

    decision = mediate(Confused(), STATE, ACTION, NO_PROVENANCE, POLICY)
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_codes == ("MALFORMED_DECISION",)


def test_mediate_passes_a_well_formed_decision_through():
    assert mediate(AllowAll(), STATE, ACTION, NO_PROVENANCE, POLICY).verdict is Verdict.ALLOW
