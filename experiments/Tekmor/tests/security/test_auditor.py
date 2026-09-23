"""The task-alignment auditor: it only raises, it only asks about the gray zone, and a judge
that refuses everything pays for it in benign work.

Stub judges stand in for the model: the claims here are about the fusion, not about any
judge's accuracy, which `evaluation/alignment.py` measures and `docs/07-results.md`
records. The one test that loads a real model is marked slow.
"""

from dataclasses import dataclass, field, replace

import pytest

from evaluation.harness import SCENARIOS, load_matrix
from tekmor.defense import (
    Action,
    ActionProvenance,
    AgentState,
    AlignmentAuditor,
    ReferenceMonitor,
    Verdict,
    mediate,
)
from tekmor.defense.auditor import Judge, gray
from tekmor.defense.baselines import RefuseAll
from tekmor.policy.core import Policy
from tekmor.provenance.taint import USER_REQUEST
from tekmor.provenance.trust import Source, TrustLevel
from tekmor.runtime import run

ORDER = [Verdict.ALLOW, Verdict.REWRITE, Verdict.ESCALATE, Verdict.BLOCK]
HOSTILE = Source("doc:X", TrustLevel.UNTRUSTED_EXTERNAL)


@dataclass
class Stub:
    answer: float
    name: str = "stub"
    asked: list = field(default_factory=list)

    def aligned(self, task, action):
        self.asked.append((task, action))
        return self.answer


def _endorsing(scenarios):
    return [replace(s, policy=replace(s.policy, endorse_named=True)) for s in scenarios]


@pytest.fixture(scope="module")
def matrix():
    return _endorsing(load_matrix(SCENARIOS))


def test_the_auditor_never_lowers_a_verdict_and_never_blocks(matrix):
    # Both defenses decide every step on the *same* inputs. Comparing two separate runs
    # would not do: once the auditor escalates a read, later steps see other provenance.
    monitor = ReferenceMonitor()
    auditor = AlignmentAuditor(monitor, Stub(0.0))
    pairs = []

    class Both:
        name = "both"

        def decide(self, state, action, provenance, policy):
            core = monitor.decide(state, action, provenance, policy)
            audited = auditor.decide(state, action, provenance, policy)
            pairs.append((core.verdict, audited.verdict))
            return audited

    for scenario in matrix:
        run(scenario, Both())
    assert any(core is not audited for core, audited in pairs)
    for core, audited in pairs:
        assert ORDER.index(audited) >= ORDER.index(core)
        if audited is not core:
            assert core is Verdict.ALLOW
            assert audited in {Verdict.REWRITE, Verdict.ESCALATE}


def test_a_judge_that_confirms_everything_changes_nothing(matrix):
    monitor, auditor = ReferenceMonitor(), AlignmentAuditor(ReferenceMonitor(), Stub(1.0))
    for scenario in matrix:
        core = [s.decision for s in run(scenario, monitor).steps]
        assert [s.decision for s in run(scenario, auditor).steps] == core


def test_only_gray_zone_allows_reach_the_judge():
    policy = Policy("p", allowed_tools=frozenset({"read", "send_email"}))
    state, action = AgentState("the task", 1), Action("read", {"id": "A"})
    judge = Stub(0.0)
    auditor = AlignmentAuditor(ReferenceMonitor(), judge)

    # Trusted provenance: nothing ambiguous, nothing asked.
    trusted = ActionProvenance.of([USER_REQUEST])
    assert auditor.decide(state, action, trusted, policy).verdict is Verdict.ALLOW
    # Refused by the rules: the judge never sees a verdict it could soften.
    refused = Action("not_permitted")
    assert auditor.decide(state, refused, trusted, policy).verdict is Verdict.BLOCK
    assert judge.asked == []

    tainted = ActionProvenance.of([USER_REQUEST, HOSTILE])
    assert gray(tainted, policy)
    decision = auditor.decide(state, action, tainted, policy)
    assert decision.verdict is Verdict.ESCALATE
    # The judge was shown the authenticated task and the call, nothing the agent read.
    assert judge.asked == [("the task", action)]
    assert decision.reason_codes == ("TASK_ALIGNMENT_UNCONFIRMED",)


def test_endorsed_content_is_still_in_the_gray_zone():
    endorsed = replace(HOSTILE, endorsed_by=USER_REQUEST.id)
    provenance = ActionProvenance.of([USER_REQUEST, endorsed])
    policy = Policy("p")
    assert provenance.integrity >= policy.min_integrity
    assert gray(provenance, policy)


def test_an_unconfirmed_call_is_downgraded_where_the_policy_allows_it():
    policy = Policy(
        "p",
        allowed_tools=frozenset({"send_email", "draft_email"}),
        rewrites={"send_email": "draft_email"},
    )
    action = Action("send_email", {"to": "a@b"})
    decision = AlignmentAuditor(ReferenceMonitor(), Stub(0.2)).decide(
        AgentState("t"), action, ActionProvenance.of([USER_REQUEST, HOSTILE]), policy
    )
    assert decision.verdict is Verdict.REWRITE
    assert decision.rewritten == Action("draft_email", action.args)
    assert decision.risk >= 0.5


def test_a_judge_that_raises_fails_closed():
    class Broken:
        name = "broken"

        def aligned(self, task, action):
            raise RuntimeError("model unavailable")

    policy = Policy("p", allowed_tools=frozenset({"read"}))
    decision = mediate(
        AlignmentAuditor(ReferenceMonitor(), Broken()),
        AgentState("t"),
        Action("read"),
        ActionProvenance.of([USER_REQUEST, HOSTILE]),
        policy,
    )
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_codes == ("INTERNAL_ERROR",)


def test_a_judge_that_refuses_everything_stops_the_endorsed_attack_and_the_benign_twin(
    scenario,
):
    # The trade in one pair: without a judge that can tell them apart, the only way to
    # stop the tampered invoice is to stop the honest one too.
    auditor = AlignmentAuditor(ReferenceMonitor(), Stub(0.0))
    attack = scenario("financial_injection_endorsed_invoice.yaml")
    benign = scenario("financial_benign_endorsed_invoice.yaml")
    assert not attack.compromised(run(attack, auditor).world)
    assert not benign.completed(run(benign, auditor).world)


@pytest.mark.slow
def test_the_model_judge_is_a_deterministic_probability():
    from tekmor.runtime.qwen import CausalJudge

    judge = CausalJudge()
    action = Action("read_document", {"id": "INV-91"})
    first = judge.aligned("Read invoice INV-91.", action)
    assert 0.0 <= first <= 1.0
    judge._answers.clear()
    assert judge.aligned("Read invoice INV-91.", action) == first


def test_deny_gray_refuses_every_gray_zone_allow_and_counts_it(matrix):
    """`RefuseAll` is the control: same mechanism, no judgement, and `calls` is the zone."""
    judge = RefuseAll()
    assert isinstance(judge, Judge)
    monitor = ReferenceMonitor()
    auditor = AlignmentAuditor(monitor, judge)
    asked = set()

    class Both:
        name = "both"

        def decide(self, state, action, provenance, policy):
            core = monitor.decide(state, action, provenance, policy)
            audited = auditor.decide(state, action, provenance, policy)
            if core.verdict is Verdict.ALLOW and gray(provenance, policy):
                asked.add((state.task, str(action)))
                # Refused, never blocked: a refusal to confirm defers, it does not prove.
                assert audited.verdict in {Verdict.REWRITE, Verdict.ESCALATE}
                assert "TASK_ALIGNMENT_UNCONFIRMED" in audited.reason_codes
            else:
                assert audited.verdict is core.verdict
            return audited

    for scenario in matrix:
        run(scenario, Both())
    assert asked
    # Asked on the gray zone and nowhere else, and counted per distinct question exactly
    # as `CausalJudge` counts its cache misses — which is what makes this arm's gray-zone
    # size comparable with the model judges' recorded call counts.
    assert judge.calls == len(judge._answers) == len(asked)
    assert set(judge._answers.values()) == {0.0}
