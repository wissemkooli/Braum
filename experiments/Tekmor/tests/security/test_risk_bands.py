"""Risk and verdict, on every scenario in the matrix: the two must not drift apart.

`tests/unit/test_risk.py` checks the bands against hand-built signals. This checks them
against real runs, where the provenance comes from what the agent actually read — and it
checks the layered defense too, because a wrapper that raised a verdict without raising
the score would publish a BLOCK sitting next to a risk of 0.1.
"""

from evaluation.harness import SCENARIOS, load_matrix
from tekmor.defense import CanaryScanner, ReferenceMonitor, Verdict, band
from tekmor.runtime import run


def decisions(defense):
    return [
        (scenario.id, step.decision)
        for scenario in load_matrix(SCENARIOS)
        for step in run(scenario, defense).steps
    ]


def layered():
    """The monitor under the canary layer, with the matrix's secrets as the registry."""
    secrets = frozenset(value for s in load_matrix(SCENARIOS) for value in s.canaries.values())
    return CanaryScanner(ReferenceMonitor(), secrets)


def test_every_decision_on_the_matrix_lands_in_the_band_of_its_score():
    for scenario_id, decision in decisions(ReferenceMonitor()):
        assert decision.risk is not None, scenario_id
        assert band(decision.risk) is decision.verdict, (scenario_id, decision.reason_codes)


def test_the_canary_layer_raises_the_score_with_the_verdict():
    scenarios = load_matrix(SCENARIOS)
    secrets = frozenset(value for s in scenarios for value in s.canaries.values())
    core = {(sid, i): d for i, (sid, d) in enumerate(decisions(ReferenceMonitor()))}
    layered = {
        (sid, i): d
        for i, (sid, d) in enumerate(decisions(CanaryScanner(ReferenceMonitor(), secrets)))
    }

    assert core.keys() == layered.keys()
    for key, decision in layered.items():
        # Monotone-safe fusion on the score as well as on the verdict: the layer may
        # only raise suspicion (monotone-safe fusion (`docs/03-architecture.md` §3.7)).
        assert decision.risk >= core[key].risk
        assert band(decision.risk) is decision.verdict


def test_the_action_the_layer_catches_scores_above_every_allowed_one():
    scored = decisions(layered())

    allowed = [d.risk for _, d in scored if d.verdict is Verdict.ALLOW]
    blocked = [d.risk for _, d in scored if d.verdict is Verdict.BLOCK]
    # The separation AUROC measures, asserted as a property rather than as a number:
    # nothing the defense allowed may score as high as anything it refused.
    assert blocked and max(allowed) < min(blocked)
