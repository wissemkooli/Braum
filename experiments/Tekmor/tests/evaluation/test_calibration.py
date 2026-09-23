"""CALIB-RISK: the Platt fit, the held-out protocol, and what the result is not.

These assert the *protocol* rather than the numbers it produces on today's matrix. A
calibration result that improves is a finding; one that is computed in-sample, or on a
fold that saw the action it scores, is a bug, and these are the tests that tell the two
apart.
"""

import pytest

from evaluation.calibration import Platt, brier, calibrate, fit, held_out, scored_actions
from evaluation.harness import SCENARIOS, evaluate, load_matrix
from evaluation.metrics import RunRecord, ece


def records():
    return evaluate(load_matrix(SCENARIOS))


def test_the_fit_stays_finite_on_a_perfectly_separated_sample():
    # The severities were built to separate, so separation is the ordinary case here and
    # an unsmoothed fit would run off to infinity and report certainty it cannot have.
    # Platt's smoothed targets are what bound it: 2 positives -> 0.75, 3 negatives -> 0.2.
    scaler = fit([0.9, 0.9, 0.1, 0.1, 0.1], [True, True, False, False, False])

    assert scaler.a < 0  # higher risk must map to higher probability
    assert scaler.probability(0.9) == pytest.approx(0.75)
    assert scaler.probability(0.1) == pytest.approx(0.2)


def test_a_fit_maps_risk_to_probability_monotonically():
    scaler = fit([0.9, 0.7, 0.5, 0.1, 0.1], [True, True, False, False, False])
    probabilities = [scaler.probability(risk) for risk in (0.0, 0.1, 0.5, 0.7, 0.9, 1.0)]

    assert probabilities == sorted(probabilities)
    assert all(0.0 < p < 1.0 for p in probabilities)


def test_one_class_has_nothing_to_calibrate_against():
    # Null, not a default: "every action here was safe" is not evidence about the scale.
    assert fit([0.1, 0.9], [False, False]) is None
    assert fit([0.1, 0.9], [True, True]) is None


def test_a_fold_whose_scores_say_nothing_does_not_invent_a_slope():
    # All-identical scores carry no ordering, so the honest fit is the base rate and a
    # flat slope. Without the ridge on the Hessian this is a division by zero instead.
    flat = fit([0.4] * 6, [True, False, False, False, False, False])

    assert flat.a == pytest.approx(0.0, abs=0.1)
    assert flat.probability(0.4) == pytest.approx(0.23, abs=0.05)


def _record(scenario, risks, unsafe):
    return RunRecord(
        scenario=scenario,
        scenario_version=1,
        domain="enterprise",
        family="indirect_injection" if any(unsafe) else "over_refusal",
        level=1,
        defense="tekmor",
        benign=not any(unsafe),
        completed=True,
        compromised=any(unsafe),
        leaked=(),
        verdicts=("allow",) * len(risks),
        risks=risks,
        unsafe=unsafe,
        first_intervention=None,
    )


def test_a_held_out_probability_never_comes_from_a_fit_that_saw_it():
    # The leakage test. One scenario's actions are scored by a scaler fitted without
    # them, so their probabilities must equal what that explicit fit produces — and the
    # all-data fit, which would be the in-sample shortcut, produces something else.
    data = [
        _record("a", (0.9, 0.1), (True, False)),
        _record("b", (0.9, 0.1), (True, False)),
        _record("c", (0.1, 0.1), (False, False)),
    ]
    actions = scored_actions(data)
    scored, fits = held_out(actions)
    without_c = fit([0.9, 0.1, 0.9, 0.1], [True, False, True, False])

    assert len(fits) == 3  # one per scenario
    c_probabilities = [probability for _, probability, _ in scored[-2:]]
    assert c_probabilities == [pytest.approx(without_c.probability(0.1))] * 2
    assert (
        c_probabilities
        != [
            pytest.approx(
                fit(
                    [risk for _, risk, _ in actions], [label for _, _, label in actions]
                ).probability(0.1)
            )
        ]
        * 2
    )


def test_a_single_scenario_cannot_be_held_out_from_itself():
    # With one scenario there is no out-of-sample half, so the protocol reports nothing
    # rather than reporting a fit scored on its own training data.
    scored, fits = held_out(scored_actions([_record("a", (0.9, 0.1), (True, False))]))

    assert (scored, fits) == ([], [])


def test_platt_scaling_reports_a_probability_where_the_ordinal_scale_reported_a_rank():
    # The claim CALIB-RISK makes: a scale whose magnitudes are arbitrary can be mapped
    # to one whose magnitudes are rates. Here the raw score is a badly-scaled version of
    # a well-ordered signal, and the fit is what recovers the rate from it.
    scaler = Platt(a=-8.0, b=4.0)
    raw = [0.9, 0.9, 0.1, 0.1]
    labels = [True, True, False, False]
    calibrated = [scaler.probability(risk) for risk in raw]

    assert ece(calibrated, labels) < ece(raw, labels)
    assert brier(calibrated, labels) < brier(raw, labels)


def test_a_defense_with_no_score_gets_nulls_rather_than_a_calibration():
    result = calibrate([r for r in records() if r.defense == "allow-all"])

    assert result.scored_actions == 0
    assert (result.ece, result.ece_calibrated, result.a) == (None, None, None)
    # Vacuously sound: no fold ran, so no fold read the score backwards.
    assert result.sound


def test_the_matrix_calibration_is_out_of_sample_and_never_reads_the_score_backwards():
    result = calibrate([r for r in records() if r.defense == "tekmor+canary"])

    # One fold per scenario, every scored action held out by exactly one of them.
    assert result.folds == len(load_matrix(SCENARIOS))
    assert result.held_out_actions == result.scored_actions
    # The invariant the calibrated columns depend on: each fold rescaled the risk score,
    # none of them inverted it. Anything else and the numbers below it mean nothing.
    assert result.inverted_folds == 0 and result.sound
    # Reported, not claimed. Whether Platt scaling *helps* on seven scenarios is a
    # finding recorded in docs/07-results.md, not something this test is here to enforce.
    assert result.ece is not None and result.ece_calibrated is not None
