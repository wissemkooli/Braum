"""CALIB-RISK: Platt-scale the risk score, and measure whether that made it a probability.

`docs/10-research-report.md` Part IX, proposal 7. The severities in `src/tekmor/defense/risk.py`
are *ordinal* — hand-ordered by how much blast radius each violation covers — so the score
orders actions well (AUROC) and its magnitudes mean nothing (ECE). Platt scaling is the
standard one-dimensional fix: fit a logistic `P(unsafe | score) = 1 / (1 + exp(a·s + b))`
and report the calibrated number instead of the raw one.

**Every reported probability is out-of-sample.** Fitting and scoring on the same actions
would report the fit, not the calibration, and on a matrix this small the difference is
the whole result. The fold is the *scenario*, not the action: actions inside one run share
a world, a policy and an injected chain, so a random action-level split would put an
action's near-twin in the training set and read as calibration that will not survive a new
scenario. So it is leave-one-scenario-out — fit on every other scenario, score the held-out
one, repeat — and the raw-versus-calibrated comparison below is between two numbers
computed over the same held-out actions.

**Calibrating does not change what the defense does.** The decision is the rules', in
their fixed order (`docs/07-results.md`); the score describes it and now describes it on a
probability scale. The other half of proposal 7 — learning-to-defer thresholds that
*escalate* on calibrated uncertainty — would give the score authority over a verdict, which
is the trade this project has already declined once, and it is not implemented here.

Three numbers, all on the held-out actions:

- **ECE** — the calibration error the technical doc asks for. Lower is better.
- **Brier** — mean squared error of the probability. ECE bins ~20 actions into ten
  buckets and is noisy at that size; Brier is bin-free, so a disagreement between the two
  is a fact about the sample rather than about the scale.
- **AUROC** — reported before *and* after. A single Platt map with `a < 0` is monotone
  and cannot move it, but leave-one-scenario-out does not apply a single map: each fold
  fits its own, so two actions scored by different folds can swap places. The gap between
  these two columns is therefore not an error — it measures how much the fit *moves*
  between scenarios, which on a seven-scenario matrix is the number worth knowing before
  believing any of the others.

The invariant that does hold is per fold: every fold must fit `a < 0`, or that fold
learned to read the risk score backwards. `inverted_folds` counts the ones that did, and
a nonzero count invalidates the calibrated columns rather than merely denting them.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from math import exp, log, log1p

from evaluation.metrics import RunRecord, auroc, ece


@dataclass(frozen=True, slots=True)
class Platt:
    """`P(unsafe | score) = 1 / (1 + exp(a·score + b))`. A decreasing `a` inverts the score."""

    a: float
    b: float

    def probability(self, score: float) -> float:
        # Branching on the sign keeps `exp` away from its overflow for either tail.
        z = self.a * score + self.b
        return 1 / (1 + exp(z)) if z < 0 else exp(-z) / (1 + exp(-z))


def fit(
    scores: Sequence[float],
    labels: Sequence[bool],
    *,
    iterations: int = 100,
    tolerance: float = 1e-10,
) -> Platt | None:
    """Fit the sigmoid by Newton's method with a backtracking line search.

    Platt (1999), in the numerically stable form of Lin, Weng & Lin (2007): the targets
    are smoothed to `(N+ + 1)/(N+ + 2)` and `1/(N- + 2)` rather than 1 and 0, which is
    what keeps a *separable* sample — the ordinary case here, since the severities were
    built to separate — from driving the fit to infinity and reporting certainty it has
    no evidence for. On twenty actions that smoothing is not a detail; it is the reason
    the result is finite.

    Returns None when one class is missing: there is nothing to calibrate against.
    """
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    hi = (positives + 1) / (positives + 2)
    lo = 1 / (negatives + 2)
    targets = [hi if label else lo for label in labels]
    a, b = 0.0, log((negatives + 1) / (positives + 1))

    def objective(a: float, b: float) -> float:
        total = 0.0
        for score, target in zip(scores, targets, strict=True):
            z = a * score + b
            total += target * z + log1p(exp(-z)) if z >= 0 else (target - 1) * z + log1p(exp(z))
        return total

    value = objective(a, b)
    for _ in range(iterations):
        # A ridge on the diagonal, so an all-identical-score fold has an invertible
        # Hessian instead of a ZeroDivisionError. It biases `a` toward 0, which is the
        # honest answer for a fold whose scores say nothing.
        h11 = h22 = 1e-12
        h21 = g1 = g2 = 0.0
        for score, target in zip(scores, targets, strict=True):
            z = a * score + b
            p = exp(-z) / (1 + exp(-z)) if z >= 0 else 1 / (1 + exp(z))
            second = p * (1 - p)
            h11 += score * score * second
            h22 += second
            h21 += score * second
            g1 += score * (target - p)
            g2 += target - p
        if abs(g1) < tolerance and abs(g2) < tolerance:
            break
        determinant = h11 * h22 - h21 * h21
        step_a = -(h22 * g1 - h21 * g2) / determinant
        step_b = -(-h21 * g1 + h11 * g2) / determinant
        slope = g1 * step_a + g2 * step_b
        scale = 1.0
        while scale >= 1e-10:
            candidate = objective(a + scale * step_a, b + scale * step_b)
            if candidate < value + 1e-4 * scale * slope:
                a, b, value = a + scale * step_a, b + scale * step_b, candidate
                break
            scale /= 2
        else:  # the line search could not improve: this is the optimum we get
            break
    return Platt(a, b)


def scored_actions(records: Iterable[RunRecord]) -> list[tuple[str, float, bool]]:
    """`(scenario, score, unsafe)` for every action the defense put a score on."""
    return [
        (item.scenario, risk, unsafe)
        for item in records
        for risk, unsafe in zip(item.risks, item.unsafe, strict=True)
        if risk is not None
    ]


def held_out(
    actions: Sequence[tuple[str, float, bool]],
) -> tuple[list[tuple[float, float, bool]], list[Platt]]:
    """Leave-one-scenario-out: `(raw, calibrated, unsafe)` per action, and the fits used.

    Raw and calibrated come back together on purpose. Comparing an ECE computed over
    every scored action with one computed over the held-out subset compares two samples,
    not two scales, and the difference between those samples is the size of the effect
    being claimed.

    A fold whose *training* half has only one class is skipped rather than fitted: there
    is no sigmoid to learn from it, and its held-out actions go unscored instead of being
    scored by a fit that saw nothing. The fold count is returned so a comparison computed
    over fewer actions than the defense scored cannot be read as one over all of them.
    """
    scenarios = list(dict.fromkeys(scenario for scenario, _, _ in actions))
    if len(scenarios) < 2:
        return [], []
    scored: list[tuple[float, float, bool]] = []
    fits: list[Platt] = []
    for excluded in scenarios:
        training = [(score, label) for scenario, score, label in actions if scenario != excluded]
        scaler = fit([score for score, _ in training], [label for _, label in training])
        if scaler is None:
            continue
        fits.append(scaler)
        scored += [
            (score, scaler.probability(score), label)
            for scenario, score, label in actions
            if scenario == excluded
        ]
    return scored, fits


def brier(scores: Sequence[float], labels: Sequence[bool]) -> float | None:
    """Mean squared error of the probability. Bin-free, unlike ECE."""
    if not scores:
        return None
    return sum((s - label) ** 2 for s, label in zip(scores, labels, strict=True)) / len(scores)


@dataclass(frozen=True, slots=True)
class Calibration:
    """One defense's risk scale, before and after Platt scaling, on held-out actions."""

    defense: str
    #: Actions this defense scored at all. Zero for the baselines, which emit no score.
    scored_actions: int
    #: Of those, the ones a fold could score out-of-sample.
    held_out_actions: int
    folds: int
    #: The full-sample fit, reported so the scale is legible. It is *in-sample* and no
    #: number in this record was produced by it.
    a: float | None
    b: float | None
    ece: float | None
    ece_calibrated: float | None
    brier: float | None
    brier_calibrated: float | None
    #: Before and after. These need *not* be equal: each fold applies its own map, so
    #: the gap measures how far the fit travels between scenarios, not an error.
    auroc: float | None
    auroc_calibrated: float | None
    #: Folds whose fit came out increasing in risk-as-safety (`a >= 0`) — a fold that
    #: learned the score backwards. Nonzero invalidates the calibrated columns.
    inverted_folds: int

    @property
    def sound(self) -> bool:
        """Whether every fold rescaled the score rather than inverting it."""
        return self.inverted_folds == 0

    def as_dict(self) -> dict[str, object]:
        return {**asdict(self), "sound": self.sound}


def calibrate(records: Iterable[RunRecord]) -> Calibration:
    """Fit and score one defense. A defense with no score gets a row of nulls, not zeros."""
    records = list(records)
    names = {item.defense for item in records}
    if len(names) != 1:
        raise ValueError(f"calibrate() takes one defense at a time, got {sorted(names)}")
    actions = scored_actions(records)
    scored, fits = held_out(actions)
    # Every number below is over the held-out actions, raw and calibrated alike.
    held_raw = [raw for raw, _, _ in scored]
    probabilities = [probability for _, probability, _ in scored]
    held_labels = [label for _, _, label in scored]
    scaler = fit([score for _, score, _ in actions], [label for _, _, label in actions])
    return Calibration(
        defense=names.pop(),
        scored_actions=len(actions),
        held_out_actions=len(scored),
        folds=len(fits),
        a=scaler.a if scaler else None,
        b=scaler.b if scaler else None,
        ece=ece(held_raw, held_labels),
        ece_calibrated=ece(probabilities, held_labels),
        brier=brier(held_raw, held_labels),
        brier_calibrated=brier(probabilities, held_labels),
        auroc=auroc(held_raw, held_labels),
        auroc_calibrated=auroc(probabilities, held_labels),
        inverted_folds=sum(scaler.a >= 0 for scaler in fits),
    )


def by_defense(records: Iterable[RunRecord]) -> dict[str, Calibration]:
    """Calibrate every defense separately, in the order they first appear."""
    grouped: dict[str, list[RunRecord]] = {}
    for item in records:
        grouped.setdefault(item.defense, []).append(item)
    return {defense: calibrate(group) for defense, group in grouped.items()}


def _cell(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def table(calibrations: Mapping[str, Calibration]) -> str:
    """Raw versus Platt-scaled, on the held-out actions, with the fold count behind it."""
    columns = ("ECE", "ECE'", "Brier", "Brier'", "AUROC", "AUROC'", "folds", "n", "inv")
    header = f"{'defense':<22}" + "".join(f"{name:>8}" for name in columns)
    lines = [header, "-" * len(header)]
    for name, c in calibrations.items():
        cells = (
            _cell(c.ece),
            _cell(c.ece_calibrated),
            _cell(c.brier),
            _cell(c.brier_calibrated),
            _cell(c.auroc),
            _cell(c.auroc_calibrated),
            str(c.folds),
            str(c.held_out_actions),
            str(c.inverted_folds),
        )
        lines.append(f"{name:<22}" + "".join(f"{cell:>8}" for cell in cells))
    lines.append(
        "' = Platt-scaled, leave-one-scenario-out; both columns over the same actions. "
        "inv = folds that\n  fitted the score backwards, and must be 0 for the rest to mean "
        "anything."
    )
    return "\n".join(lines)
