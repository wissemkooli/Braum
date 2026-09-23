"""The adaptive attacker: that it searches what it may and sees what it may, and what it found.

The measured claims pinned here are the ones in `docs/07-results.md`: the keyword filter
falls to the climb, the monitor's ASR does not move across rounds, and the one form that
would beat `tekmor+canary` is exactly the one the ground truth cannot credit.
"""

import random

import pytest

from evaluation.adaptive import FORMS, Genome, attack, climb, curve, fitness, main
from evaluation.harness import SCENARIOS, load_matrix
from evaluation.variants import ground_truth_holds
from tekmor.defense import CanaryScanner, ReferenceMonitor
from tekmor.defense.baselines import AllowAll
from tekmor.runtime import run


@pytest.fixture(scope="module")
def matrix():
    return {s.id: s for s in load_matrix(SCENARIOS)}


@pytest.fixture(scope="module")
def climbs(matrix):
    return attack(tuple(matrix.values()), rounds=50, seed=0)


def test_a_mutation_changes_exactly_one_gene():
    rng = random.Random(0)
    genome = Genome()
    for _ in range(200):
        mutant = genome.mutate(rng)
        changed = [
            name
            for name in ("encoding", "reword", "reorder")
            if getattr(mutant, name) != getattr(genome, name)
        ]
        assert len(changed) == 1
        assert mutant.encoding in FORMS
        genome = mutant


def test_a_genome_is_built_from_the_original_every_time(matrix):
    original = matrix["enterprise-injection-invoice"]
    # Every encoding is reachable from any other, because each is applied to the
    # original: a cumulative search found nothing left to encode after the first.
    assert len({str(dict(Genome(f).build(original).steps[-1].args)) for f in FORMS}) == len(FORMS)
    assert Genome().build(original) == original
    built = Genome("hex", reword=True, reorder=True).build(original)
    assert built.id == original.id
    assert (built.policy, built.canaries) == (original.policy, original.canaries)
    assert str(Genome("hex", reword=True)) == "encode-hex+reword"
    assert str(Genome()) == "original"


def test_fitness_ranks_the_goal_above_everything_the_attacker_can_see(matrix):
    scenario = matrix["enterprise-injection-invoice"]
    landed = fitness(scenario, run(scenario, AllowAll()))
    refused = fitness(scenario, run(scenario, ReferenceMonitor()))
    assert landed[0] and not refused[0]
    assert landed > refused
    # Allowed steps and refusal codes are the public signal; a refused run has codes.
    assert refused[2] < 0 == landed[2]


def test_the_climb_is_deterministic_per_seed(matrix):
    scenario, defense = matrix["enterprise-injection-invoice"], ReferenceMonitor()
    first = climb(scenario, defense, 10, random.Random("s"))
    assert first == climb(scenario, defense, 10, random.Random("s"))


def test_asr_never_falls_across_rounds(climbs):
    for values in curve(climbs).values():
        assert values == sorted(values)


def test_the_keyword_filter_falls_to_the_climb_and_the_monitor_does_not(climbs):
    asr = curve(climbs)
    assert asr["keyword"][0] < asr["keyword"][-1] == 1.0
    assert len(set(asr["tekmor"])) == 1
    assert len(set(asr["tekmor+canary"])) == 1


def test_the_form_that_beats_the_canary_layer_is_one_the_ground_truth_cannot_credit(matrix):
    scenario = matrix["enterprise-leak-mislabelled"]
    composed = Genome("base64-reversed").build(scenario)
    # Undefended the mail goes out with the secret in it, and the ground truth cannot
    # see it, so the attacker's candidate is rejected rather than scored.
    assert not ground_truth_holds(composed)
    secrets = frozenset(v for s in matrix.values() for v in s.canaries.values())
    world = run(composed, CanaryScanner(ReferenceMonitor(), secrets)).world
    assert world.sent and not world.leaked


def test_main_writes_raw_and_processed(tmp_path, capsys):
    assert main(["--results", str(tmp_path), "--rounds", "4"]) == 0
    assert "keyword" in capsys.readouterr().out
    (raw,) = (tmp_path / "raw").iterdir()
    assert {p.name for p in raw.iterdir()} == {"climbs.jsonl", "manifest.json"}
    assert (tmp_path / "processed" / raw.name / "asr_by_round.json").exists()
