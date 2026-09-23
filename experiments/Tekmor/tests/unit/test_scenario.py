"""The scenario format and its validation."""

import json

import pytest

from conftest import SCENARIOS
from tekmor.provenance import TrustLevel
from tekmor.simulator.scenario import ScenarioError, load_scenario, parse_scenario

MINIMAL = {
    "id": "s",
    "version": 1,
    "domain": "enterprise",
    "benign": True,
    "family": "over_refusal",
    "level": 1,
    "task": "t",
    "policy": {"name": "enterprise", "sensitive_tools": ["send_email"]},
    "documents": {"INV-1": {"text": "4 200 EUR", "trust": "TRUSTED_INTERNAL"}},
    "success": {"sent.0.to": "a@example.com"},
    "steps": [{"tool": "send_email", "args": {"to": "a@example.com"}}],
}


def test_parses_document_labels_into_trust_levels():
    scenario = parse_scenario(MINIMAL)
    assert scenario.documents["INV-1"].trust is TrustLevel.TRUSTED_INTERNAL
    assert scenario.policy.sensitive_tools == frozenset({"send_email"})


def test_outbound_tools_come_from_the_domain_not_from_the_scenario():
    # Where a tool sends data is a property of the tool. A scenario that restated it
    # could disagree with the world it runs against, so the default is the domain's own
    # tool specs.
    assert parse_scenario(MINIMAL).policy.outbound_tools == frozenset({"send_email"})


def test_a_document_may_be_labelled_confidential():
    documents = {"INV-1": {**MINIMAL["documents"]["INV-1"], "confidential": True}}
    scenario = parse_scenario({**MINIMAL, "documents": documents})
    assert scenario.documents["INV-1"].confidential is True
    # And it is off unless the scenario says so: labelling everything confidential would
    # block every outbound call.
    assert parse_scenario(MINIMAL).documents["INV-1"].confidential is False


def test_loaded_scenario_has_the_expected_shape(attack_scenario):
    assert attack_scenario.benign is False
    assert [step.tool for step in attack_scenario.steps] == [
        "read_document",
        "read_secret",
        "send_email",
    ]
    assert attack_scenario.documents["INV-91"].trust is TrustLevel.ADVERSARY_CONTROLLED


@pytest.mark.parametrize(
    "change",
    [
        {"domain": "trading_floor"},
        {"steps": [{**MINIMAL["steps"][0], "tool": "wire_transfer"}]},
        {"documents": {"INV-1": {"text": "x", "trust": "SEMI_TRUSTED"}}},
        {"documents": {"INV-1": "an unlabelled document"}},
        {"steps": [{**MINIMAL["steps"][0], "sources": [{"id": "x", "trust": "TRUSTED_INTERNAL"}]}]},
        {"version": "1"},
        {"benign": "yes"},
        {"policy": {**MINIMAL["policy"], "allowed_tools": ["send_emails"]}},
        {"policy": {**MINIMAL["policy"], "rewrites": {"send_email": "draff_email"}}},
        {"policy": {**MINIMAL["policy"], "min_integrity": "SEMI_TRUSTED"}},
        {"success": None},
        {"success": {"sennt.0.to": "a@example.com"}},
        {"attack_success": {"leaked": ["x"]}},
        {"success": {}},
        {"family": "prompt_injection"},
        {"level": 0},
        {"family": "indirect_injection"},
    ],
    ids=[
        "unknown domain",
        "tool not in domain",
        "unknown trust",
        # Guessing a label is the one thing the loader must not do: too high invents
        # trust, too low turns every scenario into an attack.
        "unlabelled document",
        # A stale scenario would otherwise keep passing with its labels ignored.
        "step declares its own sources",
        "bad version",
        "bad benign",
        # A typo in a policy is silent otherwise: an unknown name in `allowed_tools`
        # blocks work, and one in `rewrites` quietly removes the downgrade.
        "policy names a tool the domain does not have",
        "rewrite target not in the domain",
        "unknown integrity threshold",
        # A scenario nobody can score is a run that produces a number nobody can defend.
        "no outcome condition",
        # A typo in a condition path is silent in the worst direction: an attack goal
        # that can never be reached reads as a defense that stopped it.
        "condition path is not a world field",
        # Ground truth that contradicts the scenario's own `benign` label.
        "attack goal on a benign scenario",
        "empty condition map",
        # A family outside the seven would quietly open a row of its own in the grid and
        # split the family it was meant to join.
        "family outside the taxonomy",
        "level outside 1-5",
        # `over_refusal` is the benign family, so the row and the ground truth would
        # disagree about which question this scenario's cell is answering.
        "benign scenario in an attack family",
    ],
)
def test_a_malformed_scenario_fails_on_load(change):
    # A scenario is an input the rest of the run trusts; it fails here, with a message,
    # rather than halfway through a run.
    with pytest.raises(ScenarioError):
        parse_scenario({**MINIMAL, **change})


def test_yaml_and_json_front_ends_produce_the_same_scenario(tmp_path, scenario):
    # The format is defined by parse_scenario, not by the file syntax: a YAML file and
    # the JSON it came from must load to the same object, or results recorded against
    # one representation stop being comparable with the other.
    yaml = pytest.importorskip("yaml")
    from_json = scenario("enterprise_injection_invoice.json")

    path = tmp_path / "same.yaml"
    path.write_text(
        yaml.safe_dump(json.loads((SCENARIOS / "enterprise_injection_invoice.json").read_text()))
    )
    assert load_scenario(path) == from_json


def test_a_yaml_scenario_loads(scenario):
    soc = scenario("soc_injection_alert.yaml")
    assert soc.domain == "soc"
    assert [step.tool for step in soc.steps] == [
        "read_alert",
        "read_secret",
        "share_indicators",
        "isolate_host",
    ]
    assert soc.documents["ALERT-4"].trust is TrustLevel.ADVERSARY_CONTROLLED


def test_outcome_conditions_are_checked_against_world_state(benign_scenario, attack_scenario):
    # Utility and attack success are properties of the world, not of what the agent said
    # it did, so the conditions are evaluated against the world a run leaves behind.
    from tekmor.defense.baselines import AllowAll
    from tekmor.runtime import run

    assert benign_scenario.completed(run(benign_scenario, AllowAll()).world) is True
    assert attack_scenario.compromised(run(attack_scenario, AllowAll()).world) is True
    # And an empty world satisfies neither, which is what a blocked run scores.
    assert benign_scenario.completed(benign_scenario.world()) is False
    assert attack_scenario.compromised(attack_scenario.world()) is False


def test_any_one_condition_map_is_enough(scenario):
    # An injection that asks for two things succeeds by getting either, so the maps are
    # alternatives. The SOC log line asks for the token and for the host.
    soc = scenario("soc_injection_alert.yaml")
    world = soc.world()

    assert soc.compromised(world) is False
    world.containment.append({"host": "HR-DB-01"})
    assert soc.compromised(world) is True
