"""Scenario fixtures shared by the runtime, security, and simulator tests.

The scenarios are the evaluated matrix in `evaluation/scenarios/`, not a private copy:
the tests that assert a verdict and the harness that scores it must be looking at the
same files, or a scenario can drift out from under one of them (`docs/07-results.md`).
"""

from pathlib import Path

import pytest

from tekmor.simulator import load_scenario

SCENARIOS = Path(__file__).parent.parent / "evaluation" / "scenarios"


@pytest.fixture
def scenario():
    """Load a fixture scenario by file name, JSON or YAML."""
    return lambda name: load_scenario(SCENARIOS / name)


@pytest.fixture
def benign_scenario():
    """Legitimate work that ends in a sensitive outbound call: the hard negative."""
    return load_scenario(SCENARIOS / "enterprise_benign_invoice.json")


@pytest.fixture
def attack_scenario():
    """An injected invoice that drives a canary into an outbound email."""
    return load_scenario(SCENARIOS / "enterprise_injection_invoice.json")
