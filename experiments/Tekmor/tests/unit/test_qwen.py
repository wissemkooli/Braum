"""The Qwen3-8B adapter's parsing. The model itself is a `slow` test.

The slow test loads `$TEKMOR_QWEN_MODEL` if it is set, so the adapter can be exercised
on a small Qwen3 (`Qwen/Qwen3-0.6B` runs on CPU) without pulling 16 GB of weights onto a
machine that cannot hold them. The prompt and the parsing are the same either way; the
actions a 0.6B model proposes are not evidence about Qwen3-8B.
"""

import os

import pytest

from tekmor.defense import Action, AgentState
from tekmor.runtime.qwen import Qwen3Adapter, parse_proposal


def test_a_tool_call_is_parsed_out_of_surrounding_prose():
    text = 'Sure, I will read it.\n```json\n{"tool": "read_document", "args": {"id": "INV-1"}}\n```'
    assert parse_proposal(text) == Action("read_document", {"id": "INV-1"})


@pytest.mark.parametrize(
    "text",
    ['{"done": true}', "I am finished.", '{"tool": 7}', "{not json at all"],
    ids=["done", "prose", "bad tool", "broken json"],
)
def test_anything_that_is_not_a_tool_call_ends_the_run(text):
    # Ending the run is the safe reading of an unparseable answer: a guessed tool call
    # would be an action nobody proposed.
    assert parse_proposal(text) is None


@pytest.mark.slow
def test_the_adapter_proposes_an_action_with_a_real_model():
    pytest.importorskip("transformers")
    adapter = Qwen3Adapter(
        tools=("read_document", "send_email", "draft_email"),
        model_id=os.environ.get("TEKMOR_QWEN_MODEL", "Qwen/Qwen3-8B"),
    )
    action = adapter.propose(AgentState(task="Read invoice INV-1.", step=0), ())
    # The adapter proposes an action and nothing else: provenance is the runner's.
    assert action is None or action.tool in adapter.tools
