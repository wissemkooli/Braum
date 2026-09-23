"""runtime → defense → gateway → log, end to end on the scripted adapter."""

import json
from dataclasses import dataclass, replace

from tekmor.defense import Action, ActionProvenance, AgentState, Decision, Verdict
from tekmor.defense.baselines import AllowAll, DenySensitive
from tekmor.observability import EventLog
from tekmor.policy import Policy
from tekmor.runtime import run


@dataclass(frozen=True)
class Fixed:
    """A defense that returns the same verdict, for testing the loop around it."""

    decision: Decision
    name: str = "fixed"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        return self.decision


def test_allowed_run_completes_the_task(benign_scenario):
    result = run(benign_scenario, AllowAll())
    assert [outcome.decision.verdict for outcome in result.steps] == [Verdict.ALLOW] * 2
    assert result.world.sent[0]["to"] == "ap@northwind.example"


def test_blocked_action_never_reaches_the_world(benign_scenario):
    result = run(benign_scenario, DenySensitive())
    assert result.steps[-1].executed is None
    assert result.world.sent == []


def test_escalation_denies_by_default_and_executes_on_approval(benign_scenario):
    escalate = Fixed(Decision(Verdict.ESCALATE, ("TEST",)))
    assert run(benign_scenario, escalate).world.sent == []
    approved = run(benign_scenario, escalate, approver=lambda action: True)
    assert all(outcome.executed is not None for outcome in approved.steps)
    assert len(approved.world.sent) == 1


def test_rewrite_executes_the_rewritten_action(benign_scenario):
    draft = Action("draft_email", {"to": "vendor@example.com", "body": "confirmed"})
    result = run(benign_scenario, Fixed(Decision(Verdict.REWRITE, ("TEST",), rewritten=draft)))
    assert result.world.sent == []
    assert result.world.drafts == [dict(draft.args)] * len(benign_scenario.steps)


def test_a_failing_tool_call_is_an_outcome_not_a_crashed_run(benign_scenario):
    missing = Action("read_document", {"id": "no-such-document"})
    result = run(benign_scenario, Fixed(Decision(Verdict.REWRITE, ("TEST",), rewritten=missing)))
    assert result.steps[0].result is None
    assert "no-such-document" in result.steps[0].error


def test_every_decision_is_logged(benign_scenario, tmp_path):
    log = EventLog(tmp_path / "events.jsonl")
    result = run(benign_scenario, DenySensitive(), log=log)

    events = [json.loads(line) for line in log.path.read_text().splitlines()]
    assert [event["verdict"] for event in events] == ["allow", "block"]
    assert [event["step"] for event in events] == [0, 1]
    assert all(event["run_id"] == result.run_id for event in events)
    assert events[1]["reason_codes"] == ["TARGET_TOOL_SENSITIVE"]
    assert events[1]["integrity"] == "TRUSTED_INTERNAL"


def test_a_broken_defense_fails_closed_through_the_runner(benign_scenario):
    @dataclass(frozen=True)
    class Broken:
        name: str = "broken"

        def decide(self, state, action, provenance, policy):
            raise RuntimeError("boom")

    result = run(benign_scenario, Broken())
    assert all(outcome.decision.verdict is Verdict.BLOCK for outcome in result.steps)
    assert result.world.sent == [] and result.world.documents


def test_run_id_is_deterministic_for_a_scenario_and_defense(benign_scenario):
    assert run(benign_scenario, AllowAll()).run_id == run(benign_scenario, AllowAll()).run_id


def source_ids(log):
    return [
        [source["id"] for source in json.loads(line)["sources"]]
        for line in log.path.read_text().splitlines()
    ]


def test_provenance_is_computed_from_what_the_agent_read(attack_scenario, tmp_path):
    # The whole point of taint propagation: nothing declares these labels, the run works
    # them out from the reads it performed. The first action has only the request that
    # asked for it; each later one carries everything read before it.
    log = EventLog(tmp_path / "events.jsonl")
    run(attack_scenario, AllowAll(), log=log)

    assert source_ids(log) == [
        ["user:request"],
        ["user:request", "doc:INV-91"],
        ["user:request", "doc:INV-91", "secret:portal_token"],
    ]


def test_an_action_that_never_executed_taints_nothing(attack_scenario, tmp_path):
    # A read the monitor refused is a read the agent never saw, so it cannot have
    # influenced anything. Tainting it anyway would punish the agent for a call that was
    # stopped — over-tainting, produced by the defense's own verdict.
    blocks_the_read = replace(
        attack_scenario,
        policy=replace(attack_scenario.policy, sensitive_tools=frozenset({"read_document"})),
    )
    log = EventLog(tmp_path / "events.jsonl")
    run(blocks_the_read, DenySensitive(), log=log)

    assert all("doc:INV-91" not in ids for ids in source_ids(log))
    assert source_ids(log)[-1] == ["user:request", "secret:portal_token"]
