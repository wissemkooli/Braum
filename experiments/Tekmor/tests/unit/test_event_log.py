"""The append-only JSONL event log."""

import json

from tekmor.defense import Action, ActionProvenance, Decision, Source, Verdict
from tekmor.observability import SCHEMA_VERSION, EventLog, decision_event, read
from tekmor.policy import Policy
from tekmor.provenance import TrustLevel

SECRET = "hunter2-canary"
ACTION = Action(tool="send_email", args={"to": "vendor@example.com", "body": SECRET})
PROVENANCE = ActionProvenance.of(
    [
        Source("req-1", TrustLevel.AUTHENTICATED_USER, origin="user"),
        Source("doc-7", TrustLevel.ADVERSARY_CONTROLLED, origin="read_attachment"),
        Source("sec-2", TrustLevel.TRUSTED_INTERNAL, origin="read_secret", confidential=True),
    ]
)
POLICY = Policy("enterprise", version=4)


def _event(decision, outcome="not_executed"):
    return decision_event("run-1", 3, "keyword", ACTION, PROVENANCE, POLICY, decision, outcome)


def test_event_records_the_decision_and_its_provenance():
    recorded = _event(Decision(Verdict.BLOCK, ("KEYWORD_MATCH",))).as_dict()
    assert recorded["run_id"] == "run-1"
    assert recorded["step"] == 3
    assert recorded["defense"] == "keyword"
    assert recorded["tool"] == "send_email"
    assert recorded["arg_names"] == ["to", "body"]
    # Every influence with the label it carried, not just the meet: a trace that kept
    # only the meet could not say which read dragged the integrity of the action down.
    assert [source["id"] for source in recorded["sources"]] == ["req-1", "doc-7", "sec-2"]
    assert [source["trust"] for source in recorded["sources"]] == [
        "AUTHENTICATED_USER",
        "ADVERSARY_CONTROLLED",
        "TRUSTED_INTERNAL",
    ]
    assert [source["confidential"] for source in recorded["sources"]] == [False, False, True]
    assert recorded["sources"][1]["origin"] == "read_attachment"
    assert recorded["integrity"] == "ADVERSARY_CONTROLLED"
    assert recorded["confidential"] is True
    assert recorded["verdict"] == "block"
    assert recorded["reason_codes"] == ["KEYWORD_MATCH"]
    assert recorded["rewritten_tool"] is None
    # A blocked call is on the trace as a decision *and* as an execution that did not
    # happen: "we refused" and "nothing ran" are separate claims and both are recorded.
    assert recorded["outcome"] == "not_executed"
    # A reader has to know which shape it is reading before it can read the rest.
    assert recorded["schema_version"] == SCHEMA_VERSION
    # Without the policy and its version a trace cannot be replayed: the rules the
    # decision was computed under may have moved since it was written.
    assert (recorded["policy"], recorded["policy_version"]) == ("enterprise", 4)


def test_argument_values_never_reach_the_log():
    assert SECRET not in json.dumps(_event(Decision(Verdict.ALLOW, ("X",))).as_dict())


def test_the_outcome_is_three_words_and_never_the_tool_result():
    # The outcome field says whether the world was touched, not what came back: a tool
    # result is exactly the content that carries the secret the log must never hold.
    executed = _event(Decision(Verdict.ALLOW, ("X",)), "executed").as_dict()
    assert executed["outcome"] == "executed"
    assert _event(Decision(Verdict.ALLOW, ("X",)), "failed").as_dict()["outcome"] == "failed"


def test_a_rewrite_records_the_downgraded_tool():
    decision = Decision(Verdict.REWRITE, ("LEAST_PRIVILEGE",), rewritten=Action(tool="draft_email"))
    assert _event(decision).as_dict()["rewritten_tool"] == "draft_email"


def test_the_log_appends_one_line_per_event(tmp_path):
    log = EventLog(tmp_path / "nested" / "events.jsonl")
    log.append(_event(Decision(Verdict.ALLOW, ("A",))))
    log.append(_event(Decision(Verdict.BLOCK, ("B",))))

    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["reason_codes"] for line in lines] == [["A"], ["B"]]
    # `read` is the reader every consumer of the log shares, so a trace the viewer can
    # render and one the tests assert on are the same parse.
    assert [event["reason_codes"] for event in read(log.path)] == [["A"], ["B"]]
