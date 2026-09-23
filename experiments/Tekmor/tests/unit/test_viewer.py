"""The timeline and provenance viewer: what it shows, and what it must not execute.

The viewer renders a trace an analyst reads after an attack. Its inputs — tool names,
source ids, origins — are derived from content the threat model calls adversary-
controlled, so the page it writes is a trust boundary and the escaping below is a
security test, not a formatting one.
"""

import json

from tekmor.defense import Action, ActionProvenance, Decision, Source, Verdict
from tekmor.observability import EventLog, decision_event, read, render
from tekmor.observability.viewer import by_run, graph, sources_of, timeline
from tekmor.policy import Policy
from tekmor.provenance import TrustLevel

USER = Source("user:request", TrustLevel.AUTHENTICATED_USER, origin="user")
HOSTILE = Source("doc:INV-91", TrustLevel.ADVERSARY_CONTROLLED, origin="read_document")
SECRET = Source(
    "secret:token", TrustLevel.TRUSTED_INTERNAL, origin="read_secret", confidential=True
)
POLICY = Policy("enterprise", version=2)


def event(step, tool, sources, decision, outcome):
    return decision_event(
        "run-1",
        step,
        "tekmor",
        Action(tool=tool),
        ActionProvenance.of(sources),
        POLICY,
        decision,
        outcome,
    ).as_dict()


ALLOWED = event(
    0, "read_document", [USER], Decision(Verdict.ALLOW, ("TOOL_PERMITTED",), risk=0.0), "executed"
)
BLOCKED = event(
    1,
    "send_email",
    [USER, HOSTILE, SECRET],
    Decision(Verdict.BLOCK, ("CONFIDENTIAL_INFLUENCE",), risk=0.9),
    "not_executed",
)


def test_the_page_shows_the_whole_chain_for_one_action():
    page = timeline([BLOCKED])

    # observation + trust -> action -> policy -> decision -> outcome, all from the log.
    for shown in (
        "doc:INV-91",
        "ADVERSARY_CONTROLLED",
        "send_email",
        "enterprise@2",
        "block",
        "CONFIDENTIAL_INFLUENCE",
        "0.90",
        "not_executed",
    ):
        assert shown in page


def test_the_graph_cuts_the_edge_into_an_action_that_never_ran():
    # The picture the technical doc asks for: hostile data flowing toward a sensitive
    # call, and the edge cut where the decision stopped it. A dashed edge is that cut.
    assert "stroke-dasharray" in graph([BLOCKED])
    assert "stroke-dasharray" not in graph([ALLOWED])


def test_an_edge_is_coloured_by_its_own_source_not_by_the_meet():
    # Three sources, three colours: the whole point of logging them individually is that
    # the one adversary-controlled read among trusted ones is visible as the edge it is.
    drawn = graph([BLOCKED])
    assert drawn.count("#b3261e") >= 1 and "#2e7d32" in drawn and "#2a6f97" in drawn


def test_markup_in_a_source_id_is_escaped_rather_than_rendered():
    # A source id comes from content the attacker may control. An injected tag here
    # would run in the analyst's browser, on the page they opened to read the attack.
    injected = Source("<script>alert(1)</script>", TrustLevel.ADVERSARY_CONTROLLED)
    hostile = event(
        0,
        "<img onerror=x>",
        [injected],
        Decision(Verdict.BLOCK, ("<b>",), risk=0.5),
        "not_executed",
    )
    page = render([hostile])

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page and "&lt;img onerror=x&gt;" in page


def test_a_defense_with_no_score_is_shown_as_unknown_not_as_zero():
    unscored = event(0, "send_email", [USER], Decision(Verdict.ALLOW, ("ALLOW_ALL",)), "executed")
    assert "n/a" in timeline([unscored])
    assert "0.00" in timeline([ALLOWED])


def test_a_schema_1_event_reads_as_unknown_trust_rather_than_invented_trust():
    # The reason the schema is versioned: an older log recorded ids without labels, and
    # a reader that picked a level for them would be inventing provenance.
    old = {"run_id": "r", "step": 0, "source_ids": ["doc:1"], "verdict": "allow"}
    assert sources_of(old) == [
        {"id": "doc:1", "trust": "UNKNOWN", "origin": "", "confidential": False}
    ]


def test_runs_are_grouped_and_kept_in_the_order_the_log_wrote_them(tmp_path):
    log = EventLog(tmp_path / "decisions.jsonl")
    for raw in (ALLOWED, BLOCKED):
        log.path.write_text(log.path.read_text() if log.path.exists() else "", encoding="utf-8")
        with log.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(raw) + "\n")

    runs = by_run(read(log.path))
    assert list(runs) == ["run-1"]
    assert [step["step"] for step in runs["run-1"]] == [0, 1]
    # The page says what it is a view of, and never claims to know whether it was right.
    assert "ground truth" in render(read(log.path))


def test_the_graph_is_well_formed_svg_with_its_tooltips_on_their_nodes():
    # A malformed fragment is dropped by the browser without an error, so the graph
    # simply is not there — exactly the failure a page nobody parses would hide.
    import xml.etree.ElementTree as ET

    root = ET.fromstring(graph([ALLOWED, BLOCKED]))

    # A <title> directly under <svg> names the whole image rather than the node it was
    # written for, which silently replaces the graph's own label.
    assert [child for child in root if child.tag.endswith("title")] == []
    assert [child.tag.split("}")[-1] for child in root].count("circle") == 3
