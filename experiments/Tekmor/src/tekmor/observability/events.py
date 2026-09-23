"""Append-only JSONL event log.

One line per mediated action. `docs/10-research-report.md` Part V lists the full event
schema; this carries the fields that exist in the current implementation. Fields are
added as the components that produce them land — an event never claims a signal the
decision did not use.

The *aggregate* risk score is logged and the per-signal contributions are not. The
schema asks for both, and the breakdown is the half that is a hill-climbing channel
(`docs/03-architecture.md` §3.7), so it stays derivable from the signals rather than written next
to a verdict an attacker may get to see. `defense.risk.contributions` computes it.

Argument *values* are never written, and the rule holds whether or not a value is a
known secret: redacting against the canary registry would protect the values someone
remembered to register and no others, and a trace is not the place to find out which
those were. Argument names are enough to reconstruct which call was decided on. The same
rule is why `outcome` is one of three words rather than the tool's result or its error
message: a result is exactly the content that may carry a secret.

**Sources are logged individually, with their labels.** The meet (`integrity`) is what
the decision was computed from and is kept, but a trace that carried only the meet could
not say *which* influence dragged it down, which is the question the provenance graph
exists to answer (`viewer.py`) and the one "never silently discard provenance" is about.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from tekmor.defense.core import Action, ActionProvenance, Decision
from tekmor.policy.core import Policy
from tekmor.provenance.taint import ArgumentOrigin
from tekmor.provenance.trust import Source, TrustLevel

#: Bumped by any change that an existing reader could misread. 1 was the first schema;
#: 2 replaced `source_ids` with labelled `sources` and added `outcome`; 3 added
#: `endorsed_by` to each source, because `integrity` can now be above the meet of the
#: `trust` labels and a reader who did not know why would misread the decision; 4 added
#: `arguments`, the sources each argument value was traced to, because under
#: argument-level Trusted-Action the meet of all sources is no longer what was judged.
SCHEMA_VERSION = 4

#: What the gateway did with the decided action. Three words, no free text: "the tool
#: ran", "nothing ran", "the tool ran and raised". The message is the caller's content.
Outcome = Literal["executed", "not_executed", "failed"]


@dataclass(frozen=True, slots=True)
class DecisionEvent:
    """What one `Defense.decide` call saw and answered, and what became of the action."""

    run_id: str
    step: int
    defense: str
    tool: str
    arg_names: tuple[str, ...]
    #: Every observation that influenced the action, with the labels it carried.
    sources: tuple[Source, ...]
    #: The meet of those labels: what Trusted-Action was judged against.
    integrity: TrustLevel
    confidential: bool
    policy: str
    policy_version: int
    verdict: str
    reason_codes: tuple[str, ...]
    #: The aggregate risk score, or None for a defense that emits no score. Null and
    #: 0.0 are different claims and the log keeps them apart.
    risk: float | None
    rewritten_tool: str | None
    timestamp: str
    #: What the gateway did. "unknown" is not a value: a decision nobody executed is
    #: `not_executed`, and a decision logged outside a run has no event here at all.
    outcome: Outcome
    #: Per argument, per value, the ids of the sources it was traced to (`[]` is an
    #: untraced value). Ids only, never the values: those may be secrets.
    arguments: tuple[ArgumentOrigin, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "step": self.step,
            "defense": self.defense,
            "tool": self.tool,
            "arg_names": list(self.arg_names),
            "sources": [
                {
                    "id": source.id,
                    "trust": source.trust.name,
                    "origin": source.origin,
                    "confidential": source.confidential,
                    "endorsed_by": source.endorsed_by,
                }
                for source in self.sources
            ],
            "integrity": self.integrity.name,
            "confidential": self.confidential,
            "policy": self.policy,
            "policy_version": self.policy_version,
            "verdict": self.verdict,
            "reason_codes": list(self.reason_codes),
            "risk": self.risk,
            "rewritten_tool": self.rewritten_tool,
            "outcome": self.outcome,
            "arguments": {
                origin.name: [[source.id for source in value] for value in origin.values]
                for origin in self.arguments
            },
            "timestamp": self.timestamp,
        }


def decision_event(
    run_id: str,
    step: int,
    defense: str,
    action: Action,
    provenance: ActionProvenance,
    policy: Policy,
    decision: Decision,
    outcome: Outcome,
) -> DecisionEvent:
    """Build the event for one decided-and-executed step from the objects at hand."""
    return DecisionEvent(
        run_id=run_id,
        step=step,
        defense=defense,
        tool=action.tool,
        arg_names=tuple(action.args),
        sources=provenance.sources,
        arguments=provenance.arguments,
        integrity=provenance.integrity,
        confidential=provenance.confidential,
        # The policy a decision was computed under is part of the decision: a trace
        # without it cannot be replayed, because the rules may have moved since.
        policy=policy.name,
        policy_version=policy.version,
        verdict=decision.verdict.value,
        reason_codes=decision.reason_codes,
        risk=decision.risk,
        rewritten_tool=decision.rewritten.tool if decision.rewritten else None,
        outcome=outcome,
        timestamp=datetime.now(UTC).isoformat(),
    )


class EventLog:
    """Append-only JSONL file. Opened per write, so a crash keeps what was already logged."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: DecisionEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")


def read(path: str | Path) -> list[dict]:
    """Every event in a log file, in the order it was written.

    A dict rather than a `DecisionEvent`: a reader's job is to render what an older
    writer produced, and rejecting a line because a field moved is the opposite of what
    an append-only trace is for. `schema_version` says which shape to expect.
    """
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]
