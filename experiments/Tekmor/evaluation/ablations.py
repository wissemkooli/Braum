"""Ablations: the monitor again, with one of its inputs taken away each time.

    uv run python -m evaluation.ablations

`docs/10-research-report.md` Part VI and Part XIII, Phase 4: no provenance, no trust
propagation, no rewrite, rules only, full system. An ablation is the only honest way to
claim a mechanism contributes anything: the difference between two rows of the same
matrix is what that mechanism bought, and a mechanism whose row does not move bought
nothing *that this matrix can see*.

**Each ablation removes an input, not a line of code.** `Ablation` wraps the monitor and
changes what it is handed — the provenance set or the policy — and nothing else, so the
rules, their order and the risk score are the same object in every row. A variant of the
monitor with a branch deleted would be a second implementation, and a difference between
two implementations says nothing about which *input* mattered.

- `no-provenance`: the monitor is told only that the user asked. Every action looks
  user-driven and nothing looks confidential, so what is left is least privilege.
- `no-propagation`: the monitor is told the user's request and the *latest* observation,
  and nothing earlier. That is taint without memory: an influence counts only while it is
  the thing the agent just read. Expected to break memory poisoning and compositional
  attacks (Proposal A, *Evaluation*), which is why it is the cleanest ablation.
- `no-rewrite`: the policy's capability lattice is emptied, so a Trusted-Action
  violation escalates to the simulated human (who denies) instead of being downgraded.
- `rules-only` is `tekmor` and `full` is `tekmor+canary`, as the harness already runs
  them; their names are kept so every table in the repository means the same thing.

Nothing here reads a scenario. The ablations are built before any run, from the same
secret registry the harness uses, and see only what `run()` hands a defense.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from evaluation.harness import RESULTS, SCENARIOS, digest, evaluate, load_matrix, manifest
from evaluation.metrics import by_defense, calibration, grid, table
from tekmor.defense import (
    Action,
    ActionProvenance,
    AgentState,
    CanaryScanner,
    Decision,
    Defense,
    ReferenceMonitor,
    mediate,
)
from tekmor.policy.core import Policy
from tekmor.provenance.taint import USER_REQUEST

#: What the ablated defense is shown instead of the real input.
View = Callable[[ActionProvenance, Policy], tuple[ActionProvenance, Policy]]


def _no_provenance(provenance: ActionProvenance, policy: Policy) -> tuple[ActionProvenance, Policy]:
    return ActionProvenance.of([USER_REQUEST]), policy


def _no_propagation(
    provenance: ActionProvenance, policy: Policy
) -> tuple[ActionProvenance, Policy]:
    # ponytail: "latest" is the last *new* source, because the tracker deduplicates — an
    # agent that re-reads an earlier document is labelled by the last first read. Exact
    # recency needs the runner to hand over the observation sequence, for one ablation.
    return ActionProvenance.of(dict.fromkeys((USER_REQUEST, *provenance.sources[-1:]))), policy


def _no_rewrite(provenance: ActionProvenance, policy: Policy) -> tuple[ActionProvenance, Policy]:
    return provenance, replace(policy, rewrites={})


VIEWS: dict[str, View] = {
    "provenance": _no_provenance,
    "propagation": _no_propagation,
    "rewrite": _no_rewrite,
}


@dataclass(frozen=True, slots=True)
class Ablation:
    """`inner`, deciding from a view of its input with one mechanism's input removed."""

    inner: Defense
    ablated: str

    @property
    def name(self) -> str:
        return f"{self.inner.name}-no-{self.ablated}"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        provenance, policy = VIEWS[self.ablated](provenance, policy)
        # Through `mediate`, so an ablated monitor fails closed exactly as the real one.
        return mediate(self.inner, state, action, provenance, policy)


def defenses(secrets: frozenset[str]) -> tuple[Defense, ...]:
    """The ablations first, then rules-only and the full system they are read against."""
    monitor = ReferenceMonitor()
    return (
        *(Ablation(monitor, name) for name in VIEWS),
        monitor,
        CanaryScanner(monitor, secrets),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", type=Path, default=SCENARIOS)
    parser.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args(argv)

    scenarios = load_matrix(args.scenarios)
    records = evaluate(scenarios, build=defenses)
    metrics = by_defense(records)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    raw = args.results / "raw" / f"{stamp}-ablations"
    processed = args.results / "processed" / f"{stamp}-ablations"
    raw.mkdir(parents=True, exist_ok=True)
    processed.mkdir(parents=True, exist_ok=True)
    (raw / "runs.jsonl").write_text(
        "".join(json.dumps(item.as_dict(), sort_keys=True) + "\n" for item in records),
        encoding="utf-8",
    )
    (raw / "manifest.json").write_text(
        json.dumps(
            {
                **manifest(scenarios, list(metrics), args.scenarios),
                "inputs": digest(args.scenarios),
                "ablations": list(VIEWS),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (processed / "metrics.json").write_text(
        json.dumps({name: m.as_dict() for name, m in metrics.items()}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    print(table(metrics))
    print()
    print(calibration(metrics))
    print()
    print(grid(records))
    print(f"\n{len(records)} runs -> {raw}\n            -> {processed / 'metrics.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
