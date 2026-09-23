"""The evaluation harness: every scenario against every defense, scored and recorded.

    uv run python -m evaluation.harness

`docs/10-research-report.md` Part VI. This is the first thing in the repository that produces
a *number*; everything before it produced behaviour. What it does is small on purpose —
load the scenario matrix, run each scenario under each defense through the ordinary
`tekmor.runtime.run`, score the finished worlds with `evaluation.metrics`, and write the
run down well enough that someone else can reproduce it.

**Raw is write-once.** Each invocation gets its own directory under `results/raw/`
(decision events, per-run records, and the manifest that says how they were produced),
and the aggregate lands under `results/processed/`. Analysis never edits raw output; it
reads it and writes somewhere else (`docs/06-evaluation-methodology.md`).

**Nothing the scorer knows reaches a defense.** The defenses are constructed here from
the scenario files' *canary values* and nothing else — that registry is the organization's
own list of secrets, the DLP analogue, and is a deployment input rather than scenario
metadata (`src/defense/canary.py`). Scenario ids, `benign`, and the outcome conditions
stay on this side of the boundary; `run()` hands a defense only state, action, provenance
and policy.

**The runs are deterministic**, so the numbers are reproducible without a seed: the
scripted adapter replays the scenario's steps, the worlds are rebuilt per run, and the
simulated human denies every escalation. A model-driven run is not deterministic and will
need its seed and decoding parameters recorded in the manifest; the field is there and
says `scripted` today.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from evaluation.calibration import by_defense as calibrate_by_defense
from evaluation.calibration import table as calibration_table
from evaluation.metrics import RunRecord, by_defense, calibration, grid, record, table
from tekmor import __version__
from tekmor.defense import CanaryScanner, Defense, ReferenceMonitor
from tekmor.defense.baselines import AllowAll, DenySensitive, KeywordFilter
from tekmor.observability import EventLog, read, render
from tekmor.runtime import run
from tekmor.simulator import load_scenario
from tekmor.simulator.scenario import Scenario

REPO = Path(__file__).resolve().parent.parent
SCENARIOS = REPO / "evaluation" / "scenarios"
RESULTS = REPO / "evaluation" / "results"


def defenses(secrets: frozenset[str]) -> tuple[Defense, ...]:
    """The defenses under test, baselines first.

    The three baselines bracket the space (`src/defense/baselines.py`), `tekmor` is the
    deterministic core, and `tekmor+canary` adds the argument scan. The last two are one
    ablation pair already: the difference between their rows is exactly what CANARY-FLOW
    contributes, which is the only honest way to claim it contributes anything.
    """
    monitor = ReferenceMonitor()
    return (
        AllowAll(),
        DenySensitive(),
        KeywordFilter(),
        monitor,
        CanaryScanner(monitor, secrets),
    )


def load_matrix(directory: Path) -> tuple[Scenario, ...]:
    """Load every scenario in `directory`, in a stable order so runs are comparable."""
    paths = sorted(
        path for path in directory.iterdir() if path.suffix in {".json", ".yaml", ".yml"}
    )
    if not paths:
        raise SystemExit(f"no scenarios in {directory}")
    return tuple(load_scenario(path) for path in paths)


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):  # a tarball checkout has no git
        return ""


def manifest(scenarios: Iterable[Scenario], names: Sequence[str], directory: Path) -> dict:
    """Everything needed to say how a result was produced (`docs/06-evaluation-methodology.md`).

    The commit *and* whether the tree was dirty, because a result produced from
    uncommitted edits is not reproducible from the commit alone and should say so
    rather than look clean.
    """
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "tekmor_version": __version__,
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "adapter": "scripted",
        "seed": None,
        "approver": "deny",
        "scenario_dir": str(directory),
        "defenses": list(names),
        "scenarios": [
            {
                "id": scenario.id,
                "version": scenario.version,
                "domain": scenario.domain,
                "benign": scenario.benign,
                "family": scenario.family,
                "level": scenario.level,
            }
            for scenario in scenarios
        ],
    }


def digest(directory: Path) -> dict[str, str]:
    """SHA-256 per scenario file: the run's inputs, pinned by content rather than name."""
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.iterdir())
        if path.suffix in {".json", ".yaml", ".yml"}
    }


def evaluate(
    scenarios: Sequence[Scenario],
    log: EventLog | None = None,
    build: Callable[[frozenset[str]], Sequence[Defense]] = defenses,
) -> list[RunRecord]:
    """Run the full matrix and score it. Each run gets a fresh world and a fresh taint.

    `build` turns the secret registry into the defenses under test, so an ablation or an
    attacker study runs through this same loop rather than a copy of it.
    """
    secrets = frozenset(value for scenario in scenarios for value in scenario.canaries.values())
    return [
        record(scenario, run(scenario, defense, log=log))
        for defense in build(secrets)
        for scenario in scenarios
    ]


#: Argument roles for the matrix's tools (`send_email`, `prepare_payment`, `remember`,
#: `isolate_host`, `open_ticket`), frozen with `research/experiments/argument_provenance/README.md`.
CONTENT_ARGS = frozenset({"subject", "body", "text", "summary"})
TARGET_ARGS = frozenset({"to", "payee", "host"})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", type=Path, default=SCENARIOS)
    parser.add_argument("--results", type=Path, default=RESULTS)
    parser.add_argument(
        "--endorse", action="store_true", help="turn on Policy.endorse_named in every scenario"
    )
    parser.add_argument(
        "--arguments",
        action="store_true",
        help="judge Trusted-Action per argument (Policy.argument_provenance)",
    )
    parser.add_argument(
        "--endorse-targets",
        action="store_true",
        help="let endorsement raise target arguments too (Policy.endorse_targets)",
    )
    args = parser.parse_args(argv)

    scenarios = tuple(
        replace(
            s,
            policy=replace(
                s.policy,
                endorse_named=s.policy.endorse_named or args.endorse,
                argument_provenance=args.arguments,
                content_args=CONTENT_ARGS,
                target_args=TARGET_ARGS,
                endorse_targets=args.endorse_targets,
            ),
        )
        for s in load_matrix(args.scenarios)
    )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "".join(
        ["-arguments"] * args.arguments
        + ["-endorsed"] * args.endorse
        + ["-targets"] * args.endorse_targets
    )
    raw = args.results / "raw" / stamp
    processed = args.results / "processed" / stamp
    raw.mkdir(parents=True, exist_ok=True)
    processed.mkdir(parents=True, exist_ok=True)

    log = EventLog(raw / "decisions.jsonl")
    records = evaluate(scenarios, log)
    metrics = by_defense(records)
    calibrations = calibrate_by_defense(records)

    (raw / "runs.jsonl").write_text(
        "".join(json.dumps(item.as_dict(), sort_keys=True) + "\n" for item in records),
        encoding="utf-8",
    )
    (raw / "manifest.json").write_text(
        json.dumps(
            {
                **manifest(scenarios, list(metrics), args.scenarios),
                "inputs": digest(args.scenarios),
                "endorse_named": args.endorse,
                "argument_provenance": args.arguments,
                "endorse_targets": args.endorse_targets,
                "content_args": sorted(CONTENT_ARGS),
                "target_args": sorted(TARGET_ARGS),
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
    # Processed, not raw: the calibrated numbers are derived from the same decision
    # events by a fit that could change, and raw output is never rewritten.
    (processed / "calibration.json").write_text(
        json.dumps(
            {name: c.as_dict() for name, c in calibrations.items()}, indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    # The trace as a page, beside the trace it was rendered from. It reads the JSONL and
    # nothing else, so it is a view of the run rather than a second source of truth.
    view = raw / "timeline.html"
    view.write_text(render(read(log.path), title=f"Tekmor {stamp}"), encoding="utf-8")

    print(table(metrics))
    print()
    print(grid(records))
    print()
    print(calibration(metrics))
    print()
    print(calibration_table(calibrations))
    print(f"\n{len(records)} runs -> {raw}\n            -> {processed / 'metrics.json'}")
    print(f"            -> {processed / 'calibration.json'}\n            -> {view}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
