"""Proposal B's ablation: the monitor with and without the task-alignment auditor.

    uv sync --extra qwen [--extra agentdojo]
    uv run python -m evaluation.alignment [--judge Qwen/Qwen3-0.6B] [--endorse]
        [--dojo [--suites banking] [--limit N]]

`docs/10-research-report.md` Proposal B, *Evaluation*: remove the auditor and see what its
marginal value is, and measure the latency it adds and how far it can be trusted. The
auditor (`tekmor.defense.auditor`) only ever raises a verdict, so its row can differ
from `tekmor`'s in one of two directions only: attacks it stops, and benign work it
sends to a human who, in these runs, always says no.

**The matrix is the development set and AgentDojo is held out.** The judge prompt was
chosen among three framings on pairs drawn from the matrix (`runtime.qwen.JUDGE_PROMPT`).
The threshold is 0.5, the judge's own "more likely no than yes", and is not fitted.

`--endorse` is the setting the auditor is for: endorsement is what puts sensitive
actions driven by untrusted content back into the gray zone. Without it, the gray zone
holds only calls the policy does not consider sensitive.

The judge's probability is deterministic for one model, dtype and device, and moves in
the last digits across them. The manifest records all three.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path

from evaluation.harness import RESULTS, SCENARIOS, digest, evaluate, load_matrix, manifest
from evaluation.metrics import by_defense, grid, table
from tekmor.defense import AlignmentAuditor, Judge, ReferenceMonitor
from tekmor.defense.baselines import AllowAll, RefuseAll
from tekmor.runtime.qwen import JUDGE_PROMPT, CausalJudge


def spread(judge: Judge, threshold: float) -> dict:
    """How the judge's answers are distributed: how far from the threshold it sits."""
    answers = sorted(judge._answers.values())
    if not answers:
        return {"n": 0}
    return {
        "n": len(answers),
        "min": answers[0],
        "median": answers[len(answers) // 2],
        "max": answers[-1],
        "below_threshold": sum(a < threshold for a in answers),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", type=Path, default=SCENARIOS)
    parser.add_argument("--results", type=Path, default=RESULTS)
    parser.add_argument(
        "--judge",
        default="Qwen/Qwen3-0.6B",
        help="a model id, or 'none' for the deny-gray baseline (no model, refuses the gray zone)",
    )
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--dtype", default="float32", help="bfloat16 for models too big for RAM")
    parser.add_argument("--quant", choices=["nf4"], default=None, help="4-bit, GPU only")
    parser.add_argument("--endorse", action="store_true")
    parser.add_argument("--dojo", action="store_true", help="also run AgentDojo (held out)")
    # The same agent flags the AgentDojo driver takes, so an auditor arm can be run
    # against a model-driven agent instead of ground truth.
    from evaluation import dojo as _dojo

    _dojo.add_agent_args(parser)
    parser.add_argument("--suites", nargs="+", default=None)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)

    model_judge = (
        None
        if args.judge == "none"
        else CausalJudge(
            model_id=args.judge,
            name=args.judge.rsplit("/", 1)[-1],
            dtype=args.dtype,
            quant=args.quant,
        )
    )
    judge: Judge = RefuseAll() if model_judge is None else model_judge
    monitor = ReferenceMonitor()
    auditor = AlignmentAuditor(monitor, judge, args.threshold)

    scenarios = load_matrix(args.scenarios)
    if args.endorse:
        scenarios = tuple(
            replace(s, policy=replace(s.policy, endorse_named=True)) for s in scenarios
        )
    records = evaluate(scenarios, build=lambda secrets: (monitor, auditor))
    metrics = by_defense(records)
    matrix_cost = {"judge_calls": judge.calls, "judge_seconds": judge.seconds}

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-alignment"
    raw, processed = args.results / "raw" / stamp, args.results / "processed" / stamp
    raw.mkdir(parents=True, exist_ok=True)
    processed.mkdir(parents=True, exist_ok=True)
    (raw / "runs.jsonl").write_text(
        "".join(json.dumps(r.as_dict(), sort_keys=True) + "\n" for r in records),
        encoding="utf-8",
    )
    out = {
        "matrix": {name: m.as_dict() for name, m in metrics.items()},
        "matrix_cost": matrix_cost,
    }

    print(table(metrics))
    print()
    print(grid(records))
    runs = {(r.defense, r.scenario): r for r in records}
    flips = sorted(
        s
        for (d, s), r in runs.items()
        if d == auditor.name and r.secure != runs[monitor.name, s].secure
    )
    print(f"\nflipped by the auditor: {flips or 'none'}")
    print(f"judge: {judge.calls} uncached calls, {judge.seconds:.1f}s")
    out["matrix_flips"] = flips
    out["matrix_judge"] = spread(judge, args.threshold)
    print(f"judge answers: {out['matrix_judge']}")

    if args.dojo:
        from evaluation import dojo

        before = (judge.calls, judge.seconds)
        agent, client = dojo.agent_from_args(args, parser)
        dojo_records = dojo.evaluate(
            args.suites or list(dojo.SUITES),
            args.limit,
            args.endorse,
            build=lambda: (AllowAll(), monitor, auditor),
            agent=agent,
        )
        out["agentdojo_agent"] = dojo._agent_description(args)
        out["agentdojo_agent_empty_completions"] = getattr(client, "empty", None)
        rows = dojo.score(dojo_records)
        (raw / "agentdojo.jsonl").write_text(
            "".join(json.dumps(r.as_dict(), sort_keys=True) + "\n" for r in dojo_records),
            encoding="utf-8",
        )
        out["agentdojo"] = [asdict(m) for m in rows]
        out["agentdojo_cost"] = {
            "judge_calls": judge.calls - before[0],
            "judge_seconds": judge.seconds - before[1],
        }
        out["judge_all"] = spread(judge, args.threshold)
        print()
        print(dojo.table(rows))
        print(f"judge: {out['agentdojo_cost']['judge_calls']} uncached calls on AgentDojo")

    device = str(judge.model.device) if judge.model is not None else "not loaded"
    (raw / "manifest.json").write_text(
        json.dumps(
            {
                **manifest(scenarios, list(metrics), args.scenarios),
                "inputs": digest(args.scenarios),
                "judge": args.judge,
                # The deny-gray baseline runs no model, so the prompt, dtype and
                # quantization that describe one would be noise in its manifest.
                "judge_prompt": None if model_judge is None else JUDGE_PROMPT,
                "judge_dtype": None if model_judge is None else args.dtype,
                "judge_quant": None if model_judge is None else args.quant,
                "device": device,
                "threshold": args.threshold,
                "endorse_named": args.endorse,
                "agentdojo": {"suites": args.suites, "limit": args.limit} if args.dojo else None,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (processed / "alignment.json").write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"\n-> {raw}\n-> {processed / 'alignment.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
