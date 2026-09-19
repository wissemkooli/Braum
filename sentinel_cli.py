#!/usr/bin/env python3
"""SENTINEL command line.

    sentinel run       one scenario, one defense, one trace
    sentinel suite     every scenario against one defense
    sentinel compare   every scenario against every defense and baseline
    sentinel ablate    the ablation matrix: which signal family is load-bearing
    sentinel replay    render a recorded trace in the terminal
    sentinel dashboard build the HTML observability dashboard from traces
    sentinel calibrate how well the risk score separates the two populations
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
from typing import Dict, List

from sentinel.risk import ABLATABLE_FAMILIES
from sentinel.trace import load as load_trace
from simulator import scenario as scenario_mod
from simulator.baselines import BASELINES
from simulator.runner import RunResult, run

DEFAULT_SCENARIOS = ["scenarios"]

C = {
    "ALLOW": "\033[32m", "REWRITE": "\033[36m", "ESCALATE": "\033[33m", "BLOCK": "\033[31m",
    "PASS": "\033[32m", "FAIL": "\033[31m", "SECURE_BUT_UNHELPFUL": "\033[33m",
    "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m", "blue": "\033[34m",
}


def paint(text: str, key: str, enabled: bool = True) -> str:
    if not enabled or not sys.stdout.isatty():
        return text
    return f"{C.get(key, '')}{text}{C['off']}"


# --------------------------------------------------------------------- output
def print_run(result: RunResult, verbose: bool = True) -> None:
    s, v = result.scenario, result.verdict
    print(f"\n{paint(s.title, 'bold')}  {paint('[' + s.id + ']', 'dim')}")
    print(f"  domain={s.domain}  family={s.family}  difficulty={s.difficulty}  defense={result.defense}")
    if s.attack_present:
        print(f"  {paint('attack objective:', 'dim')} {s.attack.get('objective', '').strip()}")
    print()
    for d in result.decisions:
        mark = "!" if d["harness_label"] == "injected" else " "
        line = (f"  {mark} step {d['step']:>2}  {d['candidate']['tool']:<18}"
                f"{paint(d['intervention'].ljust(9), d['intervention'])}"
                f"risk={d['risk']['risk']:.3f}  conf={d['risk']['confidence']:.2f}")
        print(line)
        if verbose:
            codes = [c for c in d["risk"]["reason_codes"][:4]]
            if codes:
                print(f"        {paint('why: ' + ', '.join(codes), 'dim')}")
            if d["intervention"] != "ALLOW":
                print(f"        {paint(d['reason'][:150], 'dim')}")
            if d["executed"] and d["executed"]["args"] != d["candidate"]["args"]:
                print(f"        {paint('executed instead: ' + json.dumps(d['executed']['args'])[:120], 'blue')}")
    print()
    for c in v.utility:
        print(f"  utility   {'ok  ' if c.passed else 'FAIL'}  {c.name}  {paint(c.detail, 'dim')}")
    for c in v.security:
        print(f"  security  {'ok  ' if c.passed else 'FAIL'}  {c.name}  {paint(c.detail, 'dim')}")
    print(f"\n  {paint(v.overall, v.overall)}   interventions={v.interventions}   "
          f"{result.duration_ms:.0f} ms   trace={result.trace_path}\n")


def table(rows: List[dict], columns: List[str]) -> str:
    if not rows:
        return "(no rows)"
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    out = ["  ".join(c.ljust(widths[c]) for c in columns),
           "  ".join("-" * widths[c] for c in columns)]
    for r in rows:
        out.append("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in columns))
    return "\n".join(out)


# ------------------------------------------------------------------- commands
def cmd_run(args) -> int:
    result = run(args.scenario, defense=args.defense, ablate=tuple(args.ablate or ()),
                 agent_mode=args.agent, approver=args.approver, trace_dir=args.trace_dir,
                 rewrite=not args.no_rewrite, hard_rules=not args.no_hard_rules)
    print_run(result, verbose=not args.quiet)
    return 0 if result.verdict.overall == "PASS" else 1


def _run_many(paths, **kwargs) -> List[RunResult]:
    return [run(p, **kwargs) for p in paths]


def cmd_suite(args) -> int:
    paths = scenario_mod.discover(args.scenarios or DEFAULT_SCENARIOS)
    results = _run_many(paths, defense=args.defense, ablate=tuple(args.ablate or ()),
                        agent_mode=args.agent, approver=args.approver, trace_dir=args.trace_dir)
    rows = []
    for r in results:
        v = r.verdict
        rows.append({
            "scenario": r.scenario.id,
            "domain": r.scenario.domain,
            "family": r.scenario.family,
            "lvl": r.scenario.difficulty,
            "utility": "pass" if v.utility_pass else "FAIL",
            "security": "pass" if v.security_pass else "FAIL",
            "verdict": v.overall,
            "A/R/E/B": f"{v.interventions.get('ALLOW',0)}/{v.interventions.get('REWRITE',0)}"
                       f"/{v.interventions.get('ESCALATE',0)}/{v.interventions.get('BLOCK',0)}",
            "ms": f"{r.duration_ms:.0f}",
        })
    print(f"\n{paint('SUITE', 'bold')}  defense={args.defense}"
          f"{' ablate=' + ','.join(args.ablate) if args.ablate else ''}  "
          f"scenarios={len(results)}\n")
    print(table(rows, ["scenario", "domain", "family", "lvl", "utility", "security", "verdict", "A/R/E/B", "ms"]))
    passed = sum(1 for r in results if r.verdict.overall == "PASS")
    secure = sum(1 for r in results if r.verdict.security_pass)
    useful = sum(1 for r in results if r.verdict.utility_pass)
    print(f"\n  overall pass {passed}/{len(results)}   secure {secure}/{len(results)}   "
          f"task completed {useful}/{len(results)}\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([r.summary() for r in results], fh, indent=2)
        print(f"  wrote {args.json}")
    return 0 if passed == len(results) else 1


def cmd_compare(args) -> int:
    paths = scenario_mod.discover(args.scenarios or DEFAULT_SCENARIOS)
    defenses = ["sentinel"] + list(BASELINES)
    matrix: Dict[str, Dict[str, str]] = {}
    stats: Dict[str, Dict[str, int]] = {}
    for defense in defenses:
        stats[defense] = {"secure": 0, "useful": 0, "pass": 0, "escalations": 0, "n": 0}
        for r in _run_many(paths, defense=defense, agent_mode=args.agent,
                           approver=args.approver,
                           trace_dir=os.path.join(args.trace_dir, "baselines")):
            matrix.setdefault(r.scenario.id, {})[defense] = (
                ("P" if r.verdict.overall == "PASS" else
                 "u" if r.verdict.security_pass else "X")
            )
            stats[defense]["n"] += 1
            stats[defense]["secure"] += int(r.verdict.security_pass)
            stats[defense]["useful"] += int(r.verdict.utility_pass)
            stats[defense]["pass"] += int(r.verdict.overall == "PASS")
            stats[defense]["escalations"] += r.verdict.interventions.get("ESCALATE", 0)

    print(f"\n{paint('DEFENSE COMPARISON', 'bold')}   "
          f"P = attack stopped and task done, u = secure but task broken, X = attack succeeded\n")
    rows = [{"scenario": sid, **cells} for sid, cells in matrix.items()]
    print(table(rows, ["scenario"] + defenses))
    print()
    summary = [{
        "defense": d,
        "attacks stopped": f"{s['secure']}/{s['n']}",
        "tasks completed": f"{s['useful']}/{s['n']}",
        "both": f"{s['pass']}/{s['n']}",
        "human escalations": s["escalations"],
    } for d, s in stats.items()]
    print(table(summary, ["defense", "attacks stopped", "tasks completed", "both", "human escalations"]))
    print()
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"matrix": matrix, "stats": stats}, fh, indent=2)
        print(f"  wrote {args.json}\n")
    return 0


def cmd_ablate(args) -> int:
    paths = scenario_mod.discover(args.scenarios or DEFAULT_SCENARIOS)
    configs = [("full", {}, ())]
    configs += [(f"no_{fam}", {}, (fam,)) for fam in ABLATABLE_FAMILIES]
    configs += [("no_rewrite", {"rewrite": False}, ()),
                ("no_hard_rules", {"hard_rules": False}, ()),
                ("origin_only", {}, ("mandate", "context", "flow", "history")),
                ("flow_only", {}, ("mandate", "origin", "context", "history"))]

    rows, baseline_decisions, detail = [], {}, {}
    for label, kwargs, ablate in configs:
        results = _run_many(paths, defense="sentinel", ablate=ablate, agent_mode=args.agent,
                            approver=args.approver,
                            trace_dir=os.path.join(args.trace_dir, "ablation"), **kwargs)
        attacks = [r for r in results if r.scenario.attack_present]
        benign = [r for r in results if not r.scenario.attack_present]

        # Decision-level delta: the interesting question is not only "did the
        # attack still fail" but "how did the defense's behaviour change".
        current = {}
        for r in results:
            for d in r.decisions:
                current[(r.scenario.id, d["turn"], d["step"], d["candidate"]["tool"])] = (
                    d["intervention"], d["harness_label"])
        if label == "full":
            baseline_decisions = current
            changed, weaker, stronger = 0, 0, 0
        else:
            order = {"ALLOW": 0, "REWRITE": 1, "ESCALATE": 2, "BLOCK": 3}
            shifts = []
            for key, (intervention, origin) in current.items():
                before = baseline_decisions.get(key)
                if before and before[0] != intervention:
                    shifts.append((key, before[0], intervention, origin))
            changed = len(shifts)
            weaker = sum(1 for _, b, a, _ in shifts if order[a] < order[b])
            stronger = changed - weaker
            detail[label] = [
                f"{k[0]}:{k[3]}@{k[2]} {b}->{a}" + (" [attack]" if o == "injected" else " [benign]")
                for k, b, a, o in shifts
            ]

        rows.append({
            "config": label,
            "attacks stopped": f"{sum(r.verdict.security_pass for r in attacks)}/{len(attacks)}",
            "benign kept": f"{sum(r.verdict.utility_pass for r in benign)}/{len(benign)}",
            "esc": sum(r.verdict.interventions.get("ESCALATE", 0) for r in results),
            "blk": sum(r.verdict.interventions.get("BLOCK", 0) for r in results),
            "rew": sum(r.verdict.interventions.get("REWRITE", 0) for r in results),
            "decisions changed": changed,
            "softer/harder": f"{weaker}/{stronger}",
            "runs that fail": ",".join(r.scenario.id for r in results if not r.verdict.security_pass) or "-",
        })
    print(f"\n{paint('ABLATION', 'bold')}  scenarios={len(paths)}  "
          f"(changes are measured against the full configuration)\n")
    print(table(rows, ["config", "attacks stopped", "benign kept", "esc", "blk", "rew",
                       "decisions changed", "softer/harder", "runs that fail"]))
    if args.verbose_ablation:
        for label, shifts in detail.items():
            if shifts:
                print(f"\n  {label}:")
                for line in shifts:
                    print(f"    {line}")
    print()
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"summary": rows, "changed_decisions": detail}, fh, indent=2)
        print(f"  wrote {args.json}\n")
    return 0


def cmd_families(args) -> int:
    """Pass/fail aggregated by attack family, which is how the spec asks for it."""
    paths = scenario_mod.discover(args.scenarios or DEFAULT_SCENARIOS)
    buckets: Dict[str, List[RunResult]] = {}
    for r in _run_many(paths, defense="sentinel", agent_mode=args.agent,
                       approver=args.approver, trace_dir=args.trace_dir):
        buckets.setdefault(r.scenario.family, []).append(r)
    rows = []
    for family, results in sorted(buckets.items()):
        levels = sorted({r.scenario.difficulty for r in results})
        rows.append({
            "attack family": family,
            "n": len(results),
            "levels": ",".join(str(l) for l in levels),
            "attack contained": f"{sum(r.verdict.security_pass for r in results)}/{len(results)}",
            "task completed": f"{sum(r.verdict.utility_pass for r in results)}/{len(results)}",
            "both": f"{sum(r.verdict.overall == 'PASS' for r in results)}/{len(results)}",
            "blocks": sum(r.verdict.interventions.get("BLOCK", 0) for r in results),
            "rewrites": sum(r.verdict.interventions.get("REWRITE", 0) for r in results),
            "escalations": sum(r.verdict.interventions.get("ESCALATE", 0) for r in results),
        })
    print(f"\n{paint('BY ATTACK FAMILY', 'bold')}\n")
    print(table(rows, ["attack family", "n", "levels", "attack contained", "task completed",
                       "both", "blocks", "rewrites", "escalations"]))
    print()
    return 0


def cmd_calibrate(args) -> int:
    """Does the score actually separate attacker-authored actions from real ones?"""
    paths = scenario_mod.discover(args.scenarios or DEFAULT_SCENARIOS)
    induced, genuine = [], []
    for r in _run_many(paths, defense="sentinel", agent_mode=args.agent,
                       approver=args.approver,
                       trace_dir=os.path.join(args.trace_dir, "calibration")):
        for d in r.decisions:
            (induced if d["harness_label"] == "injected" else genuine).append(d["risk"]["risk"])
    if not induced or not genuine:
        print("need both populations"); return 1
    pairs = [(a, b) for a in induced for b in genuine]
    auc = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a, b in pairs) / len(pairs)
    print(f"\n{paint('RISK CALIBRATION', 'bold')}\n")
    for name, pop in (("attacker-authored actions", induced), ("genuine user actions", genuine)):
        print(f"  {name:<28} n={len(pop):<4} mean={statistics.mean(pop):.3f}  "
              f"median={statistics.median(pop):.3f}  min={min(pop):.3f}  max={max(pop):.3f}")
    print(f"\n  separation (AUC)             {auc:.4f}")
    print(f"  worst genuine action         {max(genuine):.3f}")
    print(f"  weakest attack detection     {min(induced):.3f}")
    gap = min(induced) - max(genuine)
    print(f"  margin between populations   {gap:+.3f}"
          f"   {'(no overlap)' if gap > 0 else '(OVERLAP - see failure analysis)'}\n")
    return 0


def cmd_replay(args) -> int:
    from observability.replay import render
    render(args.trace, width=args.width)
    return 0


def cmd_dashboard(args) -> int:
    from observability.build import build
    traces = args.traces or sorted(glob.glob("artifacts/*.jsonl"))
    out = build(traces, args.out)
    print(f"  dashboard written to {out}  ({len(traces)} runs)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, scenarios=True):
        if scenarios:
            p.add_argument("--scenarios", nargs="*", help="scenario files or directories")
        p.add_argument("--agent", default="susceptible", choices=["susceptible", "compliant"],
                       help="susceptible follows instructions found in content (default)")
        p.add_argument("--approver", default=None, choices=["deny", "approve", "prompt"],
                       help="how escalations are answered (default: the scenario's own setting)")
        p.add_argument("--trace-dir", default="artifacts")
        p.add_argument("--json", default=None, help="also write machine-readable results here")

    p_run = sub.add_parser("run", help="run one scenario")
    p_run.add_argument("--scenario", required=True)
    p_run.add_argument("--defense", default="sentinel",
                       choices=["sentinel"] + list(BASELINES))
    p_run.add_argument("--ablate", nargs="*", default=[], choices=list(ABLATABLE_FAMILIES))
    p_run.add_argument("--no-rewrite", action="store_true")
    p_run.add_argument("--no-hard-rules", action="store_true")
    p_run.add_argument("--quiet", action="store_true")
    common(p_run, scenarios=False)
    p_run.set_defaults(func=cmd_run)

    p_suite = sub.add_parser("suite", help="run every scenario")
    p_suite.add_argument("--defense", default="sentinel", choices=["sentinel"] + list(BASELINES))
    p_suite.add_argument("--ablate", nargs="*", default=[], choices=list(ABLATABLE_FAMILIES))
    common(p_suite)
    p_suite.set_defaults(func=cmd_suite)

    p_cmp = sub.add_parser("compare", help="sentinel against every baseline")
    common(p_cmp)
    p_cmp.set_defaults(func=cmd_compare)

    p_abl = sub.add_parser("ablate", help="turn each signal family off in turn")
    p_abl.add_argument("--verbose-ablation", action="store_true",
                       help="list every decision that changed")
    common(p_abl)
    p_abl.set_defaults(func=cmd_ablate)

    p_fam = sub.add_parser("families", help="pass/fail aggregated by attack family")
    common(p_fam)
    p_fam.set_defaults(func=cmd_families)

    p_cal = sub.add_parser("calibrate", help="score separation between populations")
    common(p_cal)
    p_cal.set_defaults(func=cmd_calibrate)

    p_rep = sub.add_parser("replay", help="render a recorded trace")
    p_rep.add_argument("trace")
    p_rep.add_argument("--width", type=int, default=100)
    p_rep.set_defaults(func=cmd_replay)

    p_dash = sub.add_parser("dashboard", help="build the HTML observability dashboard")
    p_dash.add_argument("traces", nargs="*")
    p_dash.add_argument("--out", default="observability/dashboard.html")
    p_dash.set_defaults(func=cmd_dashboard)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
