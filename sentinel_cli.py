#!/usr/bin/env python3
"""SENTINEL command line: read the traces the defense service records.

    sentinel replay    render a recorded trace in the terminal
    sentinel dashboard build the HTML observability dashboard from traces

The runs themselves are driven by the organizers' harness against Qwen3-8B
(docs/QWEN3_AGENT.md); the service writes one trace per run when
SENTINEL_TRACE_DIR is set.
"""

from __future__ import annotations

import argparse
import glob
import sys


def cmd_replay(args) -> int:
    from observability.replay import render
    render(args.trace, width=args.width)
    return 0


def cmd_dashboard(args) -> int:
    from observability.build import build
    traces = args.traces or sorted(glob.glob("artifacts/**/traces/**/*.jsonl", recursive=True))
    out = build(traces, args.out)
    print(f"  dashboard written to {out}  ({len(traces)} runs)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

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
