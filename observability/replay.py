"""Terminal trace replay.

`sentinel replay <trace.jsonl>` walks a recorded run: what the agent wanted,
what the guard saw, what it decided and why, and what the environment did
next. This and the HTML dashboard read the same file the guard wrote while
the run was happening.
"""

from __future__ import annotations

import json
import sys
import textwrap
from typing import List

from sentinel.trace import load

COLOR = {
    "ALLOW": "\033[32m", "REWRITE": "\033[36m", "ESCALATE": "\033[33m", "BLOCK": "\033[31m",
    "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m", "warn": "\033[35m",
}


def _c(text: str, key: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLOR.get(key, '')}{text}{COLOR['off']}"


def _bar(value: float, width: int = 24) -> str:
    filled = int(round(value * width))
    return "#" * filled + "." * (width - filled)


def render(path: str, width: int = 100) -> None:
    events = load(path)
    wrap = lambda t, i=8: textwrap.fill(str(t), width=width - i,
                                        initial_indent=" " * i, subsequent_indent=" " * i)

    for e in events:
        kind = e["kind"]
        if kind == "run_start":
            print(f"\n{_c('=' * width, 'dim')}")
            print(f"{_c(e['title'], 'bold')}   [{e['scenario']}]")
            print(f"  domain={e['domain']}  policy={e['policy_profile']}  defense={e['defense']}  "
                  f"agent={e['agent']}  escalations answered by: {e['approver']}")
            atk = e.get("attack") or {}
            if atk.get("present"):
                print(f"  {_c('adversary', 'warn')}: {atk['family']} (level {atk['difficulty']}) "
                      f"wrote {sum(s['chars'] for s in atk['surfaces_written'])} chars into "
                      f"{', '.join(s['target'] for s in atk['surfaces_written'])}")
                print(wrap(atk.get("objective", ""), 4))
            print(f"{_c('=' * width, 'dim')}")

        elif kind == "mandate_sealed":
            m = e["mandate"]
            print(f"\n{_c('MANDATE SEALED', 'bold')}  seal={m['seal']}  "
                  f"{'(context already exposed - weaker guarantee)' if e.get('context_already_exposed') else '(before any exposure)'}")
            print(f"  goal        {m['goal']}")
            print(f"  authorises  {', '.join(m['capabilities']) or '(none)'}")
            if m["prohibited"]:
                print(f"  refuses     {', '.join(m['prohibited'])}")
            print(f"  records     {', '.join(m['resources']) or '(none named)'}"
                  + (f"   open resolution: {', '.join(m['open_resolution_families'])}"
                     if m["open_resolution_families"] else ""))

        elif kind == "observation":
            covert = f"  decoded views: {', '.join(e['decoded_views'])}" if e["decoded_views"] else ""
            print(f"\n  {_c('OBSERVED', 'dim')} {e['obs_id']}  {e['source_ref']}  "
                  f"[{e['trust']} / {e['sensitivity']}]  {e['chars']} chars{covert}")
            print(_c(wrap(e["excerpt"][:300] + ("..." if e["chars"] > 300 else ""), 4), "dim"))

        elif kind == "agent_intent":
            flag = _c(" <- attacker-authored (ground truth)", "warn") if e["harness_label"] == "injected" else ""
            print(f"\n  {_c('AGENT WANTS', 'bold')} step {e['step']}: "
                  f"{e['tool']}({json.dumps(e['args'])[:120]}){flag}")

        elif kind == "decision":
            r = e["risk"]
            print(f"  {_c('DECISION  ' + e['intervention'], e['intervention'])}   "
                  f"risk {r['risk']:.3f} [{_bar(r['risk'])}]  confidence {r['confidence']:.2f}  "
                  f"severity {e['severity']}  capability {e['capability']}")
            for rule in e["hard_rules"]:
                print(f"      {_c('hard rule', 'warn')} {rule['code']} (floor {rule['floor']}): {rule['why']}")
            for c in e["risk"]["contributions"][:6]:
                sign = "+" if c["logit"] >= 0 else "-"
                print(f"      {sign} {c['code']:<32} {c['family']:<8} "
                      f"strength {c['strength']:.2f} x weight {c['weight']:+.1f} = {c['logit']:+.2f}")
            for alt in e.get("alternatives_considered", []):
                mark = "accepted" if alt["accepted"] else "rejected"
                print(f"      alternative [{alt['strategy']}] residual {alt['residual_risk']:.3f} "
                      f"-> {alt['would_be']} ({mark})")
            print(_c(wrap(e["reason"], 6), "dim"))
            if e.get("executed") and e["executed"]["args"] != e["candidate"]["args"]:
                print(f"      {_c('executed instead: ' + json.dumps(e['executed']), 'REWRITE')}")

        elif kind == "human_review":
            print(f"      {_c('HUMAN', 'ESCALATE')} {'approved' if e['approved'] else 'denied'} "
                  f"({e['mode']})")

        elif kind == "effect":
            print(f"      {_c('EFFECT', 'dim')} {e['effect']} committed to the environment")

        elif kind == "blocked":
            print(f"      {_c('NOT EXECUTED', e.get('intervention', 'BLOCK'))}")

        elif kind == "final_response":
            print(f"\n  {_c('AGENT RESPONDS', 'bold')}")
            print(wrap(e["content"], 4))

        elif kind == "verdict":
            print(f"\n{_c('-' * width, 'dim')}")
            print(f"{_c('VERDICT ' + e['overall'], 'bold')}   "
                  f"task completed: {e['utility_pass']}   attack contained: {e['security_pass']}")
            for c in e["utility"]:
                print(f"  utility   {'ok  ' if c['passed'] else 'FAIL'}  {c['name']}  {_c(c['detail'], 'dim')}")
            for c in e["security"]:
                print(f"  security  {'ok  ' if c['passed'] else 'FAIL'}  {c['name']}  {_c(c['detail'], 'dim')}")
            if e["leaked_canaries"]:
                print(f"  {_c('LEAKED: ' + ', '.join(e['leaked_canaries']), 'BLOCK')}")
            print(f"  interventions {e['interventions']}   {e['duration_ms']} ms")
            print(f"{_c('-' * width, 'dim')}\n")


if __name__ == "__main__":
    render(sys.argv[1])
