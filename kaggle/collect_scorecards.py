"""Turn a directory of harness scorecards into the table and the failure list for the report.

The summary table is what goes in `docs/OFFICIAL_HARNESS.md`. The failure list is the part
that matters when the agent is a real model rather than the mock: a scenario can now end in
`model_error` or run out of steps, and that is the agent failing the task, not the defense
blocking it. Reading the two together is the only way to tell those apart.

    python kaggle/collect_scorecards.py results/ --markdown results/RESULTS_QWEN3.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

COLUMNS = (
    ("defense", "defense"),
    ("split", "split"),
    ("attacker", "attacker"),
    ("seed", "run_seed"),
    ("BTU ↑", "btu"),
    ("ASR ↓", "asr"),
    ("CVR ↓", "cvr"),
    ("FBR ↓", "fbr"),
    ("UER ↓", "uer"),
    ("Brier ↓", "brier"),
    ("official score", "official_score"),
)


def load(directory: Path) -> list[dict[str, Any]]:
    cards = []
    for path in sorted(directory.rglob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if {"metrics", "score", "outcomes"} <= data.keys():
            data["_path"] = str(path)
            cards.append(data)
    return cards


def defense_of(card: dict[str, Any]) -> str:
    name = str(card.get("defense") or "?")
    return "SENTINEL (ours)" if name == "http_defense" else name


def row(card: dict[str, Any]) -> dict[str, str]:
    metrics, score = card["metrics"], card["score"]
    values = {**metrics, **score}
    out = {}
    for label, key in COLUMNS:
        if key == "defense":
            out[label] = defense_of(card)
        elif key == "split":
            out[label] = f"{card['split']} ({metrics['scenario_count']})"
        elif key == "attacker":
            out[label] = card.get("attack_mode", "static")
        elif key == "run_seed":
            out[label] = str(card.get("run_seed", 0))
        else:
            value = values.get(key)
            out[label] = "n/a" if value is None else f"{value:.3f}"
    return out


def table(cards: list[dict[str, Any]]) -> str:
    rows = [row(c) for c in cards]
    headers = [label for label, _ in COLUMNS]
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(r[h] for h in headers) + " |" for r in rows]
    return "\n".join(lines)


def problems(card: dict[str, Any]) -> list[str]:
    """Every scenario that did not end the way it should have, with why."""
    lines = []
    for outcome in card["outcomes"]:
        bad = []
        if outcome["attack_present"] and outcome["attack_success"]:
            bad.append("ATTACK SUCCEEDED")
        if not outcome["task_success"]:
            bad.append("task failed")
        if outcome["termination"] != "completed":
            bad.append(f"termination={outcome['termination']}")
        if outcome["critical_violation"]:
            bad.append("critical violation")
        if outcome["data_flow_violation"]:
            bad.append("data flow violation")
        if not bad:
            continue
        blocked = sorted({d["decision"] for d in outcome.get("decisions", []) if d.get("decision") != "allow"})
        detail = f" (defense: {', '.join(blocked)})" if blocked else ""
        lines.append(f"- `{outcome['scenario_id']}` [{outcome['domain']}] {'; '.join(bad)}{detail}")
    return lines


def paired(cards: list[dict[str, Any]]) -> list[str]:
    """The agent alone against the agent behind the defense, scenario by scenario.

    Without this the defended numbers cannot be read: a task the agent fails on
    its own is not a false block, and an attack the agent ignores on its own is
    not an attack the defense contained.
    """
    def key(card):
        return (card["split"], card.get("attack_mode", "static"), card.get("run_seed", 0))

    alone = {key(c): c for c in cards if c.get("defense") == "allow_all"}
    lines: list[str] = []
    for card in cards:
        control = alone.get(key(card))
        if card.get("defense") == "allow_all" or control is None:
            continue
        base = {o["scenario_id"]: o for o in control["outcomes"]}
        lines += [f"## Agent alone vs defended: {card['split']} / {card.get('attack_mode', 'static')}", "",
                  "| scenario | kind | task: alone | task: defended | attack: alone | attack: defended | reading |",
                  "|---|---|---|---|---|---|---|"]
        tally = {"reached": 0, "contained": 0, "benign_alone": 0, "benign_kept": 0, "benign": 0}
        for o in card["outcomes"]:
            b = base.get(o["scenario_id"])
            if b is None:
                continue
            mark = lambda v: "yes" if v else "no"
            if o["attack_present"]:
                kind = "attack"
                if b["attack_success"]:
                    tally["reached"] += 1
                    tally["contained"] += not o["attack_success"]
                    reading = "contained" if not o["attack_success"] else "**ATTACK SUCCEEDED**"
                else:
                    reading = "agent did not take the bait; nothing to contain"
                    if o["attack_success"]:
                        reading = "**attack succeeded only when defended**"
            else:
                kind = "hard negative" if o.get("hard_negative") else "benign"
                tally["benign"] += 1
                tally["benign_alone"] += bool(b["task_success"])
                tally["benign_kept"] += bool(b["task_success"] and o["task_success"])
                if b["task_success"] and not o["task_success"]:
                    reading = "**the defense cost this task**"
                elif not b["task_success"]:
                    reading = "agent fails this on its own"
                else:
                    reading = "kept"
            atk = ("-", "-") if not o["attack_present"] else (mark(b["attack_success"]), mark(o["attack_success"]))
            lines.append(f"| `{o['scenario_id']}` | {kind} | {mark(b['task_success'])} | "
                         f"{mark(o['task_success'])} | {atk[0]} | {atk[1]} | {reading} |")
        lines += ["",
                  f"- attacks that succeed against the undefended agent: **{tally['reached']}**; "
                  f"contained by the defense: **{tally['contained']}/{tally['reached']}**",
                  f"- benign tasks the agent completes alone: **{tally['benign_alone']}/{tally['benign']}**; "
                  f"still completed behind the defense: **{tally['benign_kept']}/{tally['benign_alone']}**", ""]
    return lines


def report(cards: list[dict[str, Any]]) -> str:
    parts = ["# SENTINEL on the official harness, Qwen3-8B reference agent", "", table(cards), ""]
    parts += paired(cards)
    for card in cards:
        issues = problems(card)
        heading = (f"## {defense_of(card)} / {card['split']} / attacker={card.get('attack_mode', 'static')}"
                   f" / seed {card.get('run_seed', 0)}")
        digest = card.get("deterministic_digest", "")
        parts += [heading, "", f"scorecard: `{card['_path']}`", f"digest: `{digest}`", ""]
        parts += issues or ["- every scenario completed, every task passed, no attack succeeded"]
        parts += [""]
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory holding scorecard JSON files")
    parser.add_argument("--markdown", type=Path, default=None, help="also write the report here")
    args = parser.parse_args()

    cards = load(args.directory)
    if not cards:
        raise SystemExit(f"no scorecards found under {args.directory}")
    text = report(cards)
    print(text)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(text + "\n")


if __name__ == "__main__":
    main()
