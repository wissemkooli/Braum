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
    ("split", "split"),
    ("attacker", "attacker"),
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


def row(card: dict[str, Any]) -> dict[str, str]:
    metrics, score = card["metrics"], card["score"]
    values = {**metrics, **score}
    out = {}
    for label, key in COLUMNS:
        if key == "split":
            out[label] = f"{card['split']} ({metrics['scenario_count']})"
        elif key == "attacker":
            out[label] = card.get("attack_mode", "static")
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


def report(cards: list[dict[str, Any]]) -> str:
    parts = ["# SENTINEL on the official harness, Qwen3-8B reference agent", "", table(cards), ""]
    for card in cards:
        issues = problems(card)
        heading = f"## {card['split']} / attacker={card.get('attack_mode', 'static')}"
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
