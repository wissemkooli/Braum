"""The security timeline and the provenance graph, rendered from the log alone.

    uv run python -m tekmor.observability.viewer evaluation/results/raw/<stamp>/decisions.jsonl

`docs/10-research-report.md` Part V: a reader should be able to watch attacker-controlled data
flow toward a sensitive action and see the edge get cut, without reading code. That is
what this renders — per run, the chain

    observation + trust -> candidate action -> policy -> decision -> outcome

as a table, and the influence set as a graph whose edges are labelled with the trust of
the source they come from and drawn cut where the action they fed was not executed.

**It reads the JSONL and nothing else.** Not the scenario, not `benign`, not the world:
if the viewer can show it, the trace carries it, which is the property the
observability design asks for and the reason this is the honest way to find a field the
schema is missing. It also means the viewer never knows whether a decision was *correct* — that
question is the evaluation harness's, and keeping it out of the trace renderer is what
stops a debugging tool from quietly becoming a scorer.

**No dependency, no script, no network.** One self-contained HTML file with inline CSS
and inline SVG; the collapsing is `<details>`, which is the browser's. The doc suggests
D3 or vis.js, and a static page of a finished run needs neither.

**Everything interpolated is escaped.** Tool names, source ids and origins are derived
from content the threat model treats as attacker-controlled, so a trace viewer is a
place where injected markup would execute in the analyst's browser. `html.escape` on
every value, attributes included, is the trust boundary here and is not a place to be
lazy.
"""

from __future__ import annotations

import argparse
import html
from collections.abc import Iterable, Sequence
from pathlib import Path

from tekmor.observability.events import read

#: One colour per trust level, dark to light along the lattice. "UNKNOWN" is what a
#: pre-schema-2 event gets: it recorded source ids without their labels, and a reader
#: that guessed a level for them would be inventing trust.
TRUST_COLOUR = {
    "ADVERSARY_CONTROLLED": "#b3261e",
    "UNTRUSTED_EXTERNAL": "#c77800",
    "UNTRUSTED_INTERNAL": "#9a8300",
    "TRUSTED_INTERNAL": "#2a6f97",
    "AUTHENTICATED_USER": "#2e7d32",
    "SYSTEM_POLICY": "#5b4a9e",
    "UNKNOWN": "#8a8a8a",
}

VERDICT_COLOUR = {
    "allow": "#2e7d32",
    "rewrite": "#c77800",
    "escalate": "#2a6f97",
    "block": "#b3261e",
}

CSS = """
:root { color-scheme: light dark; --fg: #1b1b1b; --bg: #fbfbfa; --line: #d8d5cf;
        --muted: #6b6b6b; --panel: #fff; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6e4e0; --bg: #16171a; --line: #34363b; --muted: #9a9a9a; --panel: #1d1f23; }
}
body { margin: 0; padding: 24px; background: var(--bg); color: var(--fg);
       font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; }
h1 { font-size: 20px; margin: 0 0 4px; }
.sub { color: var(--muted); margin-bottom: 24px; }
details { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
          margin-bottom: 12px; }
summary { cursor: pointer; padding: 10px 14px; font-weight: 600; }
.body { padding: 0 14px 14px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { color: var(--muted); font-weight: 600; white-space: nowrap; }
code { font: 12px/1.4 ui-monospace, monospace; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 10px; color: #fff;
        font-size: 12px; font-weight: 600; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px;
       border: 1px solid var(--line); color: var(--muted); margin-right: 4px; }
.bar { display: inline-block; width: 60px; height: 8px; border-radius: 4px;
       background: var(--line); overflow: hidden; vertical-align: middle; }
.bar i { display: block; height: 100%; background: currentColor; }
.cut { color: #b3261e; font-weight: 600; }
.legend span { margin-right: 12px; font-size: 12px; color: var(--muted); }
.legend b { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
            margin-right: 4px; }
svg { max-width: 100%; height: auto; }
"""

ROW = 34  # px between graph rows
TOP = 26
SOURCE_X = 250
STEP_X = 380
STEP_W = 300


def _e(value: object) -> str:
    """Escape anything before it reaches the page. Attributes included."""
    return html.escape(str(value), quote=True)


def _label(source: dict) -> str:
    """How a source's label reads on hover, endorsement included (schema 3)."""
    text = f"{source.get('trust')} via {source.get('origin') or '?'}"
    if source.get("endorsed_by"):
        text += f", endorsed by {source['endorsed_by']}"
    return text


def sources_of(event: dict) -> list[dict]:
    """The labelled influence set, or bare ids with an explicit UNKNOWN for schema 1."""
    if "sources" in event:
        return list(event["sources"])
    return [
        {"id": source_id, "trust": "UNKNOWN", "origin": "", "confidential": False}
        for source_id in event.get("source_ids", ())
    ]


def by_run(events: Iterable[dict]) -> dict[str, list[dict]]:
    """Group events by run, each run's steps in the order the log wrote them."""
    runs: dict[str, list[dict]] = {}
    for event in events:
        runs.setdefault(str(event.get("run_id", "?")), []).append(event)
    return runs


def _pill(verdict: str) -> str:
    colour = VERDICT_COLOUR.get(verdict, "#6b6b6b")
    return f'<span class="pill" style="background:{_e(colour)}">{_e(verdict)}</span>'


def _risk(risk: object) -> str:
    """The score as a bar and a number. `n/a` is a defense with no score, not a zero."""
    if risk is None:
        return '<span class="tag">n/a</span>'
    value = max(0.0, min(1.0, float(risk)))
    colour = "#b3261e" if value >= 0.8 else "#c77800" if value >= 0.25 else "#2e7d32"
    return (
        f'<span class="bar" style="color:{colour}"><i style="width:{value * 100:.0f}%"></i></span>'
        f" {value:.2f}"
    )


def graph(steps: Sequence[dict]) -> str:
    """The provenance graph for one run: sources on the left, actions on the right.

    An edge is drawn for every source that influenced a step, coloured by *that source's*
    trust rather than by the meet, so the one adversary-controlled read among five
    trusted ones is visible as the edge it is. Edges into a step the gateway did not
    execute are dashed and red: that is the cut, and seeing it is the point of the view.
    """
    order: list[dict] = []
    seen: set[str] = set()
    for step in steps:
        for source in sources_of(step):
            if source["id"] not in seen:
                seen.add(source["id"])
                order.append(source)
    rows = max(len(order), len(steps), 1)
    height = TOP + rows * ROW
    parts = [
        f'<svg viewBox="0 0 {STEP_X + STEP_W + 20} {height}" width="{STEP_X + STEP_W + 20}" '
        f'height="{height}" role="img" aria-label="provenance graph">'
    ]
    y_of = {source["id"]: TOP + index * ROW for index, source in enumerate(order)}
    step_y = [TOP + index * ROW for index in range(len(steps))]

    for step_index, step in enumerate(steps):
        cut = step.get("outcome") != "executed"
        for source in sources_of(step):
            colour = TRUST_COLOUR.get(str(source.get("trust")), TRUST_COLOUR["UNKNOWN"])
            dash = ' stroke-dasharray="4 3"' if cut else ""
            parts.append(
                f'<line x1="{SOURCE_X + 6}" y1="{y_of[source["id"]]}" x2="{STEP_X}" '
                f'y2="{step_y[step_index]}" stroke="{_e(colour)}" stroke-width="1.5" '
                f'opacity="{0.55 if cut else 0.85}"{dash} />'
            )

    for source in order:
        colour = TRUST_COLOUR.get(str(source.get("trust")), TRUST_COLOUR["UNKNOWN"])
        y = y_of[source["id"]]
        label = source["id"] + (" 🔒" if source.get("confidential") else "")
        # The <title> is a child of the circle, not a sibling of it: an SVG <title> at
        # top level names the whole image, so a stray one replaces the graph's own label
        # with whichever source happened to be drawn first.
        parts.append(
            f'<text x="{SOURCE_X - 12}" y="{y + 4}" text-anchor="end" font-size="12" '
            f'fill="currentColor">{_e(label)}</text>'
            f'<circle cx="{SOURCE_X}" cy="{y}" r="5" fill="{_e(colour)}">'
            f"<title>{_e(_label(source))}</title>"
            f"</circle>"
        )

    for step_index, step in enumerate(steps):
        y = step_y[step_index]
        colour = VERDICT_COLOUR.get(str(step.get("verdict")), "#6b6b6b")
        executed = step.get("outcome") == "executed"
        parts.append(
            f'<rect x="{STEP_X}" y="{y - 11}" width="{STEP_W}" height="22" rx="5" '
            f'fill="none" stroke="{_e(colour)}" stroke-width="1.5" '
            f"{'' if executed else 'stroke-dasharray="4 3" '}/>"
            f'<text x="{STEP_X + 10}" y="{y + 4}" font-size="12" fill="currentColor">'
            f"{_e(f'{step.get("step")}. {step.get("tool")}')}"
            f'<tspan fill="{_e(colour)}"> · {_e(step.get("verdict"))}</tspan>'
            f'<tspan opacity="0.7"> · {_e(step.get("outcome"))}</tspan></text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def timeline(steps: Sequence[dict]) -> str:
    """One row per mediated action: the decision chain, left to right, in order."""
    head = (
        "<tr><th>#</th><th>action</th><th>influenced by</th><th>integrity</th>"
        "<th>policy</th><th>verdict</th><th>risk</th><th>reasons</th><th>outcome</th></tr>"
    )
    rows = []
    for step in steps:
        influences = "".join(
            f'<span class="tag" style="border-color:'
            f'{_e(TRUST_COLOUR.get(str(s.get("trust")), TRUST_COLOUR["UNKNOWN"]))}" '
            f'title="{_e(_label(s))}">'
            f"{_e(s['id'])}{' 🔒' if s.get('confidential') else ''}"
            f"{' · endorsed' if s.get('endorsed_by') else ''}</span>"
            for s in sources_of(step)
        )
        args = ", ".join(_e(name) for name in step.get("arg_names", ()))
        rewritten = step.get("rewritten_tool")
        action = f"<code>{_e(step.get('tool'))}({args})</code>"
        if rewritten:
            action += f" &rarr; <code>{_e(rewritten)}</code>"
        outcome = str(step.get("outcome", "?"))
        rows.append(
            f"<tr><td>{_e(step.get('step'))}</td><td>{action}</td>"
            f"<td>{influences or '<span class=tag>none</span>'}</td>"
            f'<td><span class="tag" style="border-color:'
            f'{_e(TRUST_COLOUR.get(str(step.get("integrity")), TRUST_COLOUR["UNKNOWN"]))}">'
            f"{_e(step.get('integrity'))}</span>"
            f"{' 🔒' if step.get('confidential') else ''}</td>"
            f"<td><code>{_e(step.get('policy'))}@{_e(step.get('policy_version'))}</code></td>"
            f"<td>{_pill(str(step.get('verdict')))}</td><td>{_risk(step.get('risk'))}</td>"
            f"<td>{' '.join(f'<code>{_e(code)}</code>' for code in step.get('reason_codes', ()))}"
            f"</td>"
            f'<td class="{"cut" if outcome != "executed" else ""}">{_e(outcome)}</td></tr>'
        )
    return f"<table>{head}{''.join(rows)}</table>"


def _legend() -> str:
    trust = "".join(
        f'<span><b style="background:{_e(colour)}"></b>{_e(name)}</span>'
        for name, colour in TRUST_COLOUR.items()
    )
    return (
        f'<p class="legend">{trust}</p>'
        '<p class="legend"><span>A dashed edge is an influence the decision cut: '
        "the action it fed never reached the world.</span></p>"
    )


def render(events: Sequence[dict], *, title: str = "Tekmor trace") -> str:
    """The whole log as one self-contained page, one collapsible section per run."""
    runs = by_run(events)
    sections = []
    for run_id, steps in runs.items():
        verdicts = [str(step.get("verdict")) for step in steps]
        stopped = sum(step.get("outcome") != "executed" for step in steps)
        summary = (
            f"{_e(run_id)} &nbsp;<span class=tag>{len(steps)} steps</span>"
            + "".join(f"&nbsp;{_pill(verdict)}" for verdict in dict.fromkeys(verdicts))
            + (f' &nbsp;<span class="cut">{stopped} not executed</span>' if stopped else "")
        )
        sections.append(
            f"<details><summary>{summary}</summary><div class='body'>"
            f"{timeline(steps)}{graph(steps)}</div></details>"
        )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_e(title)}</title><style>{CSS}</style></head><body>"
        f"<h1>{_e(title)}</h1>"
        f"<p class='sub'>{len(events)} decisions across {len(runs)} runs. "
        "Rendered from the decision log; nothing here is ground truth.</p>"
        f"{_legend()}{''.join(sections)}</body></html>"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path, help="a decisions.jsonl written by EventLog")
    parser.add_argument("-o", "--out", type=Path, help="default: timeline.html beside the log")
    args = parser.parse_args(argv)

    out = args.out or args.log.parent / "timeline.html"
    out.write_text(render(read(args.log), title=args.log.parent.name or "Tekmor trace"), "utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
