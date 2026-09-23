"""Regenerate the documentation figures in `assets/` from recorded results.

    uv sync --extra docs --extra agentdojo
    uv run python -m evaluation.harness      # matrix metrics
    uv run python -m evaluation.ablations    # ablation metrics
    uv run python -m evaluation.dojo         # AgentDojo, ground-truth driver
    uv run python assets/figures.py

Every figure is drawn from numbers this repository produced, and the provenance of each
one is explicit:

- **Read from `evaluation/results/processed/`** wherever the run is reproducible on CPU:
  the scenario matrix, the ablations, and the AgentDojo ground-truth sweep. These are not
  transcribed — the script loads the newest matching run and fails if it is absent, so a
  figure cannot silently drift from the results it claims to show.
- **Transcribed from `docs/07-results.md`**, with the entry named in `SOURCE`, only where
  the run cannot be reproduced here: the GPU judge rows and the drift probe (an ephemeral
  Colab VM whose raw records are gone), and the adaptive attacker and argument-granularity
  arms. Those values are quoted, never recomputed, and the figure captions say so.

Nothing here computes a new result. If a number is not already in a results file or in
`docs/07-results.md`, it does not go in a figure.

Matplotlib is the `docs` extra and is needed only to regenerate the images; the committed
PNGs mean a reader never installs it.
"""

from __future__ import annotations

import json
import pathlib
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "evaluation" / "results" / "processed"
OUT = ROOT / "assets"

# A restrained palette: one accent for Tekmor, one for baselines, one for failure.
TEKMOR = "#2f6f9f"
BASELINE = "#9aa4ad"
DANGER = "#c4452d"
GOOD = "#3f8f5f"
GRID = "#dfe3e6"


def style(ax, title, xlabel="", ylabel="", pad=12):
    """Common chart furniture. `pad` lifts the title clear of a legend placed above."""
    ax.set_title(title, fontsize=12, fontweight="bold", loc="left", pad=pad)
    ax.set_xlabel(xlabel, fontsize=9)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.tick_params(labelsize=9)
    ax.set_axisbelow(True)
    ax.grid(True, color=GRID, linewidth=0.8)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)


def newest(pattern: str, must_contain: str | None = None, kind: type = dict) -> dict | list:
    """The most recent processed run matching `pattern`, or a clear failure.

    `kind` separates the two metric shapes: the matrix and the ablations write a dict
    keyed by defense, the AgentDojo sweep writes a list of per-suite rows. Without it a
    glob for the matrix happily matches an AgentDojo run that also contains the defense
    being looked for, and the figure is drawn from the wrong evaluation entirely.
    """
    candidates = sorted(RESULTS.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    for directory in candidates:
        metrics = directory / "metrics.json"
        if not metrics.exists():
            continue
        data = json.loads(metrics.read_text())
        if not isinstance(data, kind):
            continue
        if must_contain is None or must_contain in (
            data if isinstance(data, dict) else {r["defense"] for r in data}
        ):
            print(f"  from {directory.name}")
            return data
    sys.exit(
        f"no processed run matching {pattern!r}"
        + (f" containing {must_contain!r}" if must_contain else "")
        + " — see this module's docstring for the commands that produce one"
    )


def save(fig, name: str) -> None:
    OUT.mkdir(exist_ok=True)
    path = OUT / name
    fig.savefig(path, dpi=170, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  -> assets/{name}")


# --------------------------------------------------------------------------------------
# 1. The matrix: what each defense costs and what it stops
# --------------------------------------------------------------------------------------
def matrix_baselines() -> None:
    print("matrix-baselines.png")
    data = newest("*", must_contain="deny-sensitive")
    order = ["allow-all", "deny-sensitive", "keyword", "tekmor", "tekmor+canary"]
    rows = [(name, data[name]["btu"], data[name]["asr"], data[name]["fbr"]) for name in order]

    fig, ax = plt.subplots(figsize=(8.2, 4.2))
    x = range(len(rows))
    width = 0.27
    ax.bar(
        [i - width for i in x],
        [r[1] for r in rows],
        width,
        label="Benign task utility (higher better)",
        color=GOOD,
    )
    ax.bar(
        list(x),
        [r[2] for r in rows],
        width,
        label="Attack success rate (lower better)",
        color=DANGER,
    )
    ax.bar(
        [i + width for i in x],
        [r[3] for r in rows],
        width,
        label="False block rate (lower better)",
        color=BASELINE,
    )
    ax.set_xticks(list(x))
    ax.set_xticklabels([r[0] for r in rows])
    ax.set_ylim(0, 1.08)
    for i, r in enumerate(rows):
        for offset, value in ((-width, r[1]), (0, r[2]), (width, r[3])):
            ax.text(i + offset, value + 0.02, f"{value:.2f}", ha="center", fontsize=7.5)
    style(
        ax,
        "Scenario matrix: attack success, benign utility and false blocks",
        ylabel="rate",
        pad=34,
    )
    ax.legend(
        fontsize=8,
        frameon=False,
        ncol=3,
        loc="lower left",
        bbox_to_anchor=(0, 1.02),
    )
    # Derived from the loaded run, never typed in: the matrix has grown before and the
    # caption must not keep quoting the numbers it had when this was written.
    tekmor, deny = data["tekmor"], data["deny-sensitive"]
    fig.text(
        0.0,
        -0.06,
        f"Tekmor keeps every benign task (BTU {tekmor['btu']:.2f}, FBR {tekmor['fbr']:.2f}); "
        f"deny-sensitive reaches ASR {deny['asr']:.2f} by keeping {deny['btu']:.0%} of the "
        f"work.\nScripted agent, this repository's own scenarios: see docs/limitations.md.",
        fontsize=7.5,
        color="#555",
    )
    save(fig, "matrix-baselines.png")


# --------------------------------------------------------------------------------------
# 2. Ablations: which component carries the result
# --------------------------------------------------------------------------------------
def ablations() -> None:
    print("ablations.png")
    data = newest("*-ablations")
    order = [
        ("tekmor-no-provenance", "no provenance"),
        ("tekmor-no-propagation", "no propagation"),
        ("tekmor-no-rewrite", "no rewrite"),
        ("tekmor", "full (rules only)"),
        ("tekmor+canary", "full + canary"),
    ]
    rows = [(label, data[key]["asr"]) for key, label in order]

    fig, ax = plt.subplots(figsize=(7.6, 3.8))
    colours = [DANGER if v > 0.3 else (BASELINE if v > 0.08 else GOOD) for _, v in rows]
    bars = ax.barh([r[0] for r in rows], [r[1] for r in rows], color=colours, height=0.6)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.0)
    for bar, (_, value) in zip(bars, rows, strict=True):
        ax.text(
            value + 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{value:.2f}",
            va="center",
            fontsize=8.5,
        )
    style(ax, "Remove one input at a time: attack success rate", xlabel="ASR (lower is better)")
    no_prov = data["tekmor-no-provenance"]["asr"]
    no_prop = data["tekmor-no-propagation"]["asr"]
    fig.text(
        0.0,
        -0.12,
        f"Provenance carries the result: without it {no_prov:.0%} of attacks land. "
        f"Propagation carries its integrity half ({no_prop:.0%}).\nThe rewrite row cannot "
        "move on this matrix, because attack scenarios state no utility condition -- a "
        "recorded\nlimit of the matrix, not a finding about the rewrite.",
        fontsize=7.5,
        color="#555",
    )
    save(fig, "ablations.png")


# --------------------------------------------------------------------------------------
# 3. AgentDojo: the security/utility frontier, and where each mechanism sits on it
# --------------------------------------------------------------------------------------
#: Arms that cannot be reproduced on this machine, quoted from docs/07-results.md.
#: (label, BTU, ASR, label offset in points)
SOURCE = "docs/07-results.md"
AGENTDOJO_QUOTED = [
    ("tekmor+endorse", 0.69, 0.146, (11, 2)),
    ("arguments", 0.55, 0.072, (11, 3)),
    ("arguments+fields", 0.55, 0.038, (11, -5)),
    ("args+endorse", 0.68, 0.110, (11, 2)),
    ("args+endorse+fields", 0.68, 0.0755, (11, -9)),
]

#: Where each cluster label goes inside the magnified panel.
CLUSTER_OFFSETS = {"+ deny-gray": (-16, -17), "+ Phi-3-mini": (-24, 11), "+ Qwen3-8B": (9, -4)}

#: These three sit on top of each other, and that coincidence *is* the deny-gray result:
#: the two judges are reproduced by refusing the gray zone without asking anything. They
#: are drawn as one cluster rather than three labels fighting for the same pixels.
AGENTDOJO_CLUSTER = [
    ("+ deny-gray", 0.454, 0.0),
    ("+ Phi-3-mini", 0.474, 0.0),
    ("+ Qwen3-8B", 0.495, 0.0),
]

#: Where each measured baseline's label goes, so nothing overlaps.
MEASURED_OFFSETS = {
    "allow-all": (-58, 6),
    "keyword": (-52, 6),
    "deny-sensitive": (-34, 12),
    "tekmor": (10, 7),
}


def agentdojo_frontier() -> None:
    print("agentdojo-frontier.png")
    data = newest("*-agentdojo", must_contain="tekmor", kind=list)
    pooled: dict[str, list[float]] = {}
    for row in data:
        acc = pooled.setdefault(row["defense"], [0.0, 0, 0.0, 0])
        acc[0] += row["btu"] * row["benign_runs"]
        acc[1] += row["benign_runs"]
        acc[2] += row["asr"] * row["attack_runs"]
        acc[3] += row["attack_runs"]
    measured = {k: (v[0] / v[1], v[2] / v[3]) for k, v in pooled.items() if v[1] and v[3]}

    fig, ax = plt.subplots(figsize=(8.6, 6.0))

    def draw(target, label_them: bool) -> None:
        """Every point, on the full view or on the zoom. Labels only where there is room."""
        for name, (btu, asr) in measured.items():
            colour = TEKMOR if name.startswith("tekmor") else BASELINE
            target.scatter(btu, asr, s=95, color=colour, zorder=4, edgecolor="white", linewidth=1.2)
            if label_them or name in ("allow-all", "keyword"):
                target.annotate(
                    name,
                    (btu, asr),
                    textcoords="offset points",
                    xytext=MEASURED_OFFSETS.get(name, (10, 6)),
                    fontsize=9,
                )
        for label, btu, asr, offset in AGENTDOJO_QUOTED:
            target.scatter(
                btu, asr, s=70, facecolor="white", edgecolor=TEKMOR, linewidth=1.6, zorder=4
            )
            if label_them:
                target.annotate(
                    label, (btu, asr), textcoords="offset points", xytext=offset, fontsize=8.5
                )
        for name, btu, asr in AGENTDOJO_CLUSTER:
            target.scatter(
                btu, asr, s=70, facecolor="white", edgecolor=TEKMOR, linewidth=1.6, zorder=4
            )
            if label_them:
                target.annotate(
                    name,
                    (btu, asr),
                    textcoords="offset points",
                    xytext=CLUSTER_OFFSETS[name],
                    fontsize=8.5,
                )

    draw(ax, label_them=False)
    ax.set_xlim(0, 1.12)
    ax.set_ylim(-0.05, 1.12)
    style(
        ax,
        "AgentDojo v1.2.2: benign utility against attack success",
        xlabel="Benign task utility (higher is better)",
        ylabel="Attack success rate (lower is better)",
        pad=26,
    )

    # Everything interesting lives in one corner, so it gets its own panel rather than a
    # dozen labels fighting for the same pixels.
    zoom = ax.inset_axes((0.06, 0.46, 0.60, 0.48))
    draw(zoom, label_them=True)
    zoom.set_xlim(0.38, 0.78)
    zoom.set_ylim(-0.022, 0.185)
    zoom.tick_params(labelsize=7.5)
    zoom.set_axisbelow(True)
    zoom.grid(True, color=GRID, linewidth=0.7)
    for side in zoom.spines.values():
        side.set_color("#b9c2c9")
    zoom.set_title("the operating region, magnified", fontsize=9, color="#5b6770", loc="left")
    ax.indicate_inset_zoom(zoom, edgecolor="#b9c2c9", alpha=0.9)

    ax.scatter([], [], s=95, color=TEKMOR, label="measured here (CPU, reproducible)")
    ax.scatter(
        [],
        [],
        s=70,
        facecolor="white",
        edgecolor=TEKMOR,
        linewidth=1.6,
        label=f"quoted from {SOURCE}",
    )
    ax.legend(fontsize=8.5, frameon=False, loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2)
    fig.text(
        0.0,
        -0.04,
        "97 benign and 583 attack runs, pooled over four suites. Bottom-right is better. "
        "deny-gray, Phi-3-mini and\nQwen3-8B coincide at ASR 0.00 -- that is the result: "
        "the judges are reproduced by refusing the gray zone\nunasked. Every point comes "
        "from a driver that replays ground truth and obeys every injection, so ASR is an\n"
        "always-obeys bound, not comparable with CaMeL, FIDES or Task Shield. See "
        "docs/limitations.md.",
        fontsize=7.5,
        color="#555",
    )
    save(fig, "agentdojo-frontier.png")


# --------------------------------------------------------------------------------------
# 4. The adaptive attacker
# --------------------------------------------------------------------------------------
#: Quoted from docs/07-results.md §7.3. Fifty rounds, seeds 0-4, same
#: curve on every seed; the table reports rounds 0, 12, 25, 37, 50.
ADAPTIVE_ROUNDS = [0, 12, 25, 37, 50]
ADAPTIVE = {
    "keyword": [0.88, 1.00, 1.00, 1.00, 1.00],
    "tekmor": [0.06, 0.06, 0.06, 0.06, 0.06],
    "tekmor+canary": [0.00, 0.00, 0.00, 0.00, 0.00],
    "deny-sensitive": [0.00, 0.00, 0.00, 0.00, 0.00],
}


def adaptive() -> None:
    print("adaptive-attacker.png")
    fig, ax = plt.subplots(figsize=(7.4, 4.0))
    colours = {
        "keyword": DANGER,
        "tekmor": TEKMOR,
        "tekmor+canary": GOOD,
        "deny-sensitive": BASELINE,
    }
    for name, series in ADAPTIVE.items():
        ax.plot(
            ADAPTIVE_ROUNDS,
            series,
            marker="o",
            markersize=5,
            linewidth=2,
            color=colours[name],
            label=name,
        )
        ax.annotate(
            f"{series[-1]:.2f}",
            (ADAPTIVE_ROUNDS[-1], series[-1]),
            textcoords="offset points",
            xytext=(8, -3),
            fontsize=8.5,
            color=colours[name],
        )
    ax.set_ylim(-0.05, 1.1)
    ax.set_xlim(-2, 56)
    style(
        ax,
        "Adaptive attacker: attack success rate per round",
        xlabel="hill-climbing round",
        ylabel="ASR",
    )
    ax.legend(fontsize=8.5, frameon=False, loc="center right")
    fig.text(
        0.0,
        -0.09,
        "The attacker sees its goal, the verdicts and the public reason codes -- never the "
        "risk score. The keyword filter\nfalls within five rounds on every seed; the "
        "monitor does not move. Quoted from docs/07-results.md, which also\nrecords that the "
        "flat curve is partly a measurement artefact.",
        fontsize=7.5,
        color="#555",
    )
    save(fig, "adaptive-attacker.png")


# --------------------------------------------------------------------------------------
# 5. The drift probe, which failed its gate twice
# --------------------------------------------------------------------------------------
#: Quoted from docs/07-results.md §7.5 (the 0.6B proxy and the 8B reference run).
PROBE_SETS = ["synthetic\n(validation)", "Tekmor matrix\n(held out)", "AgentDojo\n(held out)"]
PROBE = {"Qwen3-0.6B (proxy)": [0.99, 0.82, 0.58], "Qwen3-8B (reference)": [0.99, 0.83, 0.65]}
PROBE_FPR = {"Qwen3-0.6B (proxy)": [0.00, 0.25, 0.82], "Qwen3-8B (reference)": [0.00, 0.25, 0.91]}


def drift_probe() -> None:
    print("drift-probe.png")
    fig, (left, right) = plt.subplots(1, 2, figsize=(9.6, 3.9))
    x = range(len(PROBE_SETS))
    width = 0.36
    for i, (name, series) in enumerate(PROBE.items()):
        left.bar(
            [v + (i - 0.5) * width for v in x],
            series,
            width,
            color=[TEKMOR, BASELINE][i],
            label=name,
        )
    left.axhline(0.5, color=DANGER, linestyle="--", linewidth=1, label="chance")
    left.set_xticks(list(x))
    left.set_xticklabels(PROBE_SETS, fontsize=8)
    left.set_ylim(0, 1.05)
    style(left, "Drift probe: AUROC", ylabel="AUROC (higher is better)")
    left.legend(fontsize=7.5, frameon=False)

    for i, (name, series) in enumerate(PROBE_FPR.items()):
        right.bar(
            [v + (i - 0.5) * width for v in x],
            series,
            width,
            color=[TEKMOR, BASELINE][i],
            label=name,
        )
    right.axhline(0.10, color=DANGER, linestyle="--", linewidth=1, label="gate: FPR < ~10%")
    right.set_xticks(list(x))
    right.set_xticklabels(PROBE_SETS, fontsize=8)
    right.set_ylim(0, 1.05)
    style(right, "Drift probe: false-positive rate", ylabel="FPR (lower is better)")
    right.legend(fontsize=7.5, frameon=False)

    fig.text(
        0.0,
        -0.10,
        "The probe separates synthetic text and not real tool output: it learned that "
        "*external text arrived*, not that\n*an instruction arrived*. It fails its "
        "pre-registered gate on both held-out sets, at 0.6B and again at 8B, and is "
        "demoted\nto future work. Quoted from docs/07-results.md.",
        fontsize=7.5,
        color="#555",
    )
    save(fig, "drift-probe.png")


if __name__ == "__main__":
    matrix_baselines()
    ablations()
    agentdojo_frontier()
    adaptive()
    drift_probe()
    print("\ndone")
