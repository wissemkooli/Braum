# SENTINEL research report template

No page limit. Report component metrics as evidence for your claims, not as an official score —
there is no official score; judging is against the rubric in [scoring.md](scoring.md). Include the
benchmark version and any scorecard digests you cite so a reader can trace them back to a run.

## 1. Abstract

100–200 words: the problem, your method, your main quantitative result (BTU, ASR, CVR, FBR — see
[scoring.md](scoring.md)), and the most important limitation.

## 2. Threat model

- Which attack families and surfaces does your defense target?
- What does the adversary know (payloads, your decisions, adaptivity)?
- What is explicitly out of scope?

## 3. Hypothesis

One or two falsifiable statements, for example: "Tracking which untrusted sources influenced an
action's arguments reduces ASR on indirect injection by at least half with less than 5% FBR."

## 4. Method

- Architecture diagram: where the defense sits (input, planning, retrieval, memory, tool authorization, output).
- Signals used (provenance, action structure, model internals, history) and how decisions are made —
  and how this stays within the Defense Rules (no scenario-id or expected-outcome hard-coding).
- Training data, objectives, and hyperparameters for any learned component.
- How `risk_score` and `confidence` are produced and calibrated; when you escalate and when you rewrite.

## 5. Experiments

- What you ran the published scenario library against, plus any extra self-test scenarios you
  authored (see [scenario-authoring.md](scenario-authoring.md)).
- Models, hardware, seeds, and the reference agent configuration (`mock` vs. `qwen3-8b`).
- Baselines compared: at least `allow_all`, `provenance`, and one other.

## 6. Results

| Defense | BTU | ASR | CVR | FBR | UER | TUI | DFI | Brier | ECE | p95 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| allow_all | | | | | | | | | | |
| provenance | | | | | | | | | | |
| ours | | | | | | | | | | |

Also break results down by domain and attack family, and include AgentDojo results if you attempted
the optional bonus track.

## 7. Ablations

Remove or modify at least one major component. Report the metric deltas and what they imply about
the hypothesis.

## 8. Failure analysis

Concrete failure categories with replay excerpts (`sentinel replay`): missed attacks, false blocks,
unnecessary escalations, and calibration errors. Explain the root cause of each category — this is
the section judges weight most heavily after the video itself.

## 9. Responsible AI and security considerations

- What the defense protects against and its known failure modes.
- Expected false-positive behavior and who bears its cost.
- What data the defense observes and whether any user content is stored.
- When humans should be consulted; how explanations and reason codes are generated.
- Performance differences across domains.

## 10. Reproducibility

- Repository commit or release tag.
- Exact commands to build, run, and self-test, for example:

```bash
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json > results/public.json
```

- Declared external models and datasets, with licenses.
- Deterministic digests of any scorecards you report.
