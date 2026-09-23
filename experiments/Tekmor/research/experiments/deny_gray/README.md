# deny-gray: the control Proposal B was never read against

**Status: pre-registered. Written and committed before the first run.**

## Why this exists

`docs/07-results.md` — *"Proposal B on a GPU"* — measured Qwen3-8B (NF4) and Phi-3-mini
(fp16) as gray-zone judges on AgentDojo v1.2.2. Both drove pooled ASR to 0.00 and cost
about a fifth of benign utility (BTU 0.69 → 0.49 and 0.47). Both also refused almost
everything they were asked: Qwen3-8B answered below the threshold on 852 of 858 calls,
Phi-3-mini on 840 of 849.

That entry closes with the gap this experiment fills, in its own words:

> **Open.** A `deny-gray` baseline (refuse every gray-zone ALLOW, no judge) on the same
> AgentDojo configuration. That is the comparison that decides whether any judge here
> adds anything.

Until that row exists, the two judge rows cannot be read. A defense that refuses 99% of
the gray zone and a defense that refuses 100% of it are the same defense to within six
calls, and neither number tells you whether *judging* did any work. This is that row.

## What is being measured

**Not a new mechanism.** `RefuseAll` (`src/tekmor/defense/baselines.py`) is a `Judge`
that returns 0.0 for every question. Wrapped in the existing `AlignmentAuditor`, it holds
the gray-zone definition (`auditor.gray`), the REWRITE-else-ESCALATE fallback and the
monotone fusion fixed, so the arms differ in the judge and nothing else. This is a
control, not a proposal, and it is filed under `baselines.py` for the same reason
`deny-sensitive` is: it exists to be beaten.

Run as `uv run python -m evaluation.alignment --judge none --endorse [--dojo]`, which
loads no model. Endorsement is on because that is the setting the auditor is for.

## Hypotheses

**H1 (derivable, stated as arithmetic, not as a guess).** `RefuseAll` refuses a superset
of what any judge at the same threshold refuses, so on identical inputs
BTU(deny-gray) ≤ BTU(judge) and ASR(deny-gray) ≤ ASR(judge), for both judges, on both
sets. Refuted by any run where deny-gray scores *higher* BTU or *higher* ASR than a judge
row. That would mean the arms are not comparable — a harness fault, not a finding.

**H2 (the question).** The judges were refusal switches, not alignment checkers. Measured
as the benign utility a judge recovers over deny-gray at equal ASR:

    gain(judge) = BTU(judge) − BTU(deny-gray),  where ASR(judge) == ASR(deny-gray)

H2 is **supported** if `gain ≤ 0.02` pooled on AgentDojo for both judges — i.e. the
judges' entire measured effect is reproduced by refusing the zone without asking anyone.
H2 is **refuted** if either judge recovers `gain ≥ 0.05` at no ASR cost, which would mean
the judgement was doing real work and the "built, not adopted" verdict was reached on an
incomplete comparison.

The band between 0.02 and 0.05 is deliberately left undecided: with 97 benign runs, two
to five runs is not a result either way, and pre-committing to call it one would be
fitting a conclusion to a resolution this harness does not have.

## Predictions, computed before the run

From the recorded rows, since the driver is deterministic and replays ground truth:

| set | predicted deny-gray | why |
|---|---|---|
| matrix (26) | BTU 0.75, ASR 0.06, 70 escalations, the same 3 flips | Phi-3-mini answered below threshold on 61 of 61 matrix calls, so it *is* deny-gray there; its recorded row must reproduce exactly |
| AgentDojo (583 pairs) | ASR 0.00 | Qwen3-8B reached 0.00 and deny-gray refuses a superset, so by H1 it can only be ≤ 0.00 |
| AgentDojo (97 benign) | BTU ≤ 0.47 | the lower of the two judge rows, by H1 |

**A validity check runs with it.** The `tekmor` row in the same run must reproduce
BTU 0.69 / ASR 0.15 from the endorsement entry. If it does not, this run is not
comparable with the GPU rows and nothing below may be read against them. This matters
more than usual here: the GPU runs happened on an ephemeral Colab VM whose `runs.jsonl`
and `decisions.jsonl` are lost, so the recorded processed metrics are the only surviving
record, and the only thing that can tie this run to them is a matching unaudited row.

## Limits, stated in advance

- **The agent is scripted.** `FooledAgent` replays ground truth and obeys every
  injection, so ASR is the always-obeys bound and BTU is "would the policy have permitted
  the oracle trace". Every limit recorded for the AgentDojo entries applies unchanged.
- **This measures the judges already run, not judges in general.** A frontier judge is
  not measured here and nothing below says anything about one. Task Shield's and
  AlignmentCheck's numbers stay out of the comparison.
- **A supported H2 is not evidence that alignment checking cannot work.** It is evidence
  that these two judges, at this threshold, on this benchmark, did not do it. The
  distinction is the whole point of running the control rather than assuming it.
- Escalation counts are reported as the deferral load a human would carry. No run here
  has a human in it: an ESCALATE is scored as a refusal, as everywhere else in this
  project.

---

# Results

Run at commit `7b88710` (this file's pre-registration commit), clean tree, CPU, no model
loaded. Full tables in `docs/07-results.md`; this section records the gates only.

## Against the pre-registered gates

**Validity check: passed.** The unaudited `tekmor` row reproduced BTU 67/97 and
ASR 85/583 — the exact counts from the endorsement entry — so this run is comparable with
the GPU rows whose raw output was lost.

**Predictions: all landed.** Matrix BTU 0.75, ASR 0.06, 70 escalations, and the same three
flips, every value computed in advance. AgentDojo ASR 0.00 as H1 required, BTU 0.45,
which is under the predicted ceiling of 0.47.

**H1: verified, no violation.** On every suite and both sets, deny-gray scored no higher
than either judge on either axis. The arms are comparable.

**H2: undecided by its own gate, and recorded that way.**

| judge | BTU | gain over deny-gray | verdict |
|---|---|---|---|
| deny-gray | 44/97 = 0.454 | — | — |
| Phi-3-mini fp16 | 46/97 = 0.474 | 2/97 = 0.021 | undecided band |
| Qwen3-8B NF4 | 48/97 = 0.495 | 4/97 = 0.041 | undecided band |

Both land inside the 0.02–0.05 band committed in advance as not a result at 97 benign
runs. Phi-3-mini's sits 0.0006 above the supported threshold and is not rounded into it.
The band was set before the numbers existed precisely so this could not be decided after
seeing them.

## Observed, independent of the gate

Three AgentDojo suites of four — banking, slack, travel — are identical to the last digit
under deny-gray and under both judges, on BTU and ASR. So is the entire matrix. Every
measurable difference between judging and refusing is in workspace: 18/40 benign runs
under deny-gray, 20/40 under Phi-3-mini, 22/40 under Qwen3-8B.

## An unplanned second run, and what it is worth

Running without `--endorse` was not pre-registered; it was added because the GPU entry
flagged its `tekmor`-without-endorsement comparison as coming from a separate run. Within
one run, deny-gray strictly dominates the core: identical BTU (44/97 both), and the 21
remaining attacks removed. Endorsement and deny-gray cancel exactly, which follows from
`auditor.gray` reading `Source.trust` rather than the endorsed `integrity`.

**This arm is exploratory and is labelled as such.** It was not pre-registered, its gate
was not set in advance, and its headline — equal BTU — is the number this driver is
weakest at: deny-gray refuses far more benign actions than the core (travel FBR
0.05 → 0.84) and completes the same tasks only because ground-truth replay scores success
from world state. Treat the dominance as a hypothesis for a model-driven run, not a
result.

## Interpretation, kept apart from the above

The earlier entry inferred from answer distributions that both judges were acting as
gray-zone refusal switches. This measures that inference directly and it holds: the switch
reproduces them almost everywhere. The consequence for Proposal B is procedural rather
than numerical — a judge's row against `tekmor` mostly measures the refusal, so from here
a judge is scored against `deny-gray`.

## Not claimed

Nothing about a frontier judge, which was not run. Nothing about a model-driven agent: ASR
is the always-obeys bound and BTU is "would the policy have permitted the oracle trace".
The two judge rows are the recorded GPU numbers, not reruns.
