# 5. Design proposals — what was considered, chosen, and what became of it

Before building anything, eight candidate mechanisms and three whole-system designs were
written down with a hypothesis each. This document records them, the choice made, and the
outcome — including the ones that failed.

---

## 5.1 The eight candidate mechanisms

Each was stated as a falsifiable hypothesis rather than a feature.

| # | Name | Hypothesis | Outcome |
|---|---|---|---|
| 1 | **PROV-GATE** | Enforcing integrity and confidentiality labels at the tool boundary blocks indirect injection and exfiltration with bounded utility loss | **Adopted — the core** |
| 2 | **CAP-REWRITE** | Mapping risky tools to reversible variants preserves utility while removing blast radius | **Adopted** |
| 3 | **TASK-ALIGN** | Actions that do not advance the user's goal are the attack surface; score alignment and stop the rest | **Built, not adopted** |
| 4 | **DRIFT-PROBE** | Task drift is linearly decodable from the model's internal activations | **Failed its gate, demoted** |
| 5 | **MASK-REEXEC** | If re-running with the user's request masked produces the same call, that call was injection-driven | **Not implemented** |
| 6 | **POLICY-DSL** | Declarative per-domain policies give deterministic, auditable least privilege | **Adopted** |
| 7 | **CALIB-RISK** | A calibrated risk score with deferral thresholds beats fixed thresholds | **Half implemented; negative result** |
| 8 | **CANARY-FLOW** | Tagging secrets and scanning outbound arguments across encodings catches exfiltration | **Adopted as a layer** |

### Why these three were adopted together

PROV-GATE, CAP-REWRITE, POLICY-DSL and CANARY-FLOW form a complete, deterministic,
legible core:

- **PROV-GATE** supplies the guarantee that survives rewording.
- **POLICY-DSL** supplies the deployment-specific "what is sensitive here".
- **CAP-REWRITE** supplies the escape from the block-everything failure mode.
- **CANARY-FLOW** covers the one residual the label-based rule structurally cannot see.

The deliberate constraint was to **avoid stacking two expensive LLM-judge layers**, which
would multiply latency and add adaptive attack surface without adding a guarantee.

### Why MASK-REEXEC was not implemented

The idea is elegant: run the agent twice, once with the user's request masked out. Any tool
call that appears in *both* runs cannot have been caused by the user's request, so it was
caused by something the agent read. The published version reports over 99% prevention.

It was not built because it **doubles inference cost** on every step and the project's core
was chosen to be deterministic and CPU-only. It remains a reasonable extension.

### CALIB-RISK, and an honest negative result

The idea was to make the risk score a calibrated probability and use thresholds to decide
when to defer to a human.

Half of it was built: the score is Platt-scaled against held-out runs and its calibration
error is measured. The result was a genuine reversal worth recording — on a seven-scenario
test set, calibration made the error **worse** (0.11 → 0.12). On the full twenty-six
scenario set it made it **better** (0.07 → 0.04). Twenty-one scored actions was simply not
enough to fit anything, and the larger set is what revealed that.

The other half — letting thresholds *decide* — was deliberately **declined**. That would
give a fitted number authority over a verdict the auditable rules produce, which is the
trade rejected in [3.6](03-architecture.md#36-the-risk-score-describes-it-does-not-decide).

## 5.2 The three whole-system proposals

### Proposal A — deterministic information-flow reference monitor

The core described throughout these documents. Labels, rules, capability downgrade; no
model in the decision path.

*Strengths:* deterministic, auditable, CPU-only, resistant to adaptive attack because it
never reads attack text.
*Weakness:* over-tainting. Taint propagation is conservative, and conservatism costs
utility.

### Proposal B — Proposal A plus a task-alignment auditor

Add an LLM judge to the **gray zone**: actions the rules *allowed* even though something
below the integrity threshold influenced them. Those are exactly the actions whose
provenance cannot distinguish attack from legitimate work. The judge is asked one question:
*does this call serve what the user asked for?*

*Strengths:* covers what provenance alone cannot separate.
*Weaknesses:* LLM in the loop means latency, non-determinism, and a new adaptive attack
surface — the judge itself can be targeted.

### Proposal C — Proposal A plus an activation-drift probe

Train a linear probe on the model's residual-stream activations to detect *task drift* —
the moment the model's internal representation of its goal shifts. Based on the TaskTracker
line of work.

*Strengths:* the most novel; uses interpretability as a live sensor rather than an analysis
tool.
*Weaknesses:* requires GPU access to the actual agent model; a probabilistic signal that
must never be load-bearing.

## 5.3 The choice, and the reasoning

**Proposal A was chosen as the stable core**, with B and C as research extensions gated on
evidence.

The reasoning was explicit: B and C both depend on the deterministic core carrying the
security guarantee. Building either first would produce a defense whose reliability rests
on a probabilistic signal — which is the failure mode the whole project exists to avoid.

Three thresholds were fixed **in advance**:

1. If benign utility falls below ~0.7 on benign and hard-negative scenarios, add an
   endorsement primitive **before** adding any new signal.
2. Observability is first-class: someone must be able to reconstruct any decision's causal
   chain from the trace alone.
3. Keep the drift probe **only if** its false-positive rate on hard negatives is below ~10%
   **and** it catches at least one attack the core misses. Otherwise demote it.

Writing gates down before running is what makes the outcomes below meaningful rather than
retrofitted.

## 5.4 What happened to each

### Endorsement — kept, opt-in

Threshold 1 fired. AgentDojo drove benign utility to 0.45, well under 0.7, so the
endorsement primitive was added as the recommendation prescribed. It is a measured trade
(see [4.5](04-provenance-and-trust.md#45-endorsement-buying-utility-back)) and stays
opt-in rather than default.

### Proposal B — built, measured, **not adopted**

The auditor was built correctly: gray zone only, monotone-safe, the judge sees the user's
task and the proposed call but never the documents the agent read.

Two judges were run on a GPU. Both drove attack success to zero, at the cost of roughly a
fifth of benign utility. That looked like a defensible trade — until the control was run.

**The control is the finding.** Running the *same mechanism with a judge that always says
no* — refuse every gray-zone action, ask nothing — reproduced both judges almost exactly:
identical on three of four AgentDojo suites and identical on the entire internal test set.
The judges' whole measurable contribution was 4 benign runs out of 97 for one and 2 for the
other, inside a band pre-registered as unresolvable at that sample size.

The judges were not checking alignment. They were **refusal switches** that happened to
have a model attached. The verdict stands as built and not adopted, and one procedural rule
now follows from it: **a judge must be scored against the refuse-everything control, never
against the bare core.** The gap to the bare core is dominated by the refusal and says
almost nothing about the judging.

### Proposal C — failed its gate twice, **demoted**

Run as a pre-registered experiment, first on a small proxy model and then on the reference
model.

| Evaluation set | AUROC (0.6B) | AUROC (8B) | False positives (8B) |
|---|---|---|---|
| Synthetic validation | 0.99 | 0.99 | 0.00 |
| Internal test set (held out) | 0.82 | 0.83 | 0.25 |
| AgentDojo (held out) | 0.58 | 0.65 | 0.91 |

Near-perfect on synthetic data, near-useless on real tool output. On AgentDojo the 8B probe
flagged 88 of 97 *clean* runs.

The diagnosis: **the probe learned that external text arrived, not that an instruction
arrived.** Those two things are perfectly correlated in synthetic training data and not at
all correlated in real agent traces.

Model size did not fix it. The gate was applied as written and Proposal C is future work.
Reviving it needs training data in the target register — real tool outputs and business
documents — which is a data-collection problem, not a modelling one.

### Argument-level provenance and field labels

Both built, both measured, both **off**. See
[4.6](04-provenance-and-trust.md#46-finer-granularity-built-measured-switched-off).

## 5.5 What the scoreboard actually says

Of the research extensions: one kept as opt-in (endorsement), one reproduced by a control
with no model in it (B), one failed its gate twice (C), and two finer-grained mechanisms
built and switched off.

That is a low hit rate, and it is reported rather than hidden. The value of writing gates
down in advance is precisely that they can be failed. Three of these outcomes would have
been easy to present as successes by choosing a different comparison after the fact — most
obviously Proposal B, which looks like a strong result right up until the control is run.
