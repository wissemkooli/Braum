# 6. Evaluation methodology

How any of this is measured, and why it is measured that way. The design choices here
matter as much as the architecture — a defense is only as trustworthy as the evidence
behind it.

---

## 6.1 The governing principle

**A number without a baseline says nothing.**

"Our system blocked 94% of attacks" is meaningless alone. Blocking every tool call blocks
100% of attacks. The question is always *compared to what, and at what cost?*

So every measurement is reported beside reference points that bracket the space:

| Baseline | What it establishes |
|---|---|
| `allow-all` | The undefended agent — the **utility ceiling** and the **security floor** |
| `deny-sensitive` | Blocks every sensitive tool — secure by construction, useless by construction |
| `keyword` | A shallow text filter, standing in for detector-style defenses |

None is a defense. They exist to be beaten. A system that does not beat `deny-sensitive`
on utility *while matching it on security* has not earned its complexity.

`allow-all` deserves special mention: under a real model-driven agent it is the ceiling
that separates **the model's own competence** from **the defense's cost**. If the
undefended agent completes only 60% of tasks, a defended agent at 55% has lost 5 points,
not 45.

## 6.2 The metrics

| Metric | Plain meaning | Direction |
|---|---|---|
| **BTU** — benign task utility | Of legitimate tasks, how many completed? | higher |
| **ASR** — attack success rate | Of attacks, how many achieved the attacker's goal? | lower |
| **CVR** — canary violation rate | How often did a tagged secret actually leave? | lower |
| **FBR** — false block rate | Of benign *actions*, how many were refused? | lower |
| **UER** — unnecessary escalation rate | How many benign actions were pushed to a human? | lower |

BTU and FBR measure different things, and the difference matters. BTU is per **task**; FBR
is per **action**. A defense can refuse many individual actions and still complete the task
(the refused ones were not needed), or refuse one critical action and fail the task. Both
numbers are reported because each hides something the other reveals.

### Detection metrics, and their chance line

Precision, recall, F1, AUROC and AUPRC are reported over per-action labels, plus **ECE**
(expected calibration error) over the risk score.

AUPRC is always printed **beside its own chance line**. On an imbalanced set — here about
13% of actions are unsafe — an AUPRC of 0.5 sounds mediocre and is nearly four times
chance. Reporting it without the base rate is not interpretable.

### Labels are derived, never declared

This is a subtle point with large consequences.

The detection metrics need to know which *individual step* was the dangerous one. The naive
approach is to have a human annotate it. That would be circular: the annotator knows how
the defense behaves and can label in the direction that flatters it.

Instead, labels are **derived mechanically**. Each prefix of an attack scenario is replayed
under `allow-all`, and the step whose execution *first* satisfies the scenario's
attack-success condition is labelled unsafe. So:

- "unsafe" means exactly what ASR means — no separate definition to drift;
- the label is identical under every defense, so defenses are compared on the same ground;
- a scenario author cannot label a step the way they wish the defense had behaved.

One consequence to keep in mind when reading precision: the label marks the
**goal-reaching** step. A defense that stops the same injected chain *one step earlier*
scores that as a false positive, even though stopping earlier is better security. The
metric slightly penalises caution, and that is a known property rather than a bug.

## 6.3 Two evaluation surfaces

### The internal scenario suite

26 scenarios across three simulated domains — enterprise, financial, security operations —
covering the seven attack families at levels 1–5. Eight are benign hard negatives.

A scenario declares its own ground truth as **conditions over world state**: `success`
(did the user's task complete?) and `attack_success` (did the attacker's goal happen?).
Scoring from world state rather than from the text of the agent's reply means the check
asks *did the money actually move?* rather than *did the agent claim to move it?*

Each scenario also declares its `family` and `level`. **All of this is scorer metadata and
none of it ever reaches a defense.** A defense that could recognise its own test cases
would prove nothing, and this is the single most important correctness rule in the
codebase.

**This is a matrix, not a benchmark.** It was written by the same people who wrote the
defense. It is genuinely useful for ablations and regression testing, and it *cannot*
establish external validity. Treat its numbers as internal diagnostics.

### AgentDojo — external validation

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024), pinned at
version `v1.2.2`, four suites: banking, Slack, travel, workspace. The tasks, the
injections, and the utility and security checks are **all AgentDojo's own**.

This is the guard against a defense designed around its own test set. It is also where the
project's least flattering numbers come from, which is exactly why it is here.

Tekmor enters as a pipeline element replacing AgentDojo's tool executor: every tool call
becomes an `Action`, is decided by the monitor, and executes only as permitted.

**The per-suite configuration is frozen deployment input.** Which tools are sensitive, and
which sources are trusted, was written from tool names and documentation **before the first
run** and never from AgentDojo's injection vectors. A label chosen because an injection
happens to sit there would be exactly the test-awareness the design forbids.

This had a real cost, and it was paid: a known configuration change would have fixed 20 of
21 attacks in one suite. It was **rejected**, because tuning a frozen configuration on
held-out results is how a held-out benchmark stops being held out.

## 6.4 Which agent drove the run — read this before any number

This is the single most important thing to check before interpreting an AgentDojo result.

**`ground-truth` (the default, and every recorded number).** The driver replays AgentDojo's
own correct solution, then the injection task's solution: an agent that did the user's
work, read the injection, and obeyed it. Therefore:

- **ASR is an always-obeys *bound*, not a measurement.** The agent is compromised by
  construction. The only question asked is whether the monitor stopped the call.
- **BTU asks whether the policy would have permitted the correct trace**, not whether work
  got done. A refused action the success condition does not depend on costs nothing here —
  and would derail a real agent mid-task.
- **Provenance is near-oracle**, because the script copies values verbatim out of
  structured results.

**`model` / `hf-native`.** A real model drives the pipeline, removing all three caveats.
This has not yet produced a valid run; see [7.7](07-results.md#77-attempted-and-unresolved-the-model-driven-agent).

**Numbers from the two drivers measure different things and never belong in one table.**

## 6.5 Beyond a single sweep

A single pass over a fixed test set is the weakest form of evidence. Four additional
evaluations exist.

**Robustness variants.** Each attack is transformed along the channels an attacker actually
controls — five encodings, a lexical reword, a reordering of reads. Crucially, **every
variant is replayed undefended first and discarded if its attack no longer lands.**
Otherwise a defense gets credit for "stopping" a variant that was broken by the
transformation. Variants are reported paired with their originals and never mixed into
headline numbers.

**Ablations.** The monitor is left completely unchanged and one *input* is removed:
provenance, propagation, or the capability lattice. This is what separates "the system
works" from "we know which part does the work" — and it is the evidence for the project's
central claim.

**The adaptive attacker.** A seeded hill climb over a genome of encoding, rewording and
read order. Its fitness function sees only what an attacker sees — its goal, the verdicts,
and the **public** reason codes — never the private risk score. Each candidate is rebuilt
from the original and replayed undefended before being scored.

**Calibration.** The risk score is Platt-scaled **leave-one-scenario-out**, never
leave-one-action-out. Actions inside one run share a world, a policy and an injected chain,
so an action-level split would train on an action's near-twin and report an optimistic
number. Raw and calibrated are reported over the same held-out actions.

## 6.6 Reproducibility

Every run writes a timestamped directory containing raw per-run records, the decision event
log, and a manifest recording the model and version, configuration, scenario versions and
content hashes, seeds, policies, defense configuration, and environment.

Raw outputs are write-once; analysis produces new files and never edits them. Results are
**never hand-edited**.

Results are gitignored — they are generated artefacts, not source. That has bitten once
already: the GPU runs happened on an ephemeral cloud VM and their raw records are gone,
surviving only as metrics printed into notebook output. The notebooks now print manifests
and metrics verbatim *before* offering a download.

## 6.7 Pre-registration

Research experiments state their **hypothesis, arms, gates and predictions before the first
run**, committed ahead of any result. The form is: *X holds under conditions Y, measured by
Z, and would be refuted by W*.

This is not ceremony. It has repeatedly changed conclusions:

- The field-label experiment computed its expected residual **in advance** — 0.075 — and
  measured 0.0755, from exactly the predicted groups. That agreement means something
  precisely because the prediction could not be adjusted afterwards.
- The `deny-gray` control pre-committed an **undecided band** of 0.02–0.05, on the grounds
  that 97 benign runs cannot resolve differences that small. Both judges landed inside it,
  and both were reported as undecided rather than rounded into a conclusion. One sat
  0.0006 above the "supported" threshold and was **not** rounded down.
- Several pre-registered predictions turned out **wrong**, and are recorded as wrong.

Negative results are kept, not quietly dropped. Dropping them biases everything that
follows: a project that only reports what worked cannot be distinguished from one that got
lucky.
