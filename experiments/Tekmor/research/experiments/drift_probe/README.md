# DRIFT-PROBE: an activation-delta linear probe for task drift (Proposal C)

Status: **hypothesis and method written before the first run** (2026-09-19). Results are
appended below, under their own heading, after the runs. Nothing above that heading is
edited to fit them.

## Hypothesis

A linear probe on residual-stream activation *deltas* separates tool outputs that carry
an injected instruction from ones that do not. The delta is the last-token hidden state
after the agent's context has absorbed the external text, minus the same state before
it (TaskTracker, Abdelnabi et al., "Get my drift?", SaTML 2025, arXiv:2406.00799). The
probe is trained only on synthetic pairs built from text unrelated to either evaluation
set.

**Evidence gate** (`docs/10-research-report.md`, Recommendations 3). The probe earns a place
beside the deterministic core only if, on held-out data:

1. its false-positive rate on benign content, hard negatives included, is **below 10%**
   at the probe's own 0.5 threshold; **and**
2. it flags **at least one attack the deterministic core misses**.

**Refuted by** an FPR of 10% or more on the benign sets, or by catching nothing the core
misses. The gate says the probe is then demoted to future work, and it is.

## The limit that decides the verdict before any number does

Part IX, limit 4: the probe must hook **the same Qwen3-8B the agent uses**. A smaller
proxy model's activations are not evidence about the agent's behaviour. This machine has
no GPU and 15 GB of RAM, and Qwen3-8B does not fit. The experiment is therefore run on
**Qwen3-0.6B as a proxy**. Whatever it shows, it validates the *pipeline* (extraction,
probe, evaluation, gate) and says nothing about Qwen3-8B. **The probe is not integrated
into `src/` on this evidence under any outcome.** A pass on the proxy means "rerun on the
reference model". A fail means "demoted, and rerun on the reference model before
reviving it".

## Method

- **Model.** `Qwen/Qwen3-0.6B`, float32, CPU, `output_hidden_states=True`, chat template
  with thinking off. The representation is the last prompt token at every layer.
- **Delta.** `h(task + data) − h(task)`. Both are the user turn, with the data block
  appended after the task in the first.
- **Training data (synthetic, disjoint from both evaluation sets).**
  - Clean data: WikiText-2 paragraphs (the locally cached `Salesforce/wikitext`,
    `wikitext-2-raw-v1` train split).
  - Primary tasks: generic instructions over a text (summarise, list entities, translate,
    extract dates, and so on).
  - Drift: the same paragraph with an injected instruction inserted at a sentence
    boundary. The instruction comes from a template list, with slot fillers for the
    attacker's action.
  - The split is **by template**: some injection templates and tasks appear only in
    validation.
- **Layer and probe.** Logistic regression with L2 on standardised deltas, in numpy. The
  layer is chosen on the validation split only.
- **Held-out set A, the Tekmor matrix.** Per scenario, the task is the scenario's task
  and the data is each document below `TRUSTED_INTERNAL`. The scenario score is the
  maximum over those documents. Attack scenarios are positives and `over_refusal`
  scenarios are the hard negatives. Scenarios with no untrusted document score 0.
- **Held-out set B, AgentDojo v1.2.2.** Per user task, the data is the concatenated tool
  outputs of its ground-truth calls. The negative is the clean environment. The positive
  is the same calls in the environment the `direct` attack injected, for that suite's
  `injection_task_0`. Contexts are capped at 4096 tokens, and the number truncated is
  reported.
- **Metrics.** AUROC, TPR and FPR at 0.5, per set, and which positives are flagged that
  the core misses: on the matrix the endorsed-invoice attack under endorsement, and on
  AgentDojo slack's URL fetch.
- **Seeds.** Every sampling step uses `random.Random(0)`.

## Amendment (2026-09-19, before any result was seen)

The first run crashed at the last stage. Slack numbers its injection tasks from 1, so
set B's "`injection_task_0`" does not exist in every suite. Set B now uses **each suite's
first injection task by id**. No output of the probe had been printed when this was
changed. Feature extraction is now cached on disk (`results/*.pkl`), so a failure
downstream of it does not repeat the forward passes.

## Assumptions

- WikiText paragraphs stand in for the benign text an agent reads. They are
  encyclopaedic, not business mail, so a probe keyed on register rather than on
  instructions would look good in training and fail on set A. Set A exists partly to
  catch that.
- An injected instruction is the thing that drifts the task. Compositional attacks,
  whose fragments are individually benign, are expected to be missed by construction.

## Results (observed, 2026-09-19)

Run: `uv run --extra qwen --extra agentdojo --with pyarrow python -m
research.experiments.drift_probe.probe` on CPU, 2 493 s. The full report is
`results/report.json` (gitignored, reproduced by rerunning). 160 training pairs and 60
validation pairs. 8 AgentDojo contexts exceeded 4 096 tokens and were truncated head and
tail.

**Layer.** 11 of 28, chosen on validation. Validation AUROC by layer rises from 0.92
(layer 1) to 0.99 (layer 11) and falls to 0.68 at the last layer.

| set | AUROC | TPR at 0.5 | FPR at 0.5 | positives / negatives |
|---|---|---|---|---|
| validation (synthetic, held-out templates and tasks) | 0.99 | 0.50 | 0.00 | 60 / 60 |
| A: Tekmor matrix | 0.82 | 0.83 | **0.25** | 18 / 8 |
| B: AgentDojo v1.2.2 | 0.58 | 0.90 | **0.82** | 97 / 97 |

**Set A, per scenario.** Every scenario with at least one untrusted document scores at
least 0.73, and 15 of those 17 score at least 0.99. Every scenario with none scores 0 by
the method's rule. That covers both benign scenarios with an untrusted document: the SOC
phishing triage (1.00) and the honest endorsed invoice (0.99). The endorsed-invoice
attack scores 0.998, one point above its benign twin. The two attacks with no untrusted
document (the direct request and the mislabelled leak) score 0.

**Set B, the attacks the core misses.** Under endorsement, 22 of set B's positive pairs
are attacks the core lets through. The probe flags 20 of them, and it also flags 18 of
their 22 clean twins.

## Interpretation (inferred)

- **The gate is failed on both held-out sets.** The FPR on benign content is 25% on the
  matrix and 82% on AgentDojo, against a threshold of 10%. Criterion 2 is met only
  nominally. The probe does flag attacks the core misses (the endorsed invoice, 20 of 22
  AgentDojo pairs), but it flags their benign twins at almost the same rate. A flag that
  does not separate the twin from the attack is not a catch.
- **What the probe learned is "external text arrived", not "an instruction arrived".**
  On the matrix its score is almost a function of whether the scenario has an untrusted
  document at all. On AgentDojo, where every run reads tool output, AUROC falls to 0.58.
  This is the register shift the *Assumptions* section named in advance: WikiText
  paragraphs versus mail, invoices and tool dumps. The synthetic validation split shared
  that register, which is why it read 0.99.
- **The validation number is the misleading one**, and it is the number a probe paper
  would lead with. It is reported first here so it is read against the two below it.

## Verdict

**Refuted on the proxy; Proposal C is demoted to future work**, as the gate prescribes.
Nothing is integrated into `src/`. Two things would have to change before reviving it:

1. **Train on the target register.** Tool outputs and business documents, with and
   without injections, disjoint from both evaluation sets. That is a data-collection
   task, not a modelling one.
2. **Run it on the reference model.** Qwen3-8B with a GPU (Part IX, limit 4). Even a pass
   on this proxy would not have counted.

**Negative result recorded, not dropped** (research code: reproducible and seeded, never a dependency).


## Amendment 2 (2026-09-19, before any Qwen3-8B result was seen)

A rerun on the reference model, the second revival condition above. Only the model
changes. The recipe, data, templates, split, seeds, layer selection, held-out sets and
gate are the ones above, and the verdict is read against the same gate.

- **Model.** `Qwen/Qwen3-8B` on a Colab T4 (`notebooks/colab_qwen3_8b.ipynb`), loaded
  **4-bit NF4 with float16 compute** (bitsandbytes), because the bf16 weights do not fit
  in 15 GB. NF4 Qwen3-8B is not the full-precision reference model. It is the model an
  agent on this hardware would run, so it meets limit 4 only for that deployment, and
  the report records `quant` and `device` beside every number.
- **Invocation.** `python -m research.experiments.drift_probe.probe --model Qwen/Qwen3-8B
  --quant nf4`. Features are cached per model in `results/<model>[-<quant>]/`, so no
  feature computed on one model is reused on another. The 0.6B run's cache moves to
  `results/Qwen3-0.6B/`.
- **What it can and cannot show.** The first revival condition, training on the target
  register, is **not** addressed. If the result is the same failure, it cannot tell model
  size apart from training register as the cause. Only a pass is informative on its own.

## Results on Qwen3-8B NF4 (observed, 2026-09-19)

Run on a Colab T4 with the Amendment 2 invocation, commit 988763c. The first attempt ran
out of GPU memory at the AgentDojo stage because the notebook kernel still held a second
copy of the model. The rerun loaded `train`, `val` and `matrix` from the per-model cache
and computed only AgentDojo. No code, data or setting changed between the two. 965 s,
8 contexts truncated at 4096 tokens (as on the proxy). Report:
`results/Qwen3-8B-nf4/report.json`, extracted verbatim from the notebook's saved output.

Layer 17 was chosen on synthetic validation (AUROC 0.994). Layers 13, 14, 16 and 18 are
at 0.98–0.99, the other layers at 0.78–0.98, and the embedding layer at 0.50.

```
set                                    AUROC   TPR@0.5   FPR@0.5   (Qwen3-0.6B, layer 11)
synthetic validation (held-out templ.)  0.99      0.52      0.00    0.99 / 0.50 / 0.00
Tekmor matrix (held out, 18+ / 8-)      0.83      0.61      0.25    0.82 / 0.83 / 0.25
AgentDojo v1.2.2 (held out, 97+ / 97-)  0.65      0.99      0.91    0.58 / 0.90 / 0.82
```

- **Criterion 1 fails on both held-out sets**, as on the proxy. On the matrix the same two
  benign scenarios are flagged (the endorsed invoice at 0.53 and the SOC phishing triage
  at 0.73). On AgentDojo it flags 88 of 97 clean runs: 15/16 banking, 15/21 slack,
  20/20 travel, 38/40 workspace.
- **The larger model is more selective on the matrix, and not in the useful direction.**
  Four attacks the proxy flagged now score below 0.08: `soc-exfil-reversed`,
  `soc-injection-alert`, `enterprise-injection-dormant` and
  `enterprise-memory-poisoned-note`. The two benign flags remain. TPR falls and FPR does
  not.
- **Criterion 2 is not evaluated separately.** At an FPR of 0.91, a flag on an attack the
  core misses carries almost no information. On the matrix, of the two attacks
  `tekmor` misses, the probe scores `enterprise-leak-mislabelled` at 0.00 and the
  endorsed-invoice injection at 1.00, but it scores that injection's benign twin at 0.53.

## Verdict on Qwen3-8B (Amendment 2)

**Refuted again; Proposal C stays demoted.** Model size was the one variable changed, and
the failure is the same: the probe still separates "external text arrived", not "an
instruction arrived". As Amendment 2 said in advance, this cannot tell size apart from
training register as the cause. What it does show is that **size alone does not fix it**,
at least for NF4 Qwen3-8B. The remaining revival condition is the first one: training data
in the target register (tool outputs and business documents).
