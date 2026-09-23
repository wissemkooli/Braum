# 8. Limitations

What the numbers in this repository do not support, and what is known to be broken.

This document exists because a defense whose limits are vague is a defense nobody can
rely on. Nothing here is hedging — each item is a specific, recorded constraint, and most
of them were written down *before* the run that produced the number they qualify.

---

## The one that qualifies almost everything

**Every AgentDojo number in this repository was produced by a scripted agent.**

`ground_truth_agent` replays AgentDojo's own ground truth and then the injection task's
ground truth — an agent that did the user's work, read the injection, and obeyed it. Three
consequences follow, and they apply to every AgentDojo figure, table and claim:

1. **ASR is an always-obeys upper bound**, not a measurement. The agent is compromised by
   construction. The only question the harness asks is whether the monitor stopped the
   call, never whether a model would have been fooled in the first place.
2. **BTU asks whether the policy would have permitted the oracle trace**, not whether work
   got done. A refused action the success condition does not depend on costs nothing here
   and would derail a real agent mid-task.
3. **Provenance is near-oracle**, because the script copies values verbatim out of
   structured tool results — precisely the case where a value is a whole field.

**No number here is comparable with CaMeL, FIDES, PACT, Task Shield or AlignmentCheck**,
all of which were measured with real models on their own configurations. They are not
compared anywhere in this repository, and they should not be.

### The attempt to remove this confound failed

A model-driven driver exists (`--agent model` / `--agent hf-native`) and was run on a
Colab T4 with Qwen3-8B in NF4. **Every arm scored BTU 0.00, including `allow-all`.** With
no utility ceiling, every pre-registered hypothesis is a ratio or difference against zero
and is undefined.

The cause was diagnosed from raw completions: driven through AgentDojo's text convention,
the model makes a correct first tool call, reads the document, then writes *"I will
proceed to send the payment"* and calls nothing. The loop ends on a turn with no call.

A fix — driving the model in its own native tool-call format — is built and unit-tested
and **has never produced a number on a GPU**. It is a hypothesis with a mechanism, not a
measurement.

One measurement from that attempt does stand, and it governs planning: **73.2 seconds per
run**, so one full four-defense sweep is ≈ 55 hours and the five pre-registered arms
≈ 277 hours. The pre-registered experiment is not feasible on a free T4, independent of
the agent defect.

## Known functional gaps

**A value laundered through world state.** The canary scanner reads arguments. A secret
bound into the world at an unguarded step and later acted on through an opaque handle —
`PAY-1`, `file_id: '13'` — is outside it. Argument-level provenance has the same blind
spot, since it sees only the arguments of the call in front of it. After field labels,
this is the **largest** remaining residual: 22 pairs against the 20 that field labels
fixed.

**Short opaque identifiers.** A two-character value cannot be traced, because a trace that
matches anywhere vouches for anything. The minimum-length floor is doing more work than
intended, and short handles are a systematic hole rather than an edge case.

**Reads that are themselves the goal.** Where fetching an attacker-chosen URL *is* the
attack and the deployment does not call that read sensitive, the rules do not fire. This
is 21 of 583 pairs on AgentDojo. It was not tuned away, because tuning the frozen
configuration on held-out results would end AgentDojo's status as held out.

**One composed encoding.** Base64 of a reversed token leaks a mislabelled secret past the
canary layer. It is pinned as a failing test (`xfail`) rather than removed, and the
ground truth that scores it shares the scanner's blind spot — so the metric cannot count
the leak it just permitted.

**Confidentiality is barely exercised externally.** Nothing in AgentDojo is labelled
confidential and no suite has a capability lattice, so Permitted-Flow and `REWRITE` are
effectively untested outside this repository's own scenarios. Half the lattice has no
external validation.

## Limits of the measurements themselves

**The matrix is not a benchmark.** 26 scenarios written by the same people who wrote the
defense. Useful for ablations and regressions; it cannot establish external validity.
That is what AgentDojo is for.

**The rewrite ablation cannot move.** Removing the capability lattice changes no scored
outcome, because attack scenarios state no utility condition. This is a limit of the
matrix, not a finding about the rewrite.

**The adaptive attacker's flat curve is partly an artefact.** The one attack form that
beats the canary layer is rejected by the ground truth that shares the scanner's blind
spot, so a real win is uncounted. The search space is 24 candidates against a scripted
agent — mutations over an argument channel, not text against a model.

**Calibration is measured, not achieved.** Severities are ordinal: their ordering is
meaningful, their magnitudes are not probabilities. ECE improved from 0.07 to 0.04 on the
larger matrix, having got *worse* on the smaller one — a reversal that shows how little
the earlier sample could support. The scale in use is still the hand-ordered one.

**The lexical reword is a substitution table**, not a model paraphrase.

## Mechanisms built but deliberately off

Three mechanisms work, were measured, and are disabled. Reading
[7.6](07-results.md#76-mechanisms-built-and-deliberately-switched-off) before flipping any
of them is not optional.

| Mechanism | Why it is off |
|---|---|
| **Alignment auditor** (Proposal B) | Both GPU judges refused ~99% of the gray zone. The `deny-gray` control — the same mechanism with no judge — reproduces them almost everywhere. The judges were refusal switches, not alignment checkers. |
| **Argument-level provenance** | Buys utility, costs security; the gate asked for dominance. It also removes the "meet" that masks a mislabelled trusted source, which is a worse failure mode than over-tainting. |
| **Field-level labels** | The mechanism is sound and the diagnosis is clean. But the fault was found *on AgentDojo* and the fix was built *for it*, so AgentDojo is no longer held out for this change. Adoption is gated on a benchmark not yet scored against. |

**Activation drift probe** (Proposal C) is demoted to future work. It failed its
pre-registered gate on a 0.6B proxy and again on the 8B reference model: it learned that
*external text arrived*, not that *an instruction arrived*, flagging 88 of 97 clean
AgentDojo runs. Reviving it needs training data in the target register — real tool outputs
and business documents — which is a data-collection task.

## Statistical limits

97 benign runs cannot resolve small utility differences. The `deny-gray` control
pre-registered an **undecided band** of 0.02–0.05 for exactly this reason, and both judges
landed inside it. They are recorded as undecided. Phi-3-mini's gain sat 0.0006 above the
"supported" threshold and was **not** rounded down into it.

Where a result rests on two or four runs out of 97, it is reported as suggestive and not
treated as evidence.

## What is explicitly not claimed

- Anything about frontier judges. Neither judge measured here is one.
- Anything about full-precision Qwen3-8B. A quantized model is a different model.
- That the native tool-call fix resolves the narration failure. Untested on a GPU.
- That a quantized 8B model failing to drive AgentDojo says anything about the benchmark's
  difficulty, about capable agents, or about the defenses.
- Any comparison with published numbers from other systems.
