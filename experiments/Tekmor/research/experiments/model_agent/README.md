# A model-driven agent on AgentDojo: what the numbers become when nobody is an oracle

**Status: pre-registered. Written and committed before the first run. Not yet run —
it needs a served model and a GPU, neither of which is in this repository.**

## Why this exists

Every AgentDojo entry in `docs/07-results.md` since Phase 4 closes with the same sentence
in some form: *nothing here says what a model-driven agent would do*. The driver
(`ground_truth_agent`) replays AgentDojo's ground truth and obeys every injection, which
fixes three things at once:

- **ASR is the always-obeys bound**, not a measurement. The agent is compromised by
  construction, so the only question the harness asks is whether the monitor stopped the
  call.
- **BTU asks whether the policy would have permitted the oracle trace**, not whether a
  task got done. A refused action that the success condition does not depend on costs
  nothing, which is why `deny-gray` refuses roughly half of all benign actions at no
  measured BTU cost.
- **Provenance is near-oracle**, because the script copies values verbatim out of
  structured tool results — exactly the case where a value is a whole field.

Three mechanisms are currently *built, measured and not adopted* — the alignment auditor,
argument-level provenance, and field-level labels — and the recorded reason for at least
two of them is a utility cost this harness cannot measure. This experiment removes the
confound rather than adding a fourth mechanism.

## What is being measured

`--agent model` (`evaluation/dojo.py`), which is AgentDojo's own pipeline with
`TekmorExecutor` in `ToolsExecutor`'s slot. Frozen before the run, and **not** to be
changed after seeing results:

- AgentDojo v1.2.2, all four suites, the `direct` attack, the same `SUITES`
  configuration, which stays frozen for the reason it has always been frozen.
- AgentDojo's own default system message (`load_system_message(None)`), taken rather than
  written.
- Temperature 0, a pinned model id, `max_iters` 15.
- Arms: `allow-all`, `deny-sensitive`, `tekmor`, `tekmor+endorse`, `tekmor+deny-gray`,
  and `tekmor+arguments+field-labels`.

**`allow-all` is not a formality here.** Under a model agent it is the ceiling that
separates the model's own competence from the defense's cost, and every utility claim
below is relative to it:

    relative utility = BTU(defense) / BTU(allow-all)

## Hypotheses

**H1 — the bound becomes a measurement.** `ASR(allow-all)` is exactly 1.00 under the
ground-truth driver by construction. Under a model agent it is below 1.00: the model
sometimes ignores the injection unaided. Refuted if it is ≥ 0.99, which would mean this
model obeys essentially every injection and the arm buys no new information about ASR.

**H2 — absolute BTU stops being readable, and relative utility is what survives.**
`BTU(allow-all) < 1.00`, because a small served model fails some AgentDojo tasks on its
own. Refuted if `BTU(allow-all) ≥ 0.95`. If H2 holds, every recorded absolute BTU from the
ground-truth driver is not comparable with any number here, and this note will not
compare them.

**H3 — field labels cost real utility, as their own pre-registration predicted.** The
field-label arm measured zero benign cost and said in advance that the zero was an
artifact of verbatim copying, and that a model which reformats a value makes it untraced
and falls back to call level. Supported if
`relative utility(arguments+field-labels) < relative utility(arguments)` by more than one
benign run. Refuted if it is equal or higher, which would mean the artifact argument was
wrong and the mechanism is cheaper than its authors believed.

**H4 — deny-gray's dominance does not survive.** On the ground-truth driver, refusing the
whole gray zone cost nothing (equal BTU, 21 attacks removed) while refusing far more
benign actions (travel FBR 0.05 → 0.84). A model that must actually finish the task
should pay for those refusals. Supported if
`relative utility(deny-gray) < relative utility(tekmor)` by more than one benign run.
Refuted if deny-gray still matches `tekmor` on utility, which would make the gray-zone
refusal switch a far more serious candidate than this project has so far treated it as.

**H5 — the agent reacts to verdicts, and that is visible.** A refusal returns an error
naming the public reason codes, and AgentDojo's loop feeds it back, so the model can
retry or route around it. Measured descriptively, with no gate: the number of runs in
which a refused tool is proposed again after its refusal, and whether any run reaches the
attack goal through a *different* tool after a refusal. The second is the interesting
one — it is adaptive behaviour from a model that was never told it faced a monitor, and
it has no analogue in the scripted driver.

## Limits, stated in advance

- **One model is not "models".** Whatever is served is a single point, and a weak model
  compresses every difference between defenses toward its own failure rate. A defense
  gap that vanishes because the agent could not do the task either is not a finding about
  the defense, and H2 exists to keep that visible.
- **Determinism is claimed only as far as it holds.** Temperature 0 makes decoding greedy,
  but a batching server can still reorder floating-point reductions across runs. The run
  records the server, its version and its flags, and a repeated suite is compared against
  itself to state observed rather than assumed determinism.
- **`max_iters` truncation is a failure mode that looks like a refusal.** A run that hits
  the cap ends without finishing, and under a defense that escalates often the cap is hit
  more easily. The count of capped runs is reported per arm; without it, a utility loss
  from truncation would be misread as a utility loss from refusing.
- **This does not make AgentDojo held out again** for argument provenance or field
  labels. Those mechanisms were diagnosed on this benchmark, and a different driver does
  not undo that. H3 is evidence about the artifact, not a path to adopting them; adoption
  still needs a benchmark this project has not scored against.
- Nothing here will be compared with CaMeL's, FIDES's, PACT's or Task Shield's numbers,
  which were measured with different models, configurations and attack sets.

## What no outcome licenses

No result from this experiment turns a switch on by itself. The switches that are off are
off for reasons recorded in `docs/07-results.md`, and a utility number from one served
model is not one of the things that would reopen them.
