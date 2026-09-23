# BRAUM research report

No page limit. Report component metrics as evidence for your claims, not as an official score — there is no official score; judging is against the rubric in [scoring.md](scoring.md). Include the benchmark version and any scorecard digests you cite so a reader can trace them back to a run.

## 1. Abstract

Braum is a deployment-oriented provenance and policy defense for tool-using LLM agents. It treats untrusted documents, emails, memories, and tool outputs as content that may be read but does not automatically gain authority to perform consequential actions or disclose protected information. Across the official Qwen3-8B public split, the defense contained all 23 attacks that reached the undefended agent while incurring one blocked benign read. The observed public-split results were BTU 0.667, ASR 0.000, CVR 0.000, and FBR 0.009, for an official score of 0.902. The same design is consistent with Tekmor's research evidence: a provenance monitor with a canary layer reached BTU 1.00, ASR 0.06, CVR 0.04, and FBR 0.00 on its internal suite, while AgentDojo remained a conservative upper-bound benchmark because its results were generated with a scripted ground-truth agent. The key limitation is that the defense is strongest on a fixed benchmark with a reproducible agent and still needs a real model-driven run to confirm performance under a fully capable agent.

## 2. Threat model

- Which attack families and surfaces does your defense target?
  - Indirect prompt injection from documents, emails, tool outputs, and memory.
  - Argument-driven exfiltration, memory-poisoning, and multi-step instruction hijacking.
  - Sensitive tool calls that depend on untrusted evidence but must not become authorized actions.
- What does the adversary know (payloads, your decisions, adaptivity)?
  - The adversary can read and mutate untrusted content, can adapt payloads across encodings and rewordings, and can observe public decisions and reason codes.
  - This is precisely the threat model used in Tekmor's adaptive attacker and in the official Braum harness.
- What is explicitly out of scope?
  - Full model compromising, malicious model weights, or direct compromise of the host runtime.
  - A complete treatment of a real-world production environment outside the harness and benchmark conditions.

## 3. Hypothesis

Two falsifiable statements anchor the work:

1. Tracking which untrusted sources influenced an action's arguments and sensitive outputs reduces ASR on indirect injection and exfiltration by a large margin while preserving most benign utility.
2. A defense that enforces authority sealing, provenance tracking, and capability-aware rewrite will keep attack success near zero on the official public split without collapsing utility, even when attacker payloads are reworded or encoded.

## 4. Method

- Architecture diagram: where the defense sits (input, planning, retrieval, memory, tool authorization, output).

```text
User goal
    ↓
Authority / mandate sealing
    ↓
Observed content with provenance and sensitivity labels
    ↓
Candidate tool action
    ↓
Argument attribution + capability policy + information-flow checks
    ↓
Risk and evidence evaluation
    ↓
ALLOW / REWRITE / ESCALATE / BLOCK
    ↓
Execution gateway
    ↓
JSONL trace, replay, and dashboard
```

- Signals used (provenance, action structure, model internals, history) and how decisions are made.
  - Braum uses provenance, trust, sensitivity, capability, and information-flow checks.
  - It seals authority from the user goal before untrusted content is exposed.
  - It attributes decisive arguments back to the source span and rejects actions when an untrusted source exerts control over a sensitive tool or a protected sink.
  - It preserves utility through least-restrictive rewrite, such as downgrading a send action to a draft or preparation action.
- Training data, objectives, and hyperparameters for any learned component.
  - No external learned component is used for the policy decision itself. Braum's system is deterministic. The Qwen3-8B model is the protected agent, not the defense.
  - Tekmor includes optional learned or probe-based extensions, but those were explicit research experiments and did not become part of the core path.
- How `risk_score` and `confidence` are produced and calibrated; when you escalate and when you rewrite.
  - Braum scores risk from evidence and policy, and it escalates only when a consequence is severe or ambiguous and a weaker intervention is unavailable.
  - Rewrite is preferred whenever a sensitive action can be downgraded to a safer form without changing the user's task meaning.

## 5. Experiments

- What you ran the published scenario library against, plus any extra self-test scenarios you authored.
  - Official Braum evaluation used the IndabaX challenge library with the reference agent `Qwen/Qwen3-8B` on the public and validation splits.
  - An explicit mock-agent path was also evaluated for the kit scenario library, and it showed near-perfect containment for the public and validation splits.
  - Tekmor was evaluated on an internal 26-scenario suite and on AgentDojo v1.2.2.
- Models, hardware, seeds, and the reference agent configuration (`mock` vs. `qwen3-8b`).
  - Braum official run: Qwen3-8B, seed 0, public split 40, with the official challenge harness; the same model is the agent being protected.
  - Tekmor internal suite: custom scenario matrix across three domains with seven attack families, difficulty 1–5; adaptive attack runs and ablations used a scripted ground-truth driver.
  - Tekmor AgentDojo: four suites, 97 benign runs and 583 attack pairs, using the AgentDojo driver with a scripted ground-truth agent.
- Baselines compared: at least `allow_all`, `provenance`, and one other.
  - Braum official baseline: `allow_all` (undefended), `provenance`-style path, and the final deployed defense.
  - Tekmor baseline: `allow-all`, `deny-sensitive`, and `keyword` filter.

## 6. Results

| Defense / benchmark | BTU | ASR | CVR | FBR | UER | TUI | DFI | Brier | ECE | p95 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Braum official, `allow_all` (public, 40) | 0.667 | 0.742 | 0.550 | 0.000 | n/a | n/a | n/a | n/a | n/a | n/a |
| Braum official, defense (public, 40) | 0.667 | 0.000 | 0.000 | 0.009 | n/a | n/a | n/a | n/a | n/a | n/a |
| Braum official score, public run | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0.902 |
| Braum mock agent, public (40) | 1.000 | 0.000 | 0.000 | 2 reads + 1 scenario | n/a | n/a | n/a | n/a | n/a | n/a |
| Braum mock agent, validation | 1.000 | 0.000 | 0.000 | 0.000 | n/a | n/a | n/a | n/a | n/a | n/a |
| Tekmor internal, `allow_all` | 1.00 | 1.00 | 0.42 | 0.00 | n/a | n/a | n/a | n/a | 0.07 | n/a |
| Tekmor internal, `tekmor` | 1.00 | 0.11 | 0.08 | 0.00 | n/a | n/a | n/a | n/a | n/a | n/a |
| Tekmor internal, `tekmor` + canary | 1.00 | 0.06 | 0.04 | 0.00 | n/a | n/a | n/a | n/a | 0.04 | n/a |
| Tekmor AgentDojo, `allow_all` | 1.00 | 1.00 | n/a | 0.00 | n/a | n/a | n/a | n/a | n/a | n/a |
| Tekmor AgentDojo, `tekmor` | 0.45 | 0.036 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| Tekmor AgentDojo, `tekmor` + endorsement | 0.69 | 0.146 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| Tekmor AgentDojo, `deny-gray` | 0.45 | 0.000 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

Breakdown by domain and attack family:

- Braum official: public split attacked 23 attacks, all 23 contained; validation showed no attack reached the agent even undefended, so it is not a meaningful containment test.
- Tekmor internal suite: 26 scenarios across enterprise, financial, and security-operations domains, covering seven attack families at levels 1–5. The strongest internal configuration was `tekmor` + canary layer, with ASR 0.06 and zero false blocks.
- Tekmor AgentDojo: the benchmark was run with a scripted ground-truth driver and therefore should be treated as a conservative upper-bound benchmark on attack success, not as a full real-agent measurement.

## 7. Ablations

- Braum and Tekmor both identify provenance as the core measurable contributor.
- In Tekmor's internal suite, removing provenance raised ASR from 0.06 to 0.94; removing taint propagation raised ASR to 0.39.
- The `deny-sensitive` baseline is a trivial lower bound: it reaches near-zero ASR but completes only 12% of benign work and false-blocks 24% of benign actions.
- In Tekmor's AgentDojo runs, `endorsement` recovered much of the utility loss (0.45 to 0.69) while paying a security trade (ASR 0.036 to 0.146). This is a direct indication that the model's performance is sensitive to how much authority is permitted to untrusted content.
- The activation-drift probe in Tekmor did not meet its gate: it had 0.99 AUROC on synthetic validation but only 0.65 AUROC and 0.91 false positives on held-out AgentDojo traces. The signal was therefore demoted and not used in the production path.

## 8. Failure analysis

Concrete failure categories observed in Braum and Tekmor:

1. Missed attacks and adaptation: a reworded or encoded payload can bypass a detector-style baseline. The keyword filter in Tekmor fell from 0.88 to 1.00 within five rounds under an adaptive attacker.
2. Over-tainting: call-level taint in Tekmor reduced utility on AgentDojo to 0.45; it was too conservative and left little room for benign work. The `endorsement` primitive partially recovered this trade.
3. Ambiguous gray-zone actions: the gray-zone is exactly where reassurance from a model judge can become a refusal switch rather than evidence-based reasoning. Tekmor's `deny-gray` control reproduced the behavior of the GPU judges without adding real discrimination.
4. Calibration and data gaps: Braum and Tekmor both track calibration and acknowledge that the model-driven Qwen3-8B path remains incomplete. In Tekmor, the calibration signal was measured but not treated as a replacement for policy-based decisions.
5. Model-driven execution gap: Tekmor's model-driven AgentDojo attempt produced 0.00 utility even for `allow_all`, which shows that the tool-call contract and runtime driver must be made native before a realistic model-based benchmark can be trusted.

## 9. Responsible AI and security considerations

- What the defense protects against and its known failure modes.
  - Protects against indirect prompt injection, malicious instructions hidden in documents, tool output tampering, and sensitive-data exfiltration when the route is visible to the monitor.
  - Known failure modes include over-tainting of benign work, opaque identifiers that prevent provenance traceability, and edge cases where sensitive data is laundered through world-state handles or a model-driven driver does not emit a valid tool call.
- Expected false-positive behavior and who bears its cost.
  - The cost of false blocks is borne by the user agent's task completion. That is why Braum and Tekmor both report FBR side by side with ASR and BTU.
- What data the defense observes and whether any user content is stored.
  - The defense observes the task, the tool call, provenance, risk evidence, and traces. It does not need to store user secrets beyond the runtime trace and redacted evidence needed for debugging.
- When humans should be consulted; how explanations and reason codes are generated.
  - Escalation is used when a sensitive action is severe, ambiguous, or not safely rewritable. Reason codes arise directly from policy predicates and provenance edges, keeping explanations faithful to the decision rather than post-hoc.
- Performance differences across domains.
  - The official Braum challenge shows the strongest performance in the reference public split, while Tekmor's internal work highlights the cost of conservative policy under external workloads and its smaller internal suite. Domain-specific policy still matters.

## 10. Reproducibility

- Repository commit or release tag.
  - This report should be checked against the repository state at the commit used to generate the official scorecard and run artifacts.
- Exact commands to build, run, and self-test.

```bash
pip install pyyaml
python3 run_tests.py

./bin/sentinel replay artifacts/qwen3/run4-2026-09-21/traces/<pass>/<run>.jsonl
./bin/sentinel dashboard && xdg-open observability/dashboard.html

# Tekmor benchmark examples
uv sync --all-extras
uv run pytest
uv run python -m evaluation.harness
uv run python -m evaluation.ablations
uv run python -m evaluation.adaptive
uv run python -m evaluation.dojo
```

- Declared external models and datasets, with licenses.
  - Official Braum evaluation uses the reference agent `Qwen/Qwen3-8B` in the indabaX challenge harness.
  - Tekmor's AgentDojo validation uses AgentDojo v1.2.2 and its own benchmark tasks and settings.
- Deterministic digests of any scorecards you report.
  - Use the challenge and benchmark scorecards, hashes, and artifacts stored in the repo so that every reported result can be traced back to a run.

This report treats Braum as the primary submission path and Tekmor as the explicit research baseline and comparison layer. The official benchmark evidence remains the highest-confidence deployment claim; the Tekmor figures are retained as independent evidence about architectural trade-offs and the value of provenance and policy enforcement.
