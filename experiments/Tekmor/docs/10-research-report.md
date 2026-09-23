# 10. Research report (appendix)

> The original long-form research report, kept as an appendix. It contains the
> full literature survey, the metric definitions and the implementation roadmap
> as they were written during the project. Documents 1-9 are the maintained,
> reader-facing versions; where they disagree with this file, they are newer.

---

# Tekmor: Designing a Measurable Safety Layer for Tool-Using LLM Agents — Deep Technical Research Report

> *Tekmor* (τέκμωρ): "sign, token, proof." The project's core principle is that untrusted content is **evidence, not authority**, and that every safety decision must be provable from its trace.

## TL;DR
- **Build an action-centric reference monitor, not a prompt-injection classifier.** Intercept every candidate tool call and decide ALLOW/BLOCK/ESCALATE/REWRITE from provenance + trust + action risk + policy, following the CaMeL/FIDES/Progent "security-by-design" line. CaMeL solves 77% of AgentDojo tasks with provable security (vs 84% undefended). Text-only detection defenses, by contrast, are bypassed by adaptive attackers: attack success rates stay above 50% in Zhan et al. (NAACL 2025) and exceed 90% against all twelve defenses tested in the strongest study (Nasr, Carlini et al., 2025).
- **The strongest design combines three cheap, defensible layers:** (1) a deterministic **provenance/information-flow gate** (taint from ADVERSARY_CONTROLLED/UNTRUSTED sources to sensitive tools), (2) a **capability-lattice action rewriter** (send→draft, execute→prepare), and (3) an **observability trace + live provenance graph** that makes every decision legible. A TaskTracker-style activation probe on Qwen3-8B is an optional research extension.
- **Build incrementally around a stable core.** Start with the deterministic provenance gate and action rewriter behind a clean `Defense` interface. Add observability and evaluation next, then optional research layers. What matters most is honest measurement: utility, attack success rate (ASR), false-block rate, calibration, at least one clean ablation, and documented failures. A defense is only as credible as the evidence behind it.

## Key Findings
1. **The problem is architectural, not detection.** Prompt injection persists because trusted instructions and untrusted data share one token stream. Detection-only defenses (classifiers, perplexity filters, LLM judges) are broken by adaptive attackers. Zhan et al. (NAACL 2025) bypassed all eight defenses they tested at >50% ASR. Nasr, Carlini, Sitawarin et al. ("The Attacker Moves Second," arXiv:2510.09023, USENIX Security '26), a joint OpenAI/Anthropic/Google DeepMind team, broke all twelve published defenses they tested, most above 90% attack success. System-level designs that constrain *what actions untrusted data can trigger* are the only approaches with provable properties.
2. **Provenance/IFC is the strongest defensible core.** CaMeL (DeepMind), FIDES (Microsoft), and Progent all enforce security at the tool-call boundary using data-flow labels or capability policies, and all report near-zero attack success on AgentDojo when policies are enabled. Tekmor's six trust levels map directly onto IFC integrity labels.
3. **Utility is the hard constraint.** Untrusted content must often be read (vendor email, raw logs). Over-tainting ("label creep") collapses utility. FIDES stops all AgentDojo prompt injections with policy checks on and, paired with reasoning models (o1, o3, o4-mini), completes ~16% more tasks than a basic planner (24% with prompt tuning). CaMeL pays only a ~7-point utility trade (77% vs 84%) for provable security. A defense that blocks everything is a failure.
4. **Mechanistic interpretability is viable but only as a *secondary* signal.** TaskTracker (Abdelnabi et al., SaTML 2025) shows a linear probe on activation deltas detects task drift at over 0.99 ROC-AUC on out-of-distribution data without fine-tuning (validated across Mistral 7B, Llama-3 8B/70B, Mixtral 8x7B, Phi-3). Qwen3-8B SAEs/probes now exist (Qwen-Scope; Qwen3-Instruct SAE). This is a genuinely novel, demonstrable component, but its evaluations have known distribution-shift weaknesses, so it must not be the sole gate.
5. **Observability has to be built, not borrowed.** OpenTelemetry GenAI and OpenInference conventions cover LLM and tool spans. They don't model trust assignment, provenance chains, or decision reason codes. A security timeline plus a provenance graph is both a debugging tool and the main way to show *why* each decision was made.

## Details

### Part I — Problem Understanding

**Core problem.** A tool-using LLM agent works in a simulated organization and must complete legitimate work while its environment (emails, documents, logs, tool outputs, memory) actively tries to manipulate it. Tekmor is a decision layer that returns **ALLOW / BLOCK / ESCALATE / REWRITE** for each action. It decides using only the agent state, the candidate action, its provenance, the active policy, and the observed content. A key design principle is that decisions must never depend on scenario identifiers, filenames, or known expected outcomes. A defense that recognizes test cases instead of reasoning about actions provides no real security evidence. The reference agent is **Qwen3-8B**, run locally.

**Project architecture (own repository).** Tekmor has four components:
1. **Environment simulator.** A lightweight synthetic world with three domains (enterprise productivity; a financial-services sandbox with a prepare → confirm → execute payment lifecycle; a security operations center). It includes typed tools, a mutable world state, secrets tagged as canaries, and scenario files written in YAML.
2. **Agent runtime.** A `ModelAdapter` interface with a mock model for fast deterministic tests and a Qwen3-8B backend (Hugging Face Transformers or vLLM). Using Transformers keeps activation hooks available for Proposal C.
3. **Defense interface.** Every candidate action passes through `Defense.decide(state, action, provenance, policy) → Decision`. This can run in-process or as a FastAPI service. Mediating every action this way is what makes the defense a reference monitor.
4. **Event log.** An append-only JSONL log of every step that feeds the observability layer and the evaluation harness.

The flow is: scenario + world + policy → runner → agent proposes an action → Tekmor decides → escalations go to a simulated human, approved actions go to the tool gateway → world state updates → events are logged. Metrics are defined in Part VI.

**The six trust levels** (SYSTEM_POLICY > AUTHENTICATED_USER > TRUSTED_INTERNAL > UNTRUSTED_INTERNAL > UNTRUSTED_EXTERNAL > ADVERSARY_CONTROLLED) form a lattice. This maps directly onto **integrity labels** in information-flow control (Biba integrity: information may not flow "up" in integrity; an action's integrity is the *minimum* integrity of all inputs that influenced it). Memory inherits trust: an entry written after reading untrusted content stays untrusted when recalled. This is exactly taint propagation. Critically, "untrusted ≠ irrelevant": the agent must *read* low-integrity content (it's evidence) but must not let it *drive* high-consequence actions (it's not authority). The whole defense turns on this read/follow distinction.

**Attack families and why each is hard.**
- *Direct instruction* (user request out of policy): requires a policy model, not injection detection. The "instruction" is authentic but disallowed.
- *Indirect injection* (instruction hidden in doc/email/log): the canonical IPI problem. Hard because the same text must be read for the task.
- *Multi-step / compositional*: an instruction split across records, each benign. Defeats per-observation classifiers; needs trajectory- or flow-level reasoning.
- *Memory poisoning*: a false "policy" stored early, recalled later as if authoritative. Requires trust inheritance through memory.
- *Tool-output tampering*: a third-party field in a tool result redirects the plan. Requires field-level provenance on tool outputs.
- *Data exfiltration* (plain/spaced/base64/hex/reversed): requires content inspection of *arguments to outbound tools*, plus canary/secret tracking. Encoding defeats naive regex.
- *Over-refusal trap*: legitimate work full of scary words. Blocking costs utility, which is why false-block rate is a primary metric.

**Difficulty levels 1–5** (Local → Contextual → Compositional → Adaptive → Long-horizon) mean the defense must reason over *history and flow*, not single messages, and must not be overfit to one wording. An adaptive attacker adjusts round by round, and a long-horizon attack can stay dormant for ~20 steps.

**ALLOW/BLOCK/ESCALATE/REWRITE as policy/action control (not labels).** This is a **reference-monitor / policy-enforcement-point** design satisfying complete mediation, tamper-resistance, and verifiability. The monitor sits at the tool boundary, makes an authorization decision, and can *transform* the action (rewrite = least-privilege downgrade) or *defer* it (escalate = human-in-the-loop / learning-to-defer). Treating it as a 4-class classifier throws away the security semantics.

### Part II — State of the Art (annotated)

**Foundational — prompt injection & instruction/data separation**
- *Greshake et al., "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"* (AISec 2023). Defined IPI; showed retrieved content can hijack agents. Foundational framing for Tekmor.
- *Wallace et al., "The Instruction Hierarchy"* (OpenAI, arXiv:2404.13208, 2024). Trains models to prioritize system > user > tool/third-party instructions. On GPT-3.5, defense against system-prompt extraction improved by 63% and jailbreak robustness by over 30%, with some over-refusal regressions; the authors note models are "likely still vulnerable to powerful adversarial attacks." Adaptable as a *concept* (trust ordering) but not a guarantee. Tekmor's trust levels are a richer, externalized hierarchy.
- *StruQ* and *SecAlign* (preference optimization to prefer the intended instruction over injected ones): model-level defenses that separate instruction/data channels. Meta SecAlign (arXiv:2507.02735) is an open secure foundation model. Useful background, but they require training/fine-tuning.
- *Spotlighting* (Hines et al., arXiv:2403.14720): mark/encode untrusted data so the model discounts it. Cheap and combinable, but bypassable alone.
- *Zverev et al., "Can LLMs Separate Instructions from Data?"* + SEP dataset: shows separation is imperfect and measurable. A good source for an evaluation metric.

**Detection (weak on its own)**
- Meta **LlamaFirewall** (arXiv:2505.03574; PurpleLlama). Open-source system-level guardrail with **PromptGuard 2** (86M/22M BERT-style injection detector; ~88.7% recall at 1% FPR on English data), **AlignmentCheck** (few-shot CoT auditor comparing the action trajectory to the user goal; reduces ASR by 83% using Llama 4 Maverick), and **CodeShield** (static analysis). Combined PromptGuard 2 + AlignmentCheck reduces AgentDojo ASR from 17.6% to 1.75% (>90% reduction) with utility ~42.7% vs 47.7% baseline. AlignmentCheck (goal-alignment auditing) is the most relevant idea for Tekmor.
- **Llama Guard 3/4**, **NeMo Guardrails** (NVIDIA, Apache-2.0, ~6.5k stars, Colang DSL, input/output/dialog/retrieval/tool rails), **Guardrails AI**, **LLM Guard** (MIT), **Lakera Guard**, **Microsoft Prompt Shields**, **Anthropic constitutional classifiers**. All are enforcement-point frameworks; most are content classifiers at heart.
- *Adaptive-attack reality checks*: Zhan et al. (NAACL 2025, arXiv:2503.00061) broke 8 IPI defenses at >50% ASR. Nasr, Carlini, Sitawarin et al., "The Attacker Moves Second" (arXiv:2510.09023, USENIX Security '26), broke all twelve published defenses tested, most above 90% attack success, using gradient descent, RL, random search, and human-guided search. **This is the most important caveat for the threat model.**

**System-level / architectural defenses (the strong line)**
- **CaMeL** (Debenedetti, Shumailov, Carlini, Tramèr et al., arXiv:2503.18813; code: google-research/camel-prompt-injection, ~356 stars). A privileged LLM plans from the trusted query; a quarantined LLM processes untrusted data with no tool access; a custom Python interpreter tracks data provenance/capabilities and enforces policy before each tool call. Solves 77% of AgentDojo tasks with *provable* security vs 84% undefended (v1 reported 67%); cost 2.82× input / 2.73× output tokens. The gold-standard reference design.
- **Design Patterns for Securing LLM Agents** (Beurer-Kellner et al., 14 authors, arXiv:2506.08837; code: ReversecLabs samples). Six patterns: Action-Selector, Plan-Then-Execute, Map-Reduce, Dual-LLM (Willison), Code-Then-Execute (CaMeL), Context-Minimization. Honest about limits: 8 of 10 case studies retain a residual (untrusted data can still shape *arguments* of permitted actions). Directly informs which pattern Tekmor should adopt (Plan-Then-Execute + argument-level provenance).
- **FIDES / "Securing AI Agents with Information-Flow Control"** (Costa, Köpf, Paverd, Russinovich et al., Microsoft, arXiv:2505.23643; code: microsoft/fides). The planner tracks confidentiality + integrity labels, deterministically enforces two policies (Trusted-Action, Permitted-Flow), and adds primitives for selectively hiding/revealing data. With policy checks enabled, FIDES stops all AgentDojo prompt injections; with reasoning models (o1/o3/o4-mini) it completes ~16% more tasks than a basic planner, rising to ~24% with prompt tuning. **The closest existing system to Tekmor's design.**
- **Progent: Programmable Privilege Control** (Shi, He, Wang, Guo, Song et al., arXiv:2504.11703; ~38-star repo). JSON-schema DSL for least-privilege tool-call policies, deterministic enforcement, SMT-checked monotonic policy updates (the permitted space can only shrink without approval), LLM-generated initial policies. Strong on AgentDojo/ASB/AgentPoison. Limitation: only the tool-call phase (text outputs unaddressed). A ready-made policy-engine design.
- **Task Shield** (Jia et al., ACL 2025, arXiv:2412.16682). Reframes defense as *task alignment*: every instruction/tool call must contribute to the user goal ("ContributeTo" scoring). ASR 2.07% at 69.79% utility on GPT-4o. Directly usable; limitations: LLM-based, susceptible to adaptive attacks, single-model evaluation.
- **MELON** (Zhu et al., ICML 2025, arXiv:2502.05174; code: kaijiezhu11/MELON). Masked re-execution: re-run with a task-neutral masked prompt. If the masked and original runs produce the *same* tool calls, those calls are driven by injected data, not the user, so they're flagged as an attack. >99% prevention with utility preserved on AgentDojo. Clever and model-agnostic, but doubles inference cost.
- Related: Prompt Flow Integrity (Kim et al., arXiv:2503.15547), AgentSpec, Conseca, RTBAS, GuardAgent, ShieldAgent, ACE architecture (arXiv:2504.20984), ARGUS (arXiv:2605.03378), AgentSentry (temporal causal diagnostics). All confirm the field is converging on **flow + policy + task alignment at the action boundary.**

**Verdict for Tekmor:** the defensible core is IFC/provenance + capability policy at the tool boundary (CaMeL/FIDES/Progent), optionally augmented by task alignment (Task Shield) and a novel activation probe (TaskTracker). Pure detection is a documented dead end against adaptive (level-4) attacks.

### Part III — Existing Tools & Open-Source Ecosystem

| Project | Community | License | Architecture | Extension point | Compute | Fit for Tekmor |
|---|---|---|---|---|---|---|
| **Tekmor (own repo)** | — | your choice (Apache-2.0 recommended to match most dependencies) | simulator + `Defense` interface + FastAPI | `Defense.decide()` | CPU (mock) / GPU (Qwen3-8B) | **Primary codebase** |
| **ethz-spylab/agentdojo** | NeurIPS 2024 | MIT | stateful agent benchmark, pipeline elements | custom defense pipeline element | API or GPU for Qwen3-8B | **Primary external harness** |
| microsoft/fides | Microsoft | MIT-ish | IFC planner + labels + policy | reimplement labels/policies | CPU + API model | High (concepts) |
| google-research/camel-prompt-injection | DeepMind (~356★) | research artifact | dual-LLM + interpreter | policy functions | API model | Medium (reference) |
| kaijiezhu11/MELON | ICML'25 | research | masked re-execution on AgentDojo | wrap agent | 2× model calls | Medium |
| Shi et al. Progent | ~38★ | research | JSON policy DSL | write policies | CPU | High (policy engine) |
| meta-llama/PurpleLlama (LlamaFirewall) | Meta, large | permissive | PromptGuard2/AlignmentCheck/CodeShield | scanners | 22–86M model, CPU-ok | High (detector layer) |
| NVIDIA-NeMo/Guardrails | ~6.5k★ | Apache-2.0 | Colang rails | rails config | CPU + LLM | Medium (heavy DSL) |
| protectai/llm-guard | active | MIT | 15 input / 20 output scanners | scanners | CPU | Medium |
| **Langfuse** | large | MIT (core) | trace store + UI | OTel/SDK ingest | CPU/Docker | **High (observability)** |
| **Arize Phoenix** | large | Elastic/OSS | OTel + OpenInference trace UI | span ingest | CPU/Docker | **High (observability)** |
| OpenInference / OpenLLMetry | CNCF-adjacent | Apache-2.0 | GenAI semantic conventions | span schema | n/a | High (schema) |
| Qwen-Scope / Qwen/SAE-Res-Qwen3-8B | Qwen/Fudan | open weights | SAEs for Qwen3-1.7B/4B/8B | residual-stream hooks | GPU | Medium (novel) |
| TransformerLens / SAELens / nnsight | large | MIT | activation hooks | probes/SAEs | GPU | Medium |
| TaskTracker (microsoft/TaskTracker) | Microsoft/CISPA | research | activation-delta probe | linear probe | GPU (extract) + CPU (probe) | High (novel) |

### Part IV — Security Architecture

The defense should be a **reference monitor** satisfying the three classic properties: *complete mediation* (every candidate action passes through it; Tekmor's runner guarantees this by routing all actions through `Defense.decide()`), *tamper-resistance* (the monitor's own state/policy has SYSTEM_POLICY trust and is never writable by content the agent observes), and *verifiability* (a small, auditable decision core). Pipeline:

```
candidate action + agent state + observations
        │
        ▼
[1 Provenance/Taint engine]  ── integrity(action)=min integrity of influencing observations;
        │                        track confidentiality (secrets/canaries touched)
        ▼
[2 Signal extractors]  ── (a) source trust  (b) target tool sensitivity
        │                  (c) exfil scan on args (plain/space/b64/hex/reversed)
        │                  (d) task-alignment score  (e) OPTIONAL activation-drift probe
        │                  [implemented: a, b and the policy predicates, in
        │                   defense/signals.py; c as the layered CanaryScanner]
        ▼
[3 Policy engine]  ── deterministic rules over signals (Trusted-Action, Permitted-Flow,
        │              least-privilege) → risk score + reason codes
        ▼
[4 Decision + rewrite]  ── ALLOW / REWRITE(capability downgrade) / ESCALATE / BLOCK (+ confidence)
        │
        ▼
[5 Observability]  ── append-only JSONL event + provenance graph edge
```

*Implementation note (stages 2-4).* The policy predicates are evaluated once into a named `Signals` value (`src/tekmor/defense/signals.py`); `ReferenceMonitor` decides from it and `src/tekmor/defense/risk.py` scores the same object, which is what makes the reported risk and the reason codes two views of one computation rather than two computations that may disagree. The score does not decide: stage 3's rules do, in a fixed order, and `risk.band()` states the Part XIII threshold table as a falsifiable claim that the bands agree with those rules (asserted over the whole scenario matrix in `tests/security/test_risk_bands.py`). The deviation from the roadmap wording, and why a weighted sum was not given authority over an auditable policy, is recorded in `docs/07-results.md`.

**Defend the action, not the model.** Text-centric defenses lose to paraphrase, encoding, and adaptive attacks. Action/flow-centric defenses bound the *blast radius* regardless of whether the model was fooled. This is the consensus of CaMeL, FIDES, Progent, and the Design Patterns paper. The gap in the literature, and Tekmor's opportunity, is a defense that is simultaneously action-centric, legibly observable, and utility-preserving under the over-refusal trap.

### Part V — Observability

A security trace event should contain: timestamp, run/seed, task ID, step index, agent state summary, observation + source + assigned trust + sensitivity, retrieved docs/tool results with per-field provenance, candidate action (target tool + args), influencing-observation set (taint sources), active policy ID, per-signal risk contributions, aggregate risk score + confidence, decision + reason codes, rewritten action (if any), outcome, side effects, and canary/secret status.

*Implementation note (`src/tekmor/observability/events.py`).* The event carries the aggregate risk score and deliberately **not** the per-signal contributions. The breakdown is the hill-climbing channel the Explainability section warns about, so it stays derivable from the signals (`risk.contributions`) rather than written next to a verdict an attacker may get to read. Argument *values* are never written at all.

OpenTelemetry GenAI semantic conventions (operations `invoke_agent`, `execute_tool`, `chat`; currently at "Development" stability) and OpenInference cover LLM/tool spans but **do not** natively model trust assignment, provenance chains, or ALLOW/BLOCK reason codes. Extend them with attributes such as `tekmor.trust_level`, `tekmor.provenance_path`, `tekmor.decision`, and `tekmor.reason_codes`.

Two views make decisions legible:
1. **Security timeline**: observation → trust assignment → risk detection → candidate action → policy evaluation → decision → execution → outcome, shown per step.
2. **Provenance graph**: document → malicious instruction → observation → candidate action → sensitive tool call → BLOCK, drawn live.

A viewer can then watch attacker-controlled data flow toward a sensitive action and see the edge get cut. Use Langfuse or Arize Phoenix as the trace backend, and render the graph with a small D3/vis.js page over the JSONL log.

*Implementation note (`src/tekmor/observability/viewer.py`).* Both views exist, as one self-contained HTML page per log: a timeline table per run and an inline-SVG provenance graph whose edges carry the trust of the source they come from and are drawn dashed into any action the gateway did not execute. **Deviation, deliberate:** no D3, no vis.js and no trace backend — a static page of a finished run needs none of them, and the collapsing is `<details>`. It reads the JSONL and nothing else (not the scenario, not `benign`, not the world), which is what makes it a way to find fields the schema is missing rather than a second source of truth, and why it cannot say whether a decision was *correct*. Everything interpolated is escaped: tool names, source ids and origins derive from adversary-controlled content, so the page an analyst opens to read an attack is a trust boundary. Rendering the trace forced two schema changes, recorded in `docs/07-results.md` — the log is at **schema version 2**, `source_ids` became per-source `sources` carrying trust, origin and confidentiality, and an `outcome` field (`executed` / `not_executed` / `failed`, never the tool's result) closes the execution end of the chain.

### Part VI — Evaluation Design

**Metrics (defined by Tekmor).**
- **BTU** (benign task utility): the fraction of benign scenarios completed correctly, checked against world state.
- **ASR** (attack success rate): the fraction of attack scenarios where the attacker's goal is reached.
- **CVR** (canary violation rate): the fraction of runs where a tagged secret reaches an outbound argument in any encoding.
- **FBR** (false-block rate): blocks and rewrites on benign actions.
- **UER** (unnecessary escalation rate): escalations the simulated human approves without changes.

In addition, report precision/recall/F1, AUROC/AUPRC, **calibration (ECE)** (does risk 0.9 really mean more dangerous than 0.4?), time-to-detection (steps), intervention latency (ms), number of compromised steps, blast radius, and attack-propagation depth.

*Implementation note (`evaluation/metrics.py`).* BTU, ASR, CVR, FBR, UER and time-to-detection are implemented and computed from world state and verdicts. Precision/recall/F1, AUROC, AUPRC and ECE are now implemented too, and two operational choices behind them matter more than the numbers. **The per-action label is derived, not declared:** `unsafe_steps` replays each prefix of an attack scenario undefended and labels the step whose execution first makes the scenario's `attack_success` conditions hold, so "unsafe" means exactly what ASR means, the label is identical under every defense, and nobody hand-labels which step a defense was supposed to stop. The cost is that it marks the *goal-reaching* step only: an intervention earlier in the same injected chain counts as a false positive, which is why precision must be read next to time-to-detection rather than instead of it. **AUROC, AUPRC and ECE are null for a defense that reports no score** (the baselines) rather than reading a missing score as zero risk, and they are computed over the ordinal severity scale in `src/tekmor/defense/risk.py` — so the ordering they measure is meaningful and the magnitudes are not yet. **AUPRC is reported beside its own chance line**, `base_rate`: unsafe actions are 19% of the scored actions here, and AUROC is insensitive to that imbalance while average precision is not, so neither replaces the other and showing one alone would flatter a defense on data shaped like this. **CALIB-RISK is now implemented and measured** (`evaluation/calibration.py`, below); on the seven-scenario matrix it made ECE worse, and on the full twenty-four-scenario matrix it improves it (0.07 -> 0.04, leave-one-scenario-out, no inverted fold) while still costing a little ranking, so the scale in use stays ordinal. **The pass/fail grid by attack family and level is implemented** (`evaluation.metrics.grid`): a scenario declares its `family` and `level`, both scorer metadata that never reach a defense, and the benign `over_refusal` rows sit in the same table as the attacks so that a defense buying its attack rows with refusals shows the price in the same column. Intervention latency and blast radius remain unimplemented. Three definitions had to be made operational, and the choices are recorded here rather than left to the reader: **FBR** counts blocked *and rewritten* actions among the actions of benign scenarios — a rewrite counts because the action the user asked for did not happen — while escalations are counted by UER instead, because a human still had the chance to approve them; **UER** is escalations inside benign scenarios over all escalations, the simulated human being an oracle that approves benign work and lives in the scorer, never in the run (runs escalate to the default approver, which denies); **CVR** is over all runs, benign included, since a benign scenario that leaks a secret is exactly the case the metric exists to catch. A rate with a zero denominator is reported as null, not as a perfect score.

**Test matrix.** Attack family (7) × difficulty level (1–5) × defense variant (full + ablations) × {secure outcome yes/no} × {utility preserved yes/no}. Report results as a pass/fail grid by attack family and level.

*Implementation note.* The matrix exists: twenty-four scenarios in `evaluation/scenarios/` covering all seven families at levels 1–5 across the three domains, seventeen attacks and seven benign (`over_refusal`). The grid is printed by `uv run python -m evaluation.harness` and the numbers are in `docs/07-results.md`. Three limits are worth carrying into any reading of it: level 4 is represented by *static* rewordings until the adaptive attacker exists (Phase 4); the cross-session memory label is declared rather than derived, because memory that carries a label between runs is not implemented; and one scenario (`enterprise-exfil-split-args`) leaks a secret that CVR cannot count, because the metric shares the canary scanner's per-argument blind spot by construction.

**Robustness variants.** Generate variants of every scenario by transforming only the untrusted content channels: paraphrase, base64/hex/spaced/reversed encodings, and reordered fragments for compositional cases. The generator must never pass scenario metadata to the defense. If ASR stays flat across variants, the defense isn't overfit to specific wordings.

**Adaptive attacker.** Build a hill-climbing mutation attacker that sees only public decisions and coarse reason codes. It mutates wording, placement, and fragmentation over N rounds to maximize ASR. Report how ASR changes across rounds.

### Part VII — Benchmarks

- **AgentDojo** (Debenedetti et al., NeurIPS 2024, arXiv:2406.13352; ethz-spylab/agentdojo; agentdojo.spylab.ai). 97 tasks + 629 security cases across banking/Slack/travel/workspace; stateful, dynamic, and extensible with new tasks, attacks, and **defenses**. Utility is checked on environment state (not an LLM judge). Custom defenses plug in as a *pipeline element* wrapping tool calls (`--defense tool_filter --attack tool_knowledge`). AgentDojo runs on any LiteLLM-compatible backend, so a local Qwen3-8B served through vLLM or Ollama works. Treat it as Tekmor's **external validation**: results on its 97 tasks and 629 security cases show generalization beyond your own scenarios, which is the strongest guard against unknowingly designing the defense around your own test set. Compute: API or one GPU for Qwen3-8B; long contexts (avg ~3.8k tokens).
- **InjecAgent** (Zhan et al., ACL Findings 2024, arXiv:2403.02691): 1,054 IPI cases, 17 user / 62 attacker tools, direct-harm vs data-stealing. Static and easy to overfit; a good smoke test.
- **ASB** (Zhang et al., ICLR 2025, arXiv:2410.02644): 10 injection attacks + memory poisoning + PoT backdoor, 13 backbones, NRP metric (utility/security balance). Highest average ASR observed exceeded 84%. Good for memory-poisoning coverage.
- **AgentHarm, ToolEmu, WASP, BIPIA, Tensor Trust, SEP**: complementary (harmful multi-step tasks; LM-emulated sandbox; web agents; QA-format IPI; separation dataset). Use SEP to quantify instruction/data separation; the rest are optional extensions.

**Recommendation:** primary evidence = Tekmor's own scenarios plus paraphrase/adaptive variants; external evidence = AgentDojo with local Qwen3-8B. Don't assume compatibility with the others; AgentDojo is the one with a clean defense plug-in and a matching threat model.

### Part VIII — Explainability

Structured explanations (risk score + signal flags like `source=ADVERSARY_CONTROLLED`, `target=restricted_tool`, `external_transmission=true`, `provenance_touches_untrusted=true`, `no_authenticated_authorization`, `sensitive_data_detected`, plus a primary reason code) are **faithful by construction** if the decision is *computed from those same signals*, unlike post-hoc chain-of-thought rationalizations, which can be unfaithful. They are reproducible (deterministic given inputs) and robust. **Risk:** the adversary observes public actions and reason codes and can hill-climb against them (the same channel that enables the adaptive attacker). Mitigation: expose *coarse* reason codes publicly, keep fine-grained sub-scores in the private trace, and never leak secret values or canary tokens in explanations.

### Part IX — Mechanistic Interpretability (honest feasibility)

**What's real and cheap:** **TaskTracker** (Abdelnabi et al., "Get my drift?", SaTML 2025, arXiv:2406.00799; 500K+-instance toolkit) shows a *linear probe* on **activation deltas** (residual-stream activations before vs after ingesting external text) detects task drift at over 0.99 ROC-AUC on out-of-distribution data across six models, zero-shot to unseen attacks, with no fine-tuning. This is the cheapest credible interpretability sensor: hook Qwen3-8B's residual stream (accessible because Tekmor runs the agent locally through the Transformers adapter), extract last-token activations at a chosen layer before/after untrusted content, and train a logistic-regression probe on synthetic drift/no-drift pairs. Probe training takes minutes on CPU once activations are cached; inference overhead is one extra activation capture per step.

**Assets that exist for Qwen3-8B:** Qwen-Scope (Fudan/Qwen, arXiv:2605.11887) and Qwen/SAE-Res-Qwen3-8B-Base (Hugging Face) provide residual-stream SAEs; Qwen3-Instruct SAE (arXiv:2606.26620) covers 1.7B/4B/8B with a refusal-steering case study. TransformerLens/SAELens/nnsight provide hooking infrastructure. An SAE-feature monitor is therefore *possible*.

**Honest limits:** (1) TaskTracker's evaluation holds out attack types but shares benign sources across splits, and real-world distribution shift degrades it (documented in follow-up work). (2) SAE features for security concepts (such as "treating untrusted content as authoritative") are not pre-labeled. Finding a reliable one is an open research question, so it belongs in a later research phase, not the core. (3) Activation signals are *correlational*, not the causal guarantee IFC gives. (4) Hooking must target the *same* Qwen3-8B the agent uses; a smaller proxy model's activations are not valid evidence about the agent's behavior. **Verdict:** use the **activation-delta linear probe** as a *secondary* risk signal and a compelling "look inside the model" demonstration. Do **not** make it the gate, and treat SAE-feature work as speculative.

### Part X — Research Gaps
1. **Argument-level residual**: even provably safe patterns let untrusted data shape *arguments* of permitted actions (Design Patterns paper: 8/10 case studies). Provenance on *fields*, not just calls, is underexplored.
2. **Utility under over-refusal**: almost no benchmark scores false blocks on scary-but-benign work. Hard-negative scenarios are rare and valuable.
3. **Adaptive robustness of *flow* defenses**: adaptive attacks are studied for detectors, much less for IFC/policy defenses interacting with a fooled planner.
4. **Calibrated risk scores**: most defenses output binary decisions; calibrated, legible risk with ECE is largely absent.
5. **Observability as security evidence**: no standard schema ties a decision to its causal provenance path; OTel GenAI doesn't cover it.
6. **Interpretability for agents (not chat)**: activation monitors are validated on QA/RAG, barely on multi-step tool agents.
7. **Memory-poisoning defenses**: trust inheritance through long-horizon memory is under-evaluated (ASB is the main benchmark).
8. **Rewrite/deferral as first-class primitives**: least-privilege *action downgrade* and learning-to-defer are rarely formalized as a capability lattice.

### Part XI — Candidate Solutions

1. **PROV-GATE (Provenance/IFC reference monitor).** *Hypothesis:* enforcing Biba-style integrity + confidentiality labels at the tool boundary blocks indirect and exfiltration attacks with bounded utility loss. Basis: CaMeL/FIDES. Defends: indirect, tool-tamper, exfil, memory-poison. Trace: label lattice + flow edges. Ablation: no taint. Complexity: medium; CPU-only. Risk: over-tainting → utility loss (needs an endorsement primitive).
2. **CAP-REWRITE (Capability-lattice action rewriter).** *Hypothesis:* mapping each risky tool to a reversible/lower-impact variant (send→draft, execute_payment→prepare_payment, delete→create_review_task, plus argument redaction) preserves utility while removing blast radius. Novelty: rewrite as a systematic least-privilege downgrade over an impact-ordered lattice. Complexity: low–medium; high demonstration value.
3. **TASK-ALIGN (ContributeTo monitor).** *Hypothesis:* actions that don't advance the authenticated user goal are the attack surface; score alignment and block non-contributing sensitive calls. Basis: Task Shield/AlignmentCheck. Risk: LLM-based, susceptible to adaptive attacks. Complexity: medium (needs a judge model call).
4. **DRIFT-PROBE (activation-delta linear probe on Qwen3-8B).** *Hypothesis:* task drift is linearly decodable from residual-stream deltas and flags injections that pass text/flow checks. Basis: TaskTracker. Novelty: interpretability as a sensor on the actual agent. Complexity: medium; GPU for extraction. **Secondary signal only.**
5. **MASK-REEXEC (MELON-style consistency check).** *Hypothesis:* if masked-prompt re-execution yields the same tool call, the call is injection-driven. Basis: MELON. Cost: 2× inference.
6. **POLICY-DSL (Progent-style declarative least privilege).** *Hypothesis:* per-domain JSON policies enforcing which tools/args are permissible given task + trust give deterministic, auditable security. Complexity: low–medium; pairs with PROV-GATE.
7. **CALIB-RISK (calibrated risk + selective escalation).** *Hypothesis:* a calibrated risk score with learning-to-defer thresholds beats fixed thresholds on the utility/security frontier. Novelty: ECE-measured, legible risk. Complexity: low (Platt-scale a small model). *(Half implemented, and the implemented half returns a negative result. `evaluation/calibration.py` Platt-scales the severity scale leave-one-**scenario**-out — the fold is the scenario because actions inside a run share a world and an injected chain — and reports ECE, Brier and AUROC raw and calibrated over the same held-out actions. On seven scenarios calibration makes ECE worse, 0.11 → 0.12 and 0.07 → 0.10, and `tekmor`'s AUROC moves 0.83 → 0.75 across folds, which measures how far the fit travels when one scenario is swapped out. Twenty-one scored actions is not enough to fit a calibration; the claim needs the larger matrix before it can be tested rather than computed. The selective-escalation half is **not** implemented: deferral thresholds would give a fit authority over a verdict the rules produce, which is the trade declined in `docs/07-results.md`.)*
8. **CANARY-FLOW (secret/canary taint + exfil decoder).** *Hypothesis:* tagging secrets as confidentiality-labeled canaries and scanning outbound args across encodings (b64/hex/spaced/reversed) catches exfiltration. Complexity: low; high demonstration value.

**Best combinations (genuine security advantage):** PROV-GATE + CAP-REWRITE + CANARY-FLOW + POLICY-DSL + observability form a complete, deterministic, legible, utility-preserving core. Add DRIFT-PROBE as the novel secondary sensor and CALIB-RISK for legible escalation. TASK-ALIGN or MASK-REEXEC add depth later. Avoid stacking two expensive LLM-judge layers (latency + adaptive attack surface).

### Part XII — Recommended Directions (tradeoffs)
- **Determinism vs coverage:** IFC/policy is deterministic and provable but can over-taint; task alignment and probes add coverage but also adaptive attack surface and latency. Use a deterministic core plus one probabilistic sensor, clearly separated in the trace.
- **Utility vs security:** the capability-rewrite path is the key innovation that escapes the "block everything" failure. It keeps the task moving (draft instead of send) while neutralizing impact.
- **Novelty vs reliability:** the activation probe is the most novel component, but reliability must come from the deterministic gate. Present the probe as an *additional* signal with honest false-positive numbers.

### Part XIII — Implementation Roadmap

These workstreams can be split among collaborators or done in sequence by one person: security core, infrastructure, evaluation, observability, and interpretability research.

- **Phase 1: Foundation.** Build the repo skeleton, the three-domain simulator, typed tools, canary-tagged secrets, and the scenario format. Add the mock and Qwen3-8B adapters, the `Defense` interface, and the JSONL event schema. Implement baselines (allow-all, deny-sensitive, keyword) so every later result has a reference point.
- **Phase 2: Core defense.** Add the trust lattice, taint propagation through memory and tool-output fields, the canary exfiltration scanner across encodings, the capability-lattice rewriter, and per-domain JSON policies. Milestone: poisoned invoice, false approval, hostile log text, and memory poisoning all end in the secure outcome.
- **Phase 3: Observability and evaluation.** Build the timeline and provenance-graph viewer and the full scenario matrix. Add calibrated risk thresholds (low→ALLOW, medium→REWRITE, high→BLOCK, ambiguous + high-impact→ESCALATE) and measure ECE. *(In progress: the harness, the metrics and a seven-scenario matrix exist — `evaluation/harness.py`, numbers in `docs/07-results.md`. Signal extraction, the risk score, the thresholds, ECE and AUPRC exist, with one deviation recorded in `docs/07-results.md`: the thresholds do not decide. The rules decide and the bands are asserted to agree with them, because a weighted sum that could overrule an auditable policy is a worse trade than a score that only describes. The viewer now exists and renders from the log alone (`src/tekmor/observability/viewer.py`), and the scale has been Platt-scaled and measured rather than merely described. **The full scenario matrix now exists** — twenty-four scenarios, seven families, levels 1–5 — and with it the calibration could finally be tested rather than merely computed: it reverses, improving ECE 0.07 → 0.04 where on seven scenarios it made ECE worse, which is the outcome the earlier entry said the larger matrix would decide. The pass/fail grid by family and level is reported. Phase 3 is complete; what it does not contain is generated robustness variants and an adaptive attacker, which are Phase 4.)*
- **Phase 4: Robustness and ablations.** Run paraphrase and encoding variants, the adaptive attacker, and ablations (no provenance, no trust propagation, no rewrite, rules only, full system). Then integrate AgentDojo. *(In progress: the robustness variants exist, `evaluation/variants.py`. Five encodings, a lexical reword and a read reorder, each validated against its own ground truth undefended and reported paired with the original. The monitor's verdicts do not move under any of them. The keyword baseline moves both ways under rewording. One composed encoding (base64 of the reversed token) leaks a mislabelled secret past `tekmor+canary` where CVR cannot count it, pinned as an xfail and recorded in `docs/07-results.md`. The reword is a substitution table, not a model paraphrase. The ablations exist too, `evaluation/ablations.py`. Without provenance, ASR is 0.94. Without propagation it is 0.35: five integrity-driven attacks land, while the exfiltrations hold on the latest read. Without rewrite no scored outcome moves, because attack scenarios state no utility condition; this is recorded in `docs/07-results.md` as a limit of the matrix. The adaptive attacker exists, `evaluation/adaptive.py`. It hill-climbs over a genome of encoding, rewording and read order, and sees only its goal, the verdicts and the public reason codes. Across fifty rounds the keyword filter goes from ASR 0.88 to 1.00 within five rounds, while `tekmor` and `tekmor+canary` stay flat. The one form that beats the canary layer (`base64-reversed` on the mislabelled leak) is rejected by the ground truth that shares the scanner's blind spot, so the flat curve is partly a measurement artefact; `docs/07-results.md` records this. The search space is 24 candidates against a scripted agent, not text against a model. AgentDojo is integrated (`evaluation/dojo.py`, suites v1.2.2). Tekmor runs as a pipeline element, with AgentDojo's ground truth driven as a fully fooled agent. It stops every valid attack except slack's URL fetch through an unguarded read (21 of 583). Its benign utility equals `deny-sensitive` on three of four suites, which is call-level over-tainting measured on tasks this project did not write, and it trips Recommendation 1. Phase 4 is complete; the numbers are in `docs/07-results.md`.)*
- **Phase 5: Research extensions.** Add Proposal B's alignment auditor and/or Proposal C's activation probe, each gated on the evidence thresholds in the Recommendations. *(In progress. AgentDojo tripped Recommendation 1, so Phase 5 opened with the endorsement primitive (`provenance.taint.endorse`, opt-in per policy). On AgentDojo it raises pooled BTU 0.45 → 0.69 and ASR 0.04 → 0.15, a trade recorded in `docs/07-results.md`; the gate is applied and measured, not passed. Proposal B's auditor is built (`defense/auditor.py`: gray zone only, monotone, the judge sees the task and the call). With the judges this CPU-only machine can run, it is not adopted. Qwen3-0.6B never answers below 0.86 and changes nothing. Phi-3-mini stops the endorsed attack on the matrix but loses two benign tasks, costs ~20 s per call, and was not run on held-out AgentDojo. Proposal C ran as a pre-registered experiment on a Qwen3-0.6B proxy (`research/experiments/drift_probe/`). Synthetic validation AUROC was 0.99, but held-out FPR was 0.25 on the matrix and 0.82 on AgentDojo: the probe learned "external text arrived", not "an instruction arrived". It fails Recommendation 3's gate and is demoted to future work. Phase 5 is complete: of the three additions, endorsement is kept as an opt-in, B is built and not adopted, and C is demoted. Both proposals were later rerun on a GPU and both failed again, and B's verdict now rests on its control rather than on its answer distributions: `deny-gray` — the same auditor with a judge that never confirms (`--judge none`) — reproduces both GPU judge rows exactly on the matrix and on three AgentDojo suites of four, so what either judge contributed over refusing the gray zone unasked is four benign runs out of 97 and two, inside the band the pre-registration declared unresolvable at this sample size. Any future judge is scored against `deny-gray`, not against `tekmor`.)*
- **Ongoing:** keep the technical write-up, safety statement, and reproducible run scripts up to date.

**Out of scope for v1:** fine-tuning Qwen3-8B, training SAEs from scratch, a full CaMeL-style interpreter, a multi-agent oversight mesh, and any single LLM judge acting as the only gate.

### Part XIV — Demonstration Strategy
1. **Benign task completes** (enterprise: summarize a thread, draft a reply). Shows utility preserved and no needless blocks.
2. **Indirect injection — poisoned invoice**: a vendor attachment tells the agent to fetch a restricted portal token and paste it into a draft. Show live: trust=ADVERSARY_CONTROLLED assigned → provenance edge → candidate action touches a restricted tool + secret → CANARY-FLOW fires → BLOCK/REWRITE → the token never leaves. The provenance graph cuts the edge on screen.
3. **Compositional/multi-step**, where no single observation looks dangerous. Show flow-level taint accumulation catching what a per-message classifier misses.
4. **Memory poisoning** (a newsletter plants a fake data-sharing policy): the later recall stays UNTRUSTED, the trusted SYSTEM_POLICY wins, and the action is blocked. The trace shows inherited trust.
5. **Adaptive round**: the attacker rewords after seeing a BLOCK; show ASR stays flat across rounds.

Optional: a **DRIFT-PROBE** panel showing the activation delta spiking on the injected step. End on one honestly documented failure, such as the argument-level residual, with an explanation. Showing where a defense breaks is part of showing it works.

### Part XV — Technical Write-up Structure
Problem → **Threat model** (adversary capabilities and limits; cite the adaptive-attack literature) → **Falsifiable hypothesis** ("action-boundary IFC + capability rewrite blocks families X–Z at ASR<k while BTU stays >m and FBR <f") → Related work → Architecture → Security model (reference-monitor properties) → Provenance model (lattice + inheritance) → Risk model → Policy engine → Observability → Explainability → Implementation → Experimental setup → Scenarios → Metrics → **Results** (pass/fail grid by family × level; utility; precision) → **Ablations, honestly reported** (no-provenance is the cleanest) → **Failure analysis** (argument residual, adaptive gains, probe false positives) → Limitations → **Responsible-AI statement** (what it protects against, failure modes, expected false positives, what data it observes, when humans are consulted) → Reproducibility (seeds, offline runs) → Future work.

---

## What We Should Actually Build — Three Concrete Architecture Proposals

### Proposal A — Deterministic Information-Flow Reference Monitor (the reliable core)

- **Core idea.** A reference monitor at the tool boundary that assigns each observation one of the six trust levels, propagates integrity as taint through memory and tool-output fields, and enforces two deterministic policies before any tool call: **Trusted-Action** (a sensitive tool may only be driven by inputs whose minimum integrity ≥ threshold) and **Permitted-Flow** (confidential/canary data may not flow into an outbound argument unless the recipient is authorized). Non-compliant actions are REWRITTEN to a lower-capability variant, ESCALATED, or BLOCKED.
- **Scientific defensibility.** A direct instantiation of FIDES and CaMeL, which report stopping all or nearly all AgentDojo prompt injections with policy checks on. Deterministic and auditable, so it resists the adaptive attacks that break classifiers.
- **Supporting research.** CaMeL (2503.18813), FIDES (2505.23643), Progent (2504.11703), Design Patterns (2506.08837).
- **Novel component.** Field-level provenance + a **capability lattice of tool variants** (impact-ordered) with automatic least-privilege downgrade, addressing the argument-residual gap the Design Patterns paper leaves open.
- **Architecture.**
```
obs ─▶ [Trust tagger] ─▶ [Taint store: memory+fields] ─▶ candidate action
                                                              │
                    ┌─────────────────────────────────────────┘
                    ▼
           [Policy engine: Trusted-Action + Permitted-Flow + least-priv]
                    │  risk + reason codes
                    ▼
        ALLOW ── REWRITE(downgrade) ── ESCALATE ── BLOCK ─▶ gateway ─▶ world
                    │
                    ▼  append-only JSONL + provenance-graph edge
```
- **Security mechanism.** Complete mediation + integrity/confidentiality lattice enforcement; blast radius bounded by construction.
- **Observability.** Security timeline + live provenance graph; every edge labeled with trust and the policy that fired.
- **Explainability.** Reason codes are the literal policy predicates that fired (faithful by construction).
- **Optional mech-interp.** None (kept deterministic); DRIFT-PROBE can be added as Proposal C.
- **Evaluation.** Family × level pass/fail grid; ablation = disable taint propagation (expect memory-poison and compositional attacks to break). External evidence: AgentDojo.
- **Expected failure modes.** Over-tainting reduces BTU on hard negatives; argument-level residual on permitted actions; needs an endorsement primitive if utility drops.
- **Complexity/compute.** Medium; **CPU-only** for the defense (Qwen3-8B only for the agent). Most feasible.
- **Build order.** Trust tagger → taint store → policies + rewrite → observability + full matrix → ablation + adaptive tests.
- **Why interesting.** It's an open reproduction of the FIDES/CaMeL approach on a *new* three-domain testbed with first-class observability: a credible research artifact, not a toy.

### Proposal B — IFC Core + Task-Alignment Auditor (the balanced option)

- **Core idea.** Proposal A's deterministic core, plus a lightweight **task-alignment auditor** (Task Shield / AlignmentCheck style) that scores whether each sensitive candidate action advances the authenticated user goal. It is used *only* to break ties in the ambiguous-risk band (→ ESCALATE or REWRITE), not as a primary gate.
- **Scientific defensibility.** Task Shield reports ASR 2.07% at 69.79% utility. Using alignment only as a *tie-breaker* avoids making the whole system depend on an LLM judge that can be fooled.
- **Supporting research.** Task Shield (2412.16682), LlamaFirewall AlignmentCheck (2505.03574), MELON (2502.05174) as an alternative consistency check.
- **Novel component.** A two-tier decision: deterministic policy decides clear cases; the alignment score only arbitrates the calibrated "gray zone," measured with ECE.
- **Architecture.**
```
candidate ─▶ [IFC policy] ──clear──▶ ALLOW/BLOCK/REWRITE
                 │ gray zone
                 ▼
        [Task-alignment auditor (small LLM)] ─▶ ESCALATE or REWRITE
                 │
                 ▼ JSONL + graph (+ alignment rationale, private)
```
- **Security mechanism.** Deterministic bound + goal-alignment coverage for subtle compositional attacks the pure lattice misses.
- **Observability/Explainability.** Same as A, plus an alignment-score panel. Keep the auditor's rationale in the private trace to avoid feeding adaptive attackers.
- **Optional mech-interp.** Swap or complement the auditor with DRIFT-PROBE.
- **Evaluation.** Ablation = remove the auditor (expect gray-zone compositional attacks to rise); measure added latency and adaptive susceptibility explicitly.
- **Expected failure modes.** Auditor latency; the auditor itself is an injection target (mitigation: it only reads *summarized*, trust-labeled context, never raw untrusted text as instruction).
- **Complexity/compute.** Medium-high (one extra model call per gray-zone action); needs Qwen3-8B or a small judge model.
- **Build order.** A's core → auditor on the gray zone only → calibration → ablation measuring the auditor's marginal value, latency, and adaptive susceptibility.
- **Why interesting.** It directly studies the deterministic-vs-semantic tradeoff, with an ablation showing where each layer helps.

### Proposal C — IFC Core + Activation-Delta Drift Probe (the novelty option)

- **Core idea.** Proposal A's core plus a **TaskTracker-style linear probe** on Qwen3-8B's residual stream that flags task drift (the model starting to *follow* untrusted text) as a secondary risk signal feeding the calibrated score.
- **Scientific defensibility.** TaskTracker reports >0.99 OOD ROC-AUC with a linear probe and no fine-tuning; Qwen3-8B residual-stream SAEs and probing infrastructure exist (Qwen-Scope, Qwen/SAE-Res-Qwen3-8B). Honest caveat: the signal is correlational and sensitive to distribution shift, so it is never the sole gate.
- **Supporting research.** TaskTracker / "Get my drift?" (2406.00799), Qwen-Scope (2605.11887), Qwen3-Instruct SAE (2606.26620).
- **Novel component.** An activation-based sensor operating on the *actual reference agent* (the same Qwen3-8B), fused with deterministic IFC. This intersection is barely explored for multi-step tool agents.
- **Architecture.**
```
Qwen3-8B forward pass ─▶ [hook residual @ layer L] ─▶ activation delta
                                                          │
candidate ─▶ [IFC policy] ─┬──────────────────────────────┤
                           ▼                              ▼
                   deterministic decision  ◀── fuse ── [linear drift probe]
                           │  (probe raises risk, never lowers a BLOCK)
                           ▼ ALLOW/REWRITE/ESCALATE/BLOCK + JSONL + graph + probe panel
```
- **Security mechanism.** The deterministic bound is authoritative; the probe only *escalates* suspicion (monotone-safe fusion), so a probe false negative can't weaken the IFC guarantee.
- **Observability/Explainability.** Add a live activation-delta plot that spikes on injected steps; label probe outputs as probabilistic in the trace.
- **Evaluation.** Ablation = probe on/off (does it catch attacks IFC misses, and at what false-positive rate on hard negatives?); report probe ECE and out-of-distribution degradation honestly.
- **Expected failure modes.** False positives on scary-but-benign text; extraction requires a GPU and hooks in the Transformers adapter; distribution shift on long-horizon scenarios.
- **Complexity/compute.** Highest; **GPU needed** for activation extraction; probe inference stays cheap (one vector + logistic regression).
- **Build order.** A's core → cache activations and train the probe on synthetic drift pairs → monotone-safe fusion → ablation and false-positive analysis. Demote to future work if the probe's FPR on hard negatives exceeds ~10%.
- **Why interesting.** It produces a new data point, activation monitoring on a multi-step tool-using agent, and it stays defensible because the deterministic core carries the security guarantee.

**How to choose (tradeoff, not a winner).** If you want maximum reliability and the cleanest evaluation, build **A**. If you have capacity for one extra model call per ambiguous action, **B** adds coverage on subtle compositional attacks and a compelling ablation. If you have a GPU and interest in interpretability, **C** gives the most novel research contribution, but *only* as A plus a probe, never the probe alone. All three share the same deterministic core, observability, and evaluation harness. The rational plan is to **build A first as the stable core**, then choose B or C based on your compute and research interests. The core is what keeps the agent useful while preventing unauthorized actions. B and C are research bets on top of it, not replacements for it.

## Recommendations
1. **Build Proposal A as Tekmor's core in your own repo before anything else.** It gives the highest security, legibility, and feasibility. *Threshold:* if BTU falls below ~0.7 on benign and hard-negative scenarios, add a FIDES-style endorsement primitive before adding new signals.
2. **Treat observability as a first-class component.** *Threshold:* someone should be able to reconstruct every decision's causal chain from the trace alone, without reading code.
3. **Add Proposal B or C only once the core is stable.** *Threshold for C:* keep the probe only if its FPR on hard negatives is below ~10% and it catches at least one attack the deterministic core misses; otherwise demote it to future work.
4. **Measure everything and document failures.** Run the full matrix, ablations, robustness variants, and the adaptive attacker, and report calibration. If adaptive ASR rises across rounds, record it as a limitation.
5. **Use AgentDojo as external validation** with local Qwen3-8B once the core passes your own scenarios.

## Caveats
- Tekmor's simulator, scenarios, and metric definitions are your own. Results on them are only as convincing as the scenarios are hard and independent of the defense's design. Write adversarial and hard-negative scenarios *before* tuning the defense, and freeze a held-out set. Rely on AgentDojo for external validity.
- Every "provable" or "near-zero ASR" claim (CaMeL 77% with provable security, FIDES stopping all AgentDojo injections, MELON >99%, Progent, Task Shield 2.07%) is measured on *their* benchmarks (mostly AgentDojo) against *their* attack sets. Adaptive attackers break many defenses that look strong on static tests: Zhan et al. (>50% ASR on 8 defenses) and Nasr/Carlini et al. (>90% on all twelve tested). Treat these numbers as upper bounds and test adaptively.
- LlamaFirewall's figures come from Meta's own paper (combined PromptGuard 2 + AlignmentCheck: AgentDojo ASR 17.6%→1.75%; AlignmentCheck −83% ASR; PromptGuard 2 ~88.7% recall at 1% FPR). Vendor blogs quoting different numbers were not used.
- TaskTracker's >0.99 ROC-AUC was reported under evaluation conditions with known distribution-shift weaknesses; expect degradation on compositional and long-horizon scenarios.
- OpenTelemetry GenAI semantic conventions are explicitly "Development"/unstable as of 2026 and don't natively model trust, provenance, or decisions; plan to extend them.
- Vendor blog claims (Meta, Microsoft, NVIDIA, guardrail vendors) were treated as marketing unless corroborated by the primary paper or code repository.