# Braum — Final Project Report

**Former repository/project name:** SENTINEL  
**Repository:** `wissemkooli/sentinel-indabax`  
**Challenge:** IndabaX Tunisia 2026 research challenge

## TL;DR

Braum is a deployment-oriented provenance and policy defense for tool-using LLM agents. It treats untrusted documents, emails, memories, and tool outputs as content that may be read but does not automatically gain authority to cause actions or disclose protected information.

The defense seals authority from the user's goal before external content is exposed, tracks provenance and sensitivity, attributes decisive arguments to their sources, applies capability and information-flow policy, and chooses the least restrictive safe intervention: allow, rewrite, escalate, or block.

The decision engine is deterministic. Qwen3-8B is the protected agent in the official evaluation, not Braum's policy engine.

## Key Findings

1. **Action-boundary enforcement is stronger than text-only detection.** Braum evaluates the proposed tool action, its arguments, provenance, capability, and information flow rather than trying to classify text as malicious.
2. **The official Braum path contains all 23 attacks that reached the undefended Qwen3-8B agent on the public split**, with one documented blocked legitimate read.
3. **Tekmor's internal research suite supports the same design direction.** Its provenance monitor plus canary layer reached 1.00 benign utility, 0.06 attack success, 0.04 secret leaks, and 0.00 false blocks.
4. **Provenance is the main measured contributor in Tekmor.** Removing it raised attack success from 0.06 to 0.94; removing taint propagation raised it to 0.39.
5. **External validation is less flattering.** On AgentDojo, Tekmor's scripted-policy evaluation achieved 0.45 benign utility and 0.036 attack success, showing the cost of conservative call-level taint.
6. **The research track keeps negative results.** Tekmor's activation probe failed its false-positive gate on held-out traces, and its model-driven AgentDojo attempt produced no valid comparative run.

## Details

### Part I — Problem Understanding

Tool-using agents read from sources their users do not control and can spend the user's authority by sending messages, moving money, changing records, or disclosing data. The central failure is that read content and trusted instructions share one context.

The shared design principle is:

> Untrusted content is evidence, not authority.

### Part II — State of the Art

Braum follows the action-centric security line represented by provenance, information-flow control, capability policies, and least-privilege tool mediation. It does not claim that a classifier can reliably detect every indirect prompt injection, especially under paraphrase, encoding, or adaptive mutation.

Tekmor's research report records the related-work analysis and distinguishes deterministic policy enforcement from optional alignment judges and activation-based signals.

### Part III — Existing Tools & Open-Source Ecosystem

Braum is organized as a self-contained deployment path:

- `sentinel/` contains the defense and policy engine.
- `submission/` contains the official v1 FastAPI service and Docker package.
- `observability/` contains trace replay and dashboarding.
- `artifacts/` contains recorded evaluation outputs.
- `experiments/Tekmor/` contains the independent research implementation and its benchmarks.

The two tracks must not be conflated. A future comparison must identify whether it evaluates unchanged Braum, unchanged Tekmor, an adapter, or a derived experimental variant.

### Part IV — Security Architecture

```text
User goal
    ↓
Authority / mandate sealing before external content is read
    ↓
Observed content with trust, sensitivity, and provenance
    ↓
Agent proposes a candidate tool action
    ↓
Argument-level provenance attribution
    ↓
Capability, mandate, policy, and information-flow checks
    ↓
Evidence and risk evaluation
    ↓
Generate and re-score safer alternatives
    ├── allow
    ├── rewrite: quarantine, redact, or downgrade
    ├── escalate to a human
    └── block
    ↓
Execution boundary
    ↓
JSONL trace, replay, and dashboard
```

Authority comes from the user's goal, not from later documents or tool results. Provenance and sensitivity remain attached to observed content, and sensitive data is not allowed to cross an unauthorized sink. The policy engine can preserve useful work by downgrading `send` to `draft` or an irreversible action to a safer preparation step.

### Part V — Observability

Braum records structured JSONL traces containing the mandate, observations, evidence, risk, policy decisions, rewrites, and execution outcomes. The trace can be replayed in the terminal or rendered in the self-contained dashboard. This makes the causal path from an untrusted source to a blocked action inspectable.

### Part VI — Evaluation Design

The official evaluation records the model, split, attacker, seed, implementation version, and limitations. The primary model is Qwen3-8B, self-hosted on a Kaggle GPU. The reported metrics include benign task utility, attack success, canary leaks, and false-block rate.

Tekmor uses the same research discipline on its own surfaces: fixed baselines, ablations, adaptive variants, external validation, and explicit negative results. Its internal suite is useful for regression and mechanism analysis; it is not treated as independent external evidence.

### Part VII — Benchmarks

#### Official Braum evaluation

The latest documented Qwen3-8B run contains all 23 attacks that reached the undefended agent on the public split. The official score and full run details remain in [TECHNICAL_REPORT](TECHNICAL_REPORT.md), [OFFICIAL_HARNESS](OFFICIAL_HARNESS.md), and `artifacts/qwen3/`.

#### Tekmor internal suite

Tekmor evaluates 26 scenarios across enterprise, financial, and security-operations domains, covering seven attack families at difficulty levels 1–5, including eight benign hard negatives.

| Tekmor configuration | Benign utility | Attack success | Secret leaks | False blocks |
|---|---:|---:|---:|---:|
| `allow-all` | 1.00 | 1.00 | 0.42 | 0.00 |
| `deny-sensitive` | 0.12 | 0.00 | 0.00 | 0.24 |
| `keyword` | 0.62 | 0.89 | 0.27 | 0.11 |
| `tekmor` | 1.00 | 0.11 | 0.08 | 0.00 |
| `tekmor` + canary layer | 1.00 | **0.06** | **0.04** | 0.00 |

#### Tekmor ablations and adaptive attacker

Removing provenance raised attack success from 0.06 to 0.94. Removing taint propagation raised it to 0.39. Over 50 hill-climbing rounds, the keyword filter reached 1.00 attack success within five rounds; `tekmor` remained at 0.06 and `tekmor` plus canary remained at 0.00.

These are internal research measurements using a scripted agent. One encoded canary case exposed a scanner/ground-truth blind spot, so the flat adaptive curve is not presented as proof of universal robustness.

#### Tekmor AgentDojo validation

Tekmor evaluated AgentDojo v1.2.2 across banking, Slack, travel, and workspace: 97 benign runs and 583 attack pairs. The core configuration achieved 0.45 benign utility and 0.036 attack success; `deny-sensitive` achieved 0.41 and 0.036. Endorsement raised utility to 0.69 but also raised attack success to 0.146. Argument provenance reached 0.55 utility and 0.072 attack success; field labels reached 0.55 and 0.038 in the measured arm.

Every AgentDojo number came from a scripted ground-truth agent. Attack success is therefore an always-obeys upper bound, and benign utility measures whether the policy permits the oracle trace. A Qwen3-8B model-driven attempt scored 0.00 utility even for `allow-all`, so it produced no valid comparative benchmark.

Full Tekmor tables and caveats are in [results](../experiments/Tekmor/docs/07-results.md), [methodology](../experiments/Tekmor/docs/06-evaluation-methodology.md), and [limitations](../experiments/Tekmor/docs/08-limitations.md).

### Part VIII — Explainability

The defense emits reason codes and structured evidence from the same signals used for the decision. This keeps explanations faithful to policy predicates rather than relying on post-hoc model rationales. Fine-grained traces remain separate from public adaptive-attacker feedback.

### Part IX — Mechanistic Interpretability (honest feasibility)

Tekmor tested an activation-delta drift probe as an optional research extension. It reached 0.99 AUROC on synthetic validation, but only 0.65 AUROC with a 0.91 false-positive rate on held-out AgentDojo traces at 8B. It flagged 88 of 97 clean runs and was demoted to future work. Braum does not depend on this probabilistic signal.

### Part X — Research Gaps

Known gaps include argument-level residual influence, opaque identifiers, secrets laundered through world state, read-as-attack scenarios, external validation of confidentiality flow, adaptive robustness against capable model-driven agents, and calibrated risk scores with enough independent data.

### Part XI — Candidate Solutions

The adopted operational solution is a deterministic provenance and policy monitor with capability-aware rewriting, information-flow checks, structured traces, and an execution boundary. Tekmor also evaluated endorsement, argument provenance, field labels, an alignment auditor, and an activation probe. These remain experimental unless a documented comparison supports adoption.

### Part XII — Recommended Directions (tradeoffs)

The stable core should remain deterministic and auditable. Utility improvements should prefer least-privilege rewrites and explicitly scoped endorsement over silently trusting observed content. Probabilistic judges or activation sensors may supplement the core, but must never be the sole security gate.

### Part XIII — Implementation Roadmap

The implementation sequence is: preserve Braum as the default path; maintain Tekmor as an explicit experimental path; align terminology and component mappings; add comparison tooling; then run regression, official, and external benchmarks with fixed configurations and recorded limitations.

### Part XIV — Demonstration Strategy

The primary demonstrations are a benign task that completes, a poisoned invoice that is blocked or rewritten, a multi-step provenance attack, a memory-poisoning attempt, and an adaptive round. Each should show the trace and the decision reason, including one honest failure boundary.

### Part XV — Technical Write-up Structure

The report follows the same research progression as Tekmor: problem and threat model, related work, architecture, security model, provenance, policy, observability, implementation, evaluation, benchmarks, ablations, failure analysis, limitations, and reproducibility.

## What We Should Actually Build — Three Concrete Architecture Proposals

1. **Deterministic information-flow reference monitor:** the reliable core for production and submission.
2. **Core plus task-alignment auditor:** an optional gray-zone experiment, judged against a refuse-everything control.
3. **Core plus activation-delta drift probe:** a future interpretability experiment that can raise suspicion but cannot weaken deterministic policy decisions.

## Recommendations

1. Keep Braum as the default production and submission path.
2. Keep Tekmor results separate, reproducible, and clearly labeled as research evidence.
3. Use official evaluation for deployment claims and AgentDojo only with its scripted-agent limitation attached.
4. Preserve negative results, ablations, and failure cases alongside headline scores.
5. Record implementation, model, benchmark, split, attacker, seed, policy, metrics, commands, and known failures for every future run.

## Caveats

- Tekmor's internal scenarios were written by the same project that wrote the defense; they are useful for ablations and regression, not external validity.
- AgentDojo results are based on a scripted ground-truth agent, not a successful model-driven run.
- The activation probe failed its pre-registered false-positive gate and is not part of the Braum security boundary.
- A benchmark-derived fix must not be presented as independent validation on that same benchmark.
- This report uses **Braum** as the project name while retaining the current repository name until a separate repository-renaming decision is made.
