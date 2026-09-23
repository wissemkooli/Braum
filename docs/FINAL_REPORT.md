# Braum — Final Project Report

**Former repository/project name:** SENTINEL  
**Repository:** `wissemkooli/sentinel-indabax`  
**Challenge:** IndabaX Tunisia 2026 research challenge

## Executive summary

Braum is a deployment-oriented provenance and policy defense for tool-using LLM agents. It treats untrusted documents, emails, memories, and tool outputs as content that may be read but does not automatically gain authority to cause actions or disclose protected information.

For each candidate action, Braum seals authority from the user's goal before external content is exposed, tracks provenance and sensitivity, attributes decisive arguments to their sources, calculates evidence-based risk, applies capability and information-flow policy, and chooses the least restrictive safe intervention: allow, rewrite, escalate, or block.

The defense is deterministic and does not use an external LLM for its decision. The Qwen3-8B model described in the evaluation is the agent being protected, not Braum's policy engine.

## Research lineage and experimental track

Braum's operational implementation is documented in the existing technical report and official-harness artifacts. A separate `experiments/tekmor/` track is reserved for importing Tekmor's research implementation, adapters, benchmark integrations, and comparative experiments.

The two tracks must not be conflated:

- **Braum default path:** the implementation in `sentinel/`, its official API in `submission/`, and its existing observability and evaluation artifacts.
- **Tekmor experimental path:** material under `experiments/tekmor/`, once the source repository is available and imported with its commit and license recorded.

No Tekmor benchmark or implementation result is claimed as a Braum result unless it is run by the Braum implementation under a documented, reproducible configuration. Likewise, a future AgentDojo result must identify whether it evaluates unchanged Braum, a Braum adapter, or a Braum-derived experimental variant.

The Tekmor repository was not accessible during preparation, so no Tekmor source files are included yet. The reserved directory is intentionally a transparent placeholder rather than an unsupported attribution.

## Defense pipeline

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

## Official evaluation

The primary evidence remains the official challenge evaluation documented in `docs/TECHNICAL_REPORT.md`, `docs/OFFICIAL_HARNESS.md`, and `artifacts/qwen3/`. Reported numbers must retain their original agent, split, attacker, seed, implementation version, and limitations.

The latest documented Qwen3-8B run reports containment of all 23 attacks that reached the undefended agent on the public split, with the documented cost of one blocked legitimate read. The report also preserves earlier failed runs and the known limitations rather than presenting only the final score.

## Deployment and observability

Braum provides:

- the provenance and policy engine under `sentinel/`
- an official v1 FastAPI service under `submission/`
- Docker packaging with a non-root runtime and health check
- structured JSONL traces
- terminal replay
- a self-contained HTML dashboard
- technical, safety, failure-analysis, and demonstration documentation

## Reproducibility rules

Every future experiment should record:

- implementation name and commit
- model and model version
- benchmark and version/commit
- scenario split
- attacker configuration
- seed
- policy configuration
- attack-success, utility, false-block, rewrite, and escalation metrics
- exact commands and known failures

This report uses **Braum** as the project name while retaining the current repository name until a separate repository-renaming decision is made.
