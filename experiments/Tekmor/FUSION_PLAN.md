# Fusion Plan: Tekmor → SENTINEL

## 1. Objective

Unify Tekmor’s research architecture with SENTINEL’s deployment-ready defense into one coherent project.

The fused project will present:

- **Tekmor** as the earlier research implementation and architectural foundation.
- **SENTINEL** as the current operational implementation.
- **SENTINEL** as carrying forward Tekmor’s core methods, architecture, and safety principles.
- Additional SENTINEL features focused on faster deployment, easier integration, official-harness compatibility, trace replay, and dashboarding.

The fusion should preserve the research depth of Tekmor while making the resulting system easier to run, demonstrate, evaluate, and submit.

## 2. Lineage and progression

### 2.1 Tekmor: research foundation

Tekmor establishes the core safety architecture for tool-using LLM agents:

- provenance-aware action evaluation
- trust and sensitivity labels
- capability and policy enforcement
- permitted information flow
- trusted-action checks
- allow, block, rewrite, and escalate decisions
- fail-closed mediation
- structured event logging
- adversarial evaluation and ablation methodology

Tekmor’s primary role in the fused project is to provide the research foundation, modular architecture, experiments, and technical rationale.

### 2.2 SENTINEL: operational continuation

SENTINEL carries the same central defense philosophy and architecture forward into a more deployment-oriented implementation.

The shared design principle is:

> Untrusted content may be read as evidence, but it must not gain authority to perform an action or disclose protected information.

SENTINEL preserves the main Tekmor concepts:

- authority should come from the user’s request and policy
- observed content must retain its provenance
- decisive arguments should be attributed to their sources
- sensitive actions require stronger controls
- confidential information must not cross unauthorized sinks
- unsafe actions should be rewritten or escalated where possible
- failures must fail closed rather than silently permit execution

### 2.3 Added SENTINEL improvements

SENTINEL extends the shared foundation with implementation improvements intended to make the defense faster and easier to deploy:

- official v1 defense API integration
- FastAPI service wrapper
- Docker packaging
- health checks
- non-root container execution
- simplified local startup
- run-level memory for sliding conversation windows
- improved handling of retry loops
- stronger credential redaction
- capability inference for unknown tools
- structured JSONL traces
- replay tooling
- self-contained HTML dashboarding
- clearer official-harness artifacts
- easier reproduction for teammates, judges, and evaluators

These additions improve operational readiness without changing the central provenance-first safety model.

## 3. Unified defense architecture

The fused defense should be described using one common pipeline:

```text
User goal
    ↓
Authority / mandate sealing
    ↓
Observed content with provenance and sensitivity
    ↓
Candidate tool action
    ↓
Argument and action attribution
    ↓
Policy, capability, and information-flow checks
    ↓
Risk and evidence evaluation
    ↓
Allow / block / rewrite / escalate
    ↓
Execution gateway
    ↓
Structured trace and dashboard
```

### 3.1 Authority sealing

At the beginning of a turn, the system derives the user’s authority from the user’s goal before external content is read.

This establishes:

- permitted capabilities
- prohibited capabilities
- named resources
- task scope
- confirmation requirements

Later content can influence what the agent proposes, but it cannot retroactively become part of the user’s original authority.

### 3.2 Provenance tracking

Every observed document, email, tool result, memory item, or external source receives provenance metadata.

The defense records:

- source identity
- source type
- trust level
- sensitivity level
- observation order
- derived relationships
- decoded or normalized views where relevant

This allows the defense to distinguish user-authored instructions from content authored by documents, tools, or attackers.

### 3.3 Argument-level attribution

The defense examines the arguments of a proposed action rather than treating the entire context as equally trusted.

For example:

```text
ticket_update(
    ticket_id = user-authorized value,
    status = attacker-authored "closed"
)
```

The system should preserve the legitimate task where possible while removing, rewriting, escalating, or blocking the attacker-controlled argument.

### 3.4 Capability and policy enforcement

Tool names alone are insufficient. The effective capability may depend on:

- the tool
- its arguments
- the target
- the requested status
- the destination
- the consequence of the operation

The policy layer determines whether the action is:

- inside the task scope
- sensitive or irreversible
- allowed to receive untrusted influence
- allowed to move confidential information
- eligible for a safer alternative

### 3.5 Information-flow protection

The system must distinguish authorization to read from authorization to disclose.

A user may authorize reading a restricted record without authorizing:

- sending its credential to an external recipient
- including its secret in a response
- writing it into memory
- forwarding it through another tool

Where possible, SENTINEL should redact only the sensitive span and preserve the legitimate remainder of the task.

### 3.6 Least-restrictive intervention

The defense should prefer the weakest effective intervention:

1. remove attacker-authored control arguments
2. redact protected content
3. downgrade an action to a safer capability
4. escalate to a human
5. block when no safe alternative exists

This preserves utility while preventing unsafe consequences.

## 4. Repository organization

The fused repository should use SENTINEL as the primary project and keep Tekmor-related work under experiments.

```text
sentinel-indabax/
├── sentinel/                 # primary defense implementation
├── submission/               # official API and Docker deployment
├── observability/            # live traces, replay, and dashboarding
├── artifacts/                # evaluation outputs and recorded traces
├── experiments/
│   └── tekmor/
│       ├── README.md
│       ├── adapters/
│       ├── variants/
│       ├── benchmarks/
│       └── results/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── LINEAGE.md
│   ├── FUSION_PLAN.md
│   ├── EVALUATION.md
│   ├── FAILURE_ANALYSIS.md
│   └── LIMITATIONS.md
└── tests/
```

## 5. Role of the Tekmor experiments

Tekmor should remain clearly identified as the research and experimental track.

The experiments can evaluate:

- alternate provenance granularity
- call-level versus argument-level attribution
- field-level labels
- cross-step provenance
- handle and world-state tracking
- alignment auditing
- deny-gray controls
- alternative risk aggregation
- different rewrite strategies
- adaptive attacker behavior
- ablations of mandate, origin, context, flow, and history signals

Each experiment should document:

- the hypothesis
- the implementation
- the configuration
- the benchmark
- the result
- whether the mechanism is enabled by default
- known limitations
- whether it was adopted, rejected, or left for future work

The official SENTINEL result should remain separate from experimental Tekmor results.

## 6. Evaluation policy

The fused repository should use the official SENTINEL evaluation as the primary deployment benchmark.

Every result should identify:

- implementation name
- commit or version
- agent
- benchmark split
- attacker configuration
- seed
- defense configuration
- score
- attack success rate
- benign task utility
- false-block rate
- rewrite and escalation counts

Recommended comparison table:

| Configuration | Role | Official score | ASR | BTU | FBR | Status |
|---|---|---:|---:|---:|---:|---|
| SENTINEL baseline | primary submission | — | — | — | — | default |
| Tekmor monitor | research baseline | — | — | — | — | experimental |
| SENTINEL + Tekmor variant | integration experiment | — | — | — | — | experimental |
| Strict ensemble | comparative control | — | — | — | — | experimental |

No Tekmor result should be presented as a SENTINEL result unless it was produced by the SENTINEL implementation under the same configuration.

## 7. Documentation plan

### README

The README should explain:

1. the problem
2. the shared Tekmor/SENTINEL design
3. the current SENTINEL implementation
4. the deployment path
5. the official results
6. the experimental Tekmor track
7. the limitations
8. the reproduction commands

### Architecture document

The architecture document should explain the unified pipeline:

- mandate sealing
- provenance ledger
- argument attribution
- policy evaluation
- information-flow checks
- rewriting
- execution gateway
- observability

### Lineage document

The lineage document should explain the progression:

```text
Tekmor research architecture
    ↓
shared provenance and policy methods
    ↓
SENTINEL operational implementation
    ↓
API, Docker, memory, redaction, replay, and dashboard improvements
```

### Experimental documentation

The Tekmor experiment documents should preserve:

- alternative mechanisms
- failed experiments
- ablation results
- benchmark caveats
- future research directions

This demonstrates that the project is measured rather than merely asserted.

## 8. Implementation sequence

### Phase 1 — Align terminology

Create one shared glossary for:

- provenance
- trust
- sensitivity
- mandate
- capability
- risk
- severity
- rewrite
- escalation
- information flow
- source attribution

### Phase 2 — Map components

Create a mapping between the two projects:

| Tekmor concept | SENTINEL concept |
|---|---|
| `Action` | `CandidateAction` |
| `AgentState` | request goal and step metadata |
| `ActionProvenance` | provenance records and context ledger |
| policy predicates | hard rules and policy profiles |
| `Verdict` | API intervention |
| `mediate()` | guard review and API adapter |
| event log | JSONL trace and dashboard |
| tool gateway | submission execution boundary |

### Phase 3 — Preserve SENTINEL as the default

Keep the current SENTINEL implementation as the default production and submission path.

Add Tekmor only behind an explicit experimental configuration:

```bash
SENTINEL_BACKEND=sentinel
SENTINEL_BACKEND=tekmor
SENTINEL_BACKEND=compare
```

### Phase 4 — Add comparison tooling

Implement decision-diff tooling that records:

- input request
- SENTINEL decision
- Tekmor decision
- reason codes
- risk and confidence
- rewritten actions
- disagreement category
- execution outcome

### Phase 5 — Run regression tests

Before and after integration, compare:

- decision outputs
- rewritten actions
- reason codes
- trace structure
- official metrics
- latency
- memory behavior
- failure handling

### Phase 6 — Finalize the report

Present:

- the shared core
- the progression from research to deployment
- the added SENTINEL operational features
- the experimental Tekmor variants
- official results
- failure analysis
- limitations
- future work

## 9. Final positioning

The final project should be described as:

> SENTINEL is a deployment-ready provenance and policy defense for tool-using LLM agents. It carries