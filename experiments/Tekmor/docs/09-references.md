# 9. References

The literature this project is built on, grouped by the role each paper plays. Every entry
is a real, checkable source; reported numbers are attributed to the paper that reported
them, and were measured on **that paper's** benchmarks against **that paper's** attack sets.

Treat all external numbers as upper bounds. None of them is comparable with the numbers in
[7. Results](07-results.md), which were measured on a different setup.

---

## 9.1 The problem: prompt injection and instruction/data separation

**Greshake et al., "Not What You've Signed Up For: Compromising Real-World LLM-Integrated
Applications with Indirect Prompt Injection"** — AISec 2023.
Defined indirect prompt injection and showed retrieved content can hijack an agent. The
foundational framing for this project.

**Wallace et al., "The Instruction Hierarchy"** — OpenAI, [arXiv:2404.13208](https://arxiv.org/abs/2404.13208).
Trains models to prioritise system > user > tool instructions. Improves resistance
substantially but the authors note models remain "likely still vulnerable to powerful
adversarial attacks". Tekmor's trust lattice is a richer, *externalised* version of the
same ordering — enforced outside the model rather than trained into it.

**Hines et al., "Spotlighting"** — [arXiv:2403.14720](https://arxiv.org/abs/2403.14720).
Mark or encode untrusted data so the model discounts it. Cheap and combinable; bypassable
alone.

**Zverev et al., "Can LLMs Separate Instructions from Data?"** — [arXiv:2403.02691](https://arxiv.org/abs/2403.02691).
Shows separation is imperfect and, importantly, *measurable*.

**Meta SecAlign** — [arXiv:2507.02735](https://arxiv.org/abs/2507.02735).
Preference optimisation so the model prefers the intended instruction. A model-level
defense: useful background, but requires fine-tuning and does not give an external
guarantee.

## 9.2 Why detection alone fails — the most important caveat

These two papers are the reason Tekmor is not a classifier.

**Zhan et al.** — NAACL 2025, [arXiv:2503.00061](https://arxiv.org/abs/2503.00061).
Broke **eight** published injection defenses, most above 50% attack success.

**Nasr, Carlini, Sitawarin et al., "The Attacker Moves Second"** — USENIX Security '26,
[arXiv:2510.09023](https://arxiv.org/abs/2510.09023).
Broke **all twelve** defenses tested, most above **90%** attack success, using gradient
descent, reinforcement learning, random search and human-guided search.

The design consequence: a defense whose guarantee depends on recognising attack text will
eventually fail against an attacker who adapts. See [2. Threat model](02-threat-model.md).

## 9.3 System-level defenses — the line Tekmor belongs to

**CaMeL** — Debenedetti, Shumailov, Carlini, Tramèr et al.,
[arXiv:2503.18813](https://arxiv.org/abs/2503.18813).
A privileged LLM plans from the trusted query; a quarantined LLM handles untrusted data
with no tool access; a custom interpreter tracks provenance and enforces policy before each
tool call. Solves 77% of AgentDojo tasks with *provable* security against 84% undefended.
The gold-standard reference design.

**FIDES / "Securing AI Agents with Information-Flow Control"** — Costa, Köpf, Paverd,
Russinovich et al. (Microsoft), [arXiv:2505.23643](https://arxiv.org/abs/2505.23643).
The planner tracks confidentiality and integrity labels and deterministically enforces two
policies — **Trusted-Action** and **Permitted-Flow**. **The closest existing system to
Tekmor's design**, and the direct source of both rule names and of the endorsement
primitive in [4.5](04-provenance-and-trust.md#45-endorsement-buying-utility-back).

**Design Patterns for Securing LLM Agents** — Beurer-Kellner et al.,
[arXiv:2506.08837](https://arxiv.org/abs/2506.08837).
Six patterns: Action-Selector, Plan-Then-Execute, Map-Reduce, Dual-LLM, Code-Then-Execute,
Context-Minimization. Notably honest about limits: **8 of 10 case studies retain a residual
where untrusted data still shapes the *arguments* of permitted actions.** That residual is
exactly what Tekmor's argument-level work in
[4.6](04-provenance-and-trust.md#46-finer-granularity-built-measured-switched-off) tried to
close.

**Progent: Programmable Privilege Control** — Shi, He, Wang, Guo, Song et al.,
[arXiv:2504.11703](https://arxiv.org/abs/2504.11703).
A JSON-schema DSL for least-privilege tool-call policies with deterministic enforcement and
monotonic policy updates. The model for Tekmor's policy layer.

**Prompt Flow Integrity** — Kim et al., [arXiv:2503.15547](https://arxiv.org/abs/2503.15547).
**ACE architecture** — [arXiv:2504.20984](https://arxiv.org/abs/2504.20984).
Related work confirming the field converging on flow plus policy at the action boundary.

## 9.4 Task alignment — the basis for Proposal B

**Task Shield** — Jia et al., ACL 2025, [arXiv:2412.16682](https://arxiv.org/abs/2412.16682).
Reframes defense as *task alignment*: every instruction and tool call must contribute to
the user's goal. Reports 2.07% attack success at 69.79% utility on GPT-4o. The direct basis
for [Proposal B](05-design-proposals.md#proposal-b--proposal-a-plus-a-task-alignment-auditor).

**LlamaFirewall** — Meta, [arXiv:2505.03574](https://arxiv.org/abs/2505.03574).
A system-level guardrail combining PromptGuard 2 (an injection detector, ~88.7% recall at
1% false positives), AlignmentCheck (a few-shot auditor comparing the trajectory to the
user's goal), and CodeShield. The combination reduces AgentDojo attack success from 17.6%
to 1.75%, with utility 42.7% against a 47.7% baseline.

> Both of these used **frontier judge models**. Tekmor's auditor was evaluated with small
> local models on consumer hardware, and its results are *not* comparable with these. See
> [8. Limitations](08-limitations.md).

## 9.5 Consistency checking — the basis for MASK-REEXEC

**MELON** — Zhu et al., ICML 2025, [arXiv:2502.05174](https://arxiv.org/abs/2502.05174).
Masked re-execution: re-run with a task-neutral masked prompt, and flag tool calls that
appear in both runs, since those cannot have been caused by the user's request. Reports
>99% prevention with utility preserved. Clever and model-agnostic; doubles inference cost,
which is why it was considered and not built.

## 9.6 Interpretability — the basis for Proposal C

**TaskTracker** — the activation-based task-drift line of work.
Probes the model's residual-stream activations to detect when its internal representation
of the task shifts. Reported >0.99 ROC-AUC, under evaluation conditions with known
distribution-shift weaknesses.

Tekmor's reproduction failed its gate on held-out data at two model sizes; see
[7.5](07-results.md#75-the-activation-drift-probe). The reported degradation under
distribution shift is exactly what was observed.

## 9.7 Benchmarks

**AgentDojo** — Debenedetti et al., NeurIPS 2024,
[arXiv:2406.13352](https://arxiv.org/abs/2406.13352).
The external benchmark used here, pinned at version `v1.2.2`. Four suites — banking, Slack,
travel, workspace — with its own tasks, injections, and utility and security checks.

**Agent Security Bench (ASB)** — [arXiv:2410.02644](https://arxiv.org/abs/2410.02644).
The main benchmark for memory-poisoning attacks, and a reference for that attack family.

**InjecAgent** — [arXiv:2403.02691](https://arxiv.org/abs/2403.02691) line of work, and
related agent-injection benchmarks surveyed in [10. Research report](10-research-report.md).

## 9.8 Argument-level provenance — the 2026 line

These informed the argument- and field-level work in
[4.6](04-provenance-and-trust.md#46-finer-granularity-built-measured-switched-off):

- **PACT** — arXiv:2605.11039. Reports that semantic argument *roles* **and** cross-step
  provenance are both necessary. Tekmor's results arrived at the same conclusion from the
  other direction: roles alone were not enough, and cross-step binding for handles is the
  largest remaining gap.
- **AuthGraph** — arXiv:2605.26497.
- **AgentDyn** — arXiv:2602.03117. The candidate benchmark for adopting field labels,
  precisely because this project has not scored against it.

## 9.9 Standards and surrounding work

**OpenTelemetry GenAI semantic conventions** — the emerging tracing standard for LLM
systems. As of 2026 it is explicitly "Development"/unstable and does **not** natively model
trust, provenance or security decisions, which is why Tekmor defines its own event schema
rather than adopting it directly.

**NeMo Guardrails** (NVIDIA), **Guardrails AI**, **LLM Guard**, **Llama Guard**, **Microsoft
Prompt Shields** — enforcement-point frameworks. Most are content classifiers at heart, and
§9.2 applies to them.

---

## A note on numbers from other systems

Every "provable" or "near-zero attack success" figure in this literature — CaMeL's 77% with
provable security, FIDES stopping all AgentDojo injections, MELON's >99%, Task Shield's
2.07% — was measured on **its own** benchmark against **its own** attack set, usually with
frontier models.

They are not compared with Tekmor's numbers anywhere in this repository, and they should
not be. Tekmor's AgentDojo runs used a scripted agent that obeys every injection by
construction, which makes its attack success rate an upper bound rather than a measurement.
See [8. Limitations](08-limitations.md).
