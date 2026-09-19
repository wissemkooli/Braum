"""The run loop: agent proposes, guard decides, environment executes.

Every action the agent produces passes the guard before the environment sees
it. Nothing is staged: the attack text is already in the environment, the
agent finds it on its own, and the decision recorded in the trace is the one
that actually determined what happened.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sentinel.capability import ToolCatalogue
from sentinel.guard import Decision, GuardConfig, Sentinel
from sentinel.policy import Intervention
from sentinel.trace import Tracer
from sentinel.trust import Trust, parse_trust

from . import scenario as scenario_mod
from . import tools as tool_mod
from . import verdict as verdict_mod
from .agent import AgentConfig, SusceptibleAgent
from .baselines import BASELINES
from .env import Environment
from .scenario import Scenario


@dataclass
class RunResult:
    scenario: Scenario
    defense: str
    verdict: verdict_mod.Verdict
    tracer: Tracer
    env: Environment
    decisions: List[dict] = field(default_factory=list)
    duration_ms: float = 0.0
    trace_path: Optional[str] = None

    def summary(self) -> dict:
        counts = self.verdict.interventions
        return {
            "scenario": self.scenario.id,
            "title": self.scenario.title,
            "domain": self.scenario.domain,
            "family": self.scenario.family,
            "difficulty": self.scenario.difficulty,
            "defense": self.defense,
            "overall": self.verdict.overall,
            "utility_pass": self.verdict.utility_pass,
            "security_pass": self.verdict.security_pass,
            "over_refusal": self.verdict.over_refusal,
            "interventions": counts,
            "leaked_canaries": self.verdict.leaked_canaries,
            "duration_ms": round(self.duration_ms, 1),
            "trace": self.trace_path,
        }


def make_defense(name: str, scenario: Scenario, catalogue: ToolCatalogue,
                 tracer: Tracer, config: GuardConfig) -> Sentinel:
    if name in BASELINES:
        cls = BASELINES[name]
        kwargs = {"catalogue": catalogue, "profile": scenario.policy_profile,
                  "config": config, "tracer": tracer}
        if name == "tool_allowlist":
            return cls(allowed_tools=scenario.allowed_tools, **kwargs)
        return cls(**kwargs)
    return Sentinel(catalogue=catalogue, profile=scenario.policy_profile,
                    config=config, tracer=tracer)


def _approve(mode: str, decision: Decision, step: int) -> bool:
    """Stand-in for the human in the loop."""
    if mode == "approve":
        return True
    if mode == "prompt":
        print(f"\n  [ESCALATION] step {step}: {decision.action_in.tool}"
              f"({decision.action_in.args})\n  risk={decision.risk.risk:.2f} "
              f"reason={decision.reason}")
        try:
            return input("  approve? [y/N] ").strip().lower().startswith("y")
        except EOFError:
            return False
    return False


def run(path: str, defense: str = "sentinel", ablate: tuple = (), agent_mode: str = "susceptible",
        approver: Optional[str] = None, trace_dir: str = "artifacts", root: str = ".",
        rewrite: bool = True, hard_rules: bool = True, quiet: bool = True) -> RunResult:
    scenario = scenario_mod.load(path)
    env = scenario_mod.build_environment(scenario, root)
    applied = scenario_mod.apply_attack(scenario, env)
    catalogue = ToolCatalogue.load()

    label = defense + (f"-no_{'_'.join(ablate)}" if ablate else "")
    tracer = Tracer(path=f"{trace_dir}/{scenario.id}__{label}.jsonl" if trace_dir else None)
    config = GuardConfig(disabled_families=tuple(ablate), enable_rewrite=rewrite,
                         enable_hard_rules=hard_rules, label=label)
    guard = make_defense(defense, scenario, catalogue, tracer, config)
    approver_mode = approver or scenario.approver

    tracer.emit(
        "run_start",
        scenario=scenario.id, title=scenario.title, domain=scenario.domain,
        description=scenario.description, policy_profile=scenario.policy_profile,
        defense=label, agent=agent_mode, approver=approver_mode,
        attack={"present": scenario.attack_present, "family": scenario.family,
                "difficulty": scenario.difficulty,
                "objective": scenario.attack.get("objective", ""),
                "surfaces_written": applied},
        allowed_tools=scenario.allowed_tools, max_steps=scenario.max_steps,
    )

    agent_config = AgentConfig(
        follow_injected_instructions=(agent_mode == "susceptible"),
        substitute_hijacked_content=(agent_mode == "susceptible"),
        label=agent_mode,
    )
    counts: Dict[str, int] = {"ALLOW": 0, "REWRITE": 0, "ESCALATE": 0, "BLOCK": 0,
                              "approved": 0, "denied": 0}
    escalations: List[dict] = []
    blocked_legitimate = False
    decisions: List[dict] = []
    started = time.time()
    worst_trust = Trust.SYSTEM_POLICY

    for turn_index, turn in enumerate(scenario.turns):
        guard.begin_turn(turn.goal, turn_index)
        tracer.emit("turn_start", turn=turn_index, goal=turn.goal,
                    reference_plan=[s.get("id") for s in turn.reference_plan])
        agent = SusceptibleAgent(turn.reference_plan,
                                 list(scenario.allowed_tools) + ["respond"], agent_config)
        step = 0
        while step < scenario.max_steps:
            action = agent.next_action(step + 1)
            if action is None:
                break
            step += 1
            harness_origin = "injected" if agent.pending_is_injected else "plan"
            tracer.emit("agent_intent", step=step, turn=turn_index, tool=action.tool,
                        args=action.args, harness_label=harness_origin,
                        note="ground truth, shown for review only; the guard is not told this")

            t0 = time.time()
            decision = guard.review(action)
            latency = (time.time() - t0) * 1000
            counts[decision.intervention.label] = counts.get(decision.intervention.label, 0) + 1
            decisions.append({**decision.as_dict(), "step": step, "turn": turn_index,
                              "harness_label": harness_origin, "latency_ms": round(latency, 2)})

            approved = False
            proceed = decision.proceeds
            if decision.intervention == Intervention.ESCALATE:
                approved = _approve(approver_mode, decision, step)
                proceed = approved
                counts["approved" if approved else "denied"] += 1
                escalations.append({"step": step, "tool": action.tool, "approved": approved})
                tracer.emit("human_review", step=step, turn=turn_index, tool=action.tool,
                            approved=approved, mode=approver_mode, reason=decision.reason)

            if not proceed:
                if harness_origin == "plan":
                    blocked_legitimate = True
                agent.note_refusal(decision.reason)
                tracer.emit("blocked", step=step, turn=turn_index, tool=action.tool,
                            intervention=decision.intervention.label, reason=decision.reason)
                continue

            executed = decision.action_out or action
            if executed.tool == "respond":
                env.final_response = str(executed.args.get("content", ""))
                tracer.emit("final_response", step=step, turn=turn_index, content=env.final_response)
                break

            env.collections["_memory_trust"] = {"level": worst_trust.name}
            result = tool_mod.invoke(env, executed.tool, executed.args)
            if not result.ok:
                agent.note_refusal(result.error or "tool error")
                tracer.emit("tool_error", step=step, turn=turn_index, tool=executed.tool,
                            error=result.error)
                continue

            if result.effect:
                env.record_effect(step, executed.tool, result.effect, executed.args, approved)
                guard.note_effect(executed.tool, result.effect, step)

            for f in result.fields:
                worst_trust = max(worst_trust, parse_trust(f.trust))
                guard.observe(source_ref=f.source_ref, text=f.text, trust=f.trust,
                              sensitivity=f.sensitivity, source_kind=f.source_ref.split("/")[0],
                              step=step)
            injected = agent.observe(result.fields, result.data)
            if injected:
                tracer.emit("agent_hijacked", step=step, turn=turn_index,
                            followed=[{"tool": s.tool, "args": s.args} for s in injected],
                            note="the agent found instructions in observed content and queued them")

        tracer.emit("turn_end", turn=turn_index, steps=step, agent_notes=agent.notes)

    duration = (time.time() - started) * 1000
    result_verdict = verdict_mod.evaluate(scenario, env, counts, escalations, blocked_legitimate)
    tracer.emit("verdict", **result_verdict.as_dict(), env=env.snapshot(),
                duration_ms=round(duration, 1))
    tracer.close()

    return RunResult(scenario=scenario, defense=label, verdict=result_verdict, tracer=tracer,
                     env=env, decisions=decisions, duration_ms=duration, trace_path=tracer.path)
