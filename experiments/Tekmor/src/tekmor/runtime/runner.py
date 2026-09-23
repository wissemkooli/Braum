"""The run loop.

`docs/10-research-report.md` Part I: scenario + world + policy → runner → the agent proposes
an action → Tekmor decides → escalations go to a simulated human, approved actions go
to the tool gateway → world state updates → events are logged.

The loop decides nothing and executes nothing itself: `mediate()` produces the verdict
and `ToolGateway` is the only thing that touches the world. What is left here is the
order of those steps, which is what makes "nothing reaches the world undecided"
checkable by reading one function.

It does own one thing: the run's `TaintTracker`. An action's provenance is what the
agent has read *before* proposing it, so the tracker is read before the call and
updated after it — which is also why an adapter cannot state its own provenance and a
blocked call adds no influence.
"""

from __future__ import annotations

from dataclasses import dataclass

from tekmor.defense import Action, ActionProvenance, AgentState, Decision, Defense
from tekmor.defense.core import mediate
from tekmor.observability import EventLog, Outcome, decision_event
from tekmor.provenance.taint import TaintTracker, endorse
from tekmor.runtime.gateway import Approver, Execution, ToolGateway, deny
from tekmor.runtime.model import ModelAdapter, ScriptedModel
from tekmor.simulator.scenario import Scenario
from tekmor.simulator.world import World


def outcome(execution: Execution) -> Outcome:
    """The three-word summary of an execution the trace records (`observability.events`)."""
    if execution.executed is None:
        return "not_executed"
    return "failed" if execution.error else "executed"


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """What happened to one proposed action, decision included."""

    action: Action
    decision: Decision
    executed: Action | None
    result: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RunResult:
    run_id: str
    scenario_id: str
    defense: str
    steps: tuple[StepOutcome, ...]
    world: World


def run(
    scenario: Scenario,
    defense: Defense,
    *,
    adapter: ModelAdapter | None = None,
    log: EventLog | None = None,
    run_id: str | None = None,
    approver: Approver = deny,
    max_steps: int = 64,
) -> RunResult:
    """Run one scenario against one defense and return what the world looks like after.

    `run_id` defaults to scenario and defense, so a rerun of the same pair is the same
    identifier: with a scripted adapter the whole run is deterministic, and two runs
    that differ differ because the defense did.
    """
    world = scenario.world()
    gateway = ToolGateway(world, approver)
    adapter = adapter or ScriptedModel(scenario.steps)
    run_id = run_id or f"{scenario.id}@{scenario.version}:{defense.name}"

    taint = TaintTracker(request=scenario.task)
    observations: list[str] = []
    outcomes: list[StepOutcome] = []

    for step in range(max_steps):
        # The state deliberately carries the task and the step index and nothing else:
        # no scenario id, no expected outcome, nothing a defense could recognise.
        state = AgentState(task=scenario.task, step=step)
        action = adapter.propose(state, tuple(observations))
        if action is None:
            break

        provenance = ActionProvenance.of(taint.sources, taint.origins(action.args))
        decision = mediate(defense, state, action, provenance, scenario.policy)

        run_step = gateway.execute(action, decision)
        if log is not None:
            # Written after the gateway, so one event covers the whole step: decision
            # *and* what became of it. The cost is that a crash between the two loses
            # the line rather than recording a decision nothing acted on — acceptable
            # because the gateway turns a failing tool into an outcome instead of an
            # exception, and a missing step index is visible in a way a wrong one is not.
            log.append(
                decision_event(
                    run_id,
                    step,
                    defense.name,
                    action,
                    provenance,
                    scenario.policy,
                    decision,
                    outcome(run_step),
                )
            )
        if run_step.source is not None:
            # The call ran and succeeded. Its payload is recorded before its own result
            # is observed, so the write carries the integrity of what drove it.
            taint.wrote(run_step.executed.args, scenario.policy.content_args)
            source = run_step.source
            if scenario.policy.endorse_named:
                # The call that *executed* produced the observation, so its arguments
                # are the ones that say what was read.
                source = endorse(source, run_step.executed.args, scenario.task)
            taint.observe(source, run_step.result or "")
        outcomes.append(
            StepOutcome(action, decision, run_step.executed, run_step.result, run_step.error)
        )
        observations.append(run_step.result or run_step.error or decision.verdict.value)

    return RunResult(run_id, scenario.id, defense.name, tuple(outcomes), world)
