"""The Sentinel guard: one decision, start to finish.

Lifecycle, per turn:

    begin_turn(goal)      derive and seal the mandate -- before any exposure
    observe(...)          register every span of content the agent reads
    review(action)        allow / rewrite / escalate / block, with evidence
    note_effect(...)      record what actually happened

The guard sees exactly four things: agent state, the candidate action, the
provenance of everything in the context, and the active policy. It has no
access to scenario metadata, expected outcomes, or ground-truth labels --
`tests/test_no_oracle.py` proves it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from . import rewrite as rewrites
from .capability import Consequence, ToolCatalogue, ToolSpec, touches_oversight
from .context import Attribution, ContextLedger, Observation
from .mandate import Mandate, derive_mandate
from .policy import HardRule, Intervention, PolicyProfile, get_profile
from .risk import RiskScore, score
from .signals import (
    CandidateAction, Evidence, context_signals, dictation_hits, flow_signals,
    history_signals, mandate_signals, origin_signals,
)
from .trace import Tracer
from .trust import Sensitivity, Trust, parse_sensitivity, parse_trust

# Transforms whose output is evidence of deliberate obfuscation rather than a
# speculative reading. rot13/reverse/leetspeak views are always produced and
# are searched for attribution, but their existence says nothing on its own.
REVEALING_TRANSFORMS = ("base64", "hex", "despace", "urldecode", "strip_invisible")


@dataclass
class GuardConfig:
    """Everything the ablation study turns on and off."""

    disabled_families: tuple = ()        # mandate | origin | context | flow | history
    enable_rewrite: bool = True
    enable_hard_rules: bool = True
    profile: Optional[str] = None
    label: str = "sentinel"
    # Tools the operator provisioned for this task. Empty means "unconstrained".
    # This is policy, not preference: SYSTEM_POLICY outranks AUTHENTICATED_USER,
    # so a tool outside the task's scope is refused even when the user asks for
    # it in their own words. That is the `direct instruction` attack family.
    allowed_tools: tuple = ()

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "allowed_tools": list(self.allowed_tools),
            "disabled_families": list(self.disabled_families),
            "rewrite": self.enable_rewrite,
            "hard_rules": self.enable_hard_rules,
        }


@dataclass
class Decision:
    action_in: CandidateAction
    intervention: Intervention
    action_out: Optional[CandidateAction]
    risk: RiskScore
    severity: Consequence
    capability: str
    hard_rules: List[HardRule] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    alternatives: List[dict] = field(default_factory=list)
    reason: str = ""
    rewrite_strategy: Optional[str] = None
    tolerance: float = 0.0
    block_threshold: float = 1.0

    @property
    def proceeds(self) -> bool:
        return self.intervention in (Intervention.ALLOW, Intervention.REWRITE)

    def as_dict(self) -> dict:
        return {
            "candidate": self.action_in.as_dict(),
            "intervention": self.intervention.label,
            "executed": self.action_out.as_dict() if self.action_out else None,
            "capability": self.capability,
            "severity": self.severity.name,
            "tolerance": self.tolerance,
            "block_threshold": self.block_threshold,
            "risk": self.risk.as_dict(),
            "hard_rules": [r.as_dict() for r in self.hard_rules],
            "evidence": [e.as_dict() for e in self.evidence],
            "alternatives_considered": self.alternatives,
            "rewrite_strategy": self.rewrite_strategy,
            "reason": self.reason,
        }


class Sentinel:
    def __init__(
        self,
        catalogue: Optional[ToolCatalogue] = None,
        profile: Optional[str] = None,
        config: Optional[GuardConfig] = None,
        tracer: Optional[Tracer] = None,
    ):
        self.catalogue = catalogue or ToolCatalogue.load()
        self.config = config or GuardConfig()
        self.profile: PolicyProfile = get_profile(self.config.profile or profile)
        self.tracer = tracer
        self.ledger = ContextLedger()
        self.mandate: Optional[Mandate] = None
        self.session = {"intercepted": 0, "completed_tools": [], "turn": 0}
        self._oversight_args = False

    # ------------------------------------------------------------------ setup
    def begin_turn(self, goal: str, turn_index: int = 0, carry_context: bool = True) -> Mandate:
        """Seal the authority envelope. Must happen before any observation."""
        if not carry_context:
            self.ledger = ContextLedger()
        self.session["turn"] = turn_index
        self.session["intercepted"] = 0
        exposed_before = self.ledger.exposed
        self.mandate = derive_mandate(goal, self.catalogue)
        self.ledger.add_trusted("user_goal", goal)
        if self.tracer:
            self.tracer.emit(
                "mandate_sealed",
                turn=turn_index,
                mandate=self.mandate.as_dict(),
                policy_profile=self.profile.name,
                guard_config=self.config.as_dict(),
                context_already_exposed=exposed_before,
            )
        return self.mandate

    def observe(
        self, source_ref: str, text: str, trust, sensitivity, source_kind: str = "tool_output",
        step: int = 0, derived_from: Sequence[str] = (),
    ) -> Observation:
        obs = self.ledger.add_observation(
            step=step,
            source_ref=source_ref,
            source_kind=source_kind,
            trust=parse_trust(trust),
            sensitivity=parse_sensitivity(sensitivity),
            text=text or "",
            derived_from=tuple(derived_from),
        )
        if self.tracer:
            self.tracer.emit(
                "observation",
                step=step,
                obs_id=obs.obs_id,
                source_ref=source_ref,
                source_kind=source_kind,
                trust=obs.trust.name,
                sensitivity=obs.sensitivity.name,
                chars=len(obs.text),
                decoded_views=[v.transform for v in obs.views
                               if v.covert and v.transform in REVEALING_TRANSFORMS],
                decoded_excerpts=[{"transform": v.transform, "text": v.text[:300]}
                                  for v in obs.views
                                  if v.covert and v.transform in REVEALING_TRANSFORMS],
                excerpt=obs.text[:400],
            )
        return obs

    def note_effect(self, tool: str, effect: str, step: int = 0) -> None:
        self.session["completed_tools"].append(tool)
        if self.tracer:
            self.tracer.emit("effect", step=step, tool=tool, effect=effect)

    # ------------------------------------------------------------- evaluation
    def _attributions(self, action: CandidateAction, spec: ToolSpec) -> Dict[str, Attribution]:
        return {
            arg: self.ledger.attribute(value)
            for arg, value in action.args.items()
            if value not in (None, "")
        }

    def _effective_capability(self, spec: ToolSpec, action: CandidateAction) -> str:
        """Resolve capability at *argument* granularity.

        `ticket_update(status=closed)` is not a ticket update, it is a ticket
        close. Tool-name allowlisting cannot see that distinction; this is
        where the defense earns its keep on the AgentDojo scenario.
        """
        effect = spec.effect_for(action.args)
        if effect != spec.name and effect in self.catalogue:
            return self.catalogue.capability_of(effect)
        return spec.capability

    def _hard_rules(
        self, spec: ToolSpec, capability: str, evidence: Sequence[Evidence]
    ) -> List[HardRule]:
        if not self.config.enable_hard_rules:
            return []
        rules: List[HardRule] = []
        codes = {e.code for e in evidence}

        if self.config.allowed_tools and spec.name not in self.config.allowed_tools:
            rules.append(HardRule(
                "TOOL_OUTSIDE_TASK_SCOPE", Intervention.BLOCK,
                f"`{spec.name}` was not provisioned for this task. The operator's scope "
                f"outranks the request, whoever made it -- including the user.",
            ))
        if self.mandate and self.mandate.forbids(capability):
            rules.append(HardRule(
                "USER_PROHIBITION", Intervention.BLOCK,
                "The user's own instruction refused this capability; no observation can grant it back.",
            ))
        if self.profile.enforce_information_flow and "EXFIL_SENSITIVE_TO_SINK" in codes:
            rules.append(HardRule(
                "SENSITIVE_FLOW", Intervention.REWRITE,
                "Content classified above this task's mandate may not cross a sink unredacted.",
            ))
        if self.profile.confirm_irreversible and spec.consequence >= Consequence.IRREVERSIBLE:
            rules.append(HardRule(
                "CONFIRMATION_REQUIRED", Intervention.ESCALATE,
                "Irreversible actions are confirmed by a human, however the agent arrived at them.",
            ))
        if self.profile.confirm_oversight_changes and (spec.oversight_impact or self._oversight_args):
            rules.append(HardRule(
                "OVERSIGHT_INTEGRITY", Intervention.ESCALATE,
                "This call reduces the monitoring that the defense itself depends on.",
            ))
        if self.profile.enforce_lifecycle and spec.requires:
            missing = [r for r in spec.requires if r not in self.session["completed_tools"]]
            if missing:
                rules.append(HardRule(
                    "LIFECYCLE_ORDER", Intervention.ESCALATE,
                    f"Required prior step(s) never happened: {', '.join(missing)}.",
                ))
        if not spec.known:
            rules.append(HardRule(
                "UNKNOWN_CAPABILITY", Intervention.ESCALATE,
                f"`{spec.name}` is not in the capability catalogue; an unmodelled tool is not waved through.",
            ))
        return rules

    def _evaluate(self, action: CandidateAction):
        spec = self.catalogue.get(action.tool)
        capability = self._effective_capability(spec, action)
        attributions = self._attributions(action, spec)
        # A reply is prose, not a command: saying "I will not disable monitoring"
        # to the user changes no monitoring. Only calls that act are matched.
        self._oversight_args = spec.sink != "user_response" and touches_oversight(action.args)
        # Being provisioned for the task is weak evidence that a tool belongs to
        # it -- not authorisation, so the mandate signal is damped, not removed.
        scoped = bool(self.config.allowed_tools) and action.tool in self.config.allowed_tools

        # Did observed content issue an instruction naming this tool? Several
        # signals condition on it, so it is computed once.
        dictated = bool(dictation_hits(self.ledger, action.tool))
        # The guard itself let an earlier step in this family run, so that
        # family is part of this task whether or not the user named it twice.
        continuation = any(
            self.catalogue.get(done).family == spec.family and done != action.tool
            for done in self.session["completed_tools"]
        )

        evidence: List[Evidence] = []
        evidence += mandate_signals(action, spec, capability, self.mandate, attributions,
                                    self.catalogue, scoped=scoped, dictated=dictated,
                                    continuation=continuation)
        evidence += origin_signals(action, spec, self.ledger, self.mandate, attributions,
                                   self.catalogue, dictated=dictated)
        evidence += context_signals(self.ledger, self.catalogue)
        evidence += flow_signals(action, spec, self.ledger, self.mandate)
        evidence += history_signals(self.session)

        decisive = [a for a in action.args if spec.role_of(a) in ("control", "target")]
        resolved = [a for a in decisive if attributions.get(a) and attributions[a].resolved]
        completeness = len(resolved) / len(decisive) if decisive else 1.0

        risk = score(
            evidence,
            provenance_completeness=completeness,
            tool_known=spec.known,
            disabled_families=self.config.disabled_families,
        )
        hard = self._hard_rules(spec, capability, evidence)
        floor = max([r.floor for r in hard], default=Intervention.ALLOW)
        by_risk = self.profile.risk_intervention(risk.risk, spec.consequence, risk.confidence)
        intervention = max(floor, by_risk)
        return spec, capability, attributions, evidence, risk, hard, intervention

    # ----------------------------------------------------------------- review
    def review(self, action: CandidateAction) -> Decision:
        if self.mandate is None:
            raise RuntimeError("begin_turn() must seal a mandate before any action is reviewed")

        spec, capability, attributions, evidence, risk, hard, intervention = self._evaluate(action)

        best = Decision(
            action_in=action,
            intervention=intervention,
            action_out=action if intervention == Intervention.ALLOW else None,
            risk=risk,
            severity=spec.consequence,
            capability=capability,
            hard_rules=hard,
            evidence=evidence,
        )
        alternatives: List[dict] = []

        # Least restrictive sufficient intervention: can a weaker action clear?
        # A rewrite exists to neutralise *evidence*, not to route around a rule
        # whose whole purpose is to put a human in the loop. Substituting a
        # weaker action for one the user explicitly asked for would be the
        # defense quietly deciding on their behalf.
        floor = max([r.floor for r in hard], default=Intervention.ALLOW)
        if self.config.enable_rewrite and intervention >= Intervention.REWRITE:
            for candidate in rewrites.candidates(action, spec, attributions, self.ledger, self.mandate):
                c_spec, _, _, _, c_risk, c_hard, c_intervention = self._evaluate(candidate.action)
                outcome = max(Intervention.REWRITE, c_intervention, floor)
                alternatives.append({
                    "strategy": candidate.strategy,
                    "action": candidate.action.as_dict(),
                    "residual_risk": round(c_risk.risk, 4),
                    "would_be": outcome.label,
                    "accepted": False,
                })
                # Accept a candidate when it is strictly weaker, and also when
                # a hard rule has already demanded a safer action but we do not
                # yet have one -- otherwise the decision would read REWRITE
                # while the unmodified call went through underneath it.
                needs_substitute = (best.intervention == Intervention.REWRITE
                                    and best.action_out is None)
                if outcome < best.intervention or (
                        needs_substitute and outcome == Intervention.REWRITE):
                    alternatives[-1]["accepted"] = True
                    for prior in alternatives[:-1]:
                        prior["accepted"] = False
                    best = Decision(
                        action_in=action,
                        intervention=outcome,
                        action_out=candidate.action if outcome == Intervention.REWRITE else None,
                        risk=risk,
                        severity=spec.consequence,
                        capability=capability,
                        hard_rules=hard,
                        evidence=evidence,
                        rewrite_strategy=candidate.strategy,
                        reason=candidate.description,
                    )

        # Fail safe: a rewrite that rewrites nothing is not a rewrite. If a
        # floor required a safer action and none could be constructed, a human
        # decides instead.
        if best.intervention == Intervention.REWRITE and best.action_out is None:
            best.intervention = Intervention.ESCALATE
            best.reason = ("A safer form of this action was required, but none could be "
                           "constructed that preserves it, so it goes to a human.")

        best.alternatives = alternatives
        best.tolerance = self.profile.tolerance_for(spec.consequence)
        best.block_threshold = self.profile.block_threshold(spec.consequence)
        if not best.reason:
            best.reason = self._explain(best, spec)
        if best.intervention != Intervention.ALLOW:
            self.session["intercepted"] += 1

        if self.tracer:
            self.tracer.emit(
                "decision",
                step=action.step,
                turn=self.session["turn"],
                **best.as_dict(),
                context=self.ledger.snapshot(),
            )
        return best

    def _explain(self, decision: Decision, spec: ToolSpec) -> str:
        """One short sentence. No chain of thought, just the deciding facts."""
        if decision.hard_rules:
            top = min(decision.hard_rules, key=lambda r: -r.floor)
            head = top.rationale
        else:
            head = ""
        codes = decision.risk.top_codes(2)
        if decision.intervention == Intervention.ALLOW:
            return head or "Inside the sealed mandate, arguments traceable to the user."
        tail = f"risk {decision.risk.risk:.2f} ({', '.join(codes) or 'policy'}), " \
               f"severity {spec.consequence.name}, confidence {decision.risk.confidence:.2f}"
        return f"{head} {tail}".strip()
