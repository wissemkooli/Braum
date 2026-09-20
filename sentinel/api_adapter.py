"""Adapter for the official SENTINEL v1 defense API.

The organizers' harness calls a defense over HTTP with a `DefenseRequest` and
expects a `DefenseDecision` back. This module does that translation in plain
dictionaries and the standard library only, so the defense core stays free of
web-framework dependencies and can be tested without installing one.

What the request gives us maps almost exactly onto what the guard already
needs:

    user_goal        ->  the mandate, sealed before anything else is read
    provenance[]     ->  trust and sensitivity labels per source
    conversation[]   ->  the provenance ledger, in order
    observation      ->  the span that arrived for this step
    candidate_action ->  the action under review
    policy_context   ->  the operator's tool declarations and policy rules
    history_digest   ->  prior tool calls, confirmations, interception count

Each call rebuilds the guard from the request. That is deliberate: the service
holds no state between requests, so two concurrent runs cannot contaminate
each other, and a replayed request always produces the same decision.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from .capability import (
    TERMINAL_STATUS, ArgSpec, Consequence, ToolCatalogue, infer_arg_roles, infer_spec,
)
from .guard import GuardConfig, Sentinel
from .policy import Intervention, PROFILES
from .signals import CandidateAction
from .trace import Tracer
from .trust import Sensitivity, Trust, parse_sensitivity, parse_trust

DECISION_NAME = {
    Intervention.ALLOW: "allow",
    Intervention.REWRITE: "rewrite",
    Intervention.ESCALATE: "escalate",
    Intervention.BLOCK: "block",
}

MAX_REASON_CODES = 16
MAX_EXPLANATION = 500
MAX_METADATA_BYTES = 4096
# What the API reports for an action refused by a blocking hard rule (see `_response`).
HARD_VIOLATION_RISK = 0.95

_BASE_CATALOGUE = ToolCatalogue.load()


# ---------------------------------------------------------------- action digest
def _canonical(value: Any) -> Any:
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def action_digest(action: dict) -> str:
    """Reproduce the harness's `CandidateAction.digest()` exactly.

    Confirmations are recorded against this digest, so getting it right is what
    stops the defense escalating the same action a human already approved.
    """
    kind = action.get("type", "tool_call")
    body: Dict[str, Any] = {
        "type": kind,
        "tool": action.get("tool"),
        "arguments": {k: _canonical(v) for k, v in sorted((action.get("arguments") or {}).items())},
        "content": action.get("content") if kind != "tool_call" else None,
    }
    inner = action.get("confirmation_for")
    if inner:
        body["confirmation_for"] = action_digest(inner)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


# ------------------------------------------------------------------- catalogue
def build_catalogue(policy_context: dict, seen_tools: Tuple[str, ...]) -> ToolCatalogue:
    """Merge the shipped capability model with what this deployment declares."""
    declared = list(policy_context.get("allowed_tools") or [])
    consequential = set(policy_context.get("consequential_tools") or [])
    consequential |= set(policy_context.get("confirmation_required_tools") or [])
    known = tuple(sorted(set(declared) | set(seen_tools) | set(_BASE_CATALOGUE.names())))

    specs = dict(_BASE_CATALOGUE.specs)
    for name in set(declared) | set(seen_tools):
        if name in specs:
            if name in consequential:
                specs[name].requires_confirmation = True
            continue
        specs[name] = infer_spec(name, consequential=name in consequential, known_tools=known)
    return ToolCatalogue(specs)


def _profile_for(policy_context: dict) -> str:
    policy_id = str(policy_context.get("policy_id") or "")
    return policy_id if policy_id in PROFILES else "enterprise_standard"


# ----------------------------------------------------------------- translation
def _provenance_index(request: dict) -> Dict[str, dict]:
    index = {}
    for record in request.get("provenance") or []:
        prov = record.get("provenance") or {}
        index[record.get("id")] = prov
    return index


def _labels(provenance_ids: List[str], index: Dict[str, dict],
            default_trust: Trust) -> Tuple[Trust, Sensitivity, str, str]:
    """Pessimistic join over every source a span carries."""
    trusts, sens, refs, kinds = [], [], [], []
    for pid in provenance_ids or []:
        prov = index.get(pid)
        if not prov:
            continue
        trusts.append(parse_trust(prov.get("trust_level"), default_trust))
        sens.append(parse_sensitivity(prov.get("sensitivity")))
        kinds.append(str(prov.get("source_type", "tool_output")))
        refs.append(f"{prov.get('source_type', 'source')}/{prov.get('source_id', pid)}")
    if not trusts:
        return default_trust, Sensitivity.INTERNAL, "unlabelled", "tool_output"
    return (max(trusts), max(sens), "; ".join(dict.fromkeys(refs)), kinds[0])


# Conversation roles that carry content the agent read, rather than the user's
# own instruction. The user's words reach the guard through `user_goal`.
OBSERVED_ROLES = ("tool", "memory", "agent", "safety", "human")

# Defaults for spans the harness did not label. Unlabelled content is *not*
# treated as adversarial: in this API, retrieved content (documents, alerts,
# logs -- everything an attacker can write into) always carries provenance,
# while the structured results of the agent's own approved calls do not.
# Assuming the worst about those turns an identifier the agent legitimately
# minted one step earlier into "attacker-authored", which blocks real work.
# Memory is the exception the specification calls out: an entry written after
# reading untrusted content is untrusted when recalled.
ROLE_DEFAULT_TRUST = {
    "tool": Trust.TRUSTED_INTERNAL,
    "memory": Trust.UNTRUSTED_INTERNAL,
    "agent": Trust.TRUSTED_INTERNAL,
    "safety": Trust.SYSTEM_POLICY,
    "human": Trust.AUTHENTICATED_USER,
}


def _to_candidate(action: dict, step: int) -> CandidateAction:
    kind = action.get("type", "tool_call")
    if kind == "tool_call":
        return CandidateAction(action.get("tool") or "unknown",
                               dict(action.get("arguments") or {}), step)
    if kind == "memory_write":
        return CandidateAction("memory_write", {"value": action.get("content") or ""}, step)
    if kind == "respond":
        return CandidateAction("respond", {"content": action.get("content") or ""}, step)
    inner = action.get("confirmation_for") or {}
    return CandidateAction(inner.get("tool") or "request_confirmation",
                           dict(inner.get("arguments") or {}), step)


def _from_candidate(original: dict, rewritten: CandidateAction) -> dict:
    """Express a rewritten action back in the harness's own shape."""
    kind = original.get("type", "tool_call")
    if kind == "tool_call":
        return {"type": "tool_call", "tool": rewritten.tool,
                "arguments": dict(rewritten.args), "final": False}
    if kind in ("memory_write", "respond"):
        content = rewritten.args.get("value") or rewritten.args.get("content") or ""
        return {"type": kind, "content": content, "final": bool(original.get("final", False))}
    return {"type": "tool_call", "tool": rewritten.tool,
            "arguments": dict(rewritten.args), "final": False}


# ---------------------------------------------------------------------- decide
def decide(request: dict, tracer: Optional[Tracer] = None) -> dict:
    """One `DefenseRequest` in, one `DefenseDecision` out."""
    policy_context = request.get("policy_context") or {}
    candidate_raw = request.get("candidate_action") or {}
    target_raw = candidate_raw.get("confirmation_for") or candidate_raw
    digest_index = _provenance_index(request)
    history = request.get("history_digest") or {}
    step = int(request.get("step_id") or 0)

    seen_tools = tuple(
        call.get("tool") for call in (history.get("tool_calls") or []) if call.get("tool")
    ) + ((target_raw.get("tool"),) if target_raw.get("tool") else ())
    catalogue = build_catalogue(policy_context, tuple(t for t in seen_tools if t))

    # The task scope only constrains tool calls; responding and remembering are
    # intrinsic to being an agent and are never "outside scope".
    scope = tuple(policy_context.get("allowed_tools") or ())
    if target_raw.get("type") != "tool_call":
        scope = ()

    guard = Sentinel(
        catalogue=catalogue,
        profile=_profile_for(policy_context),
        config=GuardConfig(label="sentinel-v1", allowed_tools=scope),
        tracer=tracer,
    )
    guard.begin_turn(str(request.get("user_goal") or ""),
                     turn_index=int(history.get("turn_index") or 0))

    for item in request.get("conversation") or []:
        role = str(item.get("role", "tool"))
        if role not in OBSERVED_ROLES:
            continue
        trust, sensitivity, ref, kind = _labels(
            item.get("provenance_ids") or [], digest_index,
            ROLE_DEFAULT_TRUST.get(role, Trust.UNTRUSTED_EXTERNAL))
        guard.observe(source_ref=ref, text=str(item.get("content") or ""), trust=trust,
                      sensitivity=sensitivity, source_kind=kind, step=step)

    observation = request.get("observation")
    if observation:
        trust, sensitivity, ref, kind = _labels(
            observation.get("provenance_ids") or [], digest_index, Trust.TRUSTED_INTERNAL)
        guard.observe(source_ref=ref, text=str(observation.get("content") or ""), trust=trust,
                      sensitivity=sensitivity, source_kind=kind, step=step)

    # History the guard would otherwise have accumulated itself.
    guard.session["completed_tools"] = [
        call.get("tool") for call in (history.get("tool_calls") or [])
        if call.get("tool") and call.get("succeeded") is not False
    ]
    guard.session["intercepted"] = int(history.get("blocked_count") or 0) + int(
        history.get("escalated_count") or 0)

    action = _to_candidate(target_raw, step)
    spec = catalogue.get(action.tool)
    catalogue.specs[action.tool] = infer_arg_roles(spec, action.args)

    # A status that retires a record is consequential whatever the tool is called.
    status = str(target_raw.get("arguments", {}).get("status", "")).strip().lower()
    if status in TERMINAL_STATUS:
        catalogue.specs[action.tool].requires_confirmation = True

    already_confirmed = action_digest(target_raw) in (history.get("confirmations_granted") or [])
    if already_confirmed:
        # A human has already approved this exact action; asking again is noise.
        catalogue.specs[action.tool].requires_confirmation = False
        guard.profile.confirm_irreversible = False
        guard.profile.confirm_oversight_changes = False

    decision = guard.review(action)

    # Asking a human for confirmation is itself a safe act: permit it unless the
    # underlying action is one we would refuse outright.
    if candidate_raw.get("type") == "request_confirmation" and decision.intervention != Intervention.BLOCK:
        return _response("allow", decision, ["CONFIRMATION_REQUESTED"],
                         "The agent is asking a human before acting, which is the outcome we want.")

    rewritten = None
    name = DECISION_NAME[decision.intervention]
    if decision.intervention == Intervention.REWRITE:
        if decision.action_out is None:
            name = "escalate"
        else:
            rewritten = _from_candidate(target_raw, decision.action_out)

    return _response(name, decision, None, None, rewritten)


def _response(name: str, decision, codes_override=None, explanation_override=None,
              rewritten: Optional[dict] = None) -> dict:
    codes = codes_override or (
        [rule.code for rule in decision.hard_rules] + decision.risk.reason_codes)
    seen, ordered = set(), []
    for code in codes:
        if code not in seen:
            seen.add(code)
            ordered.append(code)
    explanation = (explanation_override or decision.reason or "")[:MAX_EXPLANATION]

    # The guard's score is P(this action was induced by someone other than the
    # user), so a user who asks for an unprovisioned tool in their own words
    # scores near zero and is still refused by a hard rule. The API's risk_score
    # is read as "how likely is this action illegitimate", and a hard policy
    # violation is that with certainty. Report it so; the likelihood the guard
    # actually computed stays in the metadata and in the trace.
    induced = min(1.0, max(0.0, decision.risk.risk))
    violated = name == "block" and any(r.floor == Intervention.BLOCK for r in decision.hard_rules)
    reported = max(induced, HARD_VIOLATION_RISK) if violated else induced

    metadata = {
        "induced_likelihood": round(induced, 4),
        "capability": decision.capability,
        "severity": decision.severity.name,
        "tolerance": round(decision.tolerance, 3),
        "block_threshold": round(decision.block_threshold, 3),
        "logit": round(decision.risk.logit, 3),
        "evidence": [
            {"code": c.code, "family": c.family, "logit": round(c.logit, 2)}
            for c in decision.risk.contributions[:10]
        ],
        "hard_rules": [rule.code for rule in decision.hard_rules],
        "rewrite_strategy": decision.rewrite_strategy,
    }
    if len(json.dumps(metadata)) > MAX_METADATA_BYTES:
        metadata = {"induced_likelihood": round(induced, 4), "capability": decision.capability,
                    "severity": decision.severity.name}

    response = {
        "decision": name,
        "risk_score": round(reported, 4),
        "confidence": round(min(1.0, max(0.0, decision.risk.confidence)), 4),
        "reason_codes": ordered[:MAX_REASON_CODES],
        "explanation": explanation or None,
        "metadata": metadata,
    }
    if name == "rewrite":
        response["rewritten_action"] = rewritten
    return response
