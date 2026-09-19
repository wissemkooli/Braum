"""SENTINEL v1 defense API schemas.

Requests are lenient (unknown fields ignored) so the service keeps working if
the organizers add context. Responses are strict, because the evaluator
rejects anything that does not match the published shape.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CandidateAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["respond", "tool_call", "memory_write", "request_confirmation"]
    tool: Optional[str] = None
    arguments: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    content: Optional[str] = None
    final: bool = False
    confirmation_for: Optional["CandidateAction"] = None


class Provenance(_Lenient):
    source_type: str
    source_id: str
    trust_level: Literal[
        "system_policy", "authenticated_user", "trusted_internal",
        "untrusted_internal", "untrusted_external", "adversary_controlled",
    ]
    origin_actor: str
    retrieved_via: str
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"


class ProvenanceRecord(_Lenient):
    id: str
    provenance: Provenance


class ConversationItem(_Lenient):
    role: str
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class ObservationView(_Lenient):
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class ToolCallSummary(_Lenient):
    step_id: int
    tool: str
    decision: str
    succeeded: Optional[bool] = None


class HistoryDigest(_Lenient):
    steps_taken: int = 0
    turn_index: int = 0
    tool_calls: list[ToolCallSummary] = Field(default_factory=list)
    confirmations_granted: list[str] = Field(default_factory=list)
    blocked_count: int = 0
    escalated_count: int = 0
    least_trusted_seen: Optional[str] = None
    most_sensitive_seen: Optional[str] = None


class DefenseRequest(_Lenient):
    run_id: str
    step_id: int
    user_goal: str
    conversation: list[ConversationItem] = Field(default_factory=list)
    observation: Optional[ObservationView] = None
    candidate_action: CandidateAction
    policy_context: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)


class DefenseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["allow", "block", "escalate", "rewrite"]
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    explanation: Optional[str] = Field(default=None, max_length=500)
    rewritten_action: Optional[CandidateAction] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _rewrite_consistency(self):
        if self.decision == "rewrite" and self.rewritten_action is None:
            raise ValueError("rewrite decisions require 'rewritten_action'")
        if self.decision != "rewrite" and self.rewritten_action is not None:
            raise ValueError("'rewritten_action' is only valid with decision 'rewrite'")
        return self


CandidateAction.model_rebuild()
