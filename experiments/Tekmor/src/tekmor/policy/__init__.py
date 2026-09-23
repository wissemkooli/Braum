"""Tekmor policy component: per-domain policy data and its deterministic evaluation.

The two rules of `docs/10-research-report.md` Part IV — Trusted-Action and Permitted-Flow —
are `trusted_action` and `permitted_flow`. They are predicates; the verdict they lead to
is `tekmor.defense.monitor`'s.
"""

from tekmor.policy.core import (
    Policy,
    downgrade_for,
    permitted_flow,
    permitted_tool,
    recipients_of,
    trusted_action,
)

__all__ = [
    "Policy",
    "downgrade_for",
    "permitted_flow",
    "permitted_tool",
    "recipients_of",
    "trusted_action",
]
