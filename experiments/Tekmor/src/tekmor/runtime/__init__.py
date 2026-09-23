"""Tekmor runtime component: the model adapters, the run loop, and the tool gateway.

The Qwen3-8B adapter needs the `qwen` extra; see docs/03-architecture.md.
"""

from tekmor.runtime.gateway import Execution, ToolGateway, deny
from tekmor.runtime.model import ModelAdapter, ScriptedModel
from tekmor.runtime.qwen import Qwen3Adapter
from tekmor.runtime.runner import RunResult, StepOutcome, run

__all__ = [
    "Execution",
    "ModelAdapter",
    "Qwen3Adapter",
    "RunResult",
    "ScriptedModel",
    "StepOutcome",
    "ToolGateway",
    "deny",
    "run",
]
