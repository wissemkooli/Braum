"""Run the official Qwen3-8B reference agent on hardware that is not one large card.

The starter kit's `HFModelAdapter` loads the checkpoint onto a single device, and its CLI
builds a fresh adapter for every scenario. `Qwen/Qwen3-8B` in 16-bit is ~16.4 GB of
weights: that does not fit on one Kaggle T4 (16 GB, ~14.7 GB usable), and reloading it
nineteen times per split would cost more wall-clock than the evaluation itself.

This module changes exactly two things and nothing else:

1. **How the weights are loaded** -- sharded across the visible GPUs, in a precision you
   choose. The kit states this is the participant's to configure ("precision, device,
   decode budget") as long as the agent itself is untouched.
2. **How often they are loaded** -- once per process, reused across scenarios. The
   adapter's only per-run state is `_goal` and `_tools`, and the reference agent
   overwrites both in `start_turn` before the first `propose` of every turn, so a shared
   instance is observationally identical to a fresh one.

What the agent *is* stays the organizers' own: `SYSTEM_PROMPT`, the tool cards, the
message construction, greedy decoding, `max_new_tokens=768`, thinking mode off, and
`parse_action`. The banner printed at startup states the runtime choices verbatim so the
technical report can declare them.

    python kaggle/qwen_runtime.py eval public --model /path/to/Qwen3-8B \
        --defense-url http://127.0.0.1:8099

Environment:
    SENTINEL_QWEN_PRECISION   fp16 (default) | bf16 | 4bit | 8bit
    SENTINEL_QWEN_DEVICE_MAP  auto (default) | balanced | cuda:0 | cpu
    SENTINEL_QWEN_MAX_MEMORY  per-GPU cap for the shard planner, e.g. "13GiB,13GiB"
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

PRECISIONS = ("fp16", "bf16", "4bit", "8bit")
ALIASES = ("qwen3-8b", "qwen3", "qwen", "default")

_applied = False
_adapters: dict[str, Any] = {}


def precision() -> str:
    value = os.environ.get("SENTINEL_QWEN_PRECISION", "fp16").lower()
    if value not in PRECISIONS:
        raise SystemExit(f"SENTINEL_QWEN_PRECISION must be one of {', '.join(PRECISIONS)}, got {value!r}")
    return value


def _max_memory(device_count: int) -> dict[int, str] | None:
    raw = os.environ.get("SENTINEL_QWEN_MAX_MEMORY", "").strip()
    if raw:
        return {i: part.strip() for i, part in enumerate(raw.split(",")) if part.strip()}
    if device_count > 1:
        # Leave headroom on every card for activations and the KV cache: "auto" otherwise
        # packs GPU 0 to the brim and the first long prefill goes out of memory.
        return {i: "13GiB" for i in range(device_count)}
    return None


def _load_kwargs(device_count: int) -> dict[str, Any]:
    import torch

    kwargs: dict[str, Any] = {"device_map": os.environ.get("SENTINEL_QWEN_DEVICE_MAP", "auto")}
    max_memory = _max_memory(device_count)
    if max_memory:
        kwargs["max_memory"] = max_memory
    mode = precision()
    if mode in ("4bit", "8bit"):
        from transformers import BitsAndBytesConfig

        kwargs["quantization_config"] = (
            BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.float16,
            )
            if mode == "4bit"
            else BitsAndBytesConfig(load_in_8bit=True)
        )
        return kwargs
    # T4 is Turing: no bfloat16 tensor cores, so fp16 is the faithful 16-bit choice there.
    kwargs["dtype"] = torch.bfloat16 if mode == "bf16" else torch.float16
    return kwargs


def _from_pretrained(model_path: str, local_files_only: bool, kwargs: dict[str, Any]) -> Any:
    from transformers import AutoModelForCausalLM

    try:
        return AutoModelForCausalLM.from_pretrained(model_path, local_files_only=local_files_only, **kwargs)
    except TypeError as exc:
        if "dtype" not in kwargs or "dtype" not in str(exc):
            raise
        kwargs["torch_dtype"] = kwargs.pop("dtype")  # transformers < 4.56 spells it this way
        return AutoModelForCausalLM.from_pretrained(model_path, local_files_only=local_files_only, **kwargs)


def _patched_init(
    self: Any,
    model_path: str = "Qwen/Qwen3-8B",
    max_new_tokens: int = 768,
    max_context_chars: int = 12_000,
    local_files_only: bool = True,
    device: str = "auto",
    dtype: str = "auto",
    enable_thinking: bool = False,
) -> None:
    import torch
    from transformers import AutoTokenizer

    device_count = torch.cuda.device_count()
    # A directory on disk must not reach the hub; a bare repo id has to.
    offline = local_files_only and Path(model_path).is_dir()
    names = ", ".join(torch.cuda.get_device_name(i) for i in range(device_count)) or "cpu"
    print(
        f"qwen_runtime: loading {model_path} as {precision()} across {device_count or 'no'} GPU(s) [{names}]",
        file=sys.stderr,
        flush=True,
    )
    self._tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=offline)
    self._model = _from_pretrained(model_path, offline, _load_kwargs(device_count))
    self._model.eval()
    self._max_new_tokens = max_new_tokens
    self._max_context_chars = max_context_chars
    self._enable_thinking = enable_thinking
    self._goal = ""
    self._tools = []


def apply() -> str:
    """Patch loading and adapter reuse in place. Returns a banner describing the change."""
    global _applied
    from sentinel import cli
    from sentinel.models import hf_adapter

    if not _applied:
        hf_adapter.HFModelAdapter.__init__ = _patched_init  # type: ignore[method-assign]

        def model_factory(model: str) -> Any:
            if model == "mock":
                from sentinel.models.mock import MockModelAdapter

                return MockModelAdapter
            path = hf_adapter.DEFAULT_MODEL if model in ALIASES else model

            def build() -> Any:
                if path not in _adapters:
                    _adapters[path] = hf_adapter.HFModelAdapter(path)
                return _adapters[path]

            return build

        cli._model_factory = model_factory
        _applied = True

    return (
        f"qwen_runtime: precision={precision()} "
        f"device_map={os.environ.get('SENTINEL_QWEN_DEVICE_MAP', 'auto')} weights loaded once per process; "
        "prompt, tool cards, greedy decoding, max_new_tokens=768 and thinking=off are the kit's own"
    )


def main() -> None:
    print(apply(), file=sys.stderr, flush=True)
    from sentinel.cli import app

    app()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        # Proves the patch targets still exist, without pulling 16 GB of weights.
        import hashlib

        from sentinel import cli
        from sentinel.models import hf_adapter

        print("default model:", hf_adapter.DEFAULT_MODEL)
        print("system prompt sha256:", hashlib.sha256(hf_adapter.SYSTEM_PROMPT.encode()).hexdigest()[:16])
        print(apply())
        print("adapter init  :", hf_adapter.HFModelAdapter.__init__.__qualname__)
        print("model factory :", cli._model_factory.__qualname__)
        print("mock untouched:", cli._model_factory("mock").__name__)
        sys.exit(0)
    main()
