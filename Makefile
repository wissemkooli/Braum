# SENTINEL — the defense and its observability layer. Runs against Qwen3-8B are
# driven by the organizers' harness: see docs/QWEN3_AGENT.md.
RUN ?= run4-2026-09-21
.PHONY: help test dashboard clean

help:
	@echo "make test       run the test suite (stdlib only)"
	@echo "make dashboard  build observability/dashboard.html from the recorded Qwen3-8B traces"

test:
	python3 run_tests.py

dashboard:
	python3 sentinel_cli.py dashboard $$(find artifacts/qwen3/$(RUN)/traces -name "*.jsonl" | sort) --out observability/dashboard.html

clean:
	find . -name __pycache__ -type d -exec rm -rf {} +
