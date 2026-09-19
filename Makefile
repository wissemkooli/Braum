# SENTINEL — everything runs offline.
.PHONY: help test suite compare ablate calibrate probes dashboard results all clean

help:
	@echo "make test       run the test suite (34 tests, stdlib only)"
	@echo "make suite      run every scenario against the defense"
	@echo "make compare    run every scenario against every baseline"
	@echo "make ablate     the ablation matrix"
	@echo "make probes     the adaptive attacks that beat this defense"
	@echo "make dashboard  build observability/dashboard.html from artifacts/"
	@echo "make results    regenerate docs/RESULTS.md"
	@echo "make all        test + suite + dashboard + results"

LIB = scenarios/public scenarios/hard_negatives scenarios/extended

test:
	python3 run_tests.py

suite:
	python3 sentinel_cli.py suite --scenarios $(LIB)

compare:
	python3 sentinel_cli.py compare --scenarios $(LIB)

ablate:
	python3 sentinel_cli.py ablate --scenarios $(LIB) --verbose-ablation

calibrate:
	python3 sentinel_cli.py calibrate --scenarios $(LIB)

probes:
	-python3 sentinel_cli.py suite --scenarios scenarios/known_failures

dashboard:
	python3 sentinel_cli.py dashboard --out observability/dashboard.html

results:
	python3 make_results.py

all: test suite dashboard results

clean:
	rm -rf artifacts/baselines artifacts/ablation artifacts/calibration
	find . -name __pycache__ -type d -exec rm -rf {} +
