# SigmaForge Makefile. Full target set lands in Phase 10.
VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

install:
	python3 -m venv $(VENV)
	$(PIP) install -r requirements.txt
	$(PIP) install -e . --no-deps

test:
	$(PY) -m pytest tests/test_evaluator.py tests/test_metadata.py tests/test_rules.py

lint:
	$(PY) -m ruff check sigmaforge tests

coverage:
	$(PY) -m sigmaforge.coverage

.PHONY: install test lint coverage
