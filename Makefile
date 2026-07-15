# SigmaForge developer entry points. Run `make install` once, then
# `make test` for the fast Tier 1 gate and `make test-all` with the
# docker stack up for the full suite.

VENV ?= .venv
ifeq ($(OS),Windows_NT)
PY := $(VENV)/Scripts/python.exe
PIP := $(VENV)/Scripts/pip.exe
else
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
endif

install:
	python3 -m venv $(VENV) || python -m venv $(VENV)
	$(PIP) install -r requirements.txt
	$(PIP) install -e . --no-deps

test:
	$(PY) -m pytest tests/test_evaluator.py tests/test_metadata.py tests/test_rules.py

test-all:
	$(PY) -m pytest --integration

lint:
	$(PY) -m ruff check sigmaforge tests

coverage:
	$(PY) -m sigmaforge.coverage

up:
	docker compose up -d --wait

down:
	docker compose down

convert:
	$(PY) -m sigmaforge.convert $(RULE)

deploy:
	$(PY) -m sigmaforge.deploy

new-rule:
	$(PY) -m sigmaforge.scaffold $(NAME)

.PHONY: install test test-all lint coverage up down convert deploy new-rule
