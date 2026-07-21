# Agent Policy Gateway — developer tasks (macOS/Linux)
# Windows parity: dev.ps1 / deploy.ps1

PYTHON ?= python3.13
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help dev test lint typecheck check validate run proxy demo clean

help:
	@echo "make dev        - create venv and install with dev dependencies"
	@echo "make test       - run the test suite"
	@echo "make lint       - ruff lint"
	@echo "make typecheck  - mypy"
	@echo "make check      - lint + typecheck + tests + policy validate"
	@echo "make validate   - validate policy.json"
	@echo "make run        - run the gateway (needs APG_AGENT_TOKEN)"
	@echo "make proxy      - run the standalone CLI proxy (TARGET=http://...)"
	@echo "make demo       - run the CLI enforcement demo"
	@echo "make clean      - remove venv and caches"

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install -q -e ".[dev]"

dev: $(BIN)/python

test: dev
	$(BIN)/python -m pytest tests/ -q

lint: dev
	$(BIN)/ruff check src tests

typecheck: dev
	$(BIN)/mypy

validate: dev
	$(BIN)/apg policy validate policy.json

check: lint typecheck test validate

run: dev
	$(BIN)/python -m uvicorn agent_policy_gateway.main:app --port 8000 --reload

proxy: dev
	$(BIN)/apg proxy --target $(TARGET) --policy policy.json

demo: dev
	$(BIN)/apg demo

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -not -path "./frontend/*" -exec rm -rf {} +
