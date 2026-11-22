# `make verify` is what CI runs. Each step is a plain command, so it also runs by hand
# (make is not installed on every machine). It stops at the first failing step.
# The tests need Docker running: they use real Redis and Valkey containers. The audit step
# asks PyPI for known vulnerabilities, so it needs the network.
TEST_FILES := $(sort $(wildcard tests/test_*.py))

.PHONY: verify
verify:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy
	npm run typecheck
	uv run pytest $(TEST_FILES) -q
	sh scripts/audit.sh
	sh scripts/gitleaks.sh
	uv run python scripts/check_dashes.py
