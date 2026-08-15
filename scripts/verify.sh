#!/bin/sh
set -eu

export UV_CACHE_DIR=/tmp/uv
export COVERAGE_FILE=/tmp/.coverage

uv run --no-sync ruff format --check --no-cache .
uv run --no-sync ruff check --no-cache .
uv run --no-sync mypy --cache-dir=/tmp/mypy src tests
uv run --no-sync pytest --cov=claimjumper --cov-report=term-missing --cov-fail-under=85
