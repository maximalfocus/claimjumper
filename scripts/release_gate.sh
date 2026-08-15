#!/bin/sh
set -eu

started="$(date +%s)"
./scripts/verify.sh
uv run --no-sync python scripts/walkthrough.py
finished="$(date +%s)"
elapsed="$((finished - started))"
if [ "$elapsed" -ge 300 ]; then
  printf 'RELEASE_GATE=FAIL elapsed_seconds=%s\n' "$elapsed"
  exit 1
fi
printf 'RELEASE_GATE=PASS elapsed_seconds=%s\n' "$elapsed"
