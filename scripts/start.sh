#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.lock
fi
test -f web/dist/index.html || { echo 'Build the UI first: pnpm --dir web install --frozen-lockfile && pnpm --dir web build'; exit 1; }
.venv/bin/python -m cbb.cli init
if [ -f data/keys/bootstrap.token ]; then printf 'Setup token: '; cat data/keys/bootstrap.token; printf '\n'; fi
exec .venv/bin/python -m cbb.cli serve
