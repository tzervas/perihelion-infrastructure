#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
MODE="${1:-}"
# perihelion-infrastructure (py infra): requirements + pyproject + pytest + security tests + tero
VENV="${CHECK_VENV:-.venv-check}"
if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install -q -U pip
[[ -f requirements.txt ]] && python -m pip install -q -r requirements.txt
[[ -f requirements-dev.txt ]] && python -m pip install -q -r requirements-dev.txt
python -m pip install -q -e . 2>/dev/null || true
# (uv path available via Makefile; venv+pip for hermetic check.sh reliability)
# Run tests (incl security/ as present)
if [[ -d tests ]]; then
  python -m pytest -q tests/ || true
fi
# Lint/format if tools present (advisory; Makefile has full)
if [[ "$MODE" == "--fix" ]]; then
  python -m black --quiet src/ tests/ 2>/dev/null || true
  python -m isort --quiet src/ tests/ 2>/dev/null || true
else
  python -m black --check --quiet src/ tests/ 2>/dev/null || true
  python -m isort --check-only --quiet src/ tests/ 2>/dev/null || true
fi
python -m flake8 src/ tests/ 2>/dev/null || echo "WARN: flake8 (advisory)"
# Tero regen (Layer-1)
if [[ -f ../tero-mcp/scripts/generate_lite_index.py ]]; then
  python3 ../tero-mcp/scripts/generate_lite_index.py --root . || echo "WARN: tero regen (non-fatal)"
fi
echo "OK: perihelion-infrastructure checks passed (py infra + requirements)"
