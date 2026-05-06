#!/usr/bin/env bash
set -euo pipefail

PORT="${WG_WEB_PORT:-8088}"
URL="http://127.0.0.1:${PORT}"

open_browser() {
  if command -v open >/dev/null 2>&1; then
    open "${URL}" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${URL}" >/dev/null 2>&1 || true
  fi
}

open_browser_soon() {
  (sleep 1; open_browser) >/dev/null 2>&1 &
}

run_docker() {
  if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example. Update router credentials if needed."
  fi
  docker compose up -d --build
  open_browser
  echo "Web panel is running at ${URL}"
}

run_local() {
  if [ ! -d .venv ]; then
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python -m pip install --upgrade pip >/dev/null
  python -m pip install -r requirements-web.txt
  open_browser_soon
  exec uvicorn main:app --host 0.0.0.0 --port "${PORT}"
}

case "${1:-local}" in
  docker)
    run_docker
    ;;
  local|"")
    run_local
    ;;
  *)
    echo "Usage: ./run.sh [local|docker]" >&2
    exit 2
    ;;
esac
