#!/usr/bin/env bash
# DriftGuard — one-command demo launcher
set -e
cd "$(dirname "$0")"

echo "🛡 DriftGuard — starting…"
pip install -q fastapi uvicorn scikit-learn pandas 2>/dev/null || \
  pip install -q --break-system-packages fastapi uvicorn scikit-learn pandas

if [ ! -d frontend/dist ]; then
  echo "Building dashboard (first run only)…"
  (cd frontend && npm install --no-audit --no-fund && npm run build)
fi

echo "→ Dashboard: http://localhost:8000"
cd backend && python3 -m uvicorn api.main:app --port 8000
