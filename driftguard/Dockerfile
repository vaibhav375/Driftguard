# ─────────────────────────────────────────────────────────────────────────────
# DriftGuard — multi-stage Docker image
#
# Build context must be PS-02/ (parent directory of driftguard/):
#
#   cd PS-02/
#   docker build -t driftguard -f driftguard/Dockerfile .
#   docker run -p 8000:8000 driftguard
#
# Then open http://localhost:8000
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build React dashboard ───────────────────────────────────────────
FROM node:20-alpine AS ui-builder
WORKDIR /app/frontend
COPY driftguard/frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY driftguard/frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime ───────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Python dependencies
RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn[standard]==0.30.0 \
    scikit-learn==1.5.1 \
    pandas==2.2.3 \
    numpy==1.26.4

# Backend source
COPY driftguard/backend/ ./backend/

# Pre-built frontend bundle
COPY --from=ui-builder /app/frontend/dist ./frontend/dist/

# Sample data — copied from PS-02/Problem_02_Config_Drift/sample_data/
COPY Problem_02_Config_Drift/sample_data/ ./sample_data/

# Point the engine at the bundled data
ENV DRIFTGUARD_DATA_DIR=/app/sample_data

# Expose API port
EXPOSE 8000

# Single startup command — serves API + static frontend on :8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "backend"]
