# Multi-stage build: dashboard (Node) -> API/worker image (Python, non-root, no build tools).
FROM node:22.11-alpine3.20 AS frontend
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12.7-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    SENTINEL_FRONTEND_DIST=/srv/frontend
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr poppler-utils \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system sentinel && useradd --system --gid sentinel --home /srv --shell /usr/sbin/nologin sentinel
WORKDIR /srv
COPY backend/pyproject.toml backend/
COPY backend/src backend/src
RUN pip install "./backend[postgres]"
COPY --from=frontend /app/dist /srv/frontend
COPY db /srv/db
USER sentinel
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz')"
# TLS 1.3 terminates at the ingress / platform load balancer; uvicorn sits behind it.
# PORT is set by hosting platforms such as Render; defaults to 8000.
CMD ["sh", "-c", "exec uvicorn sentinel.api.main:app --host 0.0.0.0 --port \"$PORT\" --proxy-headers --forwarded-allow-ips '*'"]
