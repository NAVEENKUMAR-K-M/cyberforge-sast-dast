# DAST engine image. Pinned Python deps; Playwright/Chromium only in the
# "full" build stage (optional browser confirmation pass).
#
# Build from the repo root, because the engine reads common/cwe_families.json:
#   docker build -f dast-engine/Dockerfile --target base -t cyberforge-dast .
FROM python:3.11.9-slim AS base

WORKDIR /app/dast-engine
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dast-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dast-engine/ .
COPY common/ /app/common/

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "main.py"]
CMD ["scan", "--help"]

# ---- optional "full" stage: adds Playwright/Chromium + the zap python client ----
FROM base AS full
RUN pip install --no-cache-dir playwright==1.47.0 python-owasp-zap-v2.4==0.0.21 \
    && python -m playwright install --with-deps chromium
