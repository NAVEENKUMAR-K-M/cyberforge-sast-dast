# DAST engine image. Pinned Python deps; Playwright/Chromium only in the
# "full" build stage (optional browser confirmation pass).
FROM python:3.11.9-slim AS base

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "main.py"]
CMD ["scan", "--help"]

# ---- optional "full" stage: adds Playwright/Chromium + the zap python client ----
FROM base AS full
RUN pip install --no-cache-dir playwright==1.47.0 python-owasp-zap-v2.4==0.0.21 \
    && python -m playwright install --with-deps chromium
