# CyberForge in one image: SAST + DAST + correlator + the web workspace.
#
#   docker build -t cyberforge .
#   docker run --rm cyberforge scan --help
#
# The UI is built in the first stage, so nobody needs Node installed. The container runs as root so it can always write the
# bind-mounted ./out; the application source is mounted read-only and the UI port is published on 127.0.0.1 only.

FROM node:22-slim AS ui
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.11.9-slim AS app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY common/ common/
COPY correlator/ correlator/
COPY cyberforge/ cyberforge/
COPY sast-engine/ sast-engine/
COPY dast-engine/ dast-engine/
COPY web/ web/
COPY --from=ui /build/web/dist web/dist
COPY .env.example .env.example
RUN mkdir -p /app/out /workspace

# Scans may only read source from /workspace, and the only hosts they may touch are this machine and the Docker host.
ENV CYBERFORGE_WORKSPACE=/workspace \
    CYBERFORGE_ALLOWED_HOSTS=localhost,127.0.0.1,host.docker.internal
EXPOSE 8000
ENTRYPOINT ["python", "-m", "cyberforge"]
CMD ["scan", "--help"]
