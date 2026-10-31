FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq iputils-ping dnsutils >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/pyshop
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
# Deliberately vulnerable. Debug is off, so errors are a bare 500 as in production.
CMD ["gunicorn", "--bind", "0.0.0.0:8089", "--workers", "2", "app:create_app()"]
