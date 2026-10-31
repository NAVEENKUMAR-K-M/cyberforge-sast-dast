FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq iputils-ping >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/djshop
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# DEBUG is off, so an error is a bare 500 page, as on a real deployment.
RUN python manage.py migrate --noinput
# Deliberately vulnerable. The port is bound to loopback so it can't be reached from the network.
CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "30"]
