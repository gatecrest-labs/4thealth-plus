FROM python:3.14-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency manifests first for better layer caching
COPY pyproject.toml uv.lock ./

# Install production dependencies into the project virtualenv
RUN uv sync --extra prod --no-dev

ENV PATH="/app/.venv/bin:$PATH"

# Copy application source
COPY wsgi.py manage_users.py ./
COPY app/ app/

# Create non-root user matching the service account convention
RUN useradd --system --no-create-home --shell /sbin/nologin appuser \
    && mkdir -p /app/certs \
    && chown -R appuser:appuser /app

ENV HOME=/tmp
USER appuser

EXPOSE 8100

# Default CMD serves the web process. The collector process overrides
# this at the docker-compose/run level with:
#   command: ["python", "-m", "app.collector"]
# See docker-compose.yml and container.md.
CMD ["gunicorn", \
     "--workers", "2", \
     "--threads", "4", \
     "--worker-class", "gthread", \
     "--bind", "0.0.0.0:8100", \
     "--timeout", "120", \
     "--worker-tmp-dir", "/dev/shm", \
     "--certfile", "certs/cert.pem", \
     "--keyfile", "certs/key.pem", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "wsgi:app"]
