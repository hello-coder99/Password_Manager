# ==============================================================================
# AegisVault Backend Dockerfile (Flask + Gunicorn)
# ==============================================================================
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install minimal system dependencies for healthchecks and netcat
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user and group
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --shell /usr/sbin/nologin --create-home appuser

# Install pinned Python dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code and migrations
COPY --chown=appuser:appgroup app/ ./app/
COPY --chown=appuser:appgroup wsgi.py ./wsgi.py
COPY --chown=appuser:appgroup docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/api/health || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
