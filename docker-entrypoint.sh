#!/usr/bin/env sh
set -e

echo "[entrypoint] Running database migrations..."
flask --app wsgi:app db upgrade --directory app/migrations

echo "[entrypoint] Starting application server..."
exec "$@"
