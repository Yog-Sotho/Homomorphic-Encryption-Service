#!/bin/sh
# Starts the real backend with a throwaway database and key store for the
# full-stack Playwright suite. The log goes to $FULLSTACK_LOG so tests can read
# the email verification link (SMTP is not configured, so the backend logs it).
set -eu

BIN="${HEAAS_BACKEND_BIN:-../backend/target/debug/he-backend}"
WORK="$(mktemp -d)"

export DATABASE_URL="sqlite://$WORK/he_saas.db?mode=rwc"
export KEY_STORE_DIR="$WORK/keys"
export JOB_STORE_DIR="$WORK/jobs"
export SERVER_ADDR="127.0.0.1:${FULLSTACK_BACKEND_PORT:-18081}"
export JWT_SECRET="fullstack-test-secret-that-is-at-least-32-bytes"
export ALLOWED_ORIGINS="http://localhost:4174"
export APP_BASE_URL="http://localhost:4174"
export RUST_LOG="${RUST_LOG:-info}"
unset SMTP_HOST

exec "$BIN" >"${FULLSTACK_LOG:-e2e-fullstack/.backend.log}" 2>&1
