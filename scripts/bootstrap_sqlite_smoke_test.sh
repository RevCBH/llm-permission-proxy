#!/usr/bin/env bash

set -euo pipefail
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PORT="19090"
DB_PATH="$(mktemp "${REPO_ROOT}/data/.smoke_bootstrap_XXXXXX.db")"
LOG_FILE="${REPO_ROOT}/.smoke-bootstrap.log"
READY_URL="http://127.0.0.1:${PORT}/v1/readyz"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -f "${DB_PATH}"
}
trap cleanup EXIT

for dep in sqlite3 curl; do
  if ! command -v "${dep}" >/dev/null 2>&1; then
    echo "Required dependency missing: ${dep}" >&2
    exit 1
  fi
done

export DATABASE_URL="sqlite://${DB_PATH}"
export BIND_ADDR="127.0.0.1:${PORT}"
export BASE_URL="http://127.0.0.1:${PORT}"
export WEBAUTHN_RP_ID="127.0.0.1"
export WEBAUTHN_ORIGIN="http://127.0.0.1:${PORT}"

(
  cd "${REPO_ROOT}" &&
  cargo run --quiet
) >"${LOG_FILE}" 2>&1 &
SERVER_PID=$!

for _ in {1..30}; do
  if curl -fsS --max-time 2 "${READY_URL}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS --max-time 2 "${READY_URL}" >/dev/null 2>&1; then
  echo "server failed to become ready; check ${LOG_FILE}" >&2
  exit 1
fi

if ! sqlite3 "${DB_PATH}" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='approver_credentials' LIMIT 1;" | grep -qx '1'; then
  echo "bootstrap failed: approver_credentials table not created" >&2
  exit 1
fi

for column in algorithm public_key_format public_key_b64; do
  if ! sqlite3 "${DB_PATH}" "PRAGMA table_info(approver_credentials);" | cut -d'|' -f2 | grep -Fxq "${column}"; then
    echo "bootstrap failed: approver_credentials.${column} missing" >&2
    exit 1
  fi
done

if sqlite3 "${DB_PATH}" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations' LIMIT 1;" | grep -qx '1'; then
  echo "bootstrap unexpectedly created sqlx migration metadata table" >&2
  exit 1
fi

echo "smoke test passed: bootstrap schema created with approver credential verifier columns and no migration table."
rm -f "${LOG_FILE}"
