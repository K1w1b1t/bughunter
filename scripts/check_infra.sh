#!/usr/bin/env bash
set -euo pipefail

TIMEOUT_SECONDS="${HUNTEROPS_INFRA_TIMEOUT_SECONDS:-45}"
RETRY_INTERVAL_SECONDS="${HUNTEROPS_INFRA_RETRY_INTERVAL_SECONDS:-2}"

log() {
  printf '[check-infra] %s\n' "$1"
}

fail() {
  printf '[check-infra][error] %s\n' "$1" >&2
  exit 1
}

resolve_postgres_host_port() {
  local host="${POSTGRES_HOST:-}"
  local port="${POSTGRES_PORT:-}"
  if [[ -n "${host}" && -n "${port}" ]]; then
    printf '%s %s\n' "${host}" "${port}"
    return 0
  fi
  python - <<'PY'
import os
from urllib.parse import urlparse

dsn = os.getenv("HUNTEROPS_POSTGRES_DSN", "").strip()
if not dsn:
    print("db 5432")
else:
    parsed = urlparse(dsn)
    print(f"{parsed.hostname or 'db'} {parsed.port or 5432}")
PY
}

resolve_redis_host_port() {
  python - <<'PY'
import os
from urllib.parse import urlparse

url = os.getenv("HUNTEROPS_REDIS_URL", "redis://redis:6379/0").strip()
parsed = urlparse(url)
print(f"{parsed.hostname or 'redis'} {parsed.port or 6379}")
PY
}

wait_for_tcp() {
  local service_name="$1"
  local host="$2"
  local port="$3"
  local deadline=$((SECONDS + TIMEOUT_SECONDS))
  log "waiting_for_${service_name} host=${host} port=${port} timeout=${TIMEOUT_SECONDS}s"
  while true; do
    if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
      exec 3<&- 3>&-
      log "${service_name}_reachable host=${host} port=${port}"
      return 0
    fi
    if ((SECONDS >= deadline)); then
      fail "${service_name}_unreachable host=${host} port=${port} timeout=${TIMEOUT_SECONDS}s"
    fi
    sleep "${RETRY_INTERVAL_SECONDS}"
  done
}

read -r POSTGRES_HOST_RESOLVED POSTGRES_PORT_RESOLVED <<<"$(resolve_postgres_host_port)"
read -r REDIS_HOST_RESOLVED REDIS_PORT_RESOLVED <<<"$(resolve_redis_host_port)"

wait_for_tcp "postgres" "${POSTGRES_HOST_RESOLVED}" "${POSTGRES_PORT_RESOLVED}"
wait_for_tcp "redis" "${REDIS_HOST_RESOLVED}" "${REDIS_PORT_RESOLVED}"

log "infra_check_ok"
