#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_FILE="${TARGET_FILE:-${ROOT_DIR}/data/targets/in_scope_hosts.txt}"
LOCK_FILE="${ROOT_DIR}/.targets.lock"
SRC_FILE="${1:-}"

if [[ -z "${SRC_FILE}" ]]; then
  echo "Usage: $0 <new_targets_file>" >&2
  exit 1
fi

if [[ ! -f "${SRC_FILE}" ]]; then
  echo "[error] source file not found: ${SRC_FILE}" >&2
  exit 1
fi

mkdir -p "$(dirname "${TARGET_FILE}")"

exec 9>"${LOCK_FILE}"
flock -x 9

tmp_file="$(mktemp "${TARGET_FILE}.tmp.XXXXXX")"
trap 'rm -f "${tmp_file}"' EXIT

awk '
  {
    gsub(/\r$/, "", $0)
    sub(/[[:space:]]*#.*$/, "", $0)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
    if ($0 != "") print $0
  }
' "${SRC_FILE}" | sort -u > "${tmp_file}"

mv "${tmp_file}" "${TARGET_FILE}"
chmod 0640 "${TARGET_FILE}" || true

echo "[ok] targets updated atomically: ${TARGET_FILE}"
