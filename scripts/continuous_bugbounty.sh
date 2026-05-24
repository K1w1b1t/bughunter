#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGETS_FILE="${1:-${ROOT_DIR}/data/targets/in_scope_hosts.txt}"
CONFIG_FILE="${CONFIG_FILE:-${ROOT_DIR}/config/engine.yaml}"
SCAN_DELAY_SECONDS="${SCAN_DELAY_SECONDS:-90}"
LOOP_FOREVER="${LOOP_FOREVER:-1}"
OVERALL_OK_MODE="${OVERALL_OK_MODE:-db_only}"
WEBHOOK_MODE="${WEBHOOK_MODE:-real}"
SCOPE_REFRESH_ENABLED="${SCOPE_REFRESH_ENABLED:-1}"
SCOPE_FETCH_PROVIDERS="${SCOPE_FETCH_PROVIDERS:-hackerone,bugcrowd}"
SCOPE_FETCH_TIMEOUT="${SCOPE_FETCH_TIMEOUT:-45}"
SCOPE_FETCH_MAX_TARGETS="${SCOPE_FETCH_MAX_TARGETS:-0}"
SCOPE_FETCH_AUTOMATION_ONLY="${SCOPE_FETCH_AUTOMATION_ONLY:-1}"
SCOPE_FETCH_AUTOMATION_UNKNOWN_POLICY="${SCOPE_FETCH_AUTOMATION_UNKNOWN_POLICY:-drop}"
SCOPE_EXCLUDE_FILE="${SCOPE_EXCLUDE_FILE:-${ROOT_DIR}/config/targets_out_of_scope.txt}"
SCOPE_PROGRAMS_FILE="${SCOPE_PROGRAMS_FILE:-${ROOT_DIR}/config/programs.yaml}"
SCOPE_FETCH_SCRIPT="${SCOPE_FETCH_SCRIPT:-${ROOT_DIR}/scripts/fetch_scopes.py}"

export PATH="${HOME}/go/bin:${PATH}"
export PYTHONPATH="${ROOT_DIR}"
export HUNTEROPS_HOME="${ROOT_DIR}"

if [[ ! -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  echo "[fatal] python venv not found: ${ROOT_DIR}/.venv/bin/python" >&2
  exit 1
fi

mkdir -p "${ROOT_DIR}/logs" "${ROOT_DIR}/data/reports/smoke"

refresh_scopes() {
  if [[ "${SCOPE_REFRESH_ENABLED}" != "1" ]]; then
    return 0
  fi
  if [[ ! -f "${SCOPE_FETCH_SCRIPT}" ]]; then
    echo "[warn] scope refresh skipped (script missing): ${SCOPE_FETCH_SCRIPT}" >&2
    return 0
  fi

  local automation_flag
  case "$(echo "${SCOPE_FETCH_AUTOMATION_ONLY}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
      automation_flag="--automation-only"
      ;;
    *)
      automation_flag="--no-automation-only"
      ;;
  esac

  echo "[scope] refreshing providers=${SCOPE_FETCH_PROVIDERS} automation_only=${SCOPE_FETCH_AUTOMATION_ONLY} unknown_policy=${SCOPE_FETCH_AUTOMATION_UNKNOWN_POLICY}"
  if ! "${ROOT_DIR}/.venv/bin/python" "${SCOPE_FETCH_SCRIPT}" \
    --providers "${SCOPE_FETCH_PROVIDERS}" \
    --out "${TARGETS_FILE}" \
    --exclude-file "${SCOPE_EXCLUDE_FILE}" \
    --programs-file "${SCOPE_PROGRAMS_FILE}" \
    "${automation_flag}" \
    --automation-unknown-policy "${SCOPE_FETCH_AUTOMATION_UNKNOWN_POLICY}" \
    --timeout "${SCOPE_FETCH_TIMEOUT}" \
    --max-targets "${SCOPE_FETCH_MAX_TARGETS}"; then
    echo "[warn] scope refresh failed; reusing previous targets file (if any)." >&2
    return 0
  fi
}

run_once() {
  local target run_id safe_target ts scanned
  declare -A seen_targets=()
  scanned=0
  if [[ ! -f "${TARGETS_FILE}" ]]; then
    echo "[warn] targets file not found: ${TARGETS_FILE}" >&2
    return 0
  fi

  while IFS= read -r target || [[ -n "${target}" ]]; do
    target="${target%%#*}"
    target="${target//$'\r'/}"
    target="$(echo "${target}" | xargs)"
    [[ -z "${target}" ]] && continue
    if [[ "${target}" == "*."* ]]; then
      target="${target:2}"
    fi
    [[ -z "${target}" ]] && continue
    if [[ -n "${seen_targets[${target}]:-}" ]]; then
      continue
    fi
    seen_targets["${target}"]=1

    ts="$(date -u +%Y%m%d_%H%M%S)"
    safe_target="$(echo "${target}" | tr -cs '[:alnum:]._-/' '_' | sed 's/^_//; s/_$//')"
    run_id="cont_${ts}_${safe_target:0:40}"

    echo "[run] target=${target} run_id=${run_id}"
    if ! "${ROOT_DIR}/.venv/bin/python" "${ROOT_DIR}/scripts/test_pipeline.py" \
      --config "${CONFIG_FILE}" \
      --target "${target}" \
      --run-id "${run_id}" \
      --overall-ok-mode "${OVERALL_OK_MODE}" \
      --webhook-mode "${WEBHOOK_MODE}"; then
      echo "[warn] run_failed target=${target} run_id=${run_id}" >&2
    fi

    scanned=1
    echo "[sleep] ${SCAN_DELAY_SECONDS}s before next target"
    sleep "${SCAN_DELAY_SECONDS}"
  done < "${TARGETS_FILE}"

  if [[ "${scanned}" -eq 0 ]]; then
    echo "[warn] no valid targets in ${TARGETS_FILE}" >&2
  fi
}

if [[ "${LOOP_FOREVER}" == "1" ]]; then
  while true; do
    refresh_scopes
    run_once
  done
else
  refresh_scopes
  run_once
fi
