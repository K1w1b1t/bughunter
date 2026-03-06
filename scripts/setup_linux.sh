#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="${HUNTEROPS_HOME:-/opt/hunterops}"
ENV_FILE="${ROOT_DIR}/.env"

log() {
  printf '[setup-linux] %s\n' "$1"
}

fail() {
  printf '[setup-linux][error] %s\n' "$1" >&2
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "This installer only supports Linux."
fi

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    fail "Run as root or install sudo."
  fi
fi

run_root() {
  if [[ -n "${SUDO}" ]]; then
    ${SUDO} "$@"
  else
    "$@"
  fi
}

install_docker_apt() {
  log "Installing Docker Engine and Compose plugin (apt)..."
  run_root apt-get update
  run_root apt-get install -y ca-certificates curl gnupg lsb-release
  run_root install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg | run_root gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    run_root chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  ARCH="$(dpkg --print-architecture)"
  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  echo \
    "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") ${CODENAME} stable" \
    | run_root tee /etc/apt/sources.list.d/docker.list >/dev/null
  run_root apt-get update
  run_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_docker_dnf() {
  log "Installing Docker Engine and Compose plugin (dnf)..."
  run_root dnf -y install dnf-plugins-core
  run_root dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  run_root dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

if ! command -v docker >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    install_docker_apt
  elif command -v dnf >/dev/null 2>&1; then
    install_docker_dnf
  else
    fail "Unsupported package manager. Install Docker manually and rerun."
  fi
fi

run_root systemctl enable docker
run_root systemctl restart docker

if ! docker compose version >/dev/null 2>&1; then
  fail "Docker Compose plugin was not installed correctly."
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ENV_FILE}"
    log "Created ${ENV_FILE} from .env.example"
  else
    touch "${ENV_FILE}"
  fi
fi

if ! grep -q '^HUNTEROPS_HOME=' "${ENV_FILE}"; then
  echo "HUNTEROPS_HOME=${APP_ROOT}" >>"${ENV_FILE}"
fi
if ! grep -q '^HUNTEROPS_POSTGRES_DSN=' "${ENV_FILE}"; then
  echo "HUNTEROPS_POSTGRES_DSN=postgresql://hunter:hunter@db:5432/hunterops" >>"${ENV_FILE}"
fi

chmod 0600 "${ENV_FILE}" || true
mkdir -p "${ROOT_DIR}/data" "${ROOT_DIR}/data/reports" "${ROOT_DIR}/data/evidence" "${ROOT_DIR}/data/processed"
mkdir -p "${ROOT_DIR}/reports"
chmod 0755 "${ROOT_DIR}/data" "${ROOT_DIR}/data/reports" "${ROOT_DIR}/data/evidence" "${ROOT_DIR}/data/processed" "${ROOT_DIR}/reports" || true

if [[ -f "${ROOT_DIR}/data/sessions.yaml" ]]; then
  chmod 0600 "${ROOT_DIR}/data/sessions.yaml" || true
fi

chmod 0755 "${ROOT_DIR}/scripts/setup_env.sh" || true
chmod 0755 "${ROOT_DIR}/scripts/docker_entrypoint.sh" || true
chmod 0755 "${ROOT_DIR}/scripts/check_infra.sh" || true

log "Building HunterOps image..."
run_root docker compose -f "${ROOT_DIR}/docker-compose.yml" build app monitor

log "Starting data services..."
run_root docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d db redis

if [[ "${HUNTEROPS_ENABLE_OOB:-0}" == "1" ]]; then
  log "Starting OOB listener profile..."
  run_root docker compose -f "${ROOT_DIR}/docker-compose.yml" --profile oob up -d oob
fi

log "Starting HunterOps core..."
run_root docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d app monitor

log "Done."
cat <<'EOF'

Next steps:
1) Edit .env and fill API credentials/tokens:
   - HACKERONE_API_USER / HACKERONE_API_TOKEN
   - HUNTEROPS_OOB_* (if OOB mode enabled)
2) Validate target scope in config/programs.yaml.
3) (Optional) Enable systemd service:
   sudo cp ops/systemd/hunterops.service /etc/systemd/system/hunterops.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now hunterops.service
4) Check logs:
   docker compose logs -f app
   journalctl -u hunterops.service -f
EOF
