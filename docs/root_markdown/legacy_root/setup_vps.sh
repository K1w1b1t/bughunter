#!/usr/bin/env bash
set -euo pipefail

APP_USER="${APP_USER:-hunterops}"
APP_GROUP="${APP_GROUP:-${APP_USER}}"
APP_DIR="${APP_DIR:-/opt/hunterops}"
GO_VERSION="${GO_VERSION:-1.25.9}"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
REPO_URL="${REPO_URL:-}"
REPO_REF="${REPO_REF:-main}"
POSTGRES_USER="${POSTGRES_USER:-hunterops}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-change_me_now}"
POSTGRES_DB="${POSTGRES_DB:-hunterops}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
SSH_PORT="${SSH_PORT:-22}"
SSH_ALLOW_CIDR="${SSH_ALLOW_CIDR:-0.0.0.0/0}"
WEBHOOK_PORT="${WEBHOOK_PORT:-8081}"
WEBHOOK_ALLOW_CIDR="${WEBHOOK_ALLOW_CIDR:-0.0.0.0/0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[setup-vps] $*"; }
err() { echo "[setup-vps][error] $*" >&2; }

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    err "Run as root or install sudo."
    exit 1
  fi
fi

as_root() {
  if [[ -n "${SUDO}" ]]; then
    ${SUDO} "$@"
  else
    "$@"
  fi
}

as_app_user() {
  if [[ -n "${SUDO}" ]]; then
    ${SUDO} -u "${APP_USER}" bash -lc "$*"
  else
    su -s /bin/bash "${APP_USER}" -c "$*"
  fi
}

upsert_env() {
  local key="$1"
  local value="$2"
  local file="$3"
  if grep -qE "^${key}=" "${file}"; then
    sed -i "s#^${key}=.*#${key}=${value}#g" "${file}"
  else
    echo "${key}=${value}" >>"${file}"
  fi
}

install_docker_ubuntu() {
  log "Installing Docker Engine + Compose plugin..."
  as_root apt-get update
  as_root apt-get install -y ca-certificates curl gnupg lsb-release software-properties-common
  as_root install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" | as_root gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    as_root chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  local codename arch
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  arch="$(dpkg --print-architecture)"
  echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" \
    | as_root tee /etc/apt/sources.list.d/docker.list >/dev/null
  as_root apt-get update
  as_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_python_312() {
  if command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    log "${PYTHON_BIN} already installed."
    return
  fi
  log "Installing ${PYTHON_BIN}..."
  as_root apt-get update
  as_root apt-get install -y software-properties-common
  as_root add-apt-repository -y ppa:deadsnakes/ppa
  as_root apt-get update
  as_root apt-get install -y python3.12 python3.12-venv python3.12-dev python3-pip
}

install_go() {
  if command -v go >/dev/null 2>&1; then
    local current
    current="$(go version | awk '{print $3}' | sed 's/go//')"
    if [[ "${current}" == "${GO_VERSION}" ]]; then
      log "Go ${GO_VERSION} already installed."
      return
    fi
  fi
  log "Installing Go ${GO_VERSION}..."
  local tarball="go${GO_VERSION}.linux-amd64.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  as_root rm -rf /usr/local/go
  as_root tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"
}

configure_shell_path() {
  log "Configuring global PATH for Go + local Go bin..."
  cat <<'EOF' | as_root tee /etc/profile.d/hunterops-path.sh >/dev/null
export PATH="/usr/local/go/bin:${PATH}"
if [ -n "${HOME:-}" ] && [ -d "${HOME}/go/bin" ]; then
  export PATH="${HOME}/go/bin:${PATH}"
fi
EOF
  as_root chmod 0644 /etc/profile.d/hunterops-path.sh
}

ensure_app_user() {
  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    log "Creating user ${APP_USER}..."
    as_root groupadd --system "${APP_GROUP}" || true
    as_root useradd --system --create-home --shell /bin/bash --gid "${APP_GROUP}" "${APP_USER}"
  fi
  as_root usermod -aG docker "${APP_USER}" || true
}

prepare_app_dir() {
  log "Preparing ${APP_DIR}..."
  as_root mkdir -p "${APP_DIR}"
  as_root chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"
}

deploy_repo() {
  if [[ -d "${APP_DIR}/.git" ]]; then
    log "Repository already present at ${APP_DIR}; pulling ${REPO_REF}..."
    as_app_user "cd '${APP_DIR}' && git fetch --all --prune && git checkout '${REPO_REF}' && git pull --ff-only origin '${REPO_REF}'"
    return
  fi

  if [[ -n "${REPO_URL}" ]]; then
    log "Cloning repository ${REPO_URL} into ${APP_DIR}..."
    as_root find "${APP_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    as_app_user "git clone --branch '${REPO_REF}' --single-branch '${REPO_URL}' '${APP_DIR}'"
    return
  fi

  if [[ "${SCRIPT_DIR}" == "${APP_DIR}" ]]; then
    log "Running inside target directory; keeping current files."
    return
  fi

  err "Repository not found at ${APP_DIR}. Set REPO_URL=<git-url> and rerun."
  exit 1
}

prepare_env_file() {
  local env_file="${APP_DIR}/.env"
  if [[ ! -f "${env_file}" ]]; then
    if [[ -f "${APP_DIR}/.env.example" ]]; then
      as_root cp "${APP_DIR}/.env.example" "${env_file}"
    else
      as_root touch "${env_file}"
    fi
  fi

  as_root sed -i 's/\r$//' "${env_file}"
  upsert_env "HUNTEROPS_HOME" "${APP_DIR}" "${env_file}"
  upsert_env "POSTGRES_USER" "${POSTGRES_USER}" "${env_file}"
  upsert_env "POSTGRES_PASSWORD" "${POSTGRES_PASSWORD}" "${env_file}"
  upsert_env "POSTGRES_DB" "${POSTGRES_DB}" "${env_file}"
  upsert_env "POSTGRES_PORT" "${POSTGRES_PORT}" "${env_file}"
  upsert_env "HUNTEROPS_POSTGRES_DSN" "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}" "${env_file}"
  upsert_env "POSTGRES_DSN" "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}" "${env_file}"
  as_root chown "${APP_USER}:${APP_GROUP}" "${env_file}"
  as_root chmod 0600 "${env_file}"
}

install_python_deps() {
  log "Creating virtualenv and installing Python dependencies..."
  as_app_user "cd '${APP_DIR}' && ${PYTHON_BIN} -m venv .venv && .venv/bin/pip install --upgrade pip setuptools wheel && .venv/bin/pip install -r requirements.txt"
}

install_go_tools() {
  log "Installing Go binaries used by HunterOps..."
  as_app_user "export PATH='/usr/local/go/bin:${HOME}/go/bin:${PATH}'; cd '${APP_DIR}' && bash scripts/setup_env.sh"
}

start_postgres_compose() {
  log "Starting PostgreSQL with docker compose..."
  as_root docker compose -f "${APP_DIR}/ops/vps/docker-compose.yml" up -d
}

install_systemd_service() {
  log "Installing systemd service..."
  as_root install -m 0644 "${APP_DIR}/ops/vps/hunterops.service" /etc/systemd/system/hunterops.service
  as_root systemctl daemon-reload
  as_root systemctl enable --now hunterops.service
}

install_logrotate() {
  log "Installing logrotate policy..."
  as_root apt-get install -y logrotate
  as_root install -m 0644 "${APP_DIR}/ops/vps/logrotate-hunterops.conf" /etc/logrotate.d/hunterops
}

configure_ufw() {
  log "Configuring UFW..."
  as_root apt-get install -y ufw
  as_root ufw --force reset
  as_root ufw default deny incoming
  as_root ufw default allow outgoing
  as_root ufw allow from "${SSH_ALLOW_CIDR}" to any port "${SSH_PORT}" proto tcp
  as_root ufw allow from "${WEBHOOK_ALLOW_CIDR}" to any port "${WEBHOOK_PORT}" proto tcp
  as_root ufw --force enable
  as_root ufw status verbose
}

main() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    err "This script supports Linux only."
    exit 1
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    err "This script currently supports Ubuntu/Debian (apt-get)."
    exit 1
  fi

  as_root apt-get update
  as_root apt-get install -y git curl jq unzip make build-essential ca-certificates

  if ! command -v docker >/dev/null 2>&1; then
    install_docker_ubuntu
  fi
  as_root systemctl enable docker
  as_root systemctl restart docker

  install_python_312
  install_go
  configure_shell_path
  ensure_app_user
  prepare_app_dir
  deploy_repo
  prepare_env_file
  as_root mkdir -p "${APP_DIR}/logs" "${APP_DIR}/data/reports/smoke" "${APP_DIR}/data/postgres"
  as_root chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}/logs" "${APP_DIR}/data"
  as_root chmod +x "${APP_DIR}/scripts/continuous_bugbounty.sh"
  if [[ -f "${APP_DIR}/scripts/update_targets.sh" ]]; then
    as_root chmod +x "${APP_DIR}/scripts/update_targets.sh"
  fi

  install_python_deps
  install_go_tools
  start_postgres_compose
  install_systemd_service
  install_logrotate
  configure_ufw

  log "Bootstrap completed."
  cat <<EOF

Next steps:
1) Edit ${APP_DIR}/.env and set real secrets/webhooks.
2) Update ${APP_DIR}/targets.txt with authorized scope only.
3) Check service:
   sudo systemctl status hunterops.service
   sudo journalctl -u hunterops.service -f
4) Inspect errors:
   tail -f ${APP_DIR}/logs/error.log

EOF
}

main "$@"
