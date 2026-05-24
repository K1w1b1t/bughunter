#!/usr/bin/env bash
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "[error] Go is required. Install Go >= 1.22 and retry."
  exit 1
fi

GOBIN_DIR="${GOBIN:-$HOME/go/bin}"
export PATH="$GOBIN_DIR:$PATH"

echo "[setup] Installing HunterOps binary dependencies..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
(go install github.com/owasp-amass/amass/v4/...@latest || go install github.com/owasp-amass/amass/v3/...@latest || true)

echo "[setup] Validating installation..."
for tool in subfinder httpx naabu nuclei interactsh-client amass; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  - $tool: OK"
  else
    echo "  - $tool: MISSING (ensure $GOBIN_DIR is in PATH)"
  fi
done

echo "[setup] Completed."
