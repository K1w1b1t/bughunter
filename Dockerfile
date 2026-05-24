# syntax=docker/dockerfile:1.7
# ===================================================================
# HunterOps-AI: Multi-Stage Docker Build
# ===================================================================
# Stage 1: Go Tools (Recon + Scanning)
# Stage 2: Rust Tools (Optional Analyzer)
# Stage 3: Python Runtime (3.12 + LLM Integration)
# ===================================================================

# --- STAGE 1: Go Tools Compilation ---
FROM golang:1.25-bookworm AS go-tools

ENV GOBIN=/opt/hunterops-bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "${GOBIN}"

# Compile all Go-based security tools
RUN set -eux; \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest; \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest; \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest; \
    (go install github.com/lc/gau/v2/cmd/gau@latest || true); \
    (go install github.com/tomnomnom/assetfinder@latest || true); \
    (go install github.com/tomnomnom/waybackurls@latest || true); \
    (go install github.com/ffuf/ffuf/v2@latest || true); \
    (go install github.com/projectdiscovery/katana/cmd/katana@latest || true); \
    (go install github.com/hakluke/hakrawler@latest || true); \
    (go install github.com/jaeles-project/gospider@latest || true); \
    (go install github.com/owasp-amass/amass/v4/...@latest || go install github.com/owasp-amass/amass/v3/...@latest || true); \
    for tool in subfinder httpx naabu nuclei interactsh-client amass gau assetfinder waybackurls ffuf katana hakrawler gospider; do \
      if [ -f "/go/bin/${tool}" ]; then install -m 0755 "/go/bin/${tool}" "${GOBIN}/${tool}"; fi; \
    done

# --- STAGE 2: Rust Tools (Optional) ---
FROM rust:1.86-slim-bookworm AS rust-tools

RUN mkdir -p /opt/hunterops-bin
WORKDIR /build

# Copy Rust analyzer sources
COPY tools/rust-analyzer ./tools/rust-analyzer

RUN set -eux; \
    if [ -d "tools/rust-analyzer" ]; then \
      cd tools/rust-analyzer && \
      cargo build --release && \
      install -m 0755 target/release/hunterops_rust_analyzer /opt/hunterops-bin/hunterops_rust_analyzer; \
    fi

# --- STAGE 3: Python 3.12 Runtime (LLM + AsyncIO) ---
FROM python:3.12-slim-bookworm AS runtime

# ===================================================================
# Environment Variables
# ===================================================================

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=0 \
    PYTHONPATH=/opt/hunterops \
    HUNTEROPS_HOME=/opt/hunterops

# ===================================================================
# System Dependencies Installation
# ===================================================================

WORKDIR /opt/hunterops

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential build tools
    build-essential \
    libssl-dev \
    libffi-dev \
    \
    # Database + pgaudit support
    libpq-dev \
    postgresql-client \
    \
    # Security tools runtime dependencies
    ca-certificates \
    git \
    libpcap-dev \
    \
    # Process management
    procps \
    tini \
    \
    # Utilities
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# ===================================================================
# Python Dependencies
# ===================================================================

COPY requirements.txt ./requirements.txt

RUN python -m pip install --upgrade \
    pip \
    setuptools \
    wheel

# Install all Python dependencies
# Note: This includes new LLM + ORM packages
RUN python -m pip install --no-cache-dir -r requirements.txt

# ===================================================================
# Copy Compiled Tools from Previous Stages
# ===================================================================

# Copy Go tools
COPY --from=go-tools /opt/hunterops-bin/ /usr/local/bin/

# Copy Rust tools
COPY --from=rust-tools /opt/hunterops-bin/ /usr/local/bin/

# Ensure all binaries are executable
RUN set -eux; \
    for tool in subfinder httpx naabu nuclei interactsh-client amass hunterops_rust_analyzer \
                  gau assetfinder waybackurls ffuf katana hakrawler gospider; do \
      if command -v "${tool}" >/dev/null 2>&1; then \
        chmod 0755 "$(command -v "${tool}")"; \
      fi; \
    done

# ===================================================================
# Application Setup
# ===================================================================

# Copy application code
COPY . /opt/hunterops

# Copy entrypoint script
COPY scripts/docker_entrypoint.sh /usr/local/bin/docker_entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker_entrypoint.sh

# ===================================================================
# Security: Non-Root User Setup
# ===================================================================

RUN groupadd --system hunterops \
    && useradd --system --gid hunterops \
               --home /opt/hunterops \
               --shell /usr/sbin/nologin \
               hunterops

# Create necessary directories
RUN mkdir -p \
    /opt/hunterops/data \
    /opt/hunterops/data/logs \
    /opt/hunterops/data/evidence \
    /opt/hunterops/data/findings \
    /opt/hunterops/reports \
    /opt/hunterops/.cache \
    && chown -R hunterops:hunterops /opt/hunterops

# ===================================================================
# Environment Variables (Default Values)
# ===================================================================

ENV HUNTEROPS_ENV=production \
    LOG_LEVEL=INFO \
    LOG_FORMAT=json \
    STRUCTLOG_ENABLED=true \
    CONCURRENCY=6 \
    RATE_LIMIT_PER_SEC=10 \
    ENABLE_DEBUG=false

# ===================================================================
# Health Check
# ===================================================================

HEALTHCHECK --interval=60s --timeout=10s --retries=3 --start-period=30s \
    CMD python -c "import psutil; exit(0 if psutil.cpu_percent() >= 0 else 1)" || exit 1

# ===================================================================
# Entrypoint
# ===================================================================

# Use tini for proper PID 1 signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command (can be overridden)
CMD ["/usr/local/bin/docker_entrypoint.sh"]

# ===================================================================
# Metadata
# ===================================================================

LABEL maintainer="HunterOps-AI Team" \
      description="HunterOps-AI: Bug Bounty Automation Framework + SOC Virtual" \
      version="2.0" \
      python.version="3.12" \
      homepage="https://github.com/your-org/hunterops-ai"
