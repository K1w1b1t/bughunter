#!/usr/bin/env bash

# ===================================================================
# HunterOps-AI: PASSO 1 - Foundation Validation Script
# ===================================================================
# Purpose: Verify all PASSO 1 generation artifacts are correct
# Run this BEFORE attempting docker-compose up -d
# ===================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS=0
FAIL=0
WARN=0

# ===================================================================
# Helper Functions
# ===================================================================

print_header() {
    echo ""
    echo -e "${BLUE}■ $1${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

print_pass() {
    echo -e "${GREEN}✓ $1${NC}"
    ((PASS++))
}

print_fail() {
    echo -e "${RED}✗ $1${NC}"
    ((FAIL++))
}

print_warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
    ((WARN++))
}

# ===================================================================
# Validation Functions
# ===================================================================

check_file_exists() {
    local file=$1
    local filename=$(basename "$file")
    
    if [ -f "$file" ]; then
        local size=$(wc -c < "$file")
        print_pass "File exists: $filename ($((size / 1024)) KB)"
    else
        print_fail "File missing: $filename"
    fi
}

check_file_yaml_valid() {
    local file=$1
    local filename=$(basename "$file")
    
    if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
        print_pass "YAML syntax valid: $filename"
    else
        print_fail "YAML syntax invalid: $filename"
    fi
}

check_file_bash_valid() {
    local file=$1
    local filename=$(basename "$file")
    
    # Check if file is readable bash script
    if head -n 1 "$file" | grep -q "^#!" && bash -n "$file" 2>/dev/null; then
        print_pass "Bash syntax valid: $filename"
    else
        print_warn "Could not verify bash syntax: $filename"
    fi
}

check_file_contains_string() {
    local file=$1
    local search_string=$2
    local description=$3
    
    if grep -q "$search_string" "$file"; then
        print_pass "✓ $description"
    else
        print_fail "✗ Missing: $description"
    fi
}

check_docker_installed() {
    if command -v docker &> /dev/null; then
        local version=$(docker --version)
        print_pass "Docker installed: $version"
    else
        print_fail "Docker not installed (required for deployment)"
    fi
}

check_docker_compose_installed() {
    if command -v docker-compose &> /dev/null; then
        local version=$(docker-compose --version 2>/dev/null || echo "unknown")
        print_pass "Docker Compose installed: $version"
    else
        print_warn "Docker Compose not installed (optional, use 'docker compose' instead)"
    fi
}

check_python_installed() {
    if command -v python3 &> /dev/null; then
        local version=$(python3 --version)
        print_pass "Python 3 installed: $version"
    else
        print_fail "Python 3 not installed (needed for validation)"
    fi
}

check_postgresql_client() {
    if command -v psql &> /dev/null; then
        local version=$(psql --version)
        print_pass "PostgreSQL client installed: $version"
    else
        print_warn "PostgreSQL client not installed (optional for initial setup)"
    fi
}

# ===================================================================
# Main Validation
# ===================================================================

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  HunterOps-AI: PASSO 1 - Foundation Validation Script      ║"
    echo "║  Generated: 2026-03-20                                     ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    
    # Check system dependencies
    print_header "System Dependencies"
    check_docker_installed
    check_docker_compose_installed
    check_python_installed
    check_postgresql_client
    
    # Check primary artifacts
    print_header "Core Artifacts (REQUIRED)"
    check_file_exists "docker-compose.prod.yml"
    check_file_exists ".env.example"
    check_file_exists "Dockerfile"
    check_file_exists "INFRASTRUCTURE_SETUP.md"
    
    # Validate YAML files
    print_header "YAML Validation"
    if [ -f "docker-compose.prod.yml" ]; then
        check_file_yaml_valid "docker-compose.prod.yml"
    fi
    
    # Check docker-compose content
    print_header "docker-compose.prod.yml Content Validation"
    if [ -f "docker-compose.prod.yml" ]; then
        check_file_contains_string "docker-compose.prod.yml" "postgres:16-alpine" \
            "PostgreSQL 16 Alpine image specified"
        check_file_contains_string "docker-compose.prod.yml" "redis:7-alpine" \
            "Redis 7 Alpine image specified"
        check_file_contains_string "docker-compose.prod.yml" "pgdata:" \
            "PostgreSQL volume defined"
        check_file_contains_string "docker-compose.prod.yml" "healthcheck:" \
            "Health checks configured"
        check_file_contains_string "docker-compose.prod.yml" "networks:" \
            "Custom network defined"
    fi
    
    # Check .env.example content
    print_header ".env.example Content Validation"
    if [ -f ".env.example" ]; then
        check_file_contains_string ".env.example" "POSTGRES_USER=" \
            "PostgreSQL user config present"
        check_file_contains_string ".env.example" "ANTHROPIC_API_KEY=" \
            "LLM (Anthropic) key config present"
        check_file_contains_string ".env.example" "DISCORD_WEBHOOK_" \
            "Discord webhooks config present"
        check_file_contains_string ".env.example" "HACKERONE_API_" \
            "HackerOne integration config present"
        check_file_contains_string ".env.example" "STRUCTLOG_ENABLED" \
            "Structured logging config present"
        check_file_contains_string ".env.example" "RATE_LIMIT_PER_SEC" \
            "Rate limiting config present"
    fi
    
    # Check Dockerfile content
    print_header "Dockerfile Content Validation"
    if [ -f "Dockerfile" ]; then
        check_file_contains_string "Dockerfile" "python:3.12-slim-bookworm" \
            "Python 3.12 image specified"
        check_file_contains_string "Dockerfile" "golang:1.24-bookworm" \
            "Go 1.24 build stage present"
        check_file_contains_string "Dockerfile" "libpq-dev" \
            "PostgreSQL development libraries included"
        check_file_contains_string "Dockerfile" "postgresql-client" \
            "PostgreSQL client tools included"
        check_file_contains_string "Dockerfile" "tini" \
            "Tini init system included"
        check_file_contains_string "Dockerfile" "hunterops" \
            "Non-root user configured"
    fi
    
    # Check auxiliary scripts
    print_header "Auxiliary Scripts Validation"
    if [ -f "scripts/docker/pg-extensions-init.sql" ]; then
        check_file_contains_string "scripts/docker/pg-extensions-init.sql" "CREATE EXTENSION" \
            "PostgreSQL extensions initialization script valid"
    else
        print_fail "PostgreSQL extensions script missing"
    fi
    
    if [ -f "scripts/docker/pg-audit-init.sql" ]; then
        check_file_contains_string "scripts/docker/pg-audit-init.sql" "audit_log" \
            "PostgreSQL audit table initialization script valid"
    else
        print_fail "PostgreSQL audit script missing"
    fi
    
    if [ -f "scripts/docker/backup-entrypoint.sh" ]; then
        check_file_bash_valid "scripts/docker/backup-entrypoint.sh"
    else
        print_fail "PostgreSQL backup script missing"
    fi
    
    # Check environment secrets
    print_header "Environment Security Validation"
    if [ -f ".env.example" ]; then
        # Check for placeholder values (not filled in)
        if grep -q "<YOUR_" ".env.example"; then
            print_warn "Found unfilled placeholders in .env.example (expected - fill before deployment)"
        fi
        
        # Ensure no real secrets in .env.example
        if [ ! -f ".env.production" ] && [ ! -f ".env" ]; then
            print_pass "No sensitive .env files committed (good security practice)"
        fi
    fi
    
    # Pre-deployment checklist
    print_header "Pre-Deployment Checklist"
    echo ""
    echo "Before running 'docker-compose -f docker-compose.prod.yml up -d':"
    echo ""
    echo "  [ ] Copy .env.example to .env"
    echo "      cp .env.example .env"
    echo ""
    echo "  [ ] Generate strong passwords:"
    echo "      POSTGRES_PASSWORD=\$(openssl rand -base64 32)"
    echo "      ENCRYPTION_KEY=\$(openssl rand -hex 16)"
    echo "      JWT_SECRET=\$(openssl rand -base64 64)"
    echo ""
    echo "  [ ] Edit .env and fill all <YOUR_...> placeholders:"
    echo "      nano .env"
    echo ""
    echo "  [ ] Validate docker-compose syntax:"
    echo "      docker-compose -f docker-compose.prod.yml config"
    echo ""
    echo "  [ ] Create host directories for volumes:"
    echo "      mkdir -p /var/lib/hunterops/{postgres,redis,data,backups}"
    echo ""
    echo "  [ ] Start services:"
    echo "      docker-compose -f docker-compose.prod.yml up -d"
    echo ""
    echo "  [ ] Verify all services are healthy:"
    echo "      docker-compose -f docker-compose.prod.yml ps"
    echo "      docker logs hunterops-engine"
    echo ""
    
    # Summary
    print_header "Validation Summary"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $PASS"
    echo -e "  ${RED}Failed:${NC}  $FAIL"
    echo -e "  ${YELLOW}Warnings:${NC} $WARN"
    echo ""
    
    if [ $FAIL -eq 0 ]; then
        echo -e "${GREEN}✓ All critical checks passed!${NC}"
        echo ""
        echo "Next Steps:"
        echo "  1. Review INFRASTRUCTURE_SETUP.md for detailed volume management"
        echo "  2. Copy and customize .env file"
        echo "  3. Run: docker-compose -f docker-compose.prod.yml config"
        echo "  4. Launch with: docker-compose -f docker-compose.prod.yml up -d"
        return 0
    else
        echo -e "${RED}✗ Fix the above errors before proceeding${NC}"
        return 1
    fi
}

# Run main function
main "$@"
