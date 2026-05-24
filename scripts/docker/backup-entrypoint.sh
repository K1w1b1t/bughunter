#!/bin/bash

# ===================================================================
# HunterOps PostgreSQL Backup Script
# ===================================================================
# Purpose: Automated daily PostgreSQL backup with rotation
# Schedule: Daemon loop (default every 86400s via docker-compose service)
# Retention: 30 days (adjustable via BACKUP_RETENTION_DAYS env var)
# ===================================================================

set -e

# Source environment variables
BACKUP_PATH="${BACKUP_PATH:-/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
BACKUP_COMPRESSION="${BACKUP_COMPRESSION:-gzip}"
BACKUP_INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-86400}"
BACKUP_DAEMON_MODE="${BACKUP_DAEMON_MODE:-true}"
BACKUP_RUN_IMMEDIATELY="${BACKUP_RUN_IMMEDIATELY:-true}"

# PostgreSQL connection details (from environment)
PGHOST="${PGHOST:-db}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-hunterops}"
PGPASSWORD="${PGPASSWORD}"
PGDATABASE="${PGDATABASE:-hunterops}"

BACKUP_FILE=""
BACKUP_LOG=""
SHUTDOWN_REQUESTED=0

# ===================================================================
# Functions
# ===================================================================

log() {
    local line="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    if [ -n "$BACKUP_LOG" ]; then
        echo "$line" | tee -a "$BACKUP_LOG"
    else
        echo "$line"
    fi
}

error_exit() {
    log "ERROR: $1"
    return 1
}

prepare_cycle_files() {
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    BACKUP_FILE="${BACKUP_PATH}/hunterops-db-backup-${timestamp}.sql.gz"
    BACKUP_LOG="${BACKUP_PATH}/backup-${timestamp}.log"
}

request_shutdown() {
    SHUTDOWN_REQUESTED=1
    log "Shutdown signal received, stopping backup loop..."
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Verify backup directory exists
    if [ ! -d "$BACKUP_PATH" ]; then
        mkdir -p "$BACKUP_PATH" || error_exit "Cannot create backup directory: $BACKUP_PATH" || return 1
        log "Created backup directory: $BACKUP_PATH"
    fi
    
    # Check permissions
    if [ ! -w "$BACKUP_PATH" ]; then
        error_exit "Backup directory is not writable: $BACKUP_PATH" || return 1
    fi
    
    # Verify psql is available
    if ! command -v psql &> /dev/null; then
        error_exit "psql command not found. Is postgresql-client installed?" || return 1
    fi
    
    # Verify pg_dump is available
    if ! command -v pg_dump &> /dev/null; then
        error_exit "pg_dump command not found. Is postgresql-client installed?" || return 1
    fi
    
    log "Prerequisites check passed"
}

test_database_connection() {
    log "Testing database connection..."
    
    export PGPASSWORD
    
    if ! psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -c "SELECT 1" > /dev/null 2>&1; then
        error_exit "Cannot connect to PostgreSQL at ${PGHOST}:${PGPORT} as ${PGUSER}" || return 1
    fi
    
    log "Database connection successful"
}

create_backup() {
    log "Creating backup: $BACKUP_FILE"
    
    export PGPASSWORD
    
    # Perform full database dump with compression
    if [ "$BACKUP_COMPRESSION" = "gzip" ]; then
        pg_dump \
            -h "$PGHOST" \
            -p "$PGPORT" \
            -U "$PGUSER" \
            -d "$PGDATABASE" \
            --format=plain \
            --verbose \
            --no-owner \
            --no-privileges \
            2>> "$BACKUP_LOG" | gzip > "$BACKUP_FILE"
    else
        pg_dump \
            -h "$PGHOST" \
            -p "$PGPORT" \
            -U "$PGUSER" \
            -d "$PGDATABASE" \
            --format=plain \
            --verbose \
            --no-owner \
            --no-privileges \
            2>> "$BACKUP_LOG" > "$BACKUP_FILE"
    fi
    
    if [ $? -eq 0 ]; then
        local file_size=$(du -h "$BACKUP_FILE" | cut -f1)
        log "Backup created successfully: $BACKUP_FILE ($file_size)"
        
        # Make backup read-only
        chmod 0400 "$BACKUP_FILE"
        log "Backup file permissions set to read-only (0400)"
    else
        error_exit "pg_dump failed. Check log: $BACKUP_LOG" || return 1
    fi
}

verify_backup() {
    log "Verifying backup integrity..."
    
    if [ ! -f "$BACKUP_FILE" ]; then
        error_exit "Backup file not found: $BACKUP_FILE" || return 1
    fi
    
    # Check file size (must be > 1KB)
    local file_size=$(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE" 2>/dev/null)
    if [ "$file_size" -lt 1024 ]; then
        error_exit "Backup file is suspiciously small: ${file_size} bytes" || return 1
    fi
    
    # Try to list gzip contents
    if [ "$BACKUP_COMPRESSION" = "gzip" ]; then
        if ! gzip -t "$BACKUP_FILE" 2>/dev/null; then
            error_exit "Gzip integrity check failed for: $BACKUP_FILE" || return 1
        fi
        log "Gzip integrity verified"
    fi
    
    log "Backup verification passed"
}

rotate_backups() {
    log "Rotating old backups (retention: $BACKUP_RETENTION_DAYS days)..."
    
    local cutoff_timestamp=$(date -d "$BACKUP_RETENTION_DAYS days ago" +%s 2>/dev/null || \
                             date -v-${BACKUP_RETENTION_DAYS}d +%s 2>/dev/null || \
                             date -d "now - $BACKUP_RETENTION_DAYS days" +%s)
    
    local deleted_count=0
    
    for backup_file in "$BACKUP_PATH"/hunterops-db-backup-*.sql.gz; do
        if [ -f "$backup_file" ]; then
            local file_timestamp=$(stat -f%m "$backup_file" 2>/dev/null || stat -c%Y "$backup_file" 2>/dev/null)
            
            if [ "$file_timestamp" -lt "$cutoff_timestamp" ]; then
                rm -f "$backup_file"
                deleted_count=$((deleted_count + 1))
                log "Deleted old backup: $(basename "$backup_file")"
            fi
        fi
    done
    
    log "Rotation complete: Deleted $deleted_count old backup(s)"
}

create_manifest() {
    log "Creating backup manifest..."
    
    local manifest_file="${BACKUP_PATH}/BACKUP_MANIFEST.txt"
    {
        echo "HunterOps Database Backup Manifest"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "Latest Backups:"
        ls -lh "$BACKUP_PATH"/hunterops-db-backup-*.sql.gz 2>/dev/null | tail -10 || echo "No backups found"
        echo ""
        echo "Total Backup Size: $(du -sh "$BACKUP_PATH" | cut -f1)"
        echo ""
        echo "Retention Policy: $BACKUP_RETENTION_DAYS days"
    } > "$manifest_file"
    
    log "Manifest created: $manifest_file"
}

cleanup_old_logs() {
    log "Cleaning up old logs..."
    
    # Keep only last 10 backups' logs
    find "$BACKUP_PATH" -name "backup-*.log" -type f -mtime +10 -delete 2>/dev/null || true
    
    log "Log cleanup complete"
}

# ===================================================================
# Main Execution
# ===================================================================

main() {
    trap request_shutdown INT TERM

    if [ "${BACKUP_DAEMON_MODE}" != "true" ]; then
        prepare_cycle_files
        log "=========================================="
        log "HunterOps Database Backup Started (single run)"
        log "=========================================="
        check_prerequisites || return 1
        test_database_connection || return 1
        create_backup || return 1
        verify_backup || return 1
        rotate_backups
        create_manifest
        cleanup_old_logs
        log "=========================================="
        log "HunterOps Database Backup Completed Successfully"
        log "=========================================="
        return 0
    fi

    local skip_first_cycle=0
    if [ "${BACKUP_RUN_IMMEDIATELY}" != "true" ]; then
        skip_first_cycle=1
    fi
    log "backup_daemon_mode_enabled interval_seconds=${BACKUP_INTERVAL_SECONDS} run_immediately=${BACKUP_RUN_IMMEDIATELY}"
    while [ "${SHUTDOWN_REQUESTED}" -eq 0 ]; do
        if [ "${skip_first_cycle}" -eq 1 ]; then
            log "Initial backup skipped; first run will happen after the first sleep window."
            skip_first_cycle=0
        else
            prepare_cycle_files
            log "=========================================="
            log "HunterOps Database Backup Started"
            log "=========================================="
            if check_prerequisites && test_database_connection && create_backup && verify_backup; then
                rotate_backups
                create_manifest
                cleanup_old_logs
                log "=========================================="
                log "HunterOps Database Backup Completed Successfully"
                log "=========================================="
            else
                log "Backup cycle failed."
            fi
        fi

        if [ "${SHUTDOWN_REQUESTED}" -ne 0 ]; then
            break
        fi
        log "Sleeping ${BACKUP_INTERVAL_SECONDS}s until next backup cycle..."
        sleep "${BACKUP_INTERVAL_SECONDS}" &
        wait $! || true
    done

    log "Backup daemon stopped."
    return 0
}

main "$@"
exit $?
