# ===================================================================
# HunterOps-AI: Infrastructure & Volume Management Guide
# ===================================================================
# Environment: Oracle Cloud VPS (Ubuntu 22.04 LTS)
# Last Updated: 2026-03-20
# ===================================================================

## 📋 Quick Start

```bash
# 1. Clone repository
cd /opt/hunterops-ai
git clone <repo-url> .

# 2. Setup environment
cp .env.example .env
# Edit .env with your values

# 3. Generate secrets
POSTGRES_PASSWORD=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -base64 64)
sed -i "s/<GENERATE_STRONG_32_CHAR_PASSWORD>/$POSTGRES_PASSWORD/" .env
sed -i "s/<GENERATE_32_BYTE_HEX_KEY>/$ENCRYPTION_KEY/" .env
sed -i "s/<GENERATE_STRONG_SECRET_64_CHARS>/$JWT_SECRET/" .env

# 4. Create volume directories on host
mkdir -p /var/lib/hunterops/data/logs
mkdir -p /var/lib/hunterops/data/evidence
mkdir -p /var/lib/hunterops/data/findings
mkdir -p /var/lib/hunterops/data/reports
mkdir -p /var/lib/hunterops/backups
mkdir -p /var/lib/hunterops/postgres
mkdir -p /var/lib/hunterops/redis

# 5. Set proper permissions
sudo chown -R 999:999 /var/lib/hunterops/postgres
sudo chown -R 999:999 /var/lib/hunterops/redis
sudo chmod -R 750 /var/lib/hunterops

# 6. Start services
docker-compose -f docker-compose.prod.yml up -d

# 7. Verify
docker-compose -f docker-compose.prod.yml ps
docker logs hunterops-engine
```

---

## 🗂️ Volume Structure (Host: /var/lib/hunterops)

```
/var/lib/hunterops/
├── postgres/                    # PostgreSQL 16 persistent data
│   ├── base/                    # Database files
│   ├── pg_wal/                  # Write-ahead logs (crash recovery)
│   └── backup-manifests/        # Backup verification
│
├── redis/                       # Redis 7 cache data (optional persistence)
│   └── dump.rdb                 # Redis snapshot
│
├── data/
│   ├── logs/                    # Structured logging (JSONL)
│   │   ├── structured.jsonl     # All events (LLM-readable)
│   │   ├── findings.jsonl       # Vulnerability discoveries
│   │   ├── audit.jsonl          # Compliance audit trail
│   │   └── errors.jsonl         # Error tracking
│   │
│   ├── evidence/                # Raw findings + POCs
│   │   ├── screenshots/         # HTML/PNG evidence
│   │   ├── responses/           # HTTP responses
│   │   └── payloads/            # Exploitation payloads
│   │
│   ├── findings/                # Processed vulnerability data
│   │   ├── cvss-scores.json     # Risk assessment
│   │   └── timeline.jsonl       # Event history
│   │
│   └── reports/                 # Generated reports
│       ├── html/                # Web-viewable reports
│       ├── pdf/                 # Stakeholder reports
│       └── json/                # Machine-readable reports
│
└── backups/                     # PostgreSQL daily backups
    ├── hunterops-db-backup-20260320-000000.sql.gz
    ├── hunterops-db-backup-20260319-000000.sql.gz
    └── BACKUP_MANIFEST.txt      # Backup inventory
```

---

## 💾 PostgreSQL Volume Management

### How It Works

- **pgdata**: Contains all database files (tables, indexes, sequences)
- **pgwal**: Write-ahead logs for crash recovery and point-in-time restore
- **Daily backups**: Full dumps via `pg_dump` (automatic via `db-backup` service)

### Backup Strategy

**Frequency**: Daily at 00:00 UTC
**Retention**: 30 days (configurable via `BACKUP_RETENTION_DAYS`)
**Size**: ~50-100 MB per day (with gzip compression)
**Location**: `/var/lib/hunterops/backups/`

### Manual Backup (On-Demand)

```bash
# Create ad-hoc backup
docker exec hunterops-db-backup /backup-entrypoint.sh

# Or directly via pg_dump
docker exec hunterops-db pg_dump -U hunterops -d hunterops | \
  gzip > /var/lib/hunterops/backups/manual-backup-$(date +%Y%m%d-%H%M%S).sql.gz

# Verify backup integrity
gzip -t /var/lib/hunterops/backups/*.sql.gz
```

### Restore from Backup

```bash
# List available backups
ls -lh /var/lib/hunterops/backups/

# Restore (requires database to be running)
docker exec -i hunterops-db psql -U hunterops -d hunterops < <(gunzip -c backup.sql.gz)

# Or via psql directly
gunzip -c backup.sql.gz | docker exec -i hunterops-db psql -U hunterops -d hunterops
```

### Monitor Database Size

```bash
# Inside container
docker exec hunterops-db psql -U hunterops -d hunterops -c "
  SELECT 
    schemaname,
    SUM(pg_total_relation_size(tableoid)) / 1024 / 1024 as size_mb
  FROM pg_tables
  GROUP BY schemaname
  ORDER BY size_mb DESC;
"

# From host
du -sh /var/lib/hunterops/postgres/base
```

### Enable Audit Logging in PostgreSQL

```bash
# Connect to database
docker exec -it hunterops-db psql -U hunterops -d hunterops

# Verify pgaudit is enabled
SELECT * FROM pg_extension WHERE extname = 'pgaudit';

# View recent audit logs
SELECT * FROM audit_log_critical LIMIT 20;

# Export audit logs
docker exec hunterops-db pg_dump -U hunterops -d hunterops \
  -t audit_log | gzip > audit-export-$(date +%Y%m%d).sql.gz
```

---

## 📊 Logging Volume Management (/var/lib/hunterops/data/logs)

### File Rotation Policy

- **Max file size**: 100 MB (per `.env.example` LOG_ROTATION_SIZE_MB)
- **Retention**: 90 days (per `.env.example` LOG_RETENTION_DAYS)
- **Automatic rotation**: Handled by Python logging module

### JSONL Log Structure

Each line is a complete JSON object:

```json
{
  "timestamp": "2026-03-20T10:30:45.123Z",
  "level": "INFO",
  "logger": "hunterops.engine",
  "message": "Recon phase completed",
  "program_id": "h1:acme-corp",
  "targets_scanned": 150,
  "vulnerabilities_found": 3,
  "trace_id": "abc123def456"
}
```

### Analyzing Logs

```bash
# Stream real-time logs (pretty-printed)
tail -f /var/lib/hunterops/data/logs/structured.jsonl | \
  jq '.'

# Filter by severity
grep '"level":"ERROR"' /var/lib/hunterops/data/logs/structured.jsonl | \
  jq '.message, .error'

# Count events per hour
jq -r '.timestamp' /var/lib/hunterops/data/logs/structured.jsonl | \
  cut -d'T' -f1,2 | cut -d':' -f1-2 | sort | uniq -c

# Export to CSV (for reporting)
jq -r '[.timestamp, .level, .logger, .message] | @csv' \
  /var/lib/hunterops/data/logs/structured.jsonl > logs.csv
```

### Compress Old Logs

```bash
# Compress logs older than 30 days
find /var/lib/hunterops/data/logs -name "*.jsonl" -type f -mtime +30 -exec gzip {} \;

# Archive to separate location
tar czf /backups/logs-archive-$(date +%Y%m).tar.gz \
  /var/lib/hunterops/data/logs/*.jsonl.gz

# Remove archived logs
find /var/lib/hunterops/data/logs -name "*.jsonl.gz" -mtime +60 -delete
```

---

## 🎯 Evidence Volume Management (/var/lib/hunterops/data/evidence)

### Subdirectories

- **screenshots/**: HTTP response screenshots (HTML/PNG)
- **responses/**: Raw HTTP response bodies
- **payloads/**: Exploitation payloads + results

### Space Optimization

```bash
# Check usage
du -sh /var/lib/hunterops/data/evidence

# Delete evidence older than 90 days
find /var/lib/hunterops/data/evidence -type f -mtime +90 -delete

# Compress PDFs/large files
for f in /var/lib/hunterops/data/evidence/*.pdf; do
  gzip "$f"
done
```

---

## 🔒 Security & Permissions

### Volume Ownership

```bash
# PostgreSQL (UID 999, GID 99 inside container)
sudo chown 999:999 /var/lib/hunterops/postgres

# Redis (UID 999, GID 999 inside container)
sudo chown 999:999 /var/lib/hunterops/redis

# Application data (UID 1000, GID 1000 inside container)
sudo chown 1000:1000 /var/lib/hunterops/data

# Backups (read-only after creation)
sudo chmod 0400 /var/lib/hunterops/backups/*.sql.gz
```

### Backup Encryption (Optional)

```bash
# Encrypt backup with GPG
docker exec hunterops-db pg_dump -U hunterops -d hunterops | \
  gzip | gpg --encrypt --recipient your@email.com > backup.sql.gz.gpg

# Decrypt later
gpg --decrypt backup.sql.gz.gpg | gunzip | \
  docker exec -i hunterops-db psql -U hunterops -d hunterops
```

---

## 📈 Monitoring & Health Checks

### Container Health Status

```bash
# Check all container health
docker ps --format "table {{.Names}}\t{{.Status}}"

# View health check logs
docker logs --follow hunterops-db

# Custom health check
docker exec hunterops-db pg_isready -U hunterops
docker exec hunterops-redis redis-cli ping
```

### Disk Space Alerts

```bash
# Monitor disk usage (on cron hourly)
#!/bin/bash
USAGE=$(df /var/lib/hunterops | awk 'NR==2 {print $5}' | cut -d'%' -f1)
if [ $USAGE -gt 80 ]; then
  # Send alert
  curl -X POST $DISCORD_WEBHOOK \
    -H "Content-Type: application/json" \
    -d "{\"content\":\"🚨 Disk usage at ${USAGE}%\"}"
fi
```

---

## 🚀 Deployment Checklist

- [ ] Create all volume directories
- [ ] Set correct ownership and permissions
- [ ] Generate SSL certificates (if HTTPS needed)
- [ ] Generate strong passwords and store in HashiCorp Vault
- [ ] Configure `.env` with all secrets
- [ ] Run `docker-compose config` to validate
- [ ] Start services: `docker-compose up -d`
- [ ] Verify all containers are healthy
- [ ] Test PostgreSQL connection
- [ ] Test Redis connection
- [ ] Create first backup manually
- [ ] Setup backup rotation cron job
- [ ] Configure monitoring/alerting
- [ ] Document any customizations

---

## 📞 Troubleshooting

### PostgreSQL Out of Disk Space

```bash
# Check bloat
docker exec hunterops-db psql -U hunterops -d hunterops -c "
  SELECT schemaname, tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
  FROM pg_tables
  ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
  LIMIT 20;"

# Vacuum and analyze (remove bloat)
docker exec hunterops-db psql -U hunterops -d hunterops -c "VACUUM ANALYZE;"
```

### Redis Memory Full

```bash
# Check memory usage
docker exec hunterops-redis redis-cli INFO memory

# Clear non-essential cache
docker exec hunterops-redis redis-cli FLUSHDB

# Adjust MAXMEMORY policy
docker exec hunterops-redis redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

### Backup Failures

```bash
# Check backup logs
tail -f /var/lib/hunterops/backups/backup-*.log

# Verify database connectivity
docker exec hunterops-db pg_isready -U hunterops -d hunterops -v

# Force backup now
docker-compose -f docker-compose.prod.yml exec db-backup /backup-entrypoint.sh
```

### Container Won't Start

```bash
# Check logs
docker logs hunterops-engine

# Validate compose file
docker-compose -f docker-compose.prod.yml config

# Check resource limits
docker stats

# Rebuild if needed
docker-compose -f docker-compose.prod.yml up -d --build
```

---

## 📚 References

- Docker Compose v2 Spec: https://github.com/compose-spec/compose-spec
- PostgreSQL Backup Guide: https://www.postgresql.org/docs/current/backup.html
- Structured Logging: https://structlog.readthedocs.io/
- JSONL Format: https://jsonlines.org/

---

**Last Updated**: 2026-03-20  
**Maintainer**: HunterOps-AI DevOps Team
