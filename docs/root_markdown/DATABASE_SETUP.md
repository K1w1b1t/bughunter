## 🗄️ HunterOps-AI Database Setup Guide

### Quick Start

```bash
# 1. Install dependencies (if not already in requirements.txt)
pip install sqlalchemy[asyncio] alembic psycopg[binary]

# 2. Set DATABASE_URL environment variable
export DATABASE_URL_ASYNC="postgresql+asyncpg://hunterops:password@localhost:5432/hunterops"

# 3. Run migrations
alembic upgrade head

# 4. Verify tables created
psql -U hunterops -d hunterops -c "\dt"
```

---

## 📊 Database Architecture

### Schema Overview

```
programs (Bug Bounty Programs)
├── targets (Scope: domains, IPs, URLs)
├── findings (Discovered vulnerabilities)
│   └── evidence (Proof: screenshots, responses)
├── scan_sessions (Automation runs)
└── users (Access control)

audit_log (Compliance - created by pg-audit-init.sql)
```

### Key Design Decisions

1. **UUID Primary Keys**: Distributed system ready
2. **JSONB for Flexibility**: Store metadata without schema migration
3. **Partitioned audit_log**: Monthly partitions for performance
4. **Async SQLAlchemy 2.0**: High concurrency (connection pooling: 20+40)
5. **Relationships**: Cascade deletes for data integrity
6. **Indexes**: 26 indexes for query optimization

---

## 🔧 Alembic Migration Commands

### Running Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Apply single migration
alembic upgrade +1

# Rollback one migration
alembic downgrade -1

# Rollback all migrations
alembic downgrade base

# Show current revision
alembic current

# Show migration history
alembic history
```

### Creating New Migrations

```bash
# Auto-generate migration from model changes
alembic revision --autogenerate -m "Add new_column to findings"

# Manual migration (no auto-generation)
alembic revision -m "Custom data migration"

# Then edit the generated file in database/alembic/versions/
# And run: alembic upgrade head
```

### Offline Mode (Generate SQL without executing)

```bash
# Generate SQL without executing
alembic upgrade head --sql > migration.sql

# Review SQL before execution
cat migration.sql

# Execute on another machine
psql -U hunterops -d hunterops < migration.sql
```

---

## 🐍 Using SQLAlchemy Models in Code

### Session Management

```python
from hunterops.database import DatabaseManager, get_db
from hunterops.models import Program, Finding, Target
from sqlalchemy import select

# Initialize (in app startup)
await DatabaseManager.init()

# Get session (in async context)
async with DatabaseManager.get_session() as session:
    # Create
    program = Program(
        platform='h1',
        handle='acme-corp',
        title='ACME Corporation',
        status='active'
    )
    session.add(program)
    await session.commit()

# Query
async with DatabaseManager.get_session() as session:
    stmt = select(Program).where(Program.platform == 'h1')
    result = await session.execute(stmt)
    programs = result.scalars().all()

# Update
async with DatabaseManager.get_session() as session:
    program = await session.get(Program, program_id)
    program.status = 'paused'
    await session.commit()

# Delete
async with DatabaseManager.get_session() as session:
    program = await session.get(Program, program_id)
    await session.delete(program)
    await session.commit()
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from hunterops.database import get_db
from hunterops.models import Program

app = FastAPI()

@app.get("/programs")
async def list_programs(session: AsyncSession = Depends(get_db)):
    stmt = select(Program)
    result = await session.execute(stmt)
    return result.scalars().all()
```

### Complex Queries with Relationships

```python
# Query with joined relationships
from sqlalchemy.orm import selectinload
from sqlalchemy import and_

async with DatabaseManager.get_session() as session:
    stmt = (
        select(Program)
        .options(selectinload(Program.targets), selectinload(Program.findings))
        .where(and_(Program.platform == 'h1', Program.status == 'active'))
    )
    result = await session.execute(stmt)
    programs = result.unique().scalars().all()
    
    # Access relationships
    for program in programs:
        print(f"Program: {program.handle}")
        for target in program.targets:
            print(f"  Target: {target.value}")
        for finding in program.findings:
            print(f"  Finding: {finding.title} ({finding.severity})")
```

---

## 📈 Performance Optimization

### Connection Pooling

```python
# Already configured in DatabaseManager
# Pool size: 20 connections
# Max overflow: 40 connections
# Pre-ping: Validates connection before use

# Adjust via environment:
export DB_POOL_SIZE=20
export DB_MAX_OVERFLOW=40
```

### Query Optimization

```python
# ✅ DO: Use selectinload for relationships
stmt = select(Program).options(selectinload(Program.targets))
result = await session.execute(stmt)

# ❌ DON'T: Lazy load (causes N+1 queries)
programs = (await session.execute(select(Program))).scalars().all()
for program in programs:
    print(len(program.targets))  # Triggers query per program!
```

### Indexes

Pre-created indexes optimize these queries:
- `program_id + target_id` → Findings by program
- `severity + status` → Critical open findings
- `created_at DESC` → Recent activity
- `confidence` → High-confidence findings

---

## 🔍 Monitoring & Maintenance

### Check Database Size

```bash
# Connect to database
psql -U hunterops -d hunterops

# Table sizes
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

# Index sizes
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) as size
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;
```

### Vacuum & Analyze

```bash
# Clean up bloat and update statistics
psql -U hunterops -d hunterops -c "VACUUM ANALYZE;"

# Auto-analyze enabled in PostgreSQL config
```

### Monitor Active Connections

```bash
SELECT 
    datname,
    usename,
    application_name,
    state,
    query
FROM pg_stat_activity
WHERE datname = 'hunterops';
```

---

## 🛡️ Backup & Recovery

### Manual Backup

```bash
# Full backup
docker exec hunterops-db pg_dump \
    -U hunterops \
    -d hunterops \
    --format=plain \
    | gzip > backup-$(date +%Y%m%d).sql.gz

# Verify backup
gzip -t backup-*.sql.gz
```

### Restore from Backup

```bash
# Restore (database must exist)
gunzip -c backup-20260320.sql.gz | \
    docker exec -i hunterops-db psql \
        -U hunterops \
        -d hunterops

# Or via psql directly
psql -U hunterops -d hunterops < backup.sql
```

---

## 🧪 Testing

### In-Memory SQLite (for unit tests)

```python
# tests/conftest.py
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from hunterops.models import Base

@pytest_asyncio.fixture
async def db_session():
    # Use in-memory SQLite
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with SessionLocal() as session:
        yield session
    
    await engine.dispose()
```

### Test Data Fixtures

```python
@pytest_asyncio.fixture
async def sample_program(db_session: AsyncSession):
    program = Program(
        platform='h1',
        handle='test-program',
        title='Test Program',
        status='active'
    )
    db_session.add(program)
    await db_session.commit()
    return program
```

---

## 📋 Troubleshooting

### Migration Conflicts

```bash
# If a migration fails
# 1. Check current state
alembic current

# 2. Rollback problematic migration
alembic downgrade -1

# 3. Fix the migration file
nano database/alembic/versions/###_description.py

# 4. Try again
alembic upgrade head
```

### Connection Refused

```bash
# Ensure PostgreSQL is running
docker-compose -f docker-compose.prod.yml ps db

# Test connection from host
psql -h localhost -U hunterops -d hunterops -c "SELECT 1;"
```

### Foreign Key Constraint Errors

```bash
# Check foreign key constraints
SELECT 
    constraint_name,
    table_name,
    column_name
FROM information_schema.key_column_usage
WHERE table_name IN ('findings', 'targets', 'evidence');

# Temporarily disable for data import
ALTER TABLE findings DISABLE TRIGGER ALL;
-- Import data
ALTER TABLE findings ENABLE TRIGGER ALL;
```

---

## 📚 References

- SQLAlchemy 2.0 Docs: https://docs.sqlalchemy.org/20
- Alembic Docs: https://alembic.sqlalchemy.org/
- PostgreSQL Catalog: https://www.postgresql.org/docs/current/sql-commands.html
- Async SQLAlchemy: https://docs.sqlalchemy.org/14/orm/extensions/asyncio.html

---

## 🎯 Next Steps

After PASSO 2 (Database Schema):

1. ✅ Schema created (this phase)
2. ⏳ **PASSO 3**: LLM Integration (hunterops/llm_integration.py)
3. ⏳ **PASSO 4**: Scope Authorization
4. ⏳ **PASSO 5**: Rate Limiting
5. ⏳ **PASSO 6+**: Remaining phases

---

**Database Setup Complete!**
