-- ===================================================================
-- PostgreSQL Extensions Initialization Script
-- ===================================================================
-- This script runs automatically when the PostgreSQL container starts
-- for the first time (during docker-entrypoint.d processing)
-- ===================================================================

-- Enable essential extensions
CREATE EXTENSION IF NOT EXISTS pgaudit;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS uuid-ossp;
CREATE EXTENSION IF NOT EXISTS hstore;

-- Configure pgaudit for security compliance
-- Log all DML (INSERT, UPDATE, DELETE) and DDL operations
ALTER SYSTEM SET pgaudit.log = 'ALL';
ALTER SYSTEM SET pgaudit.log_client = on;
ALTER SYSTEM SET pgaudit.log_statement = on;
ALTER SYSTEM SET pgaudit.log_statement_once = off;

-- Select which roles trigger audit logging (empty = all)
ALTER SYSTEM SET pgaudit.role = '';

-- Recommended statement logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000; -- Log queries > 1 second

-- Connection logging
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;

-- Query planning
ALTER SYSTEM SET log_min_duration_statement = 0;

-- Revert changes requiring restart
-- SELECT pg_reload_conf();

-- Test audit is working
SELECT 1 FROM pgaudit;
