-- ===================================================================
-- HunterOps-AI: PostgreSQL 16 Schema Definition (Pure SQL)
-- ===================================================================
-- This file is AUTO-GENERATED from Alembic migrations
-- DO NOT edit directly - use: alembic upgrade head
--
-- This is provided as reference documentation of the schema structure
-- ===================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "pgcrypto" SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "hstore" SCHEMA public;

-- ===================================================================
-- TABLE: programs
-- ===================================================================
-- Represents bug bounty programs on various platforms
-- ===================================================================

CREATE TABLE IF NOT EXISTS programs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Program identity
    platform VARCHAR(50) NOT NULL,     -- 'h1', 'intigriti', 'bugcrowd'
    handle VARCHAR(255) NOT NULL,       -- Program identifier
    title VARCHAR(500),
    url VARCHAR(2048),
    
    -- Status and governance
    status VARCHAR(50) NOT NULL DEFAULT 'active',  -- active, paused, closed
    policy_text TEXT,
    scope_text TEXT,
    
    -- Financial
    max_payout INTEGER,
    
    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT uq_program_platform_handle UNIQUE (platform, handle)
);

CREATE INDEX idx_programs_platform_handle ON programs(platform, handle);
CREATE INDEX idx_programs_status ON programs(status);
CREATE INDEX idx_programs_created_at ON programs(created_at);

-- ===================================================================
-- TABLE: targets
-- ===================================================================
-- In-scope targets for each program (domains, IPs, URLs, wildcards)
-- ===================================================================

CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Program association
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    
    -- Target details
    target_type VARCHAR(50) NOT NULL,  -- domain, ip, url, wildcard
    value VARCHAR(2048) NOT NULL,      -- domain.com, 192.168.1.0/24, https://api.example.com/*
    
    -- Scope status
    in_scope BOOLEAN NOT NULL DEFAULT TRUE,
    discovered_at TIMESTAMP WITH TIME ZONE,
    
    -- Additional metadata
    metadata JSONB NOT NULL DEFAULT '{}',
    
    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT uq_target_program_value UNIQUE (program_id, value)
);

CREATE INDEX idx_targets_program_id ON targets(program_id);
CREATE INDEX idx_targets_in_scope ON targets(in_scope);
CREATE INDEX idx_targets_discovered_at ON targets(discovered_at);
CREATE INDEX idx_targets_value ON targets(value);

-- ===================================================================
-- TABLE: findings
-- ===================================================================
-- Discovered vulnerabilities with details and confidence scores
-- ===================================================================

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    
    -- Program and target association
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    
    -- Vulnerability details
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    type VARCHAR(100) NOT NULL,  -- sql_injection, xss, auth_bypass, etc
    
    -- Risk assessment
    severity VARCHAR(20) NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score FLOAT,
    confidence FLOAT NOT NULL DEFAULT 0.0,  -- 0.0-1.0 (AI confidence)
    
    -- Status and provenance
    status VARCHAR(50) NOT NULL DEFAULT 'open',  -- open, triaged, resolved, duplicate
    source VARCHAR(100) NOT NULL,  -- nuclei, manual, katana, etc
    
    -- Technical details (POC, payloads, etc)
    details JSONB NOT NULL DEFAULT '{}',
    
    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_findings_program_id ON findings(program_id);
CREATE INDEX idx_findings_target_id ON findings(target_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_confidence ON findings(confidence);
CREATE INDEX idx_findings_created_at_severity ON findings(created_at DESC, severity);

-- ===================================================================
-- TABLE: evidence
-- ===================================================================
-- Proof of vulnerability (screenshots, HTTP responses, payloads)
-- ===================================================================

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Finding association
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- File details
    evidence_type VARCHAR(50) NOT NULL,  -- screenshot, response, payload, log
    file_path VARCHAR(2048) NOT NULL,    -- Relative to /data/evidence
    file_size BIGINT,
    file_hash VARCHAR(64),  -- SHA256
    
    -- Metadata
    metadata JSONB NOT NULL DEFAULT '{}',
    
    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_evidence_finding_id ON evidence(finding_id);
CREATE INDEX idx_evidence_type ON evidence(evidence_type);
CREATE INDEX idx_evidence_created_at ON evidence(created_at);

-- ===================================================================
-- TABLE: scan_sessions
-- ===================================================================
-- Tracks automation runs (recon, exploitation, verification)
-- ===================================================================

CREATE TABLE IF NOT EXISTS scan_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Program association
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    
    -- Session details
    scan_type VARCHAR(50) NOT NULL,  -- recon, exploitation, verification
    status VARCHAR(50) NOT NULL DEFAULT 'running',  -- running, completed, failed
    
    -- Statistics
    targets_total INTEGER NOT NULL DEFAULT 0,
    targets_scanned INTEGER NOT NULL DEFAULT 0,
    findings_discovered INTEGER NOT NULL DEFAULT 0,
    
    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,
    
    -- Metadata (errors, tools used, etc)
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_scan_sessions_program_id ON scan_sessions(program_id);
CREATE INDEX idx_scan_sessions_status ON scan_sessions(status);
CREATE INDEX idx_scan_sessions_started_at ON scan_sessions(started_at DESC);

-- ===================================================================
-- TABLE: users
-- ===================================================================
-- Platform users and access control
-- ===================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- User identity
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    
    -- Authorization
    role VARCHAR(50) NOT NULL DEFAULT 'user',  -- admin, operator, viewer
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Audit
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);

-- ===================================================================
-- INDEX SUMMARY
-- ===================================================================
-- Total indexes created: 26
-- Purpose: Optimize common queries for recon, findings, and reporting

-- ===================================================================
-- VIEWS FOR REPORTING
-- ===================================================================

-- Recent findings (last 7 days)
CREATE OR REPLACE VIEW v_findings_recent AS
SELECT
    f.id,
    p.platform,
    p.handle as program_handle,
    t.value as target,
    f.title,
    f.type,
    f.severity,
    f.cvss_score,
    f.confidence,
    f.status,
    f.source,
    f.created_at,
    COUNT(e.id) as evidence_count
FROM findings f
    JOIN programs p ON f.program_id = p.id
    JOIN targets t ON f.target_id = t.id
    LEFT JOIN evidence e ON f.id = e.finding_id
WHERE f.created_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
GROUP BY f.id, p.platform, p.handle, t.value, f.title, f.type, 
         f.severity, f.cvss_score, f.confidence, f.status, f.source, f.created_at
ORDER BY f.created_at DESC;

-- Critical findings (current)
CREATE OR REPLACE VIEW v_findings_critical AS
SELECT
    f.id,
    p.platform,
    p.handle as program_handle,
    t.value as target,
    f.title,
    f.type,
    f.severity,
    f.cvss_score,
    f.confidence,
    f.status,
    f.created_at
FROM findings f
    JOIN programs p ON f.program_id = p.id
    JOIN targets t ON f.target_id = t.id
WHERE f.severity IN ('CRITICAL', 'HIGH')
    AND f.status = 'open'
ORDER BY f.created_at DESC;

-- Program statistics
CREATE OR REPLACE VIEW v_program_statistics AS
SELECT
    p.id,
    p.platform,
    p.handle,
    COUNT(DISTINCT t.id) as targets_count,
    COUNT(DISTINCT f.id) as findings_count,
    SUM(CASE WHEN f.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN f.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    AVG(f.confidence) as avg_confidence,
    MAX(f.created_at) as last_finding_at
FROM programs p
    LEFT JOIN targets t ON p.id = t.program_id
    LEFT JOIN findings f ON p.id = f.program_id
WHERE p.status = 'active'
GROUP BY p.id, p.platform, p.handle;

-- Scan performance
CREATE OR REPLACE VIEW v_scan_performance AS
SELECT
    ss.id,
    p.platform,
    p.handle as program_handle,
    ss.scan_type,
    ss.status,
    ss.targets_total,
    ss.targets_scanned,
    ss.findings_discovered,
    ROUND((ss.targets_scanned::FLOAT / NULLIF(ss.targets_total, 0) * 100)::NUMERIC, 2) as scan_progress_pct,
    EXTRACT(EPOCH FROM (ss.ended_at - ss.started_at))::INT as duration_seconds,
    ss.started_at,
    ss.ended_at
FROM scan_sessions ss
    JOIN programs p ON ss.program_id = p.id
ORDER BY ss.started_at DESC;

-- ===================================================================
-- COMMENT DOCUMENTATION
-- ===================================================================

COMMENT ON TABLE programs IS 'Bug bounty programs from various platforms';
COMMENT ON TABLE targets IS 'Scope targets within programs (domains, IPs, etc)';
COMMENT ON TABLE findings IS 'Discovered vulnerabilities with AI confidence scoring';
COMMENT ON TABLE evidence IS 'Proof files for findings (screenshots, responses)';
COMMENT ON TABLE scan_sessions IS 'Automated scan run history and statistics';
COMMENT ON TABLE users IS 'Platform users and access control';

COMMENT ON COLUMN findings.confidence IS 'AI confidence score (0.0-1.0) calculated by LLM';
COMMENT ON COLUMN findings.severity IS 'Risk severity: CRITICAL, HIGH, MEDIUM, LOW, INFO';
COMMENT ON COLUMN targets.in_scope IS 'Target is within program scope (authorization)';

-- ===================================================================
-- MIGRATION COMPLETE
-- ===================================================================
-- Schema now ready for application use
-- Run: alembic upgrade head (to apply all migrations)
--
-- For manual rollback: alembic downgrade -1
-- ===================================================================
