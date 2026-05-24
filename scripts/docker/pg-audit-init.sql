-- ===================================================================
-- PostgreSQL Audit Log Table Initialization
-- ===================================================================
-- This script creates the audit_log table for compliance logging
-- All critical HunterOps actions are logged here
-- ===================================================================

-- Create audit_log table for compliance + troubleshooting
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    
    -- Timestamp
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Action metadata
    action_type VARCHAR(50) NOT NULL,  -- INSERT, UPDATE, DELETE, LOGIN, POLICY_CHANGE, etc
    table_name VARCHAR(255) NULL,
    
    -- User/session info
    user_name VARCHAR(255) NOT NULL,
    session_id UUID NULL,
    
    -- Target/resource info
    program_id VARCHAR(255) NULL,
    target_id VARCHAR(255) NULL,
    finding_id BIGINT NULL,
    
    -- Severity
    severity VARCHAR(20) DEFAULT 'INFO',  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    -- Details
    description TEXT NULL,
    source_ip VARCHAR(45) NULL,
    request_body JSONB NULL,
    
    -- Flags
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT NULL,
    
    -- Audit trail
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
) PARTITION BY RANGE (event_timestamp);

-- Create partitions by month for performance
-- January 2026
CREATE TABLE audit_log_202601 PARTITION OF audit_log
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

-- February 2026
CREATE TABLE audit_log_202602 PARTITION OF audit_log
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

-- March 2026
CREATE TABLE audit_log_202603 PARTITION OF audit_log
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

-- April 2026 (future partition)
CREATE TABLE audit_log_202604 PARTITION OF audit_log
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

-- May 2026 (future partition)
CREATE TABLE audit_log_202605 PARTITION OF audit_log
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

-- Create indexes for compliance querying
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action_type ON audit_log(action_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_name ON audit_log(user_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_program_id ON audit_log(program_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_target_id ON audit_log(target_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_severity ON audit_log(severity);
CREATE INDEX IF NOT EXISTS idx_audit_log_success ON audit_log(success);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_action ON audit_log(event_timestamp DESC, action_type);

-- Audit view for reporting (last 7 days)
CREATE OR REPLACE VIEW audit_log_recent AS
SELECT
    id,
    event_timestamp,
    action_type,
    table_name,
    user_name,
    program_id,
    target_id,
    severity,
    description,
    success,
    error_message
FROM audit_log
WHERE event_timestamp > CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY event_timestamp DESC;

-- Audit view for critical events (last 30 days)
CREATE OR REPLACE VIEW audit_log_critical AS
SELECT
    id,
    event_timestamp,
    action_type,
    user_name,
    program_id,
    target_id,
    severity,
    description,
    source_ip,
    error_message
FROM audit_log
WHERE severity IN ('CRITICAL', 'HIGH')
  AND event_timestamp > CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY event_timestamp DESC;

-- Grant permissions (restrict to audit role)
GRANT SELECT ON audit_log TO hunterops;
GRANT SELECT ON audit_log_recent TO hunterops;
GRANT SELECT ON audit_log_critical TO hunterops;

-- Insert initial audit entry
INSERT INTO audit_log (
    action_type,
    user_name,
    severity,
    description,
    success
) VALUES (
    'SYSTEM_INITIALIZATION',
    'postgres',
    'INFO',
    'Audit logging system initialized',
    TRUE
);

-- Verify audit table was created
SELECT COUNT(*) as audit_records FROM audit_log;
