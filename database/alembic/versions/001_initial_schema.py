"""Initial schema creation for HunterOps-AI.

This migration creates all core tables and indexes for the HunterOps-AI
platform including targets, programs, findings, evidence, and audit logging.

Revision ID: 001_initial_schema
Revises: None
Create Date: 2026-03-20 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade: Create initial schema."""
    
    # Enable necessary extensions
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "hstore"')
    
    # ===================================================================
    # TABLE: programs
    # ===================================================================
    op.create_table(
        'programs',
        sa.Column('id', sa.UUID(), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('platform', sa.String(50), nullable=False),  # 'h1', 'intigriti', 'bugcrowd'
        sa.Column('handle', sa.String(255), nullable=False),   # Program identifier
        sa.Column('title', sa.String(500), nullable=True),
        sa.Column('url', sa.String(2048), nullable=True),
        sa.Column('status', sa.String(50), default='active', nullable=False),  # active, paused, closed
        sa.Column('policy_text', sa.Text(), nullable=True),
        sa.Column('scope_text', sa.Text(), nullable=True),
        sa.Column('max_payout', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_programs_platform_handle', 'programs', ['platform', 'handle'], unique=True)
    op.create_index('idx_programs_status', 'programs', ['status'])
    op.create_index('idx_programs_created_at', 'programs', ['created_at'])
    
    # ===================================================================
    # TABLE: targets
    # ===================================================================
    op.create_table(
        'targets',
        sa.Column('id', sa.UUID(), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('program_id', sa.UUID(), nullable=False),
        sa.Column('target_type', sa.String(50), nullable=False),  # domain, ip, url, wildcard
        sa.Column('value', sa.String(2048), nullable=False),      # domain.com, 192.168.1.0/24
        sa.Column('in_scope', sa.Boolean(), default=True, nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', postgresql.JSONB(), default={}, nullable=False),  # additional info
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('program_id', 'value', name='uq_target_program_value'),
    )
    op.create_index('idx_targets_program_id', 'targets', ['program_id'])
    op.create_index('idx_targets_in_scope', 'targets', ['in_scope'])
    op.create_index('idx_targets_discovered_at', 'targets', ['discovered_at'])
    op.create_index('idx_targets_value', 'targets', ['value'])
    
    # ===================================================================
    # TABLE: findings
    # ===================================================================
    op.create_table(
        'findings',
        sa.Column('id', sa.BigInteger(), nullable=False),  # Could use serial or UUID
        sa.Column('program_id', sa.UUID(), nullable=False),
        sa.Column('target_id', sa.UUID(), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('type', sa.String(100), nullable=False),  # sql_injection, xss, auth_bypass, etc
        sa.Column('severity', sa.String(20), nullable=False),  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('status', sa.String(50), default='open', nullable=False),  # open, triaged, resolved, duplicate
        sa.Column('confidence', sa.Float(), default=0.0, nullable=False),  # 0.0 - 1.0 (AI confidence)
        sa.Column('source', sa.String(100), nullable=False),  # nuclei, manual, katana, etc
        sa.Column('details', postgresql.JSONB(), default={}, nullable=False),  # POC, payload, etc
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_findings_program_id', 'findings', ['program_id'])
    op.create_index('idx_findings_target_id', 'findings', ['target_id'])
    op.create_index('idx_findings_severity', 'findings', ['severity'])
    op.create_index('idx_findings_status', 'findings', ['status'])
    op.create_index('idx_findings_confidence', 'findings', ['confidence'])
    op.create_index('idx_findings_created_at', 'findings', ['created_at', 'severity'])
    
    # ===================================================================
    # TABLE: evidence
    # ===================================================================
    op.create_table(
        'evidence',
        sa.Column('id', sa.UUID(), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('finding_id', sa.BigInteger(), nullable=False),
        sa.Column('evidence_type', sa.String(50), nullable=False),  # screenshot, response, payload, log
        sa.Column('file_path', sa.String(2048), nullable=False),    # Relative path to /data/evidence
        sa.Column('file_size', sa.BigInteger(), nullable=True),
        sa.Column('file_hash', sa.String(64), nullable=True),       # SHA256
        sa.Column('metadata', postgresql.JSONB(), default={}, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_evidence_finding_id', 'evidence', ['finding_id'])
    op.create_index('idx_evidence_type', 'evidence', ['evidence_type'])
    op.create_index('idx_evidence_created_at', 'evidence', ['created_at'])
    
    # ===================================================================
    # TABLE: scan_sessions
    # ===================================================================
    op.create_table(
        'scan_sessions',
        sa.Column('id', sa.UUID(), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('program_id', sa.UUID(), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=False),     # recon, exploitation, verification
        sa.Column('status', sa.String(50), default='running', nullable=False),  # running, completed, failed
        sa.Column('targets_total', sa.Integer(), default=0, nullable=False),
        sa.Column('targets_scanned', sa.Integer(), default=0, nullable=False),
        sa.Column('findings_discovered', sa.Integer(), default=0, nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', postgresql.JSONB(), default={}, nullable=False),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_scan_sessions_program_id', 'scan_sessions', ['program_id'])
    op.create_index('idx_scan_sessions_status', 'scan_sessions', ['status'])
    op.create_index('idx_scan_sessions_started_at', 'scan_sessions', ['started_at'])
    
    # ===================================================================
    # TABLE: users
    # ===================================================================
    op.create_table(
        'users',
        sa.Column('id', sa.UUID(), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('username', sa.String(255), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('role', sa.String(50), default='user', nullable=False),  # admin, operator, viewer
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username', name='uq_users_username'),
        sa.UniqueConstraint('email', name='uq_users_email'),
    )
    op.create_index('idx_users_role', 'users', ['role'])
    op.create_index('idx_users_is_active', 'users', ['is_active'])
    
    # ===================================================================
    # TABLE: audit_log (Already created by pg-audit-init.sql)
    # Just ensure it exists with proper structure
    # ===================================================================
    # This table is already partitioned in the init scripts
    # We just ensure basic audit functionality here


def downgrade() -> None:
    """Downgrade: Drop all tables (reverse order)."""
    
    # Drop tables in reverse order (respect foreign keys)
    op.drop_table('evidence')
    op.drop_table('scan_sessions')
    op.drop_table('findings')
    op.drop_table('targets')
    op.drop_table('users')
    op.drop_table('programs')
    
    # Drop extensions
    op.execute('DROP EXTENSION IF EXISTS "uuid-ossp"')
    op.execute('DROP EXTENSION IF EXISTS "pgcrypto"')
    op.execute('DROP EXTENSION IF EXISTS "hstore"')
