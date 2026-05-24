"""SQLAlchemy ORM models for HunterOps-AI.

Comprehensive models for:
- Programs (Bug Bounty platforms)
- Targets (Scope domains/IPs)
- Findings (Vulnerabilities discovered)
- Evidence (Proof of vulnerabilities)
- Scan Sessions (Automation runs)
- Users (Platform users)

All models use UUID primary keys, async support, and include
type hints for IDE support and type checking.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSON, JSONB, UUID as PG_UUID

from .base import Base, TimestampMixin


class Program(Base, TimestampMixin):
    """Bug bounty program model.
    
    Represents a program on HackerOne, Intigriti, Bugcrowd, etc.
    """
    __tablename__ = 'programs'
    
    # Primary Key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    
    # Program Identity
    platform: Mapped[str] = mapped_column(String(50), nullable=False)  # h1, intigriti, bugcrowd
    handle: Mapped[str] = mapped_column(String(255), nullable=False)    # Program identifier
    title: Mapped[Optional[str]] = mapped_column(String(500))
    url: Mapped[Optional[str]] = mapped_column(String(2048))
    
    # Status & Policy
    status: Mapped[str] = mapped_column(String(50), default='active', nullable=False)
    policy_text: Mapped[Optional[str]] = mapped_column(Text())
    scope_text: Mapped[Optional[str]] = mapped_column(Text())
    
    # Financial
    max_payout: Mapped[Optional[int]] = mapped_column(Integer())
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    
    # Relationships
    targets: Mapped[List['Target']] = relationship(
        'Target',
        back_populates='program',
        cascade='all, delete-orphan',
        lazy='selectin',
    )
    findings: Mapped[List['Finding']] = relationship(
        'Finding',
        back_populates='program',
        cascade='all, delete-orphan',
        lazy='selectin',
    )
    scan_sessions: Mapped[List['ScanSession']] = relationship(
        'ScanSession',
        back_populates='program',
        cascade='all, delete-orphan',
        lazy='selectin',
    )
    
    def __repr__(self) -> str:
        return f"<Program(platform={self.platform}, handle={self.handle})>"


class Target(Base, TimestampMixin):
    """Scope target model (domain, IP, URL, wildcard).
    
    Represents a single target within a program's scope.
    """
    __tablename__ = 'targets'
    __table_args__ = (
        UniqueConstraint('program_id', 'value', name='uq_target_program_value'),
    )
    
    # Primary Key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    
    # Foreign Key
    program_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey('programs.id', ondelete='CASCADE'),
        nullable=False,
    )
    
    # Target Details
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)  # domain, ip, url, wildcard
    value: Mapped[str] = mapped_column(String(2048), nullable=False)      # domain.com, 192.168.1.0/24
    
    # Scope Status
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    discovered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Additional Metadata
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        'metadata',
        JSONB(),
        default=dict,
        nullable=False,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    
    # Relationships
    program: Mapped[Program] = relationship(
        'Program',
        back_populates='targets',
    )
    findings: Mapped[List['Finding']] = relationship(
        'Finding',
        back_populates='target',
        cascade='all, delete-orphan',
        lazy='selectin',
    )
    
    def __repr__(self) -> str:
        return f"<Target(value={self.value}, in_scope={self.in_scope})>"


class Finding(Base, TimestampMixin):
    """Vulnerability finding model.
    
    Represents a discovered vulnerability with details, status, and confidence.
    """
    __tablename__ = 'findings'
    
    # Primary Key (BigInt for large result sets)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign Keys
    program_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey('programs.id', ondelete='CASCADE'),
        nullable=False,
    )
    target_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey('targets.id', ondelete='CASCADE'),
        nullable=False,
    )
    
    # Finding Details
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text(), nullable=False)
    type: Mapped[str] = mapped_column(String(100), nullable=False)  # sql_injection, xss, etc
    
    # Risk Assessment
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: Mapped[Optional[float]] = mapped_column(Float())
    confidence: Mapped[float] = mapped_column(Float(), default=0.0, nullable=False)  # 0.0-1.0
    
    # Status & Source
    status: Mapped[str] = mapped_column(String(50), default='open', nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # nuclei, manual, katana, etc
    
    # Technical Details (POC, payload, etc)
    details: Mapped[Dict[str, Any]] = mapped_column(
        JSONB(),
        default=dict,
        nullable=False,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    
    # Relationships
    program: Mapped[Program] = relationship(
        'Program',
        back_populates='findings',
    )
    target: Mapped[Target] = relationship(
        'Target',
        back_populates='findings',
    )
    evidence: Mapped[List['Evidence']] = relationship(
        'Evidence',
        back_populates='finding',
        cascade='all, delete-orphan',
        lazy='selectin',
    )
    
    @hybrid_property
    def is_critical(self) -> bool:
        """Check if finding is critical severity."""
        return self.severity == 'CRITICAL'
    
    @hybrid_property
    def is_high_confidence(self) -> bool:
        """Check if finding has high AI confidence."""
        return self.confidence >= 0.8
    
    def __repr__(self) -> str:
        return f"<Finding(title={self.title}, severity={self.severity}, confidence={self.confidence})>"


class Evidence(Base, TimestampMixin):
    """Proof of vulnerability model.
    
    Stores references to evidence files (screenshots, HTTP responses, payloads).
    """
    __tablename__ = 'evidence'
    
    # Primary Key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    
    # Foreign Key
    finding_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('findings.id', ondelete='CASCADE'),
        nullable=False,
    )
    
    # Evidence File Details
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # screenshot, response, payload, log
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)    # Relative to /data/evidence
    file_size: Mapped[Optional[int]] = mapped_column(Integer())
    file_hash: Mapped[Optional[str]] = mapped_column(String(64))            # SHA256
    
    # Additional Metadata
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        'metadata',
        JSONB(),
        default=dict,
        nullable=False,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    
    # Relationships
    finding: Mapped[Finding] = relationship(
        'Finding',
        back_populates='evidence',
    )
    
    def __repr__(self) -> str:
        return f"<Evidence(type={self.evidence_type}, path={self.file_path})>"


class ScanSession(Base, TimestampMixin):
    """Scan automation session model.
    
    Tracks recon, exploitation, and verification scan runs.
    """
    __tablename__ = 'scan_sessions'
    
    # Primary Key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    
    # Foreign Key
    program_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey('programs.id', ondelete='CASCADE'),
        nullable=False,
    )
    
    # Session Details
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)     # recon, exploitation, verification
    status: Mapped[str] = mapped_column(String(50), default='running', nullable=False)
    
    # Statistics
    targets_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    targets_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_discovered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    
    # Timing
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Metadata (errors, tools used, etc)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        'metadata',
        JSONB(),
        default=dict,
        nullable=False,
    )
    
    # Relationships
    program: Mapped[Program] = relationship(
        'Program',
        back_populates='scan_sessions',
    )
    
    @hybrid_property
    def duration_seconds(self) -> Optional[int]:
        """Calculate scan duration in seconds."""
        if self.ended_at:
            return int((self.ended_at - self.started_at).total_seconds())
        return None
    
    @hybrid_property
    def success_rate(self) -> float:
        """Calculate target scan success rate."""
        if self.targets_total == 0:
            return 0.0
        return (self.targets_scanned / self.targets_total) * 100
    
    def __repr__(self) -> str:
        return f"<ScanSession(scan_type={self.scan_type}, status={self.status})>"


class User(Base, TimestampMixin):
    """Platform user model.
    
    Manages access control and user profiles.
    """
    __tablename__ = 'users'
    
    # Primary Key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    
    # User Identity
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    
    # Authorization
    role: Mapped[str] = mapped_column(String(50), default='user', nullable=False)  # admin, operator, viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    
    def __repr__(self) -> str:
        return f"<User(username={self.username}, role={self.role})>"


__all__ = [
    'Program',
    'Target',
    'Finding',
    'Evidence',
    'ScanSession',
    'User',
]
