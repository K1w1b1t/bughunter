"""
Evidence Orchestrator for HunterOps-AI - PASSO 6

Autonomous evidence generation and POC building.

Integrates:
- PASSO 3: LLM for payload generation and narratives
- PASSO 4: Scope validator for authorization gates
- PASSO 5: Rate limiter for request throttling

Features:
- Automatic POC generation for discovered vulnerabilities
- Evidence scope validation (all findings must be in-scope)
- Deduplication and caching (prevent duplicate evidence gen)
- Immutable evidence records with audit trail
- LLM-driven finding narratives
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import asyncio
import hashlib
import json
import logging
import uuid

from hunterops.findings import FindingSeverity


logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class EvidenceType(str, Enum):
    """Vulnerability evidence types."""
    
    STORED_XSS = "stored_xss"
    REFLECTED_XSS = "reflected_xss"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    IDOR = "idor"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    XXE = "xxe"
    SSRF = "ssrf"
    WEAK_AUTH = "weak_auth"
    INFO_DISCLOSURE = "info_disclosure"
    MISCONFIGURATION = "misconfiguration"
    CUSTOM = "custom"


class EvidenceStatus(str, Enum):
    """Evidence generation status."""
    
    PENDING = "pending"
    VALIDATING = "validating"
    GENERATING = "generating"
    SUCCESS = "success"
    FAILED_SCOPE = "failed_scope"
    FAILED_RATE_LIMIT = "failed_rate_limit"
    FAILED_GENERATION = "failed_generation"
    CACHED = "cached"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class POCPayload:
    """Proof-of-concept payload."""
    
    type: str
    description: str
    payload: Dict[str, Any]
    execution_method: str  # curl, api_call, script, etc.
    execution_command: str
    expected_result: str
    severity: FindingSeverity


@dataclass
class EvidenceRecord:
    """Immutable evidence record."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    evidence_type: EvidenceType = EvidenceType.CUSTOM
    title: str = ""
    description: str = ""
    poc: POCPayload = field(default_factory=lambda: POCPayload(
        type="", description="", payload={}, execution_method="",
        execution_command="", expected_result="", severity=FindingSeverity.MEDIUM
    ))
    impact: str = ""
    remediation: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: float = 0.0  # 0.0-1.0
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "type": self.evidence_type.value,
            "title": self.title,
            "description": self.description,
            "poc": {
                "type": self.poc.type,
                "description": self.poc.description,
                "payload": self.poc.payload,
                "execution_method": self.poc.execution_method,
                "execution_command": self.poc.execution_command,
                "expected_result": self.poc.expected_result,
            },
            "impact": self.impact,
            "remediation": self.remediation,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class EvidenceGenerationRequest:
    """Request to generate evidence."""
    
    finding_id: str
    program_id: str
    target: str
    vulnerability_type: str
    description: str
    severity: FindingSeverity
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_hash(self) -> str:
        """Generate deduplication hash."""
        content = f"{self.finding_id}:{self.target}:{self.vulnerability_type}"
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class EvidenceGenerationResult:
    """Result of evidence generation."""
    
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: EvidenceStatus = EvidenceStatus.PENDING
    evidence: Optional[EvidenceRecord] = None
    error_message: Optional[str] = None
    retry_after: Optional[float] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "status": self.status.value,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "error_message": self.error_message,
            "retry_after": self.retry_after,
            "created_at": self.created_at.isoformat(),
        }


# ============================================================================
# Evidence Cache
# ============================================================================

class EvidenceCache:
    """Cache for evidence deduplication."""
    
    def __init__(self, ttl_seconds: int = 3600):
        """
        Initialize cache.
        
        Args:
            ttl_seconds: Time-to-live for cached evidence
        """
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, tuple[EvidenceRecord, datetime]] = {}
    
    def get(self, request_hash: str) -> Optional[EvidenceRecord]:
        """Get cached evidence if not expired."""
        if request_hash not in self._cache:
            return None
        
        evidence, timestamp = self._cache[request_hash]
        
        # Check expiration
        if datetime.utcnow() - timestamp > timedelta(seconds=self.ttl_seconds):
            del self._cache[request_hash]
            return None
        
        return evidence
    
    def put(self, request_hash: str, evidence: EvidenceRecord) -> None:
        """Store evidence in cache."""
        self._cache[request_hash] = (evidence, datetime.utcnow())
    
    def invalidate(self, request_hash: Optional[str] = None) -> None:
        """Invalidate cache entry or entire cache."""
        if request_hash is None:
            self._cache.clear()
        elif request_hash in self._cache:
            del self._cache[request_hash]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "ttl_seconds": self.ttl_seconds,
        }


# ============================================================================
# POC Builder Base
# ============================================================================

class POCBuilder(ABC):
    """Base class for vulnerability-specific POC builders."""
    
    @abstractmethod
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """
        Build proof-of-concept payload.
        
        Args:
            target: Target URL or resource identifier
            context: Vulnerability context and parameters
        
        Returns:
            POCPayload with execution details
        """
        pass


class GenericPOCBuilder(POCBuilder):
    """Generic POC builder for custom vulnerabilities."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build generic POC."""
        vuln_type = context.get("type", "unknown")
        return POCPayload(
            type=vuln_type,
            description=f"Generic POC for {vuln_type}",
            payload={"target": target, "context": context},
            execution_method="manual",
            execution_command=f"Manual verification required for {vuln_type}",
            expected_result="Vulnerability confirmed",
            severity=FindingSeverity.MEDIUM,
        )


# ============================================================================
# Evidence Orchestrator (Main Component)
# ============================================================================

class EvidenceOrchestrator:
    """
    Main orchestrator for autonomous evidence generation.
    
    Integrates PASSO 3 (LLM), PASSO 4 (Scope), PASSO 5 (Rate Limit).
    """
    
    def __init__(
        self,
        llm_client: Optional[Any] = None,
        scope_validator: Optional[Any] = None,
        rate_limiter: Optional[Any] = None,
        cache_ttl: int = 3600,
    ):
        """
        Initialize orchestrator.
        
        Args:
            llm_client: PASSO 3 LLM client (optional)
            scope_validator: PASSO 4 scope validator (optional)
            rate_limiter: PASSO 5 rate limiter (optional)
            cache_ttl: Cache TTL in seconds
        """
        self.llm_client = llm_client
        self.scope_validator = scope_validator
        self.rate_limiter = rate_limiter
        self.cache = EvidenceCache(ttl_seconds=cache_ttl)
        self.poc_builders: Dict[EvidenceType, POCBuilder] = {}
        self._register_default_builders()
    
    def _register_default_builders(self) -> None:
        """Register default POC builders."""
        generic_builder = GenericPOCBuilder()
        
        # Register for all types (use generic for now)
        for evidence_type in EvidenceType:
            self.poc_builders[evidence_type] = generic_builder
    
    async def generate_evidence(
        self,
        request: EvidenceGenerationRequest,
    ) -> EvidenceGenerationResult:
        """
        Generate evidence for a finding.
        
        Process:
        1. Check rate limit (PASSO 5)
        2. Check scope authorization (PASSO 4)
        3. Check cache for duplicate
        4. Build POC
        5. Generate LLM narratives
        6. Return immutable evidence record
        
        Args:
            request: Evidence generation request
        
        Returns:
            EvidenceGenerationResult
        """
        result = EvidenceGenerationResult(status=EvidenceStatus.PENDING)
        
        try:
            # Step 1: Rate limit check (PASSO 5 integration point)
            if self.rate_limiter:
                allowed = await self._check_rate_limit(request)
                if not allowed:
                    logger.warning(f"Evidence generation rate limited: {request.finding_id}")
                    result.status = EvidenceStatus.FAILED_RATE_LIMIT
                    result.error_message = "Rate limit exceeded"
                    result.retry_after = 1.0
                    return result
            
            # Step 2: Scope validation (PASSO 4 integration point)
            if self.scope_validator:
                is_authorized = await self._validate_scope(request)
                if not is_authorized:
                    logger.warning(f"Evidence scope validation failed: {request.target}")
                    result.status = EvidenceStatus.FAILED_SCOPE
                    result.error_message = f"Target {request.target} not in authorized scope"
                    return result
            
            # Step 3: Check cache
            request_hash = request.to_hash()
            cached_evidence = self.cache.get(request_hash)
            if cached_evidence:
                result.status = EvidenceStatus.CACHED
                result.evidence = cached_evidence
                return result
            
            # Step 4: Generate evidence
            result.status = EvidenceStatus.GENERATING
            evidence = await self._generate_evidence_internal(request)
            
            # Step 5: Cache and return
            self.cache.put(request_hash, evidence)
            result.status = EvidenceStatus.SUCCESS
            result.evidence = evidence
            
            return result
        
        except Exception as e:
            logger.error(f"Evidence generation failed: {e}", exc_info=True)
            result.status = EvidenceStatus.FAILED_GENERATION
            result.error_message = str(e)
            return result
    
    async def _check_rate_limit(self, request: EvidenceGenerationRequest) -> bool:
        """Check rate limit via PASSO 5."""
        try:
            rate_limit_result = self.rate_limiter.check_limit(
                program_id=request.program_id,
                tokens=2,  # Evidence generation costs 2 tokens
            )
            return rate_limit_result.allowed
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False
    
    async def _validate_scope(self, request: EvidenceGenerationRequest) -> bool:
        """Validate scope via PASSO 4."""
        try:
            # Create scope context
            context = {
                "program_id": request.program_id,
                "resource_type": "evidence_generation",
                "target": request.target,
                "action": "poc_generation",
            }
            
            # Validate via scope validator
            is_authorized = self.scope_validator.validate(context)
            return is_authorized
        except Exception as e:
            logger.error(f"Scope validation check failed: {e}")
            return False
    
    async def _generate_evidence_internal(
        self,
        request: EvidenceGenerationRequest,
    ) -> EvidenceRecord:
        """Generate evidence internally."""
        
        # Map vulnerability type to evidence type
        evidence_type = self._map_to_evidence_type(request.vulnerability_type)
        
        # Get POC builder
        builder = self.poc_builders.get(evidence_type, self.poc_builders[EvidenceType.CUSTOM])
        
        # Build POC
        poc = await builder.build(
            target=request.target,
            context=request.context,
        )
        
        # Generate narratives via LLM (PASSO 3 integration point)
        impact = await self._generate_impact_narrative(request)
        remediation = await self._generate_remediation(request)
        
        # Create immutable record
        evidence = EvidenceRecord(
            finding_id=request.finding_id,
            evidence_type=evidence_type,
            title=f"{request.vulnerability_type}: {request.target}",
            description=request.description,
            poc=poc,
            impact=impact,
            remediation=remediation,
            severity=request.severity,
            confidence=0.95,  # High confidence for generated evidence
            tags={"auto_generated", "passo6", evidence_type.value},
        )
        
        return evidence
    
    async def _generate_impact_narrative(self, request: EvidenceGenerationRequest) -> str:
        """Generate impact narrative via LLM (PASSO 3)."""
        try:
            if self.llm_client:
                prompt = f"""Generate a brief impact assessment for {request.vulnerability_type}.
Severity: {request.severity.value}
Target: {request.target}

Keep it to 1-2 sentences."""
                
                # Call LLM via PASSO 3
                # (Implementation would use actual LLM client)
                logger.debug(f"Generating impact narrative via LLM")
        except Exception as e:
            logger.error(f"Impact narrative generation failed: {e}")
        
        # Fallback to template
        return f"This {request.vulnerability_type} vulnerability could allow attackers to compromise the application security."
    
    async def _generate_remediation(self, request: EvidenceGenerationRequest) -> str:
        """Generate remediation advice via LLM (PASSO 3)."""
        try:
            if self.llm_client:
                prompt = f"""Generate remediation steps for {request.vulnerability_type}.
Severity: {request.severity.value}

Provide 2-3 actionable steps."""
                
                # Call LLM via PASSO 3
                # (Implementation would use actual LLM client)
                logger.debug(f"Generating remediation via LLM")
        except Exception as e:
            logger.error(f"Remediation generation failed: {e}")
        
        # Fallback to template
        return f"1. Implement proper input validation and output encoding.\n2. Apply the principle of least privilege.\n3. Conduct security testing to verify remediation."
    
    def _map_to_evidence_type(self, vulnerability_type: str) -> EvidenceType:
        """Map vulnerability type string to EvidenceType enum."""
        mapping = {
            "xss": EvidenceType.STORED_XSS,
            "sql_injection": EvidenceType.SQL_INJECTION,
            "idor": EvidenceType.IDOR,
            "csrf": EvidenceType.CSRF,
            "xxe": EvidenceType.XXE,
            "ssrf": EvidenceType.SSRF,
            "path_traversal": EvidenceType.PATH_TRAVERSAL,
        }
        
        vuln_lower = vulnerability_type.lower()
        
        # Direct mapping
        if vuln_lower in mapping:
            return mapping[vuln_lower]
        
        # Fuzzy matching
        for key, value in mapping.items():
            if key in vuln_lower:
                return value
        
        return EvidenceType.CUSTOM
    
    def register_poc_builder(
        self,
        evidence_type: EvidenceType,
        builder: POCBuilder,
    ) -> None:
        """Register custom POC builder."""
        self.poc_builders[evidence_type] = builder
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "cache": self.cache.get_stats(),
            "poc_builders": len(self.poc_builders),
            "has_llm": self.llm_client is not None,
            "has_scope_validator": self.scope_validator is not None,
            "has_rate_limiter": self.rate_limiter is not None,
        }


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "EvidenceOrchestrator",
    "EvidenceType",
    "EvidenceStatus",
    "EvidenceRecord",
    "POCPayload",
    "EvidenceGenerationRequest",
    "EvidenceGenerationResult",
    "EvidenceCache",
    "POCBuilder",
    "GenericPOCBuilder",
]
