"""
Submission Orchestrator for HunterOps-AI - PASSO 8

Main orchestrator for coordinating bug bounty platform submissions.

Features:
- Multi-platform routing
- Intelligent platform selection
- SLA tracking
- Status management
- Audit logging
- Rate limiting integration (PASSO 5)

Integration:
- ← PASSO 7: Report content (Markdown/JSON)
- → PASSO 5: Rate limiting (3 tokens/submission)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
import asyncio
import json
import logging
import uuid

from hunterops.platform_adapters import PlatformAdapterFactory

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class SubmissionStatus(str, Enum):
    """Submission status."""
    
    PENDING = "pending"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    INFORMATIONAL = "informational"
    NOT_APPLICABLE = "not_applicable"
    TRIAGED = "triaged"
    CLOSED = "closed"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SubmissionRequest:
    """Request to submit finding."""
    
    program_id: str
    report_content: str  # From PASSO 7
    title: str
    vulnerability_type: str
    cvss_score: float
    severity: str
    target_platform: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubmissionResult:
    """Result of submission."""
    
    submission_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    success: bool = False
    platform: Optional[str] = None
    platform_submission_id: Optional[str] = None
    status: SubmissionStatus = SubmissionStatus.PENDING
    message: str = ""
    error: Optional[str] = None
    response_time_ms: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict."""
        return {
            "submission_id": self.submission_id,
            "success": self.success,
            "platform": self.platform,
            "platform_submission_id": self.platform_submission_id,
            "status": self.status.value,
            "message": self.message,
            "error": self.error,
            "response_time_ms": self.response_time_ms,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AuditEvent:
    """Audit event log."""
    
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    submission_id: Optional[str] = None
    platform: Optional[str] = None
    status: SubmissionStatus = SubmissionStatus.PENDING
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# Submission Orchestrator
# ============================================================================

class SubmissionOrchestrator:
    """
    Main orchestrator for platform submissions.
    
    Workflow:
    1. Validate request and platform credentials
    2. Check rate limit (PASSO 5 - 3 tokens)
    3. Select platform (auto or specified)
    4. Format report for platform
    5. Submit via platform adapter
    6. Log audit event
    7. Track status
    """
    
    def __init__(
        self,
        rate_limiter: Optional[Any] = None,
        credentials_map: Optional[Dict[str, Dict[str, str]]] = None,
    ):
        """Initialize orchestrator."""
        self.rate_limiter = rate_limiter
        self.credentials_map = credentials_map or {}
        self.adapters: Dict[str, Any] = {}
        self.audit_log: List[AuditEvent] = []
        self.submission_cache: Dict[str, SubmissionResult] = {}
        
        # Initialize adapters
        self._init_adapters()
    
    def _init_adapters(self) -> None:
        """Initialize platform adapters."""
        for platform, creds in self.credentials_map.items():
            adapter = PlatformAdapterFactory.create(platform, creds)
            if adapter:
                self.adapters[platform.lower()] = adapter
    
    async def submit(self, request: SubmissionRequest) -> SubmissionResult:
        """
        Submit finding to platform.
        
        Args:
            request: SubmissionRequest
        
        Returns:
            SubmissionResult
        """
        result = SubmissionResult()
        
        try:
            # Step 1: Check rate limit (PASSO 5)
            if self.rate_limiter:
                allowed = await self._check_rate_limit(request)
                if not allowed:
                    result.success = False
                    result.message = "Rate limit exceeded"
                    result.status = SubmissionStatus.REJECTED
                    self._log_event(
                        event_type="rate_limited",
                        submission_id=result.submission_id,
                        status=SubmissionStatus.REJECTED,
                    )
                    return result
            
            # Step 2: Select platform
            platform = request.target_platform or self._select_platform()
            if not platform or platform not in self.adapters:
                result.success = False
                result.message = f"No adapter for platform: {platform}"
                self._log_event(
                    event_type="adapter_not_found",
                    submission_id=result.submission_id,
                    platform=platform,
                    status=SubmissionStatus.REJECTED,
                )
                return result
            
            # Step 3: Submit via adapter
            adapter = self.adapters[platform]
            submission_result = await adapter.submit_report(
                request.report_content,
                {
                    "finding_id": result.submission_id,
                    "title": request.title,
                    "cvss_score": request.cvss_score,
                    **request.metadata,
                },
            )
            
            # Step 4: Process result
            result.success = submission_result.get("success", False)
            result.platform = platform
            result.platform_submission_id = submission_result.get("submission_id")
            result.status = SubmissionStatus(submission_result.get("status", "pending"))
            result.message = submission_result.get("message", "Submitted")
            
            if not result.success:
                result.error = submission_result.get("error", "Unknown error")
            
            # Step 5: Log event
            self._log_event(
                event_type="submitted",
                submission_id=result.submission_id,
                platform=platform,
                status=result.status,
                message=result.message,
            )
            
            # Step 6: Cache result
            self.submission_cache[result.submission_id] = result
            
            return result
        
        except Exception as e:
            logger.error(f"Submission failed: {e}", exc_info=True)
            result.success = False
            result.error = str(e)
            result.status = SubmissionStatus.REJECTED
            self._log_event(
                event_type="error",
                submission_id=result.submission_id,
                status=SubmissionStatus.REJECTED,
                message=str(e),
            )
            return result
    
    async def _check_rate_limit(self, request: SubmissionRequest) -> bool:
        """Check rate limit (PASSO 5)."""
        try:
            # Submissions cost 3 tokens (more than reports)
            result = self.rate_limiter.check_limit(
                program_id=request.program_id,
                tokens=3,
            )
            return result.get('allowed', True)
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Continue on error (non-blocking)
    
    def _select_platform(self) -> Optional[str]:
        """Select best platform (auto-selection)."""
        preferred_order = ["hackerone", "intigriti", "bugcrowd"]
        
        for platform in preferred_order:
            if platform in self.adapters:
                return platform
        
        # Fallback to first available
        return list(self.adapters.keys())[0] if self.adapters else None
    
    async def check_status(
        self,
        platform: str,
        platform_submission_id: str,
    ) -> Optional[SubmissionStatus]:
        """Check submission status."""
        adapter = self.adapters.get(platform.lower())
        if not adapter:
            return None
        
        try:
            result = await adapter.check_status(platform_submission_id)
            status_str = result.get("status", "pending")
            return SubmissionStatus(status_str)
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            return None
    
    async def add_comment(
        self,
        platform: str,
        platform_submission_id: str,
        comment: str,
    ) -> bool:
        """Add comment to submission."""
        adapter = self.adapters.get(platform.lower())
        if not adapter:
            return False
        
        try:
            success = await adapter.add_comment(platform_submission_id, comment)
            if success:
                self._log_event(
                    event_type="comment_added",
                    platform=platform,
                    message=comment[:100],
                )
            return success
        except Exception as e:
            logger.error(f"Add comment failed: {e}")
            return False
    
    def _log_event(
        self,
        event_type: str,
        submission_id: Optional[str] = None,
        platform: Optional[str] = None,
        status: Optional[SubmissionStatus] = None,
        message: str = "",
    ) -> None:
        """Log audit event."""
        event = AuditEvent(
            event_type=event_type,
            submission_id=submission_id,
            platform=platform,
            status=status or SubmissionStatus.PENDING,
            message=message,
        )
        self.audit_log.append(event)
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get audit log."""
        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "submission_id": e.submission_id,
                "platform": e.platform,
                "status": e.status.value,
                "message": e.message,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in self.audit_log
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "platforms": len(self.adapters),
            "submissions": len(self.submission_cache),
            "audit_events": len(self.audit_log),
            "has_rate_limiter": self.rate_limiter is not None,
        }


__all__ = [
    "SubmissionOrchestrator",
    "SubmissionRequest",
    "SubmissionResult",
    "SubmissionStatus",
    "AuditEvent",
]
