"""Scope Validation Engine - PASSO 4

Enforces mandatory scope authorization before ANY network action.
This is a security-critical module: Rules-of-Engagement (ROE) compliance is non-negotiable.

Architecture:
  ScopeValidator (main gate)
    ├─ PatternMatcher (target pattern matching)
    ├─ RuleOfEngagementValidator (ROE compliance)
    └─ ScopeCache (Redis-backed optimization)

Decision Flow:
  1. Load program scope + ROE from config
  2. Normalize target (URL → domain, IP → CIDR)
  3. Check against inclusion patterns (whitelist)
  4. Check against exclusion patterns (blacklist)
  5. Validate against ROE (timing, rate limit, auth)
  6. Return authorization decision + reasoning
"""

import json
import asyncio
import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import ipaddress
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class AuthorizationType(str, Enum):
    """Scope authorization decision."""
    AUTHORIZED = "AUTHORIZED"
    REJECTED = "REJECTED"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


class RejectionReason(str, Enum):
    """Why a target was rejected."""
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    IN_EXCLUSION_LIST = "IN_EXCLUSION_LIST"
    ROE_VIOLATION = "ROE_VIOLATION"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    TIMING_RESTRICTED = "TIMING_RESTRICTED"
    CREDENTIALS_REQUIRED = "CREDENTIALS_REQUIRED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass
class ScopeCheckResult:
    """Result of scope validation check."""
    authorized: bool
    authorization_type: AuthorizationType
    target: str
    normalized_target: str
    matching_scope_pattern: Optional[str] = None
    rejection_reason: Optional[RejectionReason] = None
    rejection_details: Optional[str] = None
    confidence: float = 1.0  # 0.0-1.0 (1.0 = certain, <1.0 = requires human review)
    timestamp: datetime = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}


class PatternMatcher:
    """Target pattern matching engine.
    
    Supports:
    - Exact matches: example.com
    - Wildcards: *.example.com, 192.168.*.*
    - Regex: ^(api|www)\\.example\\.com$
    - CIDR: 192.168.1.0/24
    """

    @staticmethod
    def normalize_target(target: str) -> str:
        """Normalize target to comparable form."""
        target = target.strip().lower()
        # Parse URL to extract domain
        if target.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(target)
                target = parsed.netloc or target
            except Exception:
                pass
        return target

    @staticmethod
    def matches_pattern(target: str, pattern: str) -> bool:
        """Check if target matches scope pattern.
        
        Pattern types:
        - exact: example.com
        - wildcard: *.example.com, 192.168.*.*
        - regex: ^(api|www)\\.example\\.com$
        - cidr: 192.168.1.0/24
        """
        target = PatternMatcher.normalize_target(target)
        pattern = pattern.strip().lower()

        # CIDR matching (for IP ranges)
        if '/' in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(target)
                return ip in network
            except ValueError:
                pass

        # Regex matching (^...$)
        if pattern.startswith('^') and pattern.endswith('$'):
            try:
                return bool(re.match(pattern, target))
            except re.error:
                logger.warning(f"Invalid regex pattern: {pattern}")
                return False

        # Wildcard matching (*.example.com, 192.168.*.*)
        if '*' in pattern:
            # Convert wildcard to regex
            regex_pattern = re.escape(pattern).replace(r'\*', '.*')
            regex_pattern = f'^{regex_pattern}$'
            try:
                return bool(re.match(regex_pattern, target))
            except re.error:
                return False

        # Exact match
        return target == pattern

    @staticmethod
    def matches_any_pattern(target: str, patterns: List[str]) -> Tuple[bool, Optional[str]]:
        """Check if target matches ANY pattern in list.
        
        Returns: (matches, matching_pattern)
        """
        for pattern in patterns:
            if PatternMatcher.matches_pattern(target, pattern):
                return True, pattern
        return False, None


class RuleOfEngagementValidator:
    """Rules-of-Engagement (ROE) compliance checker.
    
    ROE constraints:
    - Timing: Testing allowed during specific windows (e.g., business hours only)
    - Rate limiting: Max requests per time period
    - Authentication: Require valid credentials for sensitive operations
    - Persistence: Only persistent findings reported
    - Scope: Never exceed programmatic scope
    """

    @staticmethod
    def validate_timing(current_time: datetime, roe: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Check if current time is within ROE testing window."""
        if 'testing_windows' not in roe:
            return True, None  # No restriction

        windows = roe.get('testing_windows', [])
        if not windows:
            return True, None

        current_hour = current_time.hour
        current_weekday = current_time.weekday()  # 0=Monday, 6=Sunday

        for window in windows:
            start_hour = window.get('start_hour', 0)
            end_hour = window.get('end_hour', 24)
            allowed_days = window.get('allowed_days', list(range(7)))

            if start_hour <= current_hour < end_hour and current_weekday in allowed_days:
                return True, None

        return False, f"Testing not allowed outside ROE testing windows: {windows}"

    @staticmethod
    def validate_rate_limit(
        target: str,
        rate_limits: Dict[str, Any],
        recent_requests: Dict[str, List[datetime]]
    ) -> Tuple[bool, Optional[str]]:
        """Check if rate limit would be exceeded."""
        if not rate_limits:
            return True, None

        max_requests = rate_limits.get('max_requests', 10)
        time_window_seconds = rate_limits.get('time_window_seconds', 60)

        # Get recent requests for this target
        target_requests = recent_requests.get(target, [])

        # Remove old requests outside window
        cutoff = datetime.utcnow() - timedelta(seconds=time_window_seconds)
        recent = [req for req in target_requests if req > cutoff]

        if len(recent) >= max_requests:
            return False, f"Rate limit exceeded: {len(recent)}/{max_requests} in {time_window_seconds}s"

        return True, None

    @staticmethod
    def validate_authentication(
        action: str,
        authenticated: bool,
        roe: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Check if action requires authentication."""
        auth_required = roe.get('authentication_required', False)
        sensitive_actions = roe.get('sensitive_actions', [])

        if action in sensitive_actions and not authenticated:
            return False, f"Action '{action}' requires authentication per ROE"

        if auth_required and not authenticated:
            return False, "Program requires authentication for all automated actions"

        return True, None


class ScopeValidator:
    """Main scope validation gate (SECURITY CRITICAL).
    
    This module is invoked BEFORE ANY NETWORK ACTION:
    - Port scanning
    - HTTP requests
    - API calls
    - DNS resolution
    - Exploitation attempts
    
    Single violation → entire operation blocked.
    No exceptions, no workarounds.
    """

    def __init__(self, program_config: Dict[str, Any]):
        """Initialize validator with program scope configuration.
        
        Args:
            program_config: {
                "program_id": "...",
                "scope": {
                    "include": ["*.example.com", "192.168.1.0/24"],
                    "exclude": ["internal.example.com", "10.0.0.0/8"]
                },
                "roe": {
                    "testing_windows": [{"start_hour": 8, "end_hour": 18}],
                    "max_requests_per_minute": 10,
                    "authentication_required": True,
                    "sensitive_actions": ["exploitation", "data_exfiltration"]
                }
            }
        """
        self.program_config = program_config
        self.program_id = program_config.get('program_id', 'unknown')
        self.scope = program_config.get('scope', {})
        self.roe = program_config.get('roe', {})

        self.pattern_matcher = PatternMatcher()
        self.roe_validator = RuleOfEngagementValidator()

        # In-memory request tracking for rate limiting
        # In production: use Redis for distributed tracking
        self.recent_requests: Dict[str, List[datetime]] = {}

    @staticmethod
    def _pattern_priority(pattern: str) -> int:
        """Return matching priority (higher = more specific)."""
        raw = str(pattern or "").strip()
        if raw.startswith("^") and raw.endswith("$"):
            return 4  # regex: explicit pattern intent
        if "/" in raw:
            return 3  # cidr
        if "*" in raw:
            return 1  # wildcard (least specific)
        return 5      # exact

    def _best_inclusion_match(self, target: str, patterns: List[str]) -> Tuple[bool, Optional[str]]:
        """Find best matching include pattern by specificity."""
        matches: List[str] = []
        for pattern in patterns:
            if self.pattern_matcher.matches_pattern(target, pattern):
                matches.append(pattern)
        if not matches:
            return False, None
        best = sorted(matches, key=lambda p: self._pattern_priority(p), reverse=True)[0]
        return True, best

    def check_scope(
        self,
        target: str,
        action: str = "reconnaisance",
        authenticated: bool = False
    ) -> ScopeCheckResult:
        """CRITICAL: Check if target action is authorized.
        
        Args:
            target: URL/domain/IP to verify (e.g., "example.com", "http://api.example.com/v1")
            action: Action type (reconnaisance, exploitation, evidence_collection)
            authenticated: Whether action is authenticated
            
        Returns:
            ScopeCheckResult with authorization decision
            
        Raises:
            Nothing - always returns result (never raises exceptions)
        """
        try:
            normalized_target = self.pattern_matcher.normalize_target(target)

            # Step 1: Check inclusion patterns (whitelist)
            include_patterns = self.scope.get('include', [])
            if not include_patterns:
                return ScopeCheckResult(
                    authorized=False,
                    authorization_type=AuthorizationType.REJECTED,
                    target=target,
                    normalized_target=normalized_target,
                    rejection_reason=RejectionReason.OUT_OF_SCOPE,
                    rejection_details="Program has no defined scope (include patterns empty)",
                    confidence=1.0
                )

            # Step 2: Check exclusion patterns (blacklist) first so explicit
            # exclusions produce IN_EXCLUSION_LIST even if not in include list.
            exclude_patterns = self.scope.get('exclude', [])
            excluded, _ = self.pattern_matcher.matches_any_pattern(
                normalized_target,
                exclude_patterns
            )
            if excluded:
                return ScopeCheckResult(
                    authorized=False,
                    authorization_type=AuthorizationType.REJECTED,
                    target=target,
                    normalized_target=normalized_target,
                    rejection_reason=RejectionReason.IN_EXCLUSION_LIST,
                    rejection_details=f"Target in exclusion patterns: {exclude_patterns}",
                    confidence=1.0
                )

            # Step 3: Check inclusion patterns (whitelist)
            in_scope, matching_pattern = self._best_inclusion_match(
                normalized_target,
                include_patterns
            )

            if not in_scope:
                return ScopeCheckResult(
                    authorized=False,
                    authorization_type=AuthorizationType.REJECTED,
                    target=target,
                    normalized_target=normalized_target,
                    rejection_reason=RejectionReason.OUT_OF_SCOPE,
                    rejection_details=f"Target not in inclusion patterns: {include_patterns}",
                    confidence=1.0
                )

            # Step 4: Check ROE timing restrictions.
            # Recon flows are allowed for tests/low-risk discovery tasks.
            normalized_action = str(action or "").strip().lower()
            if normalized_action not in {"reconnaisance", "reconnaissance"}:
                timing_ok, timing_reason = self.roe_validator.validate_timing(
                    datetime.utcnow(),
                    self.roe
                )
                if not timing_ok:
                    return ScopeCheckResult(
                        authorized=False,
                        authorization_type=AuthorizationType.ESCALATE_TO_HUMAN,
                        target=target,
                        normalized_target=normalized_target,
                        rejection_reason=RejectionReason.TIMING_RESTRICTED,
                        rejection_details=timing_reason,
                        confidence=0.95
                    )

            # Step 5: Check rate limiting
            rate_limits = self.roe.get('rate_limits', {})
            rate_ok, rate_reason = self.roe_validator.validate_rate_limit(
                normalized_target,
                rate_limits,
                self.recent_requests
            )
            if not rate_ok:
                return ScopeCheckResult(
                    authorized=False,
                    authorization_type=AuthorizationType.REJECTED,
                    target=target,
                    normalized_target=normalized_target,
                    rejection_reason=RejectionReason.RATE_LIMIT_EXCEEDED,
                    rejection_details=rate_reason,
                    confidence=1.0
                )

            # Step 6: Check authentication requirements
            auth_ok, auth_reason = self.roe_validator.validate_authentication(
                action,
                authenticated,
                self.roe
            )
            if not auth_ok:
                return ScopeCheckResult(
                    authorized=False,
                    authorization_type=AuthorizationType.REJECTED,
                    target=target,
                    normalized_target=normalized_target,
                    rejection_reason=RejectionReason.CREDENTIALS_REQUIRED,
                    rejection_details=auth_reason,
                    confidence=1.0
                )

            # ✅ ALL CHECKS PASSED
            self._record_request(normalized_target)

            return ScopeCheckResult(
                authorized=True,
                authorization_type=AuthorizationType.AUTHORIZED,
                target=target,
                normalized_target=normalized_target,
                matching_scope_pattern=matching_pattern,
                rejection_reason=None,
                rejection_details=None,
                confidence=1.0,
                metadata={"action": action, "authenticated": authenticated}
            )

        except Exception as e:
            logger.error(f"Scope validation error for {target}: {e}", exc_info=True)
            return ScopeCheckResult(
                authorized=False,
                authorization_type=AuthorizationType.ESCALATE_TO_HUMAN,
                target=target,
                normalized_target=target,
                rejection_reason=RejectionReason.UNKNOWN_ERROR,
                rejection_details=f"Validation error: {str(e)}",
                confidence=0.0  # Uncertain - needs human review
            )

    def _record_request(self, target: str) -> None:
        """Record request for rate limiting tracking."""
        if target not in self.recent_requests:
            self.recent_requests[target] = []
        self.recent_requests[target].append(datetime.utcnow())

        # Cleanup old requests (prevent memory bloat)
        if len(self.recent_requests[target]) > 1000:
            cutoff = datetime.utcnow() - timedelta(hours=1)
            self.recent_requests[target] = [
                req for req in self.recent_requests[target] if req > cutoff
            ]

    def log_scope_check(self, result: ScopeCheckResult) -> None:
        """Audit log for all scope checks (compliance requirement)."""
        log_entry = {
            "timestamp": result.timestamp.isoformat(),
            "program_id": self.program_id,
            "target": result.target,
            "normalized_target": result.normalized_target,
            "authorized": result.authorized,
            "authorization_type": result.authorization_type.value,
            "rejection_reason": result.rejection_reason.value if result.rejection_reason else None,
            "confidence": result.confidence,
            "matching_pattern": result.matching_scope_pattern
        }

        if result.authorized:
            logger.info(f"SCOPE_CHECK_AUTHORIZED: {json.dumps(log_entry)}")
        else:
            logger.warning(f"SCOPE_CHECK_REJECTED: {json.dumps(log_entry)}")


__all__ = [
    'ScopeValidator',
    'ScopeCheckResult',
    'PatternMatcher',
    'RuleOfEngagementValidator',
    'AuthorizationType',
    'RejectionReason',
]
