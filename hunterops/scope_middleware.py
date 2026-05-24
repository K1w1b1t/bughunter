"""Scope Validation Middleware - Integration with executor.py

This module provides middleware and decorators for enforcing scope validation
in the HunterOps executor, attack pipeline, and evidence generator.

Integration points:
1. HTTP request middleware (intercept all network calls)
2. DNS resolution gate (prevent DNS for out-of-scope domains)
3. Port scanning authorization (before naabu/httpx)
4. Vulnerability scanning authorization (before nuclei)
5. Exploitation authorization (before exploit execution)

CRITICAL: These decorators must wrap ALL network-generating functions.
"""

import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, Optional, List
from functools import wraps
import inspect

from hunterops.scope_validator import (
    ScopeValidator,
    ScopeCheckResult,
    AuthorizationType,
)

logger = logging.getLogger(__name__)


class ScopeAuthorizationError(Exception):
    """Raised when scope check fails."""

    def __init__(
        self,
        message: str,
        target: str,
        rejection_reason: str,
        program_id: str
    ):
        self.message = message
        self.target = target
        self.rejection_reason = rejection_reason
        self.program_id = program_id
        super().__init__(message)


class ScopeMiddleware:
    """Middleware layer for scope enforcement in async operations."""

    def __init__(self, scope_validator: ScopeValidator):
        """Initialize middleware with scope validator."""
        self.validator = scope_validator
        self.call_count = 0
        self.authorized_count = 0
        self.rejected_count = 0

    async def check_and_authorize(
        self,
        target: str,
        action: str = "reconnaisance",
        authenticated: bool = False,
        raise_on_reject: bool = True
    ) -> ScopeCheckResult:
        """Check authorization and optionally raise exception if rejected.

        Args:
            target: Target URL/domain/IP
            action: Action type (reconnaisance, exploitation, evidence_collection)
            authenticated: Whether action uses valid credentials
            raise_on_reject: If True, raise exception on rejection

        Returns:
            ScopeCheckResult with decision

        Raises:
            ScopeAuthorizationError if rejected and raise_on_reject=True
        """
        self.call_count += 1

        # Run check (synchronous, so no await needed)
        result = self.validator.check_scope(target, action, authenticated)

        # Log check
        self.validator.log_scope_check(result)

        if result.authorized:
            self.authorized_count += 1
        else:
            self.rejected_count += 1

            if raise_on_reject:
                raise ScopeAuthorizationError(
                    message=f"Scope check failed for {target}: {result.rejection_details}",
                    target=target,
                    rejection_reason=result.rejection_reason.value if result.rejection_reason else "UNKNOWN",
                    program_id=self.validator.program_id
                )

        return result

    def get_statistics(self) -> Dict[str, Any]:
        """Get middleware statistics."""
        return {
            "total_checks": self.call_count,
            "authorized": self.authorized_count,
            "rejected": self.rejected_count,
            "rejection_rate": (
                self.rejected_count / self.call_count * 100
                if self.call_count > 0
                else 0
            )
        }


# Global middleware instance (set by executor on startup)
_scope_middleware: Optional[ScopeMiddleware] = None


def set_scope_middleware(middleware: ScopeMiddleware) -> None:
    """Set global scope middleware instance."""
    global _scope_middleware
    _scope_middleware = middleware


def get_scope_middleware() -> ScopeMiddleware:
    """Get global scope middleware instance."""
    if _scope_middleware is None:
        raise RuntimeError("Scope middleware not initialized. Call set_scope_middleware() first.")
    return _scope_middleware


def require_scope_authorization(
    action: str = "reconnaisance",
    extract_target_from: Optional[str] = None,
    raise_on_reject: bool = True
):
    """Decorator for functions that require scope authorization.

    Usage:
        @require_scope_authorization(
            action="port_scanning",
            extract_target_from="target"  # Parameter name containing target
        )
        async def scan_ports(host: str, port_range: str) -> Dict:
            ...

    Args:
        action: Authorization action type
        extract_target_from: Parameter name containing target (if None, uses first param)
        raise_on_reject: Whether to raise exception on rejection
    """

    def decorator(func: Callable) -> Callable:
        is_async = asyncio.iscoroutinefunction(func)

        if is_async:

            @wraps(func)
            async def async_wrapper(*args, **kwargs) -> Any:
                middleware = get_scope_middleware()

                # Extract target from parameters
                target = _extract_target(func, args, kwargs, extract_target_from)

                # Check authorization
                await middleware.check_and_authorize(
                    target=target,
                    action=action,
                    authenticated=kwargs.get('authenticated', False),
                    raise_on_reject=raise_on_reject
                )

                # Call original function
                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @wraps(func)
            def sync_wrapper(*args, **kwargs) -> Any:
                middleware = get_scope_middleware()

                # Extract target from parameters
                target = _extract_target(func, args, kwargs, extract_target_from)

                # Check authorization (synchronous)
                result = middleware.validator.check_scope(
                    target,
                    action,
                    kwargs.get('authenticated', False)
                )

                if not result.authorized and raise_on_reject:
                    raise ScopeAuthorizationError(
                        message=f"Scope check failed for {target}: {result.rejection_details}",
                        target=target,
                        rejection_reason=result.rejection_reason.value if result.rejection_reason else "UNKNOWN",
                        program_id=middleware.validator.program_id
                    )

                # Call original function
                return func(*args, **kwargs)

            return sync_wrapper

    return decorator


def _extract_target(
    func: Callable,
    args: tuple,
    kwargs: dict,
    extract_target_from: Optional[str]
) -> str:
    """Extract target from function parameters."""
    # If specified, use that parameter
    if extract_target_from:
        if extract_target_from in kwargs:
            return str(kwargs[extract_target_from])

        # Try to find in function signature
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        if extract_target_from in params:
            param_index = params.index(extract_target_from)
            if param_index < len(args):
                return str(args[param_index])

    # Fallback: use first positional argument
    if args:
        return str(args[0])

    raise ValueError("Could not extract target from function parameters")


class ScopedTargetList:
    """Helper for batch authorization of multiple targets.

    Usage:
        targets = ScopedTargetList(['example.com', 'api.example.com'], 'port_scanning')
        for target in targets:
            if target.is_authorized():
                await scan(target.value)
    """

    def __init__(
        self,
        targets: List[str],
        action: str,
        middleware: Optional[ScopeMiddleware] = None
    ):
        """Initialize scoped target list."""
        self.targets = targets
        self.action = action
        self.middleware = middleware or get_scope_middleware()
        self.results: Dict[str, ScopeCheckResult] = {}

        # Pre-check all targets
        for target in self.targets:
            result = self.middleware.validator.check_scope(target, action)
            self.results[target] = result

    async def authorize_all(self) -> Dict[str, bool]:
        """Return authorization status for all targets.

        Returns: {target: authorized}
        """
        return {target: result.authorized for target, result in self.results.items()}

    def get_authorized_targets(self) -> List[str]:
        """Get list of authorized targets only."""
        return [
            target for target, result in self.results.items()
            if result.authorized
        ]

    def get_rejected_targets(self) -> Dict[str, str]:
        """Get rejected targets with reasons.

        Returns: {target: rejection_reason}
        """
        return {
            target: result.rejection_reason.value if result.rejection_reason else "UNKNOWN"
            for target, result in self.results.items()
            if not result.authorized
        }

    def __iter__(self):
        """Iterate over targets (only authorized ones)."""
        for target in self.get_authorized_targets():
            yield target

    def __len__(self) -> int:
        """Count of authorized targets."""
        return len(self.get_authorized_targets())


# Predefined authorization decorators for common operations

def require_recon_authorization(extract_target_from: Optional[str] = None):
    """Decorator for reconnaissance operations."""
    return require_scope_authorization(
        action="reconnaisance",
        extract_target_from=extract_target_from
    )


def require_scanning_authorization(extract_target_from: Optional[str] = None):
    """Decorator for vulnerability scanning."""
    return require_scope_authorization(
        action="vulnerability_scanning",
        extract_target_from=extract_target_from
    )


def require_exploitation_authorization(extract_target_from: Optional[str] = None):
    """Decorator for exploitation attempts."""
    return require_scope_authorization(
        action="exploitation",
        extract_target_from=extract_target_from
    )


def require_evidence_authorization(extract_target_from: Optional[str] = None):
    """Decorator for evidence collection."""
    return require_scope_authorization(
        action="evidence_collection",
        extract_target_from=extract_target_from
    )


__all__ = [
    'ScopeMiddleware',
    'ScopeAuthorizationError',
    'ScopedTargetList',
    'set_scope_middleware',
    'get_scope_middleware',
    'require_scope_authorization',
    'require_recon_authorization',
    'require_scanning_authorization',
    'require_exploitation_authorization',
    'require_evidence_authorization',
]
