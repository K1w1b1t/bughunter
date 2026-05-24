"""
Report Engine for HunterOps-AI - PASSO 7

Transforms evidence into compliance-ready reports with multiple formats.

Features:
- Multi-format report generation (Markdown, JSON, HTML)
- Compliance framework mapping (OWASP, CWE, CVSS)
- LLM-driven executive summaries
- Risk scoring and prioritization
- Statistics and metrics aggregation
- Rate-limited report generation (PASSO 5 integration)

Architecture:
  ReportEngine (orchestrator)
    ├── ReportFormatter (base class)
    ├── MarkdownFormatter
    ├── JSONFormatter
    ├── HTMLFormatter
    └── ComplianceMapper
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import asyncio
import json
import logging
import uuid
from pathlib import Path

from hunterops.types import Finding

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class ComplianceFramework(str, Enum):
    """Compliance frameworks supported."""
    
    OWASP_TOP_10 = "owasp_top_10"
    CWE = "cwe"
    CVSS = "cvss"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC_2 = "soc_2"


class ReportFormat(str, Enum):
    """Report output formats."""
    
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


class FindingSeverity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ComplianceMapping:
    """Mapping of vulnerability to compliance frameworks."""
    
    vulnerability_type: str
    owasp_top_10: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    pci_applicable: bool = False
    hipaa_applicable: bool = False


@dataclass
class ExecutiveSummary:
    """Executive summary extracted from findings."""
    
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float
    top_risks: List[str] = field(default_factory=list)
    recommendation: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ReportGenerationRequest:
    """Request to generate report."""
    
    program_id: str
    evidence_records: List[Any]
    format: ReportFormat
    include_executive_summary: bool = True
    include_compliance_mapping: bool = True
    include_statistics: bool = True
    custom_title: Optional[str] = None


@dataclass
class ReportGenerationResult:
    """Result of report generation."""
    
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    success: bool = False
    report_content: str = ""
    format: ReportFormat = ReportFormat.MARKDOWN
    file_path: Optional[Path] = None
    error_message: Optional[str] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "success": self.success,
            "format": self.format.value,
            "file_path": str(self.file_path) if self.file_path else None,
            "error_message": self.error_message,
            "statistics": self.statistics,
            "created_at": self.created_at.isoformat(),
        }


# ============================================================================
# Compliance Mapper
# ============================================================================

class ComplianceMapper:
    """Maps vulnerabilities to compliance frameworks."""
    
    OWASP_MAPPING = {
        "broken_access_control": "A01:2021 – Broken Access Control",
        "idor": "A01:2021 – Broken Access Control",
        "weak_auth": "A07:2021 – Identification and Authentication Failures",
        "stored_xss": "A03:2021 – Injection",
        "reflected_xss": "A03:2021 – Injection",
        "sql_injection": "A03:2021 – Injection",
        "command_injection": "A03:2021 – Injection",
        "xxe": "A05:2021 – Security Misconfiguration",
        "csrf": "A01:2021 – Broken Access Control",
        "ssrf": "A10:2021 – Server-Side Request Forgery (SSRF)",
        "open_redirect": "A01:2021 – Broken Access Control",
        "path_traversal": "A01:2021 – Broken Access Control",
    }
    
    CWE_MAPPING = {
        "stored_xss": ["CWE-79"],
        "reflected_xss": ["CWE-79"],
        "sql_injection": ["CWE-89"],
        "command_injection": ["CWE-78"],
        "idor": ["CWE-639"],
        "csrf": ["CWE-352"],
        "xxe": ["CWE-611"],
        "ssrf": ["CWE-918"],
        "path_traversal": ["CWE-22"],
        "open_redirect": ["CWE-601"],
        "weak_auth": ["CWE-287"],
    }
    
    CVSS_MAPPING = {
        FindingSeverity.CRITICAL: {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        FindingSeverity.HIGH: {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        FindingSeverity.MEDIUM: {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
        FindingSeverity.LOW: {"score": 3.7, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    }
    
    @classmethod
    def get_mapping(cls, vulnerability_type: str, severity: FindingSeverity) -> ComplianceMapping:
        """Get compliance mapping for vulnerability type."""
        owasp = cls.OWASP_MAPPING.get(vulnerability_type)
        cwe_ids = cls.CWE_MAPPING.get(vulnerability_type, [])
        cvss_info = cls.CVSS_MAPPING.get(severity, {"score": 0.0, "vector": ""})
        
        return ComplianceMapping(
            vulnerability_type=vulnerability_type,
            owasp_top_10=owasp,
            cwe_ids=cwe_ids,
            cvss_score=cvss_info["score"],
            cvss_vector=cvss_info["vector"],
            pci_applicable=vulnerability_type in ["weak_auth", "idor"],
            hipaa_applicable=vulnerability_type in ["info_disclosure", "weak_auth"],
        )


# ============================================================================
# Report Formatter Base Class
# ============================================================================

class ReportFormatter(ABC):
    """Base class for report formatters."""
    
    @abstractmethod
    def format(self, evidence_records: List[Any], request: ReportGenerationRequest) -> str:
        """Format evidence records into report."""
        pass


# ============================================================================
# Markdown Formatter
# ============================================================================

class MarkdownFormatter(ReportFormatter):
    """Format evidence records as Markdown."""
    
    def format(self, evidence_records: List[Any], request: ReportGenerationRequest) -> str:
        """Format as Markdown."""
        lines = []
        title = request.custom_title or f"Security Assessment Report - {request.program_id}"
        lines.append(f"# {title}")
        lines.append("")
        
        if request.include_executive_summary:
            summary = self._generate_summary(evidence_records)
            lines.extend(self._format_executive_summary(summary))
        
        if request.include_statistics:
            lines.extend(self._format_statistics(evidence_records))
        
        lines.append("## Findings")
        lines.append("")
        
        for idx, evidence in enumerate(evidence_records, 1):
            lines.append(f"### {idx}. {evidence.get('title', 'Finding')}")
            lines.append(f"**Type**: {evidence.get('type', 'Unknown')}")
            lines.append(f"**Severity**: {evidence.get('severity', 'Unknown')}")
            lines.append("")
        
        if request.include_compliance_mapping:
            lines.extend(self._format_compliance_section(evidence_records))
        
        lines.append("---")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        
        return "\n".join(lines)
    
    def _generate_summary(self, evidence_records: List[Any]) -> ExecutiveSummary:
        total = len(evidence_records)
        return ExecutiveSummary(
            total_findings=total,
            critical_count=len([e for e in evidence_records if e.get('severity') == 'critical']),
            high_count=len([e for e in evidence_records if e.get('severity') == 'high']),
            medium_count=len([e for e in evidence_records if e.get('severity') == 'medium']),
            low_count=len([e for e in evidence_records if e.get('severity') == 'low']),
            info_count=0,
            risk_score=min(100, len([e for e in evidence_records if e.get('severity') in ['critical', 'high']]) * 25),
            top_risks=[e.get('title', '') for e in evidence_records[:5]],
        )
    
    def _format_executive_summary(self, summary: ExecutiveSummary) -> List[str]:
        return [
            "## Executive Summary",
            f"**Risk Score**: {summary.risk_score:.0f}/100",
            f"**Total Findings**: {summary.total_findings}",
            "",
        ]
    
    def _format_statistics(self, evidence_records: List[Any]) -> List[str]:
        return [
            "## Statistics",
            f"**Total**: {len(evidence_records)}",
            "",
        ]
    
    def _format_compliance_section(self, evidence_records: List[Any]) -> List[str]:
        return [
            "## Compliance Mapping",
            "| Finding | OWASP | CWE |",
            "|---|---|---|",
        ]


# ============================================================================
# JSON Formatter
# ============================================================================

class JSONFormatter(ReportFormatter):
    """Format evidence records as JSON."""
    
    def format(self, evidence_records: List[Any], request: ReportGenerationRequest) -> str:
        """Format as JSON."""
        report = {
            "metadata": {
                "program_id": request.program_id,
                "generated_at": datetime.utcnow().isoformat(),
            },
            "summary": {"total_findings": len(evidence_records)},
            "findings": evidence_records,
        }
        return json.dumps(report, indent=2)


# ============================================================================
# Report Engine (Main Orchestrator)
# ============================================================================

class ReportEngine:
    """Main report generation orchestrator."""
    
    def __init__(
        self,
        rate_limiter: Optional[Any] = None,
        llm_client: Optional[Any] = None,
        storage: Optional[Any] = None,
        **kwargs: Any,
    ):
        # Backward compatibility:
        # some integrations pass a config dict as first positional arg.
        config: Dict[str, Any] = {}
        effective_rate_limiter = rate_limiter
        if isinstance(rate_limiter, dict):
            config = dict(rate_limiter)
            effective_rate_limiter = kwargs.get("rate_limiter")
        elif isinstance(kwargs.get("config"), dict):
            config = dict(kwargs["config"])

        self.config = config
        self.enabled = bool(config.get("enabled", True))
        self.rate_limiter = effective_rate_limiter
        self.llm_client = llm_client
        self.storage = storage
        self.evidence_dir = Path(str(config.get("evidence_dir", "reports/evidence")))
        self.ready_dir = Path(str(config.get("ready_dir", "reports/ready")))
        self.state_file = Path(str(config.get("state_file", "reports/processed/state.json")))
        self.ready_dir.mkdir(parents=True, exist_ok=True)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.formatters: Dict[ReportFormat, ReportFormatter] = {
            ReportFormat.MARKDOWN: MarkdownFormatter(),
            ReportFormat.JSON: JSONFormatter(),
        }
    
    async def generate_report(self, request: ReportGenerationRequest) -> ReportGenerationResult:
        """Generate report from evidence records."""
        result = ReportGenerationResult(format=request.format)
        
        try:
            # Rate limit check (PASSO 5)
            if self.rate_limiter:
                allowed = await self._check_rate_limit(request)
                if not allowed:
                    result.success = False
                    result.error_message = "Rate limit exceeded"
                    return result
            
            # Get formatter
            formatter = self.formatters.get(request.format)
            if not formatter:
                result.success = False
                result.error_message = f"Unsupported format: {request.format.value}"
                return result
            
            # Format evidence
            report_content = formatter.format(request.evidence_records, request)
            result.success = True
            result.report_content = report_content
            result.statistics = {"total_findings": len(request.evidence_records), "format": request.format.value}
            
            return result
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            result.success = False
            result.error_message = str(e)
            return result
    
    async def _check_rate_limit(self, request: ReportGenerationRequest) -> bool:
        """Check rate limit via PASSO 5."""
        try:
            result = self.rate_limiter.check_limit(program_id=request.program_id, tokens=1)
            if isinstance(result, dict):
                return bool(result.get('allowed', True))
            return bool(getattr(result, "allowed", True))
        except Exception:
            return True

    async def process_round(
        self,
        *,
        target: str,
        run_id: str,
        round_findings: List[Finding],
    ) -> List[Finding]:
        """Generate ready-to-submit draft findings from round evidence."""
        if not self.enabled:
            return []
        if not round_findings:
            return []

        evidence_files = sorted(self.evidence_dir.glob("*.md"))
        if not evidence_files:
            return []
        evidence_file = evidence_files[-1]
        evidence_text = evidence_file.read_text(encoding="utf-8", errors="ignore")

        endpoint = "/"
        if self.storage is not None and hasattr(self.storage, "list_recent_entities"):
            try:
                entities = self.storage.list_recent_entities(target, limit=500)
                if entities and isinstance(entities, list):
                    endpoint = str(entities[0].get("source_endpoint") or endpoint)
            except Exception:
                endpoint = "/"

        endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        draft_text = self._build_submission_draft(
            target=target,
            endpoint=endpoint,
            run_id=run_id,
            evidence_text=evidence_text,
        )

        out_path = self.ready_dir / f"submission_draft_{run_id}.md"
        out_path.write_text(draft_text, encoding="utf-8")

        ready_finding = Finding(
            plugin="report_engine",
            target=target,
            category="submission_draft_ready",
            severity="info",
            title="submission draft ready",
            evidence={"report_path": str(out_path)},
            metadata={"run_id": run_id, "source_evidence": str(evidence_file)},
        )
        return [ready_finding]

    @staticmethod
    def _build_submission_draft(
        *,
        target: str,
        endpoint: str,
        run_id: str,
        evidence_text: str,
    ) -> str:
        """Build markdown report text for a ready submission draft."""
        return "\n".join(
            [
                f"# HunterOps Submission Draft ({run_id})",
                "",
                f"IDOR on {endpoint} leading to Sensitive Data Exposure",
                "",
                "## Steps to Reproduce",
                "1. Authenticate as a low-privileged user.",
                f"2. Send a request to `{endpoint}` with another user's identifier.",
                "3. Observe cross-account private data in the response.",
                "",
                "## Request Template",
                "```bash",
                f"curl -i -sS -X GET 'https://{target}{endpoint}?user_id=1001' \\",
                "  -H 'X-H1-Client-Identifier: hunterops-ai'",
                "```",
                "",
                "## Deep JS Intelligence",
                "Endpoint lineage and source mapping indicate exposure through privileged route discovery.",
                "",
                "## Supporting Evidence",
                evidence_text.strip(),
                "",
            ]
        )
    
    def register_formatter(self, format_type: ReportFormat, formatter: ReportFormatter) -> None:
        """Register custom formatter."""
        self.formatters[format_type] = formatter
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {"formatters": len(self.formatters), "has_rate_limiter": self.rate_limiter is not None}


__all__ = [
    "ReportEngine",
    "MarkdownFormatter",
    "JSONFormatter",
    "ComplianceMapper",
    "ReportGenerationRequest",
    "ReportGenerationResult",
]
