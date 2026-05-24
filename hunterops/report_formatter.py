"""Report formatters for PASSO 7."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, List, Optional
import json


class FormatterStyle(str, Enum):
    """Formatting style options."""

    COMPACT = "compact"
    DETAILED = "detailed"
    EXECUTIVE = "executive"


@dataclass
class FormatterConfig:
    """Configuration for formatters."""

    style: FormatterStyle = FormatterStyle.DETAILED
    include_timestamps: bool = True
    include_metadata: bool = True
    color_coding: bool = False
    pagination_size: Optional[int] = None


class HTMLFormatter:
    """Format evidence records as HTML."""

    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 24px;
      background: #f7f7f7;
      color: #1f2937;
    }}
    .card {{
      background: white;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
      border-left: 4px solid #6b7280;
      box-shadow: 0 1px 2px rgba(0,0,0,0.08);
    }}
    .critical {{ border-left-color: #dc2626; }}
    .high {{ border-left-color: #ea580c; }}
    .medium {{ border-left-color: #ca8a04; }}
    .low {{ border-left-color: #6b7280; }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(5, minmax(120px, 1fr));
      gap: 8px;
      margin-bottom: 16px;
    }}
    .summary-item {{
      background: white;
      border-radius: 8px;
      padding: 12px;
      text-align: center;
    }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e5e7eb; text-align: left; }}
    th {{ background: #f3f4f6; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p>Program: {program_id}</p>
  <p>Generated at: {generated_at}</p>
  {summary_section}
  {findings_section}
  {compliance_section}
</body>
</html>
""".strip()

    def __init__(self, config: Optional[FormatterConfig] = None):
        self.config = config or FormatterConfig()

    def format(self, evidence_records: List[Any], title: str, program_id: str) -> str:
        summary = self._calculate_summary(evidence_records)
        return self.HTML_TEMPLATE.format(
            title=title,
            program_id=program_id,
            generated_at=datetime.utcnow().isoformat(),
            summary_section=self._format_summary_section(summary),
            findings_section=self._format_findings_section(evidence_records),
            compliance_section=self._format_compliance_section(evidence_records),
        )

    def _calculate_summary(self, evidence_records: List[Any]) -> dict[str, int]:
        return {
            "total": len(evidence_records),
            "critical": sum(1 for e in evidence_records if str(e.get("severity", "")).lower() == "critical"),
            "high": sum(1 for e in evidence_records if str(e.get("severity", "")).lower() == "high"),
            "medium": sum(1 for e in evidence_records if str(e.get("severity", "")).lower() == "medium"),
            "low": sum(1 for e in evidence_records if str(e.get("severity", "")).lower() == "low"),
        }

    def _format_summary_section(self, stats: dict[str, int]) -> str:
        return (
            '<div class="summary">'
            f'<div class="summary-item"><strong>Total</strong><br>{stats["total"]}</div>'
            f'<div class="summary-item"><strong>Critical</strong><br>{stats["critical"]}</div>'
            f'<div class="summary-item"><strong>High</strong><br>{stats["high"]}</div>'
            f'<div class="summary-item"><strong>Medium</strong><br>{stats["medium"]}</div>'
            f'<div class="summary-item"><strong>Low</strong><br>{stats["low"]}</div>'
            '</div>'
        )

    def _format_findings_section(self, evidence_records: List[Any]) -> str:
        if not evidence_records:
            return "<h2>Findings</h2><p>No findings.</p>"
        chunks = ["<h2>Findings</h2>"]
        for idx, record in enumerate(evidence_records, start=1):
            severity = str(record.get("severity", "low")).lower()
            chunks.append(
                """
<div class="card {sev}">
  <h3>{idx}. {title}</h3>
  <p><strong>Type:</strong> {typ}</p>
  <p><strong>Severity:</strong> {sev_up}</p>
  <p><strong>Description:</strong> {desc}</p>
  <p><strong>Impact:</strong> {impact}</p>
</div>
""".format(
                    idx=idx,
                    title=record.get("title", "Finding"),
                    typ=record.get("type", "unknown"),
                    sev=severity,
                    sev_up=severity.upper(),
                    desc=record.get("description", "N/A"),
                    impact=record.get("impact", "N/A"),
                ).strip()
            )
        return "\n".join(chunks)

    def _format_compliance_section(self, evidence_records: List[Any]) -> str:
        if not evidence_records:
            return "<h2>Compliance Mapping</h2><p>No rows.</p>"
        rows = []
        for record in evidence_records:
            rows.append(
                "<tr><td>{title}</td><td>{typ}</td><td>{sev}</td></tr>".format(
                    title=record.get("title", "Finding"),
                    typ=record.get("type", "unknown"),
                    sev=str(record.get("severity", "low")).upper(),
                )
            )
        return (
            "<h2>Compliance Mapping</h2>"
            "<table><thead><tr><th>Finding</th><th>Type</th><th>Severity</th></tr></thead>"
            "<tbody>{rows}</tbody></table>".format(rows="".join(rows))
        )


class CSVFormatter:
    """Format evidence records as CSV text."""

    def format(self, evidence_records: List[Any]) -> str:
        header = "title,type,severity,description,impact"
        if not evidence_records:
            return header
        rows = [header]
        for record in evidence_records:
            title = str(record.get("title", "N/A")).replace('"', "''").replace("\n", " ")
            typ = str(record.get("type", "N/A")).replace('"', "''").replace("\n", " ")
            severity = str(record.get("severity", "N/A")).replace('"', "''").replace("\n", " ")
            description = str(record.get("description", "N/A")).replace('"', "''").replace("\n", " ")
            impact = str(record.get("impact", "N/A")).replace('"', "''").replace("\n", " ")
            rows.append(f'"{title}","{typ}","{severity}","{description}","{impact}"')
        return "\n".join(rows)


class XMLFormatter:
    """Format evidence records as XML text."""

    def format(self, evidence_records: List[Any], program_id: str) -> str:
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<report>",
            f"  <program_id>{self._escape_xml(program_id)}</program_id>",
            f"  <generated_at>{datetime.utcnow().isoformat()}</generated_at>",
            f"  <total_findings>{len(evidence_records)}</total_findings>",
            "  <findings>",
        ]
        for record in evidence_records:
            lines.extend(
                [
                    "    <finding>",
                    f"      <title>{self._escape_xml(str(record.get('title', 'N/A')))}</title>",
                    f"      <type>{self._escape_xml(str(record.get('type', 'N/A')))}</type>",
                    f"      <severity>{self._escape_xml(str(record.get('severity', 'N/A')))}</severity>",
                    f"      <description>{self._escape_xml(str(record.get('description', 'N/A')))}</description>",
                    f"      <impact>{self._escape_xml(str(record.get('impact', 'N/A')))}</impact>",
                    "    </finding>",
                ]
            )
        lines.extend(["  </findings>", "</report>"])
        return "\n".join(lines)

    @staticmethod
    def _escape_xml(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )


class TemplateFormatter:
    """Format evidence using a custom string template."""

    def __init__(self, template: str):
        self.template = str(template)

    def format(self, evidence_records: List[Any]) -> str:
        output = self.template
        output = output.replace("{total_findings}", str(len(evidence_records)))
        output = output.replace("{generated_at}", datetime.utcnow().isoformat())
        if "{findings_list}" in output:
            items = "".join(f"<li>{record.get('title', 'Finding')}</li>" for record in evidence_records)
            output = output.replace("{findings_list}", items)
        return output


__all__ = [
    "HTMLFormatter",
    "CSVFormatter",
    "XMLFormatter",
    "TemplateFormatter",
    "FormatterConfig",
    "FormatterStyle",
]
