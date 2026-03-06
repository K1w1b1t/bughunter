from __future__ import annotations

from typing import Any

from hunterops.types import Finding

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_FINANCIAL_MARKERS = (
    "price",
    "amount",
    "total",
    "quantity",
    "cost",
    "wallet",
    "invoice",
    "transaction",
    "payment",
    "transfer",
    "withdraw",
    "redeem",
    "coupon",
    "discount",
    "promo",
    "currency",
)
_ADMIN_MARKERS = ("admin", "internal", "/v1/", "/v2/", "debug", "config")


def _severity_index(value: str) -> int:
    raw = str(value or "info").strip().lower()
    if raw in _SEVERITY_ORDER:
        return _SEVERITY_ORDER.index(raw)
    return _SEVERITY_ORDER.index("low")


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in markers)


def calculate_impact(finding: Finding) -> dict[str, Any]:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    endpoint = str(
        evidence.get(
            "endpoint",
            evidence.get("path", evidence.get("url", evidence.get("base_url", evidence.get("modified_url", "")))),
        )
    )
    combined = " ".join(
        [
            str(finding.category or ""),
            str(finding.title or ""),
            str(endpoint or ""),
            str(evidence.get("tested_parameter", "")),
            str(evidence.get("parameter", "")),
        ]
    ).lower()
    impact_score = float(metadata.get("impact", 50) or 50)
    severity_index = _severity_index(finding.severity)
    financial = _contains_any(combined, _FINANCIAL_MARKERS)
    administrative = _contains_any(combined, _ADMIN_MARKERS)

    if financial:
        impact_score += 18.0
        severity_index = min(len(_SEVERITY_ORDER) - 1, severity_index + 1)
    if administrative:
        impact_score += 12.0
        severity_index = min(len(_SEVERITY_ORDER) - 1, severity_index + 1)

    return {
        "impact_score": round(max(0.0, min(100.0, impact_score)), 2),
        "adjusted_severity": _SEVERITY_ORDER[severity_index],
        "financial_context": financial,
        "administrative_context": administrative,
        "endpoint": endpoint,
    }

