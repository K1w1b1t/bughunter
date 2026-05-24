from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def export_json(path: Path, rows: list[dict[str, Any]]) -> None:
    write_json(path, {"count": len(rows), "findings": rows})


def export_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["plugin", "target", "category", "severity", "title", "risk_score"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fields})


def export_markdown(path: Path, rows: list[dict[str, Any]], target_label: str) -> None:
    lines = [f"# HunterOps Report - {target_label}", "", f"Total findings: {len(rows)}", ""]
    for r in rows:
        lines.extend(
            [
                f"## {r.get('title')}",
                f"- Target: {r.get('target')}",
                f"- Severity: {r.get('severity')}",
                f"- Risk Score: {r.get('risk_score')}",
                f"- Category: {r.get('category')}",
                f"- Plugin: {r.get('plugin')}",
                f"- Evidence: `{json.dumps(r.get('evidence', {}), ensure_ascii=True)}`",
                "",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def export_html(path: Path, rows: list[dict[str, Any]], target_label: str) -> None:
    items = []
    for r in rows:
        items.append(
            "<tr>"
            f"<td>{html.escape(str(r.get('target', '')))}</td>"
            f"<td>{html.escape(str(r.get('title', '')))}</td>"
            f"<td>{html.escape(str(r.get('severity', '')))}</td>"
            f"<td>{html.escape(str(r.get('category', '')))}</td>"
            f"<td>{html.escape(str(r.get('risk_score', '')))}</td>"
            f"<td><pre>{html.escape(json.dumps(r.get('evidence', {}), ensure_ascii=True))}</pre></td>"
            "</tr>"
        )

    html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>HunterOps Report</title>
<style>
body{{font-family:Arial,sans-serif;padding:20px;background:#f7f7f7}}
table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{border:1px solid #ddd;padding:8px;vertical-align:top}}
th{{background:#222;color:#fff}}
</style></head><body>
<h1>HunterOps Report - {html.escape(target_label)}</h1>
<p>Total findings: {len(rows)}</p>
<table><thead><tr><th>Target</th><th>Title</th><th>Severity</th><th>Category</th><th>Risk</th><th>Evidence</th></tr></thead>
<tbody>{''.join(items)}</tbody></table>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_doc, encoding="utf-8")


def export_dashboard(path: Path, rows: list[dict[str, Any]]) -> None:
    total = len(rows)
    auth_related = sum(1 for r in rows if "auth" in str(r.get("category", "")).lower())
    suspects = sum(1 for r in rows if r.get("risk_score", 0) >= 60)
    criticals = sum(1 for r in rows if str(r.get("severity", "")).lower() in {"critical", "high"})
    endpoints = set()
    for r in rows:
        ev = r.get("evidence", {})
        if isinstance(ev, dict):
            for k in ("url", "base_url", "mutated_url"):
                if ev.get(k):
                    endpoints.add(str(ev[k]))
    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>HunterOps Dashboard</title>
<style>
body{{font-family:Arial,sans-serif;background:#0e1116;color:#f3f5f7;padding:20px}}
.grid{{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px}}
.card{{background:#171d26;border:1px solid #2b3542;border-radius:8px;padding:14px}}
.num{{font-size:28px;font-weight:700}}
</style></head><body>
<h1>HunterOps Overview</h1>
<div class="grid">
<div class="card"><div>Total Findings</div><div class="num">{total}</div></div>
<div class="card"><div>Auth Related</div><div class="num">{auth_related}</div></div>
<div class="card"><div>Suspicious (score>=60)</div><div class="num">{suspects}</div></div>
<div class="card"><div>Critical/High</div><div class="num">{criticals}</div></div>
</div>
<p>Unique endpoints referenced: <strong>{len(endpoints)}</strong></p>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
