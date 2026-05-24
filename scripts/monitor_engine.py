#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor engine metrics and emit alerts")
    parser.add_argument("--metrics", default="data/reports/engine/metrics.json")
    parser.add_argument("--out", default="data/reports/engine/alerts.json")
    parser.add_argument("--max-error-rate", type=float, default=35.0)
    parser.add_argument("--max-latency-sec", type=float, default=20.0)
    parser.add_argument("--min-throughput", type=float, default=0.3, help="minimum findings/run ratio for critical plugins")
    parser.add_argument("--critical-plugins", default="auth_compare,idor_auto,role_access,auth_token_tests,cve_matcher")
    args = parser.parse_args()

    mpath = Path(args.metrics)
    if not mpath.exists():
        raise SystemExit("metrics file not found")
    doc = json.loads(mpath.read_text(encoding="utf-8"))
    pmetrics = doc.get("plugin_metrics", {})
    alerts: list[dict[str, Any]] = []
    critical = {x.strip() for x in args.critical_plugins.split(",") if x.strip()}
    for plugin, m in pmetrics.items():
        if float(m.get("error_rate", 0)) > args.max_error_rate:
            alerts.append({"plugin": plugin, "type": "high_error_rate", "value": m.get("error_rate")})
        if float(m.get("avg_latency_sec", 0)) > args.max_latency_sec:
            alerts.append({"plugin": plugin, "type": "high_latency", "value": m.get("avg_latency_sec")})
        runs = max(1.0, float(m.get("runs", 0.0)))
        throughput = float(m.get("findings", 0.0)) / runs
        if plugin in critical and throughput < args.min_throughput:
            alerts.append({"plugin": plugin, "type": "low_throughput", "value": round(throughput, 4)})
        if plugin in critical and float(m.get("findings", 0.0)) == 0.0:
            alerts.append({"plugin": plugin, "type": "no_signal", "value": 0})

    out = {"alerts": alerts, "ok": len(alerts) == 0}
    op = Path(args.out)
    op.parent.mkdir(parents=True, exist_ok=True)
    op.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[monitor] alerts={len(alerts)} out={args.out}")
    raise SystemExit(0 if not alerts else 2)


if __name__ == "__main__":
    main()
