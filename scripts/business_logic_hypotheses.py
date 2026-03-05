#!/usr/bin/env python3
"""Generate business-logic test hypotheses from endpoint catalog."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from common import read_json, write_json


RULES = [
    {
        "id": "BL-ID-SWAP",
        "name": "ID swap / object ownership check",
        "when_params": {"id", "user_id", "account_id", "invoice_id", "tenant_id"},
        "action": "Test object ID replacement across tenants/users and verify authorization enforcement.",
        "priority": "high",
    },
    {
        "id": "BL-TENANT-BOUNDARY",
        "name": "Tenant boundary break",
        "when_path_contains": ["tenant", "organization", "org", "workspace"],
        "action": "Attempt cross-tenant data access with same privilege level.",
        "priority": "high",
    },
    {
        "id": "BL-WORKFLOW-SKIP",
        "name": "Workflow step bypass",
        "when_path_contains": ["checkout", "payment", "approval", "confirm", "finalize"],
        "action": "Skip required steps and replay final action endpoint directly.",
        "priority": "high",
    },
    {
        "id": "BL-RATE-ABUSE",
        "name": "Rate/coupon/credit abuse",
        "when_path_contains": ["coupon", "credit", "discount", "redeem", "wallet"],
        "action": "Test replay/race and repeated application beyond expected limits.",
        "priority": "medium",
    },
]


def params_set(item: dict[str, Any]) -> set[str]:
    params = item.get("params", [])
    if not isinstance(params, list):
        return set()
    return {str(x).lower() for x in params}


def main() -> None:
    parser = argparse.ArgumentParser(description="Business logic hypothesis generator")
    parser.add_argument("--catalog", default="data/processed/endpoints_catalog.json")
    parser.add_argument("--out", default="data/findings/business_logic_hypotheses.json")
    args = parser.parse_args()

    catalog = read_json(Path(args.catalog))
    hypotheses: list[dict[str, Any]] = []

    for cluster_name, entries in catalog.get("clusters", {}).items():
        for item in entries:
            endpoint = str(item.get("endpoint", "")).lower()
            pset = params_set(item)
            for rule in RULES:
                matched = False
                param_triggers = rule.get("when_params")
                path_triggers = rule.get("when_path_contains")
                if param_triggers and (pset & {x.lower() for x in param_triggers}):
                    matched = True
                if path_triggers and any(k in endpoint for k in path_triggers):
                    matched = True
                if matched:
                    hypotheses.append(
                        {
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "endpoint": item.get("endpoint"),
                            "cluster": cluster_name,
                            "params": sorted(pset),
                            "priority": rule["priority"],
                            "recommended_test": rule["action"],
                        }
                    )

    write_json(Path(args.out), {"total": len(hypotheses), "hypotheses": hypotheses})
    print("[business-logic] out=" + args.out)
    print("[business-logic] generated=" + str(len(hypotheses)))


if __name__ == "__main__":
    main()
