from __future__ import annotations

from hunterops.http_client import request_http
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "graphql_scan"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        timeout = context["runtime"]["timeout_seconds"]
        url = f"https://{task.target}/graphql"
        findings: list[Finding] = []

        introspection_q = {"query": "{ __schema { types { name } } }"}
        r1 = request_http("POST", url, body=introspection_q, timeout=timeout)
        if r1["status"] in {200, 201} and "__schema" in r1["text"]:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="graphql_introspection",
                    severity="medium",
                    title="GraphQL introspection appears enabled",
                    evidence={"url": url, "status": r1["status"], "sample": r1["text"][:600]},
                    metadata={"novelty": 70, "confidence": 78, "impact": 55},
                )
            )

        deep_q = {"query": "query Q{__typename}"}
        r2 = request_http("POST", url, body=deep_q, timeout=timeout)
        if r2["status"] == 200 and "errors" not in r2["text"].lower():
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="graphql_access_control_signal",
                    severity="medium",
                    title="GraphQL endpoint responds to anonymous query",
                    evidence={"url": url, "status": r2["status"], "sample": r2["text"][:600]},
                    metadata={"novelty": 62, "confidence": 66, "impact": 50},
                )
            )
        return findings

