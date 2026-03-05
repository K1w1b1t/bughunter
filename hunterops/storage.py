from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse


def _normalize_endpoint(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        return parsed.path or "/"
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.path or "/"
    if raw.startswith("/"):
        return raw
    return f"/{raw}"


class PostgresStorage:
    def __init__(self, dsn: str, enabled: bool = False) -> None:
        self.dsn = dsn
        self.enabled = enabled
        self._conn = None

    def connect(self) -> None:
        if not self.enabled:
            return
        try:
            import psycopg  # type: ignore
        except Exception as err:
            raise RuntimeError("psycopg is required for postgres storage") from err
        self._conn = psycopg.connect(self.dsn, connect_timeout=5)
        with self._conn.cursor() as cur:
            cur.execute(
                """
                create table if not exists hunterops_findings (
                  id bigserial primary key,
                  run_id text not null,
                  plugin text not null,
                  target text not null,
                  category text not null,
                  severity text not null,
                  title text not null,
                  risk_score double precision not null,
                  discovery_source text default '',
                  confidence_score double precision default 0,
                  payload jsonb not null,
                  created_at timestamptz default now()
                )
                """
            )
            cur.execute("alter table hunterops_findings add column if not exists discovery_source text default ''")
            cur.execute("alter table hunterops_findings add column if not exists confidence_score double precision default 0")
        self._conn.commit()

    def write_findings(self, run_id: str, rows: list[dict[str, Any]]) -> None:
        if not self.enabled:
            return
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    insert into hunterops_findings
                    (run_id, plugin, target, category, severity, title, risk_score, discovery_source, confidence_score, payload)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    """,
                    (
                        run_id,
                        r.get("plugin", ""),
                        r.get("target", ""),
                        r.get("category", ""),
                        r.get("severity", ""),
                        r.get("title", ""),
                        float(r.get("risk_score", 0)),
                        str((r.get("metadata", {}) or {}).get("discovery_source", "")),
                        float((r.get("metadata", {}) or {}).get("confidence_score", (r.get("metadata", {}) or {}).get("confidence", 0))),
                        json.dumps(r, ensure_ascii=True),
                    ),
                )
        self._conn.commit()

    def ensure_research_schema(self) -> None:
        if not self.enabled:
            return
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                create table if not exists hunterops_scan_state (
                  id bigserial primary key,
                  run_id text not null,
                  plugin text not null,
                  target text not null,
                  endpoint text not null,
                  scanned_at timestamptz default now(),
                  unique(run_id, plugin, target, endpoint)
                )
                """
            )
            cur.execute(
                """
                create table if not exists attack_graph_nodes (
                  id bigserial primary key,
                  run_id text not null,
                  node_type text not null,
                  node_key text not null,
                  target text not null,
                  discovery_source text not null default '',
                  confidence_score double precision not null default 0,
                  metadata jsonb not null default '{}'::jsonb,
                  created_at timestamptz default now(),
                  unique(run_id, node_type, node_key, target)
                )
                """
            )
            cur.execute(
                """
                create table if not exists attack_graph_edges (
                  id bigserial primary key,
                  run_id text not null,
                  src_node_id bigint not null references attack_graph_nodes(id) on delete cascade,
                  dst_node_id bigint not null references attack_graph_nodes(id) on delete cascade,
                  edge_type text not null,
                  confidence_score double precision not null default 0,
                  evidence_ref text default '',
                  metadata jsonb not null default '{}'::jsonb,
                  created_at timestamptz default now()
                )
                """
            )
            cur.execute(
                """
                create table if not exists objects (
                  id bigserial primary key,
                  run_id text not null,
                  object_type text not null,
                  object_key text not null,
                  source_endpoint text not null,
                  confidence_score double precision not null default 0,
                  discovery_source text not null default '',
                  discovered_at timestamptz default now()
                )
                """
            )
            cur.execute(
                """
                create table if not exists object_relationships (
                  id bigserial primary key,
                  run_id text not null,
                  parent_object_type text not null,
                  parent_object_key text not null,
                  child_object_type text not null,
                  child_object_key text not null,
                  relation_type text not null,
                  confidence_score double precision not null default 0,
                  evidence_ref text default '',
                  discovered_at timestamptz default now()
                )
                """
            )
            cur.execute(
                """
                create table if not exists endpoint_parameters (
                  id bigserial primary key,
                  run_id text not null,
                  endpoint text not null,
                  method text not null default 'GET',
                  param_name text not null,
                  param_location text not null,
                  param_type text not null,
                  risk_score double precision not null default 0,
                  discovery_source text not null default '',
                  evidence_ref text default '',
                  first_seen timestamptz default now(),
                  last_seen timestamptz default now(),
                  unique(run_id, endpoint, method, param_name, param_location)
                )
                """
            )
            cur.execute(
                """
                create table if not exists discovered_entities (
                  id bigserial primary key,
                  run_id text not null,
                  target text not null,
                  entity_type text not null,
                  entity_value text not null,
                  source_plugin text not null default '',
                  source_endpoint text not null default '',
                  confidence_score double precision not null default 0,
                  metadata jsonb not null default '{}'::jsonb,
                  first_seen timestamptz default now(),
                  last_seen timestamptz default now(),
                  unique(target, entity_type, entity_value, source_plugin, source_endpoint)
                )
                """
            )
        self._conn.commit()

    def was_endpoint_scanned(self, run_id: str, plugin: str, target: str, endpoint: str) -> bool:
        if not self.enabled:
            return False
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select 1
                from hunterops_scan_state
                where run_id=%s and plugin=%s and target=%s and endpoint=%s
                limit 1
                """,
                (run_id, plugin, target, endpoint),
            )
            row = cur.fetchone()
        return bool(row)

    def mark_endpoint_scanned(self, run_id: str, plugin: str, target: str, endpoint: str) -> None:
        if not self.enabled:
            return
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                insert into hunterops_scan_state (run_id, plugin, target, endpoint)
                values (%s,%s,%s,%s)
                on conflict do nothing
                """,
                (run_id, plugin, target, endpoint),
            )
        self._conn.commit()

    def upsert_attack_graph_nodes(
        self,
        run_id: str,
        target: str,
        nodes: list[dict[str, Any]],
        discovery_source: str,
        confidence_score: float,
    ) -> None:
        if not self.enabled or not nodes:
            return
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            for n in nodes:
                cur.execute(
                    """
                    insert into attack_graph_nodes
                    (run_id, node_type, node_key, target, discovery_source, confidence_score, metadata)
                    values (%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (run_id, node_type, node_key, target)
                    do update set
                      discovery_source=excluded.discovery_source,
                      confidence_score=greatest(attack_graph_nodes.confidence_score, excluded.confidence_score),
                      metadata=excluded.metadata
                    """,
                    (
                        run_id,
                        str(n.get("node_type", "")),
                        str(n.get("node_key", "")),
                        target,
                        discovery_source,
                        float(confidence_score),
                        json.dumps(n.get("metadata", {}), ensure_ascii=True),
                    ),
                )
        self._conn.commit()

    def upsert_endpoint_parameters(self, run_id: str, rows: list[dict[str, Any]]) -> None:
        if not self.enabled or not rows:
            return
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    insert into endpoint_parameters
                    (run_id, endpoint, method, param_name, param_location, param_type, risk_score, discovery_source, evidence_ref)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    on conflict (run_id, endpoint, method, param_name, param_location)
                    do update set
                      param_type=excluded.param_type,
                      risk_score=excluded.risk_score,
                      discovery_source=excluded.discovery_source,
                      evidence_ref=excluded.evidence_ref,
                      last_seen=now()
                    """,
                    (
                        run_id,
                        str(r.get("endpoint", "")),
                        str(r.get("method", "GET")),
                        str(r.get("param_name", "")),
                        str(r.get("param_location", "query")),
                        str(r.get("param_type", "string")),
                        float(r.get("risk_score", 0)),
                        str(r.get("discovery_source", "")),
                        str(r.get("evidence_ref", "")),
                    ),
                )
        self._conn.commit()

    def upsert_discovered_entities(self, run_id: str, target: str, rows: list[dict[str, Any]]) -> int:
        if not self.enabled or not rows:
            return 0
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        inserted = 0
        with self._conn.cursor() as cur:
            for r in rows:
                entity_type = str(r.get("entity_type", "")).strip().lower()
                entity_value = str(r.get("entity_value", "")).strip()
                if not entity_type or not entity_value:
                    continue
                source_plugin = str(r.get("source_plugin", "")).strip()
                source_endpoint = _normalize_endpoint(str(r.get("source_endpoint", "")).strip())
                confidence_score = float(r.get("confidence_score", 0) or 0)
                metadata = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
                cur.execute(
                    """
                    insert into discovered_entities
                    (run_id, target, entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata)
                    values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (target, entity_type, entity_value, source_plugin, source_endpoint)
                    do update set
                      run_id=excluded.run_id,
                      confidence_score=greatest(discovered_entities.confidence_score, excluded.confidence_score),
                      metadata=excluded.metadata,
                      last_seen=now()
                    """,
                    (
                        run_id,
                        target,
                        entity_type,
                        entity_value[:512],
                        source_plugin,
                        source_endpoint,
                        confidence_score,
                        json.dumps(metadata, ensure_ascii=True),
                    ),
                )
                inserted += 1
        self._conn.commit()
        return inserted

    def list_recent_entities(self, target: str, limit: int = 200, entity_types: list[str] | None = None) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        safe_limit = max(1, min(int(limit), 5000))
        with self._conn.cursor() as cur:
            if entity_types:
                kinds = [str(x).strip().lower() for x in entity_types if str(x).strip()]
                cur.execute(
                    """
                    select entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata
                    from discovered_entities
                    where target=%s and entity_type = any(%s::text[])
                    order by last_seen desc
                    limit %s
                    """,
                    (target, kinds, safe_limit),
                )
            else:
                cur.execute(
                    """
                    select entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata
                    from discovered_entities
                    where target=%s
                    order by last_seen desc
                    limit %s
                    """,
                    (target, safe_limit),
                )
            rows = cur.fetchall()
            for row in rows:
                out.append(
                    {
                        "entity_type": str(row[0] or ""),
                        "entity_value": str(row[1] or ""),
                        "source_plugin": str(row[2] or ""),
                        "source_endpoint": str(row[3] or ""),
                        "confidence_score": float(row[4] or 0),
                        "metadata": row[5] if isinstance(row[5], dict) else {},
                    }
                )
        return out

    def list_endpoint_parameters(self, run_id: str, limit: int = 1000) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        safe_limit = max(1, min(int(limit), 20000))
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select endpoint, method, param_name, param_location, param_type, risk_score
                from endpoint_parameters
                where run_id=%s
                order by risk_score desc, id desc
                limit %s
                """,
                (run_id, safe_limit),
            )
            rows = cur.fetchall()
            for row in rows:
                out.append(
                    {
                        "endpoint": str(row[0] or ""),
                        "method": str(row[1] or "GET"),
                        "param_name": str(row[2] or ""),
                        "param_location": str(row[3] or "query"),
                        "param_type": str(row[4] or "string"),
                        "risk_score": float(row[5] or 0),
                    }
                )
        return out

    def list_known_endpoints(self, target: str, run_id: str = "", limit: int = 500) -> list[str]:
        if not self.enabled:
            return []
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        safe_limit = max(1, min(int(limit), 5000))
        out: set[str] = set()
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select node_key
                from attack_graph_nodes
                where target=%s and node_type='endpoint'
                order by id desc
                limit %s
                """,
                (target, safe_limit),
            )
            for row in cur.fetchall():
                ep = _normalize_endpoint(str(row[0] or ""))
                if ep:
                    out.add(ep)

            if run_id:
                cur.execute(
                    """
                    select endpoint
                    from endpoint_parameters
                    where run_id=%s
                    order by id desc
                    limit %s
                    """,
                    (run_id, safe_limit),
                )
                for row in cur.fetchall():
                    ep = _normalize_endpoint(str(row[0] or ""))
                    if ep:
                        out.add(ep)

            cur.execute(
                """
                select payload
                from hunterops_findings
                where target=%s
                order by id desc
                limit %s
                """,
                (target, safe_limit),
            )
            rows = cur.fetchall()
            for row in rows:
                payload = row[0] if row else {}
                data: dict[str, Any] = {}
                if isinstance(payload, dict):
                    data = payload
                else:
                    try:
                        maybe = json.loads(str(payload))
                        if isinstance(maybe, dict):
                            data = maybe
                    except Exception:
                        data = {}
                if not data:
                    continue
                evidence = data.get("evidence", {}) if isinstance(data.get("evidence"), dict) else {}
                for k in ("url", "base_url", "modified_url", "endpoint", "path"):
                    v = evidence.get(k)
                    if isinstance(v, str):
                        ep = _normalize_endpoint(v)
                        if ep:
                            out.add(ep)
                req = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}
                req_url = req.get("url")
                if isinstance(req_url, str):
                    ep = _normalize_endpoint(req_url)
                    if ep:
                        out.add(ep)
                arr = evidence.get("endpoints", [])
                if isinstance(arr, list):
                    for item in arr:
                        if isinstance(item, str):
                            ep = _normalize_endpoint(item)
                            if ep:
                                out.add(ep)
        normalized = sorted([x for x in out if x and x.startswith("/")])
        return normalized[:safe_limit]

    def get_previous_run_id(self, target: str, current_run_id: str) -> str:
        if not self.enabled:
            return ""
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select run_id
                from hunterops_findings
                where target=%s and run_id<>%s
                order by id desc
                limit 1
                """,
                (target, current_run_id),
            )
            row = cur.fetchone()
        if not row:
            return ""
        return str(row[0] or "")

    def fetch_run_findings(self, run_id: str, target: str) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select payload
                from hunterops_findings
                where run_id=%s and target=%s
                order by id asc
                """,
                (run_id, target),
            )
            rows = cur.fetchall()
            for row in rows:
                payload = row[0] if row else {}
                if isinstance(payload, dict):
                    out.append(payload)
                else:
                    try:
                        out.append(json.loads(str(payload)))
                    except Exception:
                        continue
        return out
