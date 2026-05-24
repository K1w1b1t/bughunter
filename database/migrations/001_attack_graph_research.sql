-- HunterOps research schema migration (attack graph + object relationships + endpoint parameters)

ALTER TABLE hunterops_findings
ADD COLUMN IF NOT EXISTS discovery_source TEXT DEFAULT '',
ADD COLUMN IF NOT EXISTS confidence_score DOUBLE PRECISION DEFAULT 0;

CREATE TABLE IF NOT EXISTS endpoint_parameters (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  param_name TEXT NOT NULL,
  param_location TEXT NOT NULL,
  param_type TEXT NOT NULL,
  risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
  discovery_source TEXT NOT NULL DEFAULT '',
  evidence_ref TEXT DEFAULT '',
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(run_id, endpoint, method, param_name, param_location)
);

CREATE TABLE IF NOT EXISTS objects (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  source_endpoint TEXT NOT NULL,
  confidence_score DOUBLE PRECISION NOT NULL,
  discovery_source TEXT NOT NULL,
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS object_relationships (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  parent_object_type TEXT NOT NULL,
  parent_object_key TEXT NOT NULL,
  child_object_type TEXT NOT NULL,
  child_object_key TEXT NOT NULL,
  relation_type TEXT NOT NULL,
  confidence_score DOUBLE PRECISION NOT NULL,
  evidence_ref TEXT,
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attack_graph_nodes (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  node_type TEXT NOT NULL,
  node_key TEXT NOT NULL,
  target TEXT NOT NULL,
  discovery_source TEXT NOT NULL DEFAULT '',
  confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(run_id, node_type, node_key, target)
);

CREATE TABLE IF NOT EXISTS attack_graph_edges (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  src_node_id BIGINT NOT NULL REFERENCES attack_graph_nodes(id) ON DELETE CASCADE,
  dst_node_id BIGINT NOT NULL REFERENCES attack_graph_nodes(id) ON DELETE CASCADE,
  edge_type TEXT NOT NULL,
  confidence_score DOUBLE PRECISION NOT NULL,
  evidence_ref TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attack_paths (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  path_type TEXT NOT NULL,
  path_nodes JSONB NOT NULL,
  confidence_score DOUBLE PRECISION NOT NULL,
  evidence_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hunterops_scan_state (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  plugin TEXT NOT NULL,
  target TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(run_id, plugin, target, endpoint)
);
