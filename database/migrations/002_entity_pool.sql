-- HunterOps research expansion: Global Entity Pool for cross-pollination.

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
);

create index if not exists idx_discovered_entities_target_last_seen
  on discovered_entities (target, last_seen desc);

create index if not exists idx_discovered_entities_type
  on discovered_entities (entity_type);
