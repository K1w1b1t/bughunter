# Polyglot Extension

## Goal
Use each language where it adds strongest value:
- Go: high-throughput network scans
- Python: orchestration, analysis, validation, reporting
- Node/TypeScript: SPA/GraphQL/browser automation
- Rust: fast and safe critical parsers/analyzers
- C/C++: low-level and native experiments
- Lua/Nmap: rapid protocol/network scripts
- Java/Kotlin: enterprise/JVM surface analysis
- R: statistical payout/acceptance analysis
- SQL/Postgres: persistent memory for KPIs and feedback

## Current Integration
- Engine plugin: `hunterops/plugins/polyglot_stack.py`
- Runtime commands: `config/engine.yaml -> modules.polyglot_stack.commands`
- Tool locations:
  - `tools/node/spa_probe.mjs`
  - `tools/rust-analyzer/`
  - `tools/native/`
  - `tools/lua/nmap_quick_scan.nse`
  - `tools/jvm/`
  - `tools/r/analytics.R`

## Postgres
- Enable in `config/engine.yaml`:
  - `storage.postgres.enabled: true`
- Set env:
  - `HUNTEROPS_POSTGRES_DSN`

## Notes
- Missing runtime/toolchain does not break pipeline.
- Polyglot plugin skips unavailable commands safely.
