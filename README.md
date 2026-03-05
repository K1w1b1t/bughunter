# HunterOps - Bug Bounty Automation Stack

Professional bug bounty operations framework for authorized programs only.

## Core Principles
- Test only in-scope targets and follow each program policy.
- Keep full evidence for every action and finding.
- Prioritize signal quality over scan volume.
- Always prove impact, not only potential.

## Project Layout
- `config/`: programs, risk model, and tool settings.
- `data/`: targets, raw outputs, normalized assets, findings, reports.
- `docs/`: architecture, roadmap, operating standards.
- `ops/`: rules of engagement and daily operating routine.
- `scripts/`: automation scripts for scope filtering, orchestration, dedupe, reporting.
- `templates/`: report and scanner templates.
- `workflows/`: repeatable execution workflows.

## Quick Start
0. Professional engine full scan:
   - `python main.py --target example.com --full-scan`
   - `python main.py --targets-file data/targets/in_scope_hosts.txt --full-scan`
1. Fill `config/programs.yaml` with your real programs and scopes.
2. Add candidate targets to `data/targets/candidate_hosts.txt`.
3. Filter scope:
   - `python scripts/scope_guard.py --program all --in data/targets/candidate_hosts.txt --out data/targets/in_scope_hosts.txt`
4. Run orchestrated pipeline (Python controlling external tools):
   - `python scripts/main.py --in data/targets/in_scope_hosts.txt --wordlist wordlists/common.txt`
5. Delta recon (new assets/endpoints/ports/stack):
   - `python scripts/delta_recon.py --today 2026-03-04`
6. Endpoint/parameter catalog and clustering:
   - `python scripts/endpoint_pipeline.py --date 2026-03-04`
7. Authenticated surface collection (when profile auth enabled):
   - `python scripts/playwright_auth_runner.py --date 2026-03-04`
8. Generate business-logic hypotheses:
   - `python scripts/business_logic_hypotheses.py`
9. Dedupe findings:
   - `python scripts/dedupe_findings.py --in data/findings/raw_findings.jsonl --out data/findings/triaged_findings.jsonl`
10. Build daily top queue:
   - `python scripts/priority_queue.py`
11. Generate final report draft:
   - `python scripts/generate_report.py --template templates/reports/bug_report.md --finding data/findings/sample_finding.json --out data/reports/sample_report.md`
12. Run pre-submission quality gate:
   - `python scripts/quality_gate.py --finding data/findings/sample_finding.json`
13. Run weekly coverage, gaps, KPI and priority queue:
   - `python scripts/coverage_and_kpi.py --week-start 2026-03-02`
14. Curate nuclei templates by performance:
   - `python scripts/nuclei_curation.py`
15. Build CVE catalog (local files or feed fetch):
   - `python scripts/cve_feed_update.py --out data/processed/cve_catalog.json`
16. Build CVE top queue from engine findings:
   - `python scripts/cve_prioritized_queue.py --findings data/reports/engine/findings.json`

## Professional Engine
- Config: `config/engine.yaml`
- Core package: `hunterops/`
- Plugins: `hunterops/plugins/`
- Docs: `docs/engine-professional.md`
- Multi-account auth profiles: `data/sessions.yaml`
- Polyglot modules: `tools/node`, `tools/rust-analyzer`, `tools/native`, `tools/lua`, `tools/jvm`, `tools/r`
- Optional persistent storage: Postgres via `HUNTEROPS_POSTGRES_DSN`
- Program packs: `config/program_packs.yaml`
- CVE catalog (NVD/KEV/EPSS normalized): `data/processed/cve_catalog.json`

## Governance Baseline
- Formal matrix file: `config/control-matrix.yaml`
- Required finding schema: `config/finding_schema.json`
- Governance playbook: `docs/governance-standards.md`
- Hybrid stack strategy: `docs/hybrid-stack-strategy.md`

## Professional Quality Gate Checklist
- In-scope confirmed
- Reproduction 100%
- Evidence complete (request/response, timestamp, hash, tools)
- Business impact validated
- Duplicate likelihood low

## Required External Tools
- `subfinder`, `amass`, `assetfinder`, `dnsx`, `httpx`, `katana`, `hakrawler`, `gospider`
- `ffuf`, `gobuster`, `wfuzz`, `dirsearch`
- `nuclei`, `dalfox`, `sqlmap`, `XSStrike`, `commix`
- `playwright` runtime for authenticated workflows (`python -m playwright install chromium`)
- `python 3.11+`

## Setup
- Copy `.env.example` to `.env` and fill credentials.
- Fill `data/sessions.yaml` with user/admin session tokens or cookies for auth/role tests.
- Install Python dependencies:
  - `pip install -r requirements.txt`
 - Run automated framework tests:
   - `python -m unittest discover -s tests -p \"test_*.py\"`
 - Optional JS deps:
   - `cd tools/node && npm install`

## Windows Workflows
- Environment setup:
  - `powershell -ExecutionPolicy Bypass -File workflows/setup.ps1`
- Daily operation:
  - `powershell -ExecutionPolicy Bypass -File workflows/daily.ps1`
- Weekly coverage/KPI:
  - `powershell -ExecutionPolicy Bypass -File workflows/weekly.ps1`
- 24/7 scheduler setup:
  - `powershell -ExecutionPolicy Bypass -File workflows/scheduler_setup.ps1`
- Engine daily run:
  - `powershell -ExecutionPolicy Bypass -File workflows/engine_daily.ps1`
- Engine recovery run:
  - `powershell -ExecutionPolicy Bypass -File workflows/engine_recovery.ps1`
 - Platform sync operational job:
  - `powershell -ExecutionPolicy Bypass -File workflows/platform_sync_job.ps1`
 - CI (Windows):
  - `powershell -ExecutionPolicy Bypass -File scripts/ci/ci.ps1`

Notes:
- `platform_sync` is operational and runs outside the hunting pipeline.
- `engine_daily` runs strict OPSEC by default and requires secrets + Postgres DSN.
- CI can bypass mandatory DB by setting `HUNTEROPS_DB_OPTIONAL=1`.

These workflows auto-detect a real Python install and avoid the Windows Store alias issue.

## Safety
This stack is designed for authorized bug bounty workflows. Do not run against non-authorized targets.
