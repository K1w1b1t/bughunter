# HunterOps Engine (Professional)

## CLI
Example:
`python main.py --target example.com --full-scan`

Multi-target:
`python main.py --targets-file data/targets/in_scope_hosts.txt --full-scan`

## What It Implements
1. Central config (`config/engine.yaml`)
2. Dynamic plugin system (`hunterops/plugins`)
3. Professional CLI (`main.py`)
4. Structured logs (JSON file + colored terminal)
5. Global exception fail-safe
6. Async execution with internal queue
7. Automatic rate limiting
8. Retry with exponential backoff
9. Internal task queue
10. Multi-target parallel mode
11. Auto deduplication
12. Heuristic risk scoring
13. Sensitive pattern detector
14. HTTP response anomaly parser
15. Baseline comparison report
16. Cookie/token capture (Playwright plugin)
17. Browser automation (headless)
18. Request interceptor for hidden endpoints
19. Report generation (Markdown/HTML)
20. Export JSON/CSV/Markdown/HTML
21. Fingerprint plugin
22. Subdomain takeover plugin
23. CORS misconfiguration plugin
24. Stealth mode support (UA/proxy rotation)
25. HackerOne/Bugcrowd API sync plugin (env-driven)
26. Massive surface discovery (subdomains, wayback, params, JS)
27. Intelligent crawler (dynamic params, JS route extraction)
28. Smart fuzz filter (size/structure/behavior delta)
29. Auth vs unauth comparator
30. Automated IDOR parameter mutation tests
31. Role-based access comparison (user/admin)
32. Sensitive endpoint detector
33. Sensitive data detector (email, CPF, JWT, keys)
34. Token/auth robustness tests
35. Undocumented API discovery (JS/OpenAPI/Swagger/GraphQL)
36. GraphQL scanner (introspection/access signal)
37. Basic race-condition detector
38. Payment logic surface parser
39. Deep endpoint analysis mode (methods/params variations)
40. Executive dashboard (`dashboard.html`)
41. Polyglot execution bridge (Node/Rust/JVM/R integration)
42. Optional Postgres persistence for historical memory
43. Program-pack targeting (critical endpoints, per-program checks, per-program wordlists)
44. Delta-first queue prioritization
45. Session/role baseline tracking
46. Automatic PoC kit generation for high-value classes
47. Strict OPSEC mode and mandatory secrets for production runs

## Outputs
`data/reports/engine/`
- `findings.json`
- `findings.csv`
- `findings.md`
- `findings.html`
- `findings.jsonl`
- `baseline.json`
- `baseline_diff.json`
- `engine_<timestamp>.jsonl` (structured logs)
- `metrics.json`
- `alerts.json`
- `impact_validated.json`
- `platform_sync.json`
- `run_audit.json`
- `delta_first_queue.json`
- `role_baseline.json`
- `role_baseline_diff.json`
- `poc_kits/`
- Postgres table: `hunterops_findings` (mandatory when enabled)


## Notes
- Only run against authorized in-scope targets.
- Platform API sync requires:
  - `HACKERONE_API_USER`
  - `HACKERONE_API_TOKEN`
  - `BUGCROWD_API_TOKEN`
  - optional: `HACKERONE_PROGRAM_HANDLE` for scope sync
- Multi-account auth testing requires:
  - `data/sessions.yaml` with `token_env`/`cookie_env`
  - corresponding env vars set in runtime environment
