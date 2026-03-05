$ErrorActionPreference = "Stop"
. "$PSScriptRoot\\common.ps1"
$py = Resolve-PythonExe

& $py scripts/opsec_check.py --sessions data/sessions.yaml --programs config/programs.yaml --out data/reports/opsec_check.json --strict-secrets
if ($LASTEXITCODE -ne 0) { throw "OPSEC check failed" }

if (-not [bool](Get-Item -Path "env:HUNTEROPS_POSTGRES_DSN" -ErrorAction SilentlyContinue).Value) {
  throw "Missing HUNTEROPS_POSTGRES_DSN for mandatory Postgres mode"
}

& $py scripts/cve_feed_update.py --out data/processed/cve_catalog.json
if ($LASTEXITCODE -ne 0) { throw "CVE feed update failed" }

& $py main.py --config config/engine.yaml --full-scan --targets-file data/targets/in_scope_hosts.txt --out-dir data/reports/engine --verbose
if ($LASTEXITCODE -ne 0) { throw "Engine scan failed with exit code $LASTEXITCODE" }

& $py scripts/feedback_loop.py --submissions data/findings/submissions.jsonl --findings data/reports/engine/findings.json --out data/processed/feedback_weights.json
if ($LASTEXITCODE -ne 0) { throw "Feedback loop failed" }

& $py scripts/calibrate_profiles.py --profiles config/program_profiles.yaml --submissions data/findings/submissions.jsonl --out config/program_profiles.calibrated.yaml
if ($LASTEXITCODE -ne 0) { throw "Program calibration failed" }

& $py scripts/impact_validation.py --findings data/reports/engine/findings.json --out data/reports/engine/impact_validated.json
if ($LASTEXITCODE -ne 0) { throw "Impact validation failed" }

& $py scripts/role_baseline.py --findings data/reports/engine/findings.json --baseline data/reports/engine/role_baseline.json --out-diff data/reports/engine/role_baseline_diff.json
if ($LASTEXITCODE -ne 0) { throw "Role baseline update failed" }

& $py scripts/delta_first_queue.py --findings data/reports/engine/findings.json --baseline-diff data/reports/engine/baseline_diff.json --out data/reports/engine/delta_first_queue.json
if ($LASTEXITCODE -ne 0) { throw "Delta-first queue generation failed" }

& $py scripts/cve_prioritized_queue.py --findings data/reports/engine/findings.json --out data/reports/engine/cve_priority_queue.json --top-n 25
if ($LASTEXITCODE -ne 0) { throw "CVE priority queue generation failed" }

& $py scripts/generate_poc_kit.py --findings data/reports/engine/impact_validated.json --out-dir data/reports/engine/poc_kits --top-n 15
if ($LASTEXITCODE -ne 0) { throw "PoC kit generation failed" }

& $py scripts/monitor_engine.py --metrics data/reports/engine/metrics.json --out data/reports/engine/alerts.json
if ($LASTEXITCODE -ne 0) { Write-Warning "Engine alerts detected. Use workflows/engine_recovery.ps1" }

Write-Host "Engine daily run completed"
