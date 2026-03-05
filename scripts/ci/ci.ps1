$ErrorActionPreference = "Stop"
. "$PSScriptRoot\\..\\..\\workflows\\common.ps1"
$py = Resolve-PythonExe

$env:HUNTEROPS_USER_TOKEN = "ci_dummy"
$env:HUNTEROPS_USER_B_TOKEN = "ci_dummy"
$env:HUNTEROPS_ADMIN_TOKEN = "ci_dummy"
$env:HUNTEROPS_DB_OPTIONAL = "1"

& $py -m unittest discover -s tests -p "test_*.py"
if ($LASTEXITCODE -ne 0) { throw "Unit tests failed" }
& $py scripts/opsec_check.py --sessions data/sessions.yaml --programs config/programs.yaml --out data/reports/opsec_check.json
if ($LASTEXITCODE -ne 0) { throw "OPSEC check failed" }
& $py main.py --config config/engine.yaml --targets-file data/targets/in_scope_hosts.txt --out-dir data/reports/engine
if ($LASTEXITCODE -ne 0) { throw "Main engine run failed" }
& $py scripts/monitor_engine.py --metrics data/reports/engine/metrics.json --out data/reports/engine/alerts.json --critical-plugins none --min-throughput 0
if ($LASTEXITCODE -ne 0) { throw "Monitor check failed" }

Write-Host "CI pipeline completed"
