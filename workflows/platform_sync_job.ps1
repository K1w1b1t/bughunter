$ErrorActionPreference = "Stop"
. "$PSScriptRoot\\common.ps1"
$py = Resolve-PythonExe

& $py main.py --config config/engine.yaml --target platforms.local --plugins platform_sync --out-dir data/reports/platform_sync --verbose
if ($LASTEXITCODE -ne 0) { throw "Platform sync run failed" }

& $py scripts/platform_sync_export.py --findings data/reports/platform_sync/findings.json --out data/reports/platform_sync/platform_sync.json
if ($LASTEXITCODE -ne 0) { throw "Platform sync export failed" }

Write-Host "Platform sync job completed"
