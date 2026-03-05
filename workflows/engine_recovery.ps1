$ErrorActionPreference = "Stop"
. "$PSScriptRoot\\common.ps1"
$py = Resolve-PythonExe

try {
  & $py main.py --config config/engine.yaml --full-scan --targets-file data/targets/in_scope_hosts.txt --out-dir data/reports/engine --verbose
  if ($LASTEXITCODE -ne 0) { throw "engine failed" }
  & $py scripts/monitor_engine.py --metrics data/reports/engine/metrics.json --out data/reports/engine/alerts.json
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Engine healthy"
    exit 0
  }
}
catch {
  Write-Warning "Primary run unhealthy. Retrying with reduced scope."
}

# Recovery mode: conservative plugin subset
& $py main.py --config config/engine.yaml --targets-file data/targets/in_scope_hosts.txt --plugins recon,fingerprint,scan,cors --out-dir data/reports/engine --verbose
if ($LASTEXITCODE -ne 0) { throw "Recovery run failed" }
& $py scripts/monitor_engine.py --metrics data/reports/engine/metrics.json --out data/reports/engine/alerts.json --max-error-rate 50 --max-latency-sec 40

Write-Host "Engine recovery run completed"
