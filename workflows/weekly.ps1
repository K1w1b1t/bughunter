$ErrorActionPreference = "Stop"
$weekStart = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")
. "$PSScriptRoot\\common.ps1"
$py = Resolve-PythonExe

& $py scripts/coverage_and_kpi.py --week-start $weekStart
& $py scripts/nuclei_curation.py

Write-Host "Weekly coverage/KPI workflow completed from $weekStart"
