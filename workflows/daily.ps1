$ErrorActionPreference = "Stop"
$today = Get-Date -Format "yyyy-MM-dd"
$yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
. "$PSScriptRoot\\common.ps1"
$py = Resolve-PythonExe

& $py scripts/scope_guard.py --program all --in data/targets/candidate_hosts.txt --out data/targets/in_scope_hosts.txt
& $py scripts/main.py --in data/targets/in_scope_hosts.txt --date $today --wordlist wordlists/common.txt
& $py scripts/delta_recon.py --today $today --yesterday $yesterday
& $py scripts/endpoint_pipeline.py --date $today
& $py scripts/playwright_auth_runner.py --date $today
& $py scripts/business_logic_hypotheses.py
& $py scripts/dedupe_findings.py --in data/findings/raw_findings.jsonl --out data/findings/triaged_findings.jsonl
& $py scripts/priority_queue.py

Write-Host "Daily workflow completed for $today"
