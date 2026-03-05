$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

$dailyAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$repo\workflows\daily.ps1`""
$dailyTrigger = New-ScheduledTaskTrigger -Daily -At 02:00
Register-ScheduledTask -TaskName "HunterOps-Daily" -Action $dailyAction -Trigger $dailyTrigger -Description "HunterOps daily pipeline" -Force | Out-Null

$weeklyAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$repo\workflows\weekly.ps1`""
$weeklyTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 03:00
Register-ScheduledTask -TaskName "HunterOps-Weekly" -Action $weeklyAction -Trigger $weeklyTrigger -Description "HunterOps weekly KPI and curation" -Force | Out-Null

$engineAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$repo\workflows\engine_daily.ps1`""
$engineTrigger = New-ScheduledTaskTrigger -Daily -At 01:00
Register-ScheduledTask -TaskName "HunterOps-Engine-Daily" -Action $engineAction -Trigger $engineTrigger -Description "HunterOps professional engine daily run" -Force | Out-Null

$recoveryAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$repo\workflows\engine_recovery.ps1`""
$recoveryTrigger = New-ScheduledTaskTrigger -Daily -At 04:00
Register-ScheduledTask -TaskName "HunterOps-Engine-Recovery" -Action $recoveryAction -Trigger $recoveryTrigger -Description "HunterOps engine health recovery run" -Force | Out-Null

$platformAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$repo\workflows\platform_sync_job.ps1`""
$platformTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 05:00
Register-ScheduledTask -TaskName "HunterOps-Platform-Sync" -Action $platformAction -Trigger $platformTrigger -Description "HunterOps platform sync operational job" -Force | Out-Null

Write-Host "Scheduled tasks created: HunterOps-Daily, HunterOps-Weekly, HunterOps-Engine-Daily, HunterOps-Engine-Recovery, HunterOps-Platform-Sync"
