$ErrorActionPreference = "Stop"
. "$PSScriptRoot\\common.ps1"
$py = Resolve-PythonExe

& $py --version
& $py -m pip install -r requirements.txt
& $py -m playwright install chromium

Write-Host "Setup completed"
