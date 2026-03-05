function Resolve-PythonExe {
    $candidates = @(
        "python",
        "py",
        "$env:LocalAppData\Programs\Python\Python314\python.exe",
        "$env:LocalAppData\Programs\Python\Python313\python.exe",
        "$env:LocalAppData\Programs\Python\Python312\python.exe",
        "$env:LocalAppData\Programs\Python\Python311\python.exe"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -in @("python", "py")) {
            $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($cmd -and $cmd.Source -notlike "*WindowsApps*") {
                return $candidate
            }
            continue
        }

        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "Python executable not found. Install Python 3.11+ and disable Microsoft Store python alias if needed."
}
