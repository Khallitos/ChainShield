# Attacker-side listener for live presentation (real PowerShell window).
# Usage:  .\scripts\attacker-listen.ps1
# Requires: backend running on port 8000 (uvicorn app.main:app --port 8000)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host ""
Write-Host "Open this window on the ATTACKER screen, exfil prints here, not in the browser." -ForegroundColor Gray
Write-Host ""

Set-Location $Root

$listenerArgs = @("--port", "8000", "--path", "/v1/lab/install-alert") + $args

$venvPy = Join-Path $Root "backend\.venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    & $venvPy "$Root\scripts\attacker_listener.py" @listenerArgs
    exit $LASTEXITCODE
}

$py = Get-Command python -ErrorAction SilentlyContinue
if ($py) {
    python "$Root\scripts\attacker_listener.py" @listenerArgs
    exit $LASTEXITCODE
}

$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
    node "$Root\scripts\attacker-listener.mjs" @listenerArgs
    exit $LASTEXITCODE
}

Write-Host "ERROR: Install Python or Node.js to run the attacker listener." -ForegroundColor Red
exit 1
