# Reset lab victim folders for a fresh presentation (Windows).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$Victims = @(
  "demo-site\lab-victim-typo-only",
  "demo-site\lab-victim-dep-confusion\confused",
  "demo-site\lab-victim-dep-confusion\safe"
)

Write-Host "==> Resetting lab victim installs…"
foreach ($dir in $Victims) {
  $full = Join-Path $Root $dir
  if (Test-Path $full) {
    Write-Host "    $dir"
    $nm = Join-Path $full "node_modules"
    if (Test-Path $nm) { Remove-Item -Recurse -Force $nm }
  }
}

$LabDir = Join-Path $env:USERPROFILE ".supply-chain-lab"
if (Test-Path $LabDir) {
  Write-Host "==> Clearing forensic cache…"
  Remove-Item -Force (Join-Path $LabDir "last-atk*.json") -ErrorAction SilentlyContinue
}

try {
  $null = Invoke-WebRequest -Uri "http://127.0.0.1:8000/v1/health" -UseBasicParsing -TimeoutSec 2
  # /v1/trust/baseline/rebuild is operator-only (it overwrites the trust
  # baseline that backs the install decision). Present the same local operator
  # token the server expects: $env:CHAINSHIELD_LOCAL_TOKEN, else backend\.chainshield-local-token.
  $Token = $env:CHAINSHIELD_LOCAL_TOKEN
  $TokenFile = Join-Path $Root "backend\.chainshield-local-token"
  if (-not $Token -and (Test-Path $TokenFile)) {
    $Token = (Get-Content $TokenFile -Raw).Trim()
  }
  if (-not $Token) {
    Write-Host "    (no operator token - skipping authenticated trust rebuild; set CHAINSHIELD_LOCAL_TOKEN)"
  } else {
    Write-Host "==> Rebuilding trust baseline…"
    Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/v1/trust/baseline/rebuild" `
      -Headers @{ Authorization = "Bearer $Token" }
  }
} catch {
  Write-Host "    (backend not running, skip trust rebuild)"
}

Write-Host ""
Write-Host "Demo reset complete."
Write-Host "Next: start backend, frontend, attacker-listen.ps1, then run-victim-install.ps1 atk1"
