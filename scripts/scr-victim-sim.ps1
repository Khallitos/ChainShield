# SCR Victim Sim: Supply Chain Security Lab
# Simulates a developer installing a dependency (runs postinstall + attacker alert).
param(
  [ValidateSet("atk1", "atk2", "atk2-safe")]
  [string]$Attack = "atk1"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

if (-not $env:DEMO_SECRET) { $env:DEMO_SECRET = "demo-api-key-7f3a" }

switch ($Attack) {
  "atk1" { $Dir = Join-Path $Root "demo-site\lab-victim-typo-only"; $Pkg = "training-leder"; $Label = "ATK1 typosquat" }
  "atk2" { $Dir = Join-Path $Root "demo-site\lab-victim-dep-confusion\confused"; $Pkg = "corp-internal-ledger-api"; $Label = "ATK2 dependency confusion" }
  "atk2-safe" { $Dir = Join-Path $Root "demo-site\lab-victim-dep-confusion\safe"; $Pkg = "corp-internal-ledger-api (internal)"; $Label = "ATK2 safe baseline" }
}

Write-Host "╔══════════════════════════════════════════════════════════╗"
Write-Host "║  SCR Victim Sim, Supply Chain Security Lab              ║"
Write-Host "╚══════════════════════════════════════════════════════════╝"
Write-Host "  Scenario : $Label"
Write-Host "  Package  : $Pkg"
Write-Host "  DEMO_SECRET=$env:DEMO_SECRET"
Set-Location $Dir
node (Join-Path $Root "scripts\scr-npm.mjs") install --training-setup
Write-Host ""
Write-Host "✓ SCR Victim Sim complete. Check attacker PowerShell for beacon / exfil output."
