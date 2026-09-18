# Backward-compatible alias: use scr-victim-sim.ps1 for new demos.
param(
  [ValidateSet("atk1", "atk2", "atk2-safe")]
  [string]$Attack = "atk1"
)
& (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "scr-victim-sim.ps1") -Attack $Attack
