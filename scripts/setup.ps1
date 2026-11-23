# One-command setup for Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

python -m venv .venv
. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
if (-Not (Test-Path .env)) { Copy-Item .env.example .env }

Write-Host "== smoke test =="
python -m sim.run_experiment --policies baseline invariant --runs 2 --smoke
Write-Host "== unit tests =="
python -m pytest -q
Write-Host ""
Write-Host "Ready. Activate with: .\.venv\Scripts\Activate.ps1"
Write-Host "Full sweep: python -m sim.run_experiment --policies all"
