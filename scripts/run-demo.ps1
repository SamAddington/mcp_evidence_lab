$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
python run_lab.py --scenario baseline
python analyze.py --latest baseline
python run_lab.py --scenario attack
python analyze.py --latest attack

