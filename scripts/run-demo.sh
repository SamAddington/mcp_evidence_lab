#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 run_lab.py --scenario baseline
python3 analyze.py --latest baseline
python3 run_lab.py --scenario attack
python3 analyze.py --latest attack

