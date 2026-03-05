#!/usr/bin/env bash
set -euo pipefail

export HUNTEROPS_USER_TOKEN="ci_dummy"
export HUNTEROPS_USER_B_TOKEN="ci_dummy"
export HUNTEROPS_ADMIN_TOKEN="ci_dummy"
export HUNTEROPS_DB_OPTIONAL="1"

python -m unittest discover -s tests -p "test_*.py"
python scripts/opsec_check.py --sessions data/sessions.yaml --programs config/programs.yaml --out data/reports/opsec_check.json
python main.py --config config/engine.yaml --targets-file data/targets/in_scope_hosts.txt --out-dir data/reports/engine
python scripts/monitor_engine.py --metrics data/reports/engine/metrics.json --out data/reports/engine/alerts.json --critical-plugins none --min-throughput 0

echo "CI pipeline completed"
