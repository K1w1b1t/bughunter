SHELL := /bin/bash
PYTHON := python3

ifeq ($(OS),Windows_NT)
PYTHON := python
endif

.PHONY: sign-scope verify-scope test e2e start-observability go-no-go calibrate-thresholds runbook-pause runbook-resume runbook-reduce-rate runbook-block-host

sign-scope:
	$(PYTHON) -c "from pathlib import Path; import shutil; Path('examples').mkdir(parents=True, exist_ok=True); src=Path('examples/scope_unsigned.json'); src.exists() or shutil.copyfile('config/scope.json.example', src)"
	$(PYTHON) -c "from pathlib import Path; import secrets; key=Path('config/signer.key'); key.exists() or key.write_text(secrets.token_hex(32), encoding='utf-8')"
	$(PYTHON) tools/sign_scope.py --input examples/scope_unsigned.json --output examples/scope_signed.json --algo hmac-sha256 --key config/signer.key

verify-scope:
	$(PYTHON) tools/verify_scope.py examples/scope_signed.json

test:
	PYTHONPATH=/opt/hunterops .venv/bin/pytest -q

e2e:
	docker compose -f examples/mockserver/docker-compose.yml up -d
	MOCKSERVER_URL=http://localhost:8008 PYTHONPATH=/opt/hunterops .venv/bin/pytest -q tests/test_pipeline_e2e.py

start-observability:
	docker compose -f observability/docker-compose.yml up -d

go-no-go:
	PYTHONPATH=/opt/hunterops .venv/bin/python tools/go_no_go.py --config attack_pipeline.yaml

calibrate-thresholds:
	PYTHONPATH=/opt/hunterops .venv/bin/python tools/calibrate_thresholds.py examples/labeled_scan_results.csv --report reports/threshold_recommendation.md --pdf reports/threshold_recommendation.pdf

runbook-pause:
	PYTHONPATH=/opt/hunterops .venv/bin/python tools/runbook_action.py pause --minutes 15 --reason "manual_pause"

runbook-resume:
	PYTHONPATH=/opt/hunterops .venv/bin/python tools/runbook_action.py resume

runbook-reduce-rate:
	PYTHONPATH=/opt/hunterops .venv/bin/python tools/runbook_action.py reduce-rate --multiplier 0.5 --minutes 20

runbook-block-host:
	PYTHONPATH=/opt/hunterops .venv/bin/python tools/runbook_action.py block-host example.com --minutes 15
