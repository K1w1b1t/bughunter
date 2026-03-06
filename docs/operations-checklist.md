# Operations Checklist

## Daily
1. Run `python scripts/research_pipeline.py --config config/engine.yaml --out-dir /opt/hunterops/reports/research`
2. Review `data/reports/delta_recon.json` and `data/reports/daily_priority_queue.json`
3. Validate top findings with `scripts/quality_gate.py`
4. Generate report drafts and submit only `PASS` findings

## Weekly
1. Run `python scripts/coverage_and_kpi.py`
2. Review:
- `data/reports/coverage_report.json`
- `data/findings/backlog_gaps.json`
- `data/reports/weekly_kpis.json`
- `data/reports/top_priority_queue.json`
3. Convert top gaps into next-week hunting tasks
4. Re-run `scripts/setup_linux.sh` after environment/path changes

## Submission Standard
- In-scope confirmed
- Reproduction 100%
- Evidence chain complete
- Business impact validated
- Duplicate probability low
