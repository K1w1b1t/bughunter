# Operations Checklist

## Daily
1. Run `workflows/daily.ps1`
2. Review `data/reports/delta_recon.json` and `data/reports/daily_priority_queue.json`
3. Validate top findings with `scripts/quality_gate.py`
4. Generate report drafts and submit only `PASS` findings

## Weekly
1. Run `workflows/weekly.ps1`
2. Review:
- `data/reports/coverage_report.json`
- `data/findings/backlog_gaps.json`
- `data/reports/weekly_kpis.json`
- `data/reports/top_priority_queue.json`
3. Convert top gaps into next-week hunting tasks
4. Re-run `workflows/scheduler_setup.ps1` after environment/path changes

## Submission Standard
- In-scope confirmed
- Reproduction 100%
- Evidence chain complete
- Business impact validated
- Duplicate probability low
