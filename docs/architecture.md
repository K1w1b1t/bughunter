# Architecture

## Pipeline
1. Intake
- Candidate hosts and URLs enter `data/targets/`.

2. Scope enforcement
- `scope_guard.py` filters everything to approved targets.

3. Recon and enrichment
- `recon_pipeline.py` executes discovery tools and stores raw outputs by date.

4. Normalization
- Normalize outputs into canonical host/url/entity lists in `data/processed/`.

5. Finding triage
- Raw findings are deduplicated and prioritized.

6. Report generation
- `generate_report.py` converts structured finding JSON into report drafts.

## Data Design
- `data/raw/YYYY-MM-DD/`: immutable command outputs.
- `data/processed/`: normalized datasets for analysis.
- `data/findings/`: candidate and triaged findings.
- `data/reports/`: report drafts and final versions.

## Reliability Controls
- Every output file has timestamp and source tool metadata.
- Failed tool runs do not break entire pipeline.
- Missing tools are reported with explicit warning.
