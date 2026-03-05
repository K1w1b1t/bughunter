# Governance Standards

## Mandatory Baseline
- OWASP WSTG
- OWASP ASVS
- OWASP API Top 10
- MITRE ATT&CK
- CWE
- CVSS v3.1

## Single Control Matrix
- Source of truth: `config/control-matrix.yaml`
- Every test scenario must map to:
  - one control id
  - at least one OWASP reference
  - one or more CWE entries
  - CVSS scoring
  - MITRE ATT&CK technique when applicable

## Finding Mapping Requirements
Each finding must include:
- `taxonomy.cwe`
- `taxonomy.cvss.vector` and `taxonomy.cvss.base_score`
- `taxonomy.mitre_attack` object
- `asset` and `surface`
- validated `business_impact.statement`

## Quality Gate
Use `scripts/quality_gate.py` before submission.

Mandatory pass criteria:
- in-scope confirmed
- reproduction at 100%
- complete evidence chain
- evidence hash matches artifacts
- real business impact proven
- anti-false-positive checks passed
- probable duplicate check passed (exact + semantic)

## Evidence Chain
Required metadata:
- request file
- response file
- UTC timestamp
- SHA-256 hash
- tool versions

Store artifacts under `data/evidence/<finding-id>/`.

## Coverage and Backlog
Use `scripts/coverage_and_kpi.py` weekly.
- Measures per-program coverage for surfaces, OWASP refs, MITRE techniques.
- Emits gap backlog automatically in `data/findings/backlog_gaps.json`.

## KPI Cadence
Weekly KPI outputs:
- acceptance rate
- duplicate rate
- average time to submission
- payout per hour
