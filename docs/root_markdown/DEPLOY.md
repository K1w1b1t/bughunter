# HunterOps Predator Deployment Guide (Ubuntu 22.04/24.04)

## 1) Clone and permissions
```bash
git clone <YOUR_REPO_URL> /opt/hunterops
cd /opt/hunterops
chmod +x scripts/*.sh
```

## 2) Production environment file
```bash
cp .env.production .env
nano .env
```

Fill at minimum:
- `H1_API_IDENTIFIER`
- `H1_API_TOKEN`
- `HACKERONE_API_TOKEN`
- `HUNTEROPS_POSTGRES_DSN`
- `HUNTEROPS_REDIS_URL`
- `HUNTEROPS_DISCORD_RESEARCH_WEBHOOK`
- `HUNTEROPS_DISCORD_CRITICAL_WEBHOOK`
- `HUNTEROPS_SLACK_RESEARCH_WEBHOOK`
- `HUNTEROPS_SLACK_CRITICAL_WEBHOOK`

## 3) Infrastructure
```bash
docker compose up -d
```

## 4) Bootstrap
```bash
./scripts/setup_linux.sh
```

## 5) Alert diagnostics (dry run)
This bypasses recon/scan and validates Discord+Slack dispatch, rich embed formatting, impact routing, and Discord `.md` PoC upload.
```bash
python scripts/research_pipeline.py --alert-dry-run
```

## 6) Full hunt (massive scan example)
Replace `api.target.tld` with an in-scope HackerOne asset.
```bash
python scripts/research_pipeline.py \
  --config config/engine.yaml \
  --target api.target.tld \
  --plugins deep_js_intelligence,parameter_intelligence,business_logic_sniper,race_condition_turbo,differential_auth_prover,vulnerability_correlation_engine,logic_prover,auth_matrix_engine,entity_cross_pollinator,report_synthesis,evidence_packager \
  --out-dir /opt/hunterops/reports/research \
  --verbose
```

## 7) Container health and logs
```bash
docker compose ps
docker compose logs -f app
docker compose logs -f db redis
```

`scripts/check_infra.sh` is executed by the container entrypoint before engine start (disable only if needed with `HUNTEROPS_SKIP_INFRA_CHECK=1`).
