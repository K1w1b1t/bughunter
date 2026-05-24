# 📋 HUNTEROPS-AI: QUICK REFERENCE & CHECKLIST

**Guia rápido para validação e deployment do sistema definitivo**

---

## 🎯 EXECUTIVE SUMMARY

### O que é o HunterOps-AI System Prompt?

Um conjunto de **regras não negociáveis** que governa como a IA inteligente do HunterOps decide:

1. **QUANDO ATACAR** → Validação de escopo + confirmação de permissão
2. **ONDE ATACAR** → Priorização por probabilidade de sucesso  
3. **COMO ATACAR** → Sequência de ferramentas + feedback adaptativo
4. **QUANDO PARAR** → Circuit breakers + compliance checks
5. **COMO COMUNICAR** → Alertas estruturados + observabilidade

### Garantias Criadas:

✅ **Zero violações de escopo** (hard abort se domínio não autorizado)  
✅ **Compliance automático** (rate limiting, secrets redaction)  
✅ **High-confidence findings** (LLM triage + heurística = 80%+ confiança)  
✅ **Observabilidade total** (Discord alerts + audit logs)  
✅ **Feedback loops adaptativos** (agressividade escala automaticamente)

---

## 📁 ARQUIVOS CRIADOS

| Arquivo | Propósito | Para Quem |
|---|---|---|
| **SYSTEM_PROMPT.md** | Definição completa do "cérebro" da IA | Dev team + Orientador |
| **IMPLEMENTATION_GUIDE.md** | Como codificar em Python + LLM | Dev team |
| **DISCORD_EXAMPLES.json** | Templates de notificações reais | DevOps + Discord admin |
| **QUICK_REFERENCE.md** (THIS FILE) | Checklists + referência rápida | Everyone |

---

## 🚀 PRE-DEPLOYMENT CHECKLIST

### FASE 1: Validação Técnica ✓

- [ ] **Scope Authorization**
  - [ ] `config/scope.json` carregável e válido
  - [ ] Assinatura criptográfica verifica
  - [ ] Padrões fnmatch testados com domínios reais
  - [ ] Datas de validade configuradas corretamente

- [ ] **Rate Limiting**
  - [ ] `global_http_rate_limit_per_sec: 10` ativo
  - [ ] `http_client.py` enforça limite
  - [ ] Backoff exponencial testado
  - [ ] Monitore consumo de créditos de API do VPS

- [ ] **PostgreSQL**
  - [ ] Container iniciando sem erros
  - [ ] Índices em `target_id, timestamp` criados
  - [ ] Backup automatizado configurado
  - [ ] Retenção de dados define corretamente

- [ ] **Tools**
  - [ ] Nuclei v3.x + templates curados validados
  - [ ] HTTPX funciona com rate-limit
  - [ ] Subfinder retorna subdomínios válidos
  - [ ] Playwright (browser) inicializa sem crash

- [ ] **LLM Integration** (novo)
  - [ ] `ANTHROPIC_API_KEY` configurada
  - [ ] LLM consegue carregar System Prompt (> 5000 chars)
  - [ ] Teste unitário passou: `pytest tests/test_system_prompt.py`
  - [ ] Timeout LLM setado para 15 segundos max

- [ ] **Discord**
  - [ ] `recon_webhook_url` respondendo com 204
  - [ ] `findings_webhook_url` respondendo com 204
  - [ ] Bot consegue postar embeds coloridos
  - [ ] Redação de secrets funcionando

### FASE 2: Compliance & Segurança ✓

- [ ] **Escopo**
  - [ ] Scope assinado digitalmente por `signer.key`
  - [ ] Nenhum test domain no scope (evitar acidentes)
  - [ ] VDP vs Bug Bounty oficial diferenciados
  - [ ] Permissão para automação checada

- [ ] **Secrets**
  - [ ] Nenhuma API key em `.yaml` em plain text
  - [ ] Todas credenciais vêm de env vars
  - [ ] `.env` está em `.gitignore`
  - [ ] Logs não contêm Bearer tokens, API keys
  - [ ] Discord webhook URLs mascaradas em debug output

- [ ] **Logging & Audit**
  - [ ] Audit log criado: `data/logs/audit_2026-03-20.log`
  - [ ] Todos eventos críticos loggados
  - [ ] Logs não expostos em Discord (exceto mensagens estruturadas)
  - [ ] Retenção de logs configurada (recomendado: 90 dias)

- [ ] **Rate Limiting as Defesa**
  - [ ] 10 req/s max enforçado globalmente
  - [ ] User-Agent randomizado
  - [ ] Delay injected entre requisições
  - [ ] Proxy VPS não compartilha IP com outros users

### FASE 3: Integrações Funcionando ✓

- [ ] **HackerOne API**
  - [ ] API credentials funcionando
  - [ ] Consegue criar DRAFT (não auto-submitter!)
  - [ ] Feedback de programa sincroniza com DB
  - [ ] Duplicatas são detectadas antes de submeter

- [ ] **State Machine**
  - [ ] Transição Recon → Exploitation testada
  - [ ] Confidence score > 0.80 dispara escalação
  - [ ] Adaptive levels funcionam (1→2→3)
  - [ ] Demoting funciona com negative feedback

- [ ] **Feedback Loop**
  - [ ] Clean rounds counter incrementa
  - [ ] Escalação automática após 1 clean round
  - [ ] Timeout > 3 dispara demoting
  - [ ] Multiple rate_limits disparam backoff

### FASE 4: Observabilidade & Alerting ✓

- [ ] **Discord Notifications**
  - [ ] Recon channel recebe descobertas
  - [ ] Findings channel recebe POCs validados
  - [ ] Cores corretas por severidade (🔴🟡🟠🔵)
  - [ ] Deduplication funciona (não flood)
  - [ ] Timezone correto (UTC nos timestamps)

- [ ] **Metrics & Health**
  - [ ] Prometheus scrape ativo (se configurado)
  - [ ] Grafana dashboard mostra métricas
  - [ ] Alertas de downtime funcionam
  - [ ] Session health checks a cada 5 min

- [ ] **Error Handling**
  - [ ] Tool crash não derruba engine
  - [ ] Circuit breaker interrompe ataque agressivo
  - [ ] Retry logic respeita timeouts
  - [ ] Fallback behavior definido (conservative vs aggressive)

---

## ⚠️ CRITICAL BOUNDARIES (Não Viole!)

```
╔════════════════════════════════════════════════════════════╗
║ LISTA DE VALIDAÇÕES OBRIGATÓRIAS                           ║
╠════════════════════════════════════════════════════════════╣
║ ✓ SEMPRE validar escopo ANTES de enviar primeiro pacote    ║
║ ✓ NUNCA fazer força bruta de credentials (brute force banned) ║
║ ✓ NUNCA DoS intencional (circuit breaker stops automatically) ║
║ ✓ NUNCA submeter automaticamente no H1 (sempre review manual) ║
║ ✓ NUNCA exponha secrets em logs/Discord                    ║
║ ✓ NUNCA exceda 10 req/s global (hard limit)                ║
║ ✓ SEMPRE respeitar rules_of_engagement do programa         ║
╚════════════════════════════════════════════════════════════╝
```

---

## 🧪 VALIDATION TESTS

### Test Suite 1: Scope Authorization (CRÍTICO)

```bash
# Test se escopo valida corretamente
cd tests/
pytest test_scope_authorization.py -v
# Output esperado: 5 passed

# Detalhes:
# ✓ Test 1: Valida domínio no scope
# ✓ Test 2: Rejeita domínio fora scope
# ✓ Test 3: Valida padrões fnmatch
# ✓ Test 4: Valida datas de expiração
# ✓ Test 5: Assinatura criptográfica verifica
```

### Test Suite 2: System Prompt Loading (CRÍTICO)

```bash
pytest test_system_prompt.py -v
# Output esperado: 3 passed

# Detalhes:
# ✓ Test 1: System prompt carrega sem erros
# ✓ Test 2: Contém seções críticas
# ✓ Test 3: LLM consegue processar
```

### Test Suite 3: State Machine (CRÍTICO)

```bash
pytest test_attack_state_machine.py -v
# Output esperado: 6 passed

# Detalhes:
# ✓ Test 1: Transição Recon → Valid
# ✓ Test 2: Escalação após clean round
# ✓ Test 3: Demoting com negative feedback
# ✓ Test 4: Confidence score > 0.80 → POC_VALID
# ✓ Test 5: LLM triage integração funciona
# ✓ Test 6: Verdict mapeamento correto
```

### Test Suite 4: Discord Integration (Informativo)

```bash
pytest test_discord_notifier.py -v
# Output esperado: 4 passed

# Detalhes:
# ✓ Test 1: Embed formatação válida
# ✓ Test 2: Cores corretas por severidade
# ✓ Test 3: Deduplication funciona
# ✓ Test 4: Secrets mascarados
```

### Test Suite 5: Rate Limiting (Crítico)

```bash
pytest test_rate_limiting.py -v
# Output esperado: 3 passed

# Detalhes:
# ✓ Test 1: Respeita 10 req/s
# ✓ Test 2: Backoff exponencial funciona
# ✓ Test 3: Circuit breaker ativa ao exceder
```

---

## 📊 PERFORMANCE TARGETS

| Métrica | Target | Status |
|---|---|---|
| HTTP requests/sec | Max 10 | ✅ Enforçado |
| LLM latency | < 15s | ⏳ Testar |
| Finding validation | < 30s | ⏳ Testar |
| Discord notification | < 2s | ⏳ Testar |
| Database query | < 100ms | ⏳ Testar |
| Scope validation | < 50ms | ✅ Esperado |
| Nuclei execution | Variable | 📊 Monitor |
| Session recovery time | < 5min | ⏳ Testar |

---

## 🔍 DRY-RUN EXECUTION (Pré-Produção)

### Cenário de Teste

```yaml
Program:
  id: "test_acme_corp"
  domain: "test.acme.com"  # DOMAIN CONTROLADO
  scope: ["test.acme.com"]
  rules: "VDP allowed, no brute force"
  
Execution Plan:
  1. Initialize engine (Level 1 - Passive)
  2. Run Subfinder (descobrir test subdomains)
  3. Validate HTTPX (mapear hosts vivos)
  4. Run Nuclei Low severity only
  5. Monitor Discord alerts
  6. Check logs for violations
  7. Verify compliance
  8. Generate report
```

### Passos Execução

```bash
# 1. Preparar ambiente
export HUNTEROPS_ENV=staging
export HUNTEROPS_SCOPE_PATH=config/scope.test.json
export ANTHROPIC_API_KEY=sk-test-xxx

# 2. Validar carregamento
python -c "from hunterops.llm_integration import load_system_prompt; print(f'Loaded {len(load_system_prompt())} chars')"
# Esperado: "Loaded 89234 chars"

# 3. Rodar dry-run com escopo pequeno
python main.py --program test_acme_corp --dry-run --max-endpoints 10

# 4. Monitorar Discord
# Verificar que alertas chegam em #recon channel
# Verificar que nenhum alert em #findings (não deve achar vulnerabilidades reais)

# 5. Check database
sqlite3 data/processed/task_queue.db "SELECT COUNT(*) FROM tasks WHERE status='complete';"
# Esperado: 1-2 tasks completadas sem erro

# 6. Review logs
cat data/logs/audit_$(date +%Y-%m-%d).log | grep -i "violation\|error\|critical"
# Esperado: ZERO violations/errors

# 7. Generate report
python -c "from hunterops.reporting import generate_session_report; generate_session_report('test_run')"
```

### Sign-Off Requerido

- [ ] Dev lead: "Código implementado e testado"
- [ ] Security lead: "Escopo validado, compliance verificado"
- [ ] DevOps: "VPS, DB, Discord tudo funciona"
- [ ] Professor/Orientador: "Pronto para produção"

---

## 📈 PRODUCTION DEPLOYMENT

### Ambiente Checklist

```bash
# Antes de rodar em produção

# 1. PostgreSQL backup
pg_dump hunterops > backup_$(date +%Y-%m-%d).sql

# 2. Verificar credenciais estão em .env (não em código)
grep -r "ANTHROPIC_API_KEY" . --exclude-dir=.git
# Esperado: APENAS em .env

# 3. Verificar rate limits estão hardcoded
grep -r "rate_limit_per_sec" config/
# Esperado: 10 req/s configurado

# 4. Teste HackerOne draft creation
python scripts/test_h1_draft.py
# Esperado: Draft criado em sandbox

# 5. Teste Discord webhook
python scripts/test_discord.py
# Esperado: Mensagem de teste em Discord
```

### Rollback Plan

```
Se algo der errado em produção:

1. Container: `docker stop hunterops-engine`
2. Reverter DB: `psql -c "ROLLBACK;"`
3. Check logs: `tail -f data/logs/audit.log`
4. Notify: Discord error channel
5. Rollback code se necessário

Tempo esperado de recovery: < 5 minutos
```

---

## 📞 TROUBLESHOOTING RÁPIDO

### "Escopo não valida"
```bash
# Check scope file exists
ls -la config/scope.json
# Verify JSON syntax
python -m json.tool config/scope.json
# Check patterns
python -c "from hunterops.scope_authorization import load_authorized_scope; print(load_authorized_scope())"
```

### "LLM não responde"
```bash
# Check API key
echo $ANTHROPIC_API_KEY
# Test connection
curl https://api.anthropic.com/health
# Check quota
python scripts/check_anthropic_quota.py
```

### "Discord não envia alertas"
```bash
# Test webhook
curl -X POST $DISCORD_FINDINGS_WEBHOOK \
  -H "Content-Type: application/json" \
  -d '{"content":"Test message"}'
# Esperado: 204 No Content
```

### "Rate limit exceeded"
```bash
# Monitor requisições
grep -i "429\|rate" data/logs/audit.log
# Reduzir taxa: config/engine.yaml → rate_limit_per_sec: 5
# Aguardar 30 minutos, testar novamente
```

### "Estado machine não escala"
```bash
# Check adaptive_levels config
grep -A5 "adaptive_levels:" config/engine.yaml
# Verify clean_rounds_counter
python -c "from hunterops.attack_state_machine import debug_state(); debug_state()"
# Check LLM confidence scores
grep "confidence:" data/logs/audit.log | tail -20
```

---

## ✅ FINAL VALIDATION CHECKLIST

Antes de considerar "PRONTO", verifique:

### Funcionalidade
- [ ] Escopo valida corretamente
- [ ] Ferramentas executam sem timeout
- [ ] LLM triage retorna verdicts razoáveis
- [ ] Adaptability escala/desescala conforme esperado
- [ ] Discord alertas chegam em tempo real

### Segurança
- [ ] Zero secrets em logs
- [ ] Rate limit enforçado (10 req/s)
- [ ] Compliance com rules-of-engagement
- [ ] Circuit breaker interrompe ataque se necessário
- [ ] Auditoria completa de todas ações

### Observabilidade
- [ ] Discord funciona para todos severity levels
- [ ] Logs estruturados e pesquisáveis
- [ ] Métricas coletadas (Prometheus)
- [ ] Relatórios gerados automaticamente

### Documentação
- [ ] README.md atualizado
- [ ] SYSTEM_PROMPT.md presente e válido
- [ ] IMPLEMENTATION_GUIDE.md completo
- [ ] Exemplos Discord documentados
- [ ] Checklist assinado

---

## 🎓 INTEGRAÇÃO COM TCC

### Seções Recomendadas para Monografia

#### Capítulo 4: Implementação

**Seção 4.1: Arquitetura de Decisão da IA**
- Referência: SYSTEM_PROMPT.md (seções 1-3)
- Explicar: State machine, transições Recon→Exploitation
- Diagrama: ASCII art de attack_state_machine.py

**Seção 4.2: Ciclo de Orquestração**
- Referência: SYSTEM_PROMPT.md (seção 4)
- Explicar: Sequência de ferramenta (Subfinder→HTTPX→Nuclei)
- Código: Tool runner integration

**Seção 4.3: Validação de Findings**
- Referência: SYSTEM_PROMPT.md (seção 3, transição)
- Explicar: Heurística + LLM triage
- Tabela: Verdicts e confiança

**Seção 4.4: Compliance & Segurança**
- Referência: SYSTEM_PROMPT.md (seção 2, 5, 7)
- Explicar: Hard boundaries, rate limiting, redaction
- Gráfico: Rate limit enforcement

#### Capítulo 5: Resultados

**Seção 5.1: Validação de Findings**
- Gráfico: Verdicts distribution (POC_VALID vs False Positive)
- Tabela: Confidence scores médios por tipo de vulnerabilidade  
- Case study: 1 CRITICAL + 3 HIGH + 5 MEDIUM encontradas

**Seção 5.2: Eficiência do AI Orchestration**
- Gráfico: Tempo de transição (Recon → Exploitation)
- Tabela: Taxa de false positives antes vs depois de LLM
- Análise: ROI do rate limit vs findings missed

### Apêndices

**Apêndice A**: SYSTEM_PROMPT.md completo (80 páginas)  
**Apêndice B**: IMPLEMENTATION_GUIDE.md (código-fonte)  
**Apêndice C**: DISCORD_EXAMPLES.json (payloads reais)  
**Apêndice D**: Logs de execução real (anonymized)

---

## 🚀 PRÓXIMOS PASSOS

### Imediatamente
1. [ ] Implementar `hunterops/llm_integration.py`
2. [ ] Modificar `attack_state_machine.py` para usar LLM
3. [ ] Rodar test suite completo

### Semana 1
1. [ ] Dry-run com escopo de teste
2. [ ] Validate com orientador
3. [ ] Pequenos ajustes

### Semana 2
1. [ ] Deploy em staging
2. [ ] Executar com programa real pequeno
3. [ ] Refinar thresholds

### Semana 3
1. [ ] Deploy em produção  
2. [ ] Monitorar primeira campanha real
3. [ ] Documentar learnings para TCC

---

**PRONTO PARA COMEÇAR? Vá ao passo 1 acima!**

Qualquer dúvida, consulte:
- `SYSTEM_PROMPT.md` para conceitos
- `IMPLEMENTATION_GUIDE.md` para código
- `DISCORD_EXAMPLES.json` para notificações
