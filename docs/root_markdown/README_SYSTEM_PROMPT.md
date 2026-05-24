# 🎯 HunterOps-AI: System Prompt & Implementation Suite

**Complete documentation for the intelligent decision-making core of HunterOps Bug Bounty Framework**

---

## 📁 Documentation Suite

This folder contains 4 comprehensive documents defining the System Prompt (AI decision-making rules) for HunterOps-AI:

### 1. **SYSTEM_PROMPT.md** (MAIN REFERENCE)
   **Purpose**: The definitive blueprint for how HunterOps-AI makes decisions
   
   **Contains**:
   - ✅ Identity & Purpose (who you are, what you do)
   - ✅ Hard Boundaries (non-negotiable security rules)
   - ✅ Decision Logic (state machine, transitions, verdicts)
   - ✅ Tool Integration (Nuclei, HTTPX, Subfinder)
   - ✅ Observability (Discord, logging, compliance)
   - ✅ Feedback Loops (adaptive escalation/demotion)
   
   **For**: Anyone who needs to understand *why* HunterOps makes specific decisions  
   **Length**: ~10,000 words, 100+ inline code examples  
   **Last Updated**: 2026-03-20
   
   ---

### 2. **IMPLEMENTATION_GUIDE.md** (CODING REFERENCE)
   **Purpose**: How to code the System Prompt into Python + LLM integration
   
   **Contains**:
   - ✅ `hunterops/llm_integration.py` (complete source code)
   - ✅ Modifications to `attack_state_machine.py`
   - ✅ Modifications to `discord_notifier.py`
   - ✅ Configuration YAML examples
   - ✅ Environment setup (.env)
   - ✅ Unit tests for validation
   - ✅ Troubleshooting guide
   
   **For**: Dev team implementing the features  
   **Effort**: 2-3 hours to implement  
   **Dependencies**: Anthropic Claude API key  
   
   ---

### 3. **DISCORD_EXAMPLES.json** (OPERATIONAL REFERENCE)
   **Purpose**: Real-world Discord notification templates for every scenario
   
   **Contains**:
   - ✅ Recon discovery alerts (new subdomains, tech fingerprints, endpoints)
   - ✅ Critical findings (RCE, SQLi, IDOR)
   - ✅ Medium/Low findings (exposed config, missing headers)
   - ✅ Operational alerts (session start/complete, escalation, WAF detected)
   - ✅ Python integration code
   - ✅ Color mapping & emoji reference
   
   **For**: DevOps, Security team monitoring campaigns  
   **Why**: Pre-built embeds save time, ensure consistency  
   
   ---

### 4. **QUICK_REFERENCE.md** (CHECKLIST & VALIDATION)
   **Purpose**: Pre-deployment checklists, test suites, troubleshooting
   
   **Contains**:
   - ✅ Executive summary (one-page overview)
   - ✅ Pre-deployment checklist (4 phases, 40+ items)
   - ✅ Critical boundaries (do's and don'ts)
   - ✅ Validation test suites (pytest commands)
   - ✅ Performance targets
   - ✅ Dry-run execution plan
   - ✅ Troubleshooting FAQ
   - ✅ TCC integration recommendations
   
   **For**: Dev lead, QA, Professor reviewing before production  
   **Use When**: "Is the system ready for production?"
   
   ---

## 🎓 Document Selection Guide

**Choose the right document based on your need:**

| I Need To... | Read This |
|---|---|
| Understand **what** HunterOps decides | SYSTEM_PROMPT.md (sections 1-3) |
| Understand **why** it decides that way | SYSTEM_PROMPT.md (sections 5-7) |
| **Code** the decision logic | IMPLEMENTATION_GUIDE.md |
| **Design** Discord notifications | DISCORD_EXAMPLES.json |
| **Test** before going live | QUICK_REFERENCE.md (checklists) |
| **Debug** a problem in production | QUICK_REFERENCE.md (troubleshooting) |
| **Document** for my TCC | All files (see TCC section in QUICK_REFERENCE.md) |
| **Review** with stakeholders | QUICK_REFERENCE.md (executive summary) |

---

## 🚀 Quick Start (5 minutes)

### For Decision-Makers
1. Read: SYSTEM_PROMPT.md sections 1-2 (Identity + Hard Boundaries)
2. Read: QUICK_REFERENCE.md (Executive Summary)
3. Decision: "Ready for production?" → Use QUICK_REFERENCE.md checklist

### For Developers
1. Read: SYSTEM_PROMPT.md sections 3-4 (Decision Logic + Tools)
2. Read: IMPLEMENTATION_GUIDE.md (full implementation)
3. Code: Create `hunterops/llm_integration.py`
4. Test: `pytest tests/test_system_prompt.py -v`

### For DevOps/Ops
1. Read: DISCORD_EXAMPLES.json (notification structure)
2. Setup: Discord webhook URLs in environment
3. Monitor: Channel layouts and alert routing
4. Debug: QUICK_REFERENCE.md troubleshooting section

### For Academic (TCC/Thesis)
1. Read: SYSTEM_PROMPT.md (complete)
2. Read: IMPLEMENTATION_GUIDE.md (architecture)
3. Appendix: All 4 documents + logs
4. Results: Include execution metrics + findings statistics

---

## 📊 Key Metrics & Definitions

### Confidence Score
**Definition**: AI's belief that a POC is genuinely valid (0.0-1.0)

- **< 0.60**: FALSE_POSITIVE (discard, don't alert)
- **0.60-0.80**: INCONCLUSIVE (needs manual review)
- **>= 0.80**: POC_VALID (create finding, alert Discord)

**Sources**: Heuristic pattern matching + LLM triage

---

### State Transitions

```
┌─────────────────┐
│   RECON MODE    │  (Level 1-3: passive→active discovery)
│ Subfinder→HTTPX │
│ →Nuclei(Low)    │
└────────┬────────┘
         │ confidence > 0.80?
         │ + priority_score > 0.65?
         ↓
┌──────────────────────┐
│ EXPLOITATION MODE    │  (Targeted attack on high-priority)
│ IDOR→SQLi→GraphQL    │
│ →Browser Automation  │
└────────┬─────────────┘
         │ POC validated?
         │ (heuristic + LLM)
         ↓
┌──────────────────┐
│  ALERT DISCORD   │  (Severity-based notification)
│ + Create H1 Draft│
└──────────────────┘
```

---

### Adaptive Levels

| Level | Aggression | Tools | Speed | When? |
|---|---|---|---|---|
| 1 | Passive | Recon only | 5 req/s | Initial scan |
| 2 | Medium | Recon + Fuzzing | 10 req/s | After 1 clean round |
| 3 | Aggressive | All + Bypass attempts | 10 req/s | After 2+ clean rounds |

**Clean Round**: No vulnerabilities found in entire round  
**Escalate Trigger**: `escalate_after_clean_rounds: 1`  
**Demote Trigger**: Timeout >3 OR negative feedback OR rate-limited >2x

---

## 🔐 Critical Security Guarantees

### Hard Boundaries (Never Bypass)

```
BEFORE ANY ACTION:
✓ Is domain in scope.json?
✓ Is automation allowed by program?
✓ Are rate limits enforced?
✓ Are secrets redacted?
✓ Is audit logged?
```

### Compliance Checklist

- [ ] Zero violations of authorized scope
- [ ] Max 10 requests/second global
- [ ] No brute force / DoS attempts
- [ ] No automatic submission to HackerOne (manual review only)
- [ ] All findings >= 0.80 confidence
- [ ] All secrets masked in output

---

## 🧪 Testing Framework

### Run All Tests
```bash
pytest tests/test_system_prompt.py tests/test_scope_authorization.py \
        tests/test_attack_state_machine.py tests/test_rate_limiting.py -v
```

### Test Coverage

| Component | Tests | Status |
|---|---|---|
| Scope Authorization | 5/5 | ✅ Must pass |
| System Prompt Loading | 3/3 | ✅ Must pass |
| State Machine | 6/6 | ✅ Must pass |
| Rate Limiting | 3/3 | ✅ Must pass |
| Discord Integration | 4/4 | ⏳ Optional |

---

## 📈 Deployment Path

```
PRE-IMPLEMENTATION
(6 hours)
├── Read all 4 documents
├── Review with team
└── Get stakeholder approval
        ↓
IMPLEMENTATION
(8-12 hours)
├── Create llm_integration.py
├── Modify attack_state_machine.py
├── Configure Discord webhooks
└── Run test suite (must pass)
        ↓
STAGING DEPLOYMENT
(4-6 hours)
├── Dry-run with test scope
├── Monitor discord alerts
├── Verify compliance
└── Get security review
        ↓
PRODUCTION DEPLOYMENT
├── Database backup
├── Deploy container
├── Monitor first campaign
└── Document learnings for TCC
```

**Total Time to Production**: ~1-2 weeks (depending on team size)

---

## 🐛 Common Issues & Solutions

### Issue: "scope_authorization.py returns False for valid domain"
**Solution**: 
1. Verify `config/scope.json` contains your domain
2. Check fnmatch pattern: `*.target.com` matches `api.target.com`
3. Verify dates: `valid_from <= now <= valid_to`

**File**: QUICK_REFERENCE.md → Troubleshooting section

---

### Issue: "LLM not responding / timeout"
**Solution**:
1. Check `ANTHROPIC_API_KEY` is set
2. Verify Anthropic quota not exceeded
3. Increase timeout in `config/hunterops_llm_config.yaml`
4. Set fallback to "heuristic" (use pattern-matching only)

**File**: IMPLEMENTATION_GUIDE.md → Section 4

---

### Issue: "Discord webhook 404 Not Found"
**Solution**:
1. Regenerate webhook URL in Discord
2. Update `DISCORD_FINDINGS_WEBHOOK` env var
3. Test with curl: `curl -X POST $WEBHOOK -H "Content-Type: application/json" -d '{"content":"test"}'`
4. Expected response: HTTP 204

**File**: DISCORD_EXAMPLES.json → Section 14

---

### Issue: "Rate limited / WAF detected"
**Solution**:
1. System automatically backs off (exponential): 5s → 10s → 30s
2. After 3 failures: skips target
3. Waits 30 min before retry
4. Recommend reducing overall rate to 5 req/s temporarily

**File**: SYSTEM_PROMPT.md → Section 5.1

---

## 📚 Learning Path

### Graph: Concept Dependency

```
SYSTEM_PROMPT.md (Understanding)
    ├─ Identity & Purpose
    ├─ Hard Boundaries
    ├─ State Machine
    │   └─ Confidence Score concept
    │       └─ LLM Triage explanation
    │           └─ IMPLEMENTATION_GUIDE.md (Coding)
    ├─ Tool Integration
    │   └─ IMPLEMENTATION_GUIDE.md (Tool Runner code)
    ├─ Discord Notifications
    │   └─ DISCORD_EXAMPLES.json (Real payloads)
    └─ Compliance
        └─ QUICK_REFERENCE.md (Checklists)
```

### Recommended Reading Order

**For Developers**:
1. SYSTEM_PROMPT.md (sections 1-3)
2. IMPLEMENTATION_GUIDE.md (full)
3. DISCORD_EXAMPLES.json (reference)
4. QUICK_REFERENCE.md (tests)

**For Decision-Makers**:
1. SYSTEM_PROMPT.md (sections 1-2)
2. QUICK_REFERENCE.md (executive summary + checklist)

**For Academic Documentation**:
1. All files (in order above)
2. Extract diagrams and pseudocode
3. Create appendices for TCC/thesis

---

## 👥 Stakeholder Reference

### For Your Thesis Advisor/Professor
**Documents to review**: SYSTEM_PROMPT.md + IMPLEMENTATION_GUIDE.md  
**Key concepts**: State machine, LLM integration, compliance automation  
**Time commitment**: 2-3 hours

### For Your Dev Lead
**Documents to review**: IMPLEMENTATION_GUIDE.md + QUICK_REFERENCE.md  
**Key concepts**: Code structure, testing, deployment  
**Time commitment**: 4-6 hours

### For Security Review
**Documents to review**: SYSTEM_PROMPT.md (section 2+7) + QUICK_REFERENCE.md (compliance)  
**Key concepts**: Rate limiting, scope validation, secrets redaction  
**Time commitment**: 2-3 hours

### For DevOps/Infrastructure
**Documents to review**: IMPLEMENTATION_GUIDE.md + DISCORD_EXAMPLES.json  
**Key concepts**: Docker setup, webhook URLs, monitoring  
**Time commitment**: 2 hours

---

## 📝 Document Maintenance

### When to Update These Documents

| Trigger | Action | File(s) |
|---|---|---|
| Change rate limits | Update SYSTEM_PROMPT.md (2.3) + QUICK_REFERENCE.md (Performance) | Both |
| Add new Discord channel | Update DISCORD_EXAMPLES.json + IMPLEMENTATION_GUIDE.md | Both |
| Modify state machine | Update SYSTEM_PROMPT.md (3.1) + IMPLEMENTATION_GUIDE.md | Both |
| New tool integrated | Update SYSTEM_PROMPT.md (4) + IMPLEMENTATION_GUIDE.md | Both |
| Pre-deployment checklist changes | Update QUICK_REFERENCE.md | Single |
| Bug discovered | Update QUICK_REFERENCE.md (troubleshooting) | Single |

### Version Control

- Commit to git as: `git commit -m "docs: Update System Prompt for new adaptive_level logic"`
- Tag releases: `git tag -a v1.1-system-prompt -m "Stable version for production"`

---

## 🎯 Success Criteria

After reading all 4 documents, you should be able to:

- [ ] Explain the 3 core hard boundaries (scope, rate limit, secrets)
- [ ] Describe the Recon→Exploitation transition logic (confidence > 0.80)
- [ ] Implement LLM triage in attack_state_machine.py
- [ ] Create a Discord finding alert with correct color & fields
- [ ] Run the complete validation test suite
- [ ] Identify and fix issues using troubleshooting guide
- [ ] Deploy to production with zero compliance violations
- [ ] Document findings for your TCC

**✅ If yes to all → Ready for production!**

---

## 📞 Support

### Questions About Architecture?
→ SYSTEM_PROMPT.md (relevant section)

### Questions About Implementation?
→ IMPLEMENTATION_GUIDE.md + code comments

### Questions About Alerts?
→ DISCORD_EXAMPLES.json

### Questions About Readiness?
→ QUICK_REFERENCE.md checklists

### Questions About Troubleshooting?
→ QUICK_REFERENCE.md (FAQ section)

---

## 🏆 Credits

**Created by**: Engenheiro de Prompt Senior + Colaborador Gemini  
**For**: HunterOps-AI Framework  
**Date**: 2026-03-20  
**Status**: ✅ Production-Ready

---

## 📄 File Manifest

```
hunterops-main/
├── SYSTEM_PROMPT.md              (10,000 words | AI decision rules)
├── IMPLEMENTATION_GUIDE.md       (5,000 words | How to code)
├── DISCORD_EXAMPLES.json         (3,000 words | Notification templates)
├── QUICK_REFERENCE.md            (4,000 words | Checklists & validation)
│
├── config/
│   ├── engine.yaml               (Runtime configuration)
│   ├── scope.json                (Authorized targets - cryptographically signed)
│   └── hunterops_llm_config.yaml (LLM settings)
│
├── hunterops/
│   ├── attack_state_machine.py   (To be modified - add LLM integration)
│   ├── llm_integration.py        (NEW - to be created)
│   ├── scope_authorization.py    (Existing - reference in docs)
│   ├── discord_notifier.py       (To be modified - structured embeds)
│   └── [other existing modules]
│
├── tests/
│   ├── test_system_prompt.py     (NEW - validate prompt loading)
│   ├── test_scope_authorization.py
│   ├── test_attack_state_machine.py
│   ├── test_rate_limiting.py
│   └── test_discord_notifier.py
│
└── README.md                     (This file)
```

---

## ✅ Final Checklist Before Going Live

- [ ] All 4 documents read and understood
- [ ] Team review completed
- [ ] Security review approved
- [ ] Test suite passes (pytest -v)
- [ ] Dry-run executed successfully
- [ ] Discord webhooks working
- [ ] Database backed up
- [ ] LLM API key configured
- [ ] Docker containers ready
- [ ] Scope file signed and validated
- [ ] Rate limits enforced
- [ ] Secrets redaction working
- [ ] Logging captures all critical events
- [ ] Professor/advisor signed off

**🚀 If all checked → DEPLOY TO PRODUCTION!**

---

**Questions? Issues? Updates needed?**

Refer to the relevant document or consult with your team lead.

**Last Updated**: 2026-03-20  
**Maintainer**: HunterOps Development Team
