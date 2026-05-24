# 📑 HUNTEROPS-AI DOCUMENTATION INDEX

**Complete navigation guide for System Prompt & Implementation Suite**

---

## 🗺️ DOCUMENT MAP

```
📦 HunterOps-AI Documentation Suite
│
├── 📋 README_SYSTEM_PROMPT.md ⭐ START HERE
│   │ Purpose: Overview + stakeholder guide
│   │ Time: 5 minutes
│   │ For: Everyone
│   │
│   └─→ "Choose the right document based on your need"
│
├── 🎯 SYSTEM_PROMPT.md (10 sections)
│   │ Purpose: THE definitive blueprint
│   │ Time: 30-60 minutes to read fully
│   │ For: Architects, decision-makers, documentation
│   │
│   ├─ Section 1: Identity & Purpose
│   ├─ Section 2: Hard Boundaries ⚠️ CRITICAL
│   ├─ Section 3: State Machine & Decision Logic
│   ├─ Section 4: Tool Integration
│   ├─ Section 5: Observability & Alerting
│   ├─ Section 6: Integration with Platforms
│   ├─ Section 7: Compliance & Evasion
│   ├─ Section 8: Process Decision Example
│   ├─ Section 9: Adjustments & Safety Measures
│   └─ Section 10: Conformance Checklist
│
├── 🔧 IMPLEMENTATION_GUIDE.md (9 sections)
│   │ Purpose: HOW to code the System Prompt
│   │ Time: 4-8 hours to implement
│   │ For: Developers
│   │
│   ├─ Section 1: LLM Integration (hunterops/llm_integration.py)
│   ├─ Section 2: Modifications to attack_state_machine.py
│   ├─ Section 3: Modifications to discord_notifier.py
│   ├─ Section 4: Configuration YAML
│   ├─ Section 5: Environment Setup (.env)
│   ├─ Section 6: Testing Framework
│   ├─ Section 7: Checklist
│   ├─ Section 8: Troubleshooting
│   └─ Section 9: TCC Integration
│
├── 📨 DISCORD_EXAMPLES.json (14 templates)
│   │ Purpose: Real Discord notification payloads
│   │ Time: Reference as needed
│   │ For: DevOps, Operations, Discord setup
│   │
│   ├─ Template 1: Base Payload Structure
│   ├─ Template 2: Recon - New Subdomains
│   ├─ Template 3: Recon - Technology Fingerprint
│   ├─ Template 4: Recon - API Endpoints
│   ├─ Template 5: Findings - CRITICAL RCE 🔴
│   ├─ Template 6: Findings - HIGH IDOR 🟡
│   ├─ Template 7: Findings - MEDIUM - Info Exposure 🟠
│   ├─ Template 8: Findings - LOW - Missing Headers 🔵
│   ├─ Template 9: Operations - Session Start
│   ├─ Template 10: Operations - Session Complete
│   ├─ Template 11: Operations - Level Escalation
│   ├─ Template 12: Error - WAF Detected
│   ├─ Template 13: Python Integration Code
│   └─ Template 14: Webhook Configuration
│
├── ✅ QUICK_REFERENCE.md (14 sections)
│   │ Purpose: Checklists, validation, troubleshooting
│   │ Time: Use as reference during deployment
│   │ For: QA, Dev Lead, Security review, Production
│   │
│   ├─ Executive Summary
│   ├─ Pre-Deployment Checklist (4 phases)
│   ├─ Critical Boundaries
│   ├─ Validation Tests
│   ├─ Performance Targets
│   ├─ Dry-Run Execution Plan
│   ├─ Production Deployment
│   ├─ Rollback Plan
│   ├─ Troubleshooting FAQ
│   ├─ Final Validation Checklist
│   ├─ TCC Integration
│   ├─ Next Steps
│   └─ Sign-Off Required
│
└── 🔧 CONFIGURATION_EXAMPLES.yaml (6 configs)
    │ Purpose: Production-ready YAML templates
    │ Time: Copy-paste and customize
    │ For: DevOps, SysAdmin
    │
    ├─ 1. config/engine.yaml (DEFINITIVE VERSION)
    ├─ 2. config/hunterops_llm_config.yaml (NEW)
    ├─ 3. .env.example (Environment variables)
    ├─ 4. config/scope.json.example (Authorized targets)
    ├─ 5. config/programs.yaml (Managed programs)
    └─ 6. Python config loader (code example)
```

---

## 📌 QUICK ACCESS BY ROLE

### 👨‍🎓 **Professor / Academic Advisor**
**Time Available**: 2-3 hours

**Step 1**: Read this file (10 min)
```
README_SYSTEM_PROMPT.md → "Document Selection Guide"
```

**Step 2**: Read business logic overview (15 min)
```
SYSTEM_PROMPT.md → Sections 1, 2, 3
```

**Step 3**: Understand decision making (20 min)
```
SYSTEM_PROMPT.md → Section 8 (Full Example)
```

**Step 4**: Check implementation feasibility (15 min)
```
QUICK_REFERENCE.md → "Pre-Deployment Checklist"
```

**Step 5**: Review for TCC integration (30 min)
```
QUICK_REFERENCE.md → "TCC Integration Recommendations"
```

**Total: 90 minutes**

---

### 👨‍💻 **Developer (Implementation)**
**Time Available**: 1-2 weeks

**Week 1: Understanding**
- Day 1: SYSTEM_PROMPT.md (full - 60 min)
- Day 2: IMPLEMENTATION_GUIDE.md - Sections 1-3 (60 min)
- Day 2-3: Sketch implementation plan (120 min)

**Week 1-2: Implementation**
- IMPLEMENTATION_GUIDE.md - Follow section-by-section
- Create: `hunterops/llm_integration.py` (2-3 hours)
- Modify: `attack_state_machine.py` (1-2 hours)
- Modify: `discord_notifier.py` (1-2 hours)
- Configure: YAML files from CONFIGURATION_EXAMPLES.yaml (1 hour)

**Week 2: Testing & Validation**
- Run: `pytest tests/test_system_prompt.py -v`
- Run: Full validation suite from QUICK_REFERENCE.md
- Fix: Any test failures
- Document: Changes in git commit messages

---

### 🔒 **Security Review Team**
**Time Available**: 2-3 hours

**Read These Sections**:

1. SYSTEM_PROMPT.md → Section 2 (Hard Boundaries)
   - Rate limiting rules
   - Scope validation
   - Secrets protection
   - Compliance enforcement

2. SYSTEM_PROMPT.md → Section 5 (Compliance & Evasion)
   - Rate limiting strategy
   - Escopo & authorization
   - Operational compliance

3. QUICK_REFERENCE.md → "Critical Boundaries"
   - Security guarantees
   - Compliance checklist

4. QUICK_REFERENCE.md → "Pre-Deployment Checklist" (Phase 2)
   - All security validations

---

### 🚀 **DevOps / Infrastructure**
**Time Available**: 3-4 hours

**Step 1**: Setup (1 hour)
- CONFIGURATION_EXAMPLES.yaml → Section 6
- Set environment variables (.env)
- Configure Docker containers

**Step 2**: Discord Integration (30 min)
- DISCORD_EXAMPLES.json → Section 14
- Create webhook URLs in Discord
- Test webhooks with curl

**Step 3**: Testing (1 hour)
- QUICK_REFERENCE.md → "Dry-Run Execution Plan"
- Execute test campaign
- Monitor logs and Discord

**Step 4**: Production (1 hour)
- QUICK_REFERENCE.md → "Production Deployment"
- Final health checks
- Monitoring setup

---

### 👥 **Project Manager / Team Lead**
**Time Available**: 1-2 hours

**Read**:
1. README_SYSTEM_PROMPT.md (entire file - 20 min)
2. QUICK_REFERENCE.md (executive summary - 10 min)
3. QUICK_REFERENCE.md (deployment path - 15 min)
4. QUICK_REFERENCE.md (pre-deployment checklist - 20 min)

**Decision**: "Are we ready to go live?" → Last section of QUICK_REFERENCE.md

---

## 🔍 FIND ANSWER TO YOUR QUESTION

### "How does the AI decide to escalate from Recon to Exploitation?"
→ SYSTEM_PROMPT.md, Section 3.1 (Transições de Estado)

### "What's the exact Discord payload format?"
→ DISCORD_EXAMPLES.json, Section 5 (JSON template)

### "How do I configure rate limiting?"
→ CONFIGURATION_EXAMPLES.yaml, Section 1 (engine.yaml)

### "What if something goes wrong?"
→ QUICK_REFERENCE.md, Troubleshooting FAQ

### "Is the system production-ready?"
→ QUICK_REFERENCE.md, Final Validation Checklist

### "How do I integrate with HackerOne?"
→ SYSTEM_PROMPT.md, Section 6 (Platform Integration)

### "How do I handle security violations?"
→ SYSTEM_PROMPT.md, Section 2 (Hard Boundaries)

### "What should go in my TCC chapter?"
→ QUICK_REFERENCE.md, TCC Integration section

### "How do I test this locally?"
→ IMPLEMENTATION_GUIDE.md, Section 6 (Test Suite)

### "What are the performance targets?"
→ QUICK_REFERENCE.md, Performance Targets table

---

## 📊 READ TIME ESTIMATES

| Document | Skim | Read | Study | Code |
|---|---|---|---|---|
| README_SYSTEM_PROMPT.md | 5 min | 15 min | 30 min | N/A |
| SYSTEM_PROMPT.md | 15 min | 60 min | 120 min | N/A |
| IMPLEMENTATION_GUIDE.md | 10 min | 45 min | 90 min | 180 min |
| DISCORD_EXAMPLES.json | 10 min | 30 min | 60 min | 45 min |
| QUICK_REFERENCE.md | 10 min | 45 min | 90 min | 240 min |
| CONFIGURATION_EXAMPLES.yaml | 5 min | 20 min | 45 min | 60 min |

**TOTAL**: 55-180 reading hours + 525 implementation hours

---

## 🎯 SUCCESS MILESTONES

### Milestone 1: Understanding ✓
- [ ] Read SYSTEM_PROMPT.md fully
- [ ] Understand state machine transitions
- [ ] Can explain hard boundaries to others

**Sign-off**: "Understood"

### Milestone 2: Implementation ✓
- [ ] Created `hunterops/llm_integration.py`
- [ ] Modified `attack_state_machine.py`
- [ ] All files compile without errors
- [ ] Test suite passes

**Sign-off**: "Implemented"

### Milestone 3: Validation ✓
- [ ] Dry-run execution passed
- [ ] Discord alerts working
- [ ] No compliance violations
- [ ] Security review approved

**Sign-off**: "Validated"

### Milestone 4: Production ✓
- [ ] Deployed to VPS
- [ ] First campaign completed
- [ ] All findings documented
- [ ] TCC integrated

**Sign-off**: "Live"

---

## 📞 GETTING HELP

**Question Type → Resource**

| Question | Resource | Time |
|---|---|---|
| "How does X work?" | SYSTEM_PROMPT.md (search section) | 5 min |
| "How do I code X?" | IMPLEMENTATION_GUIDE.md (code example) | 10 min |
| "What payload for X?" | DISCORD_EXAMPLES.json (template) | 5 min |
| "Is X ready?" | QUICK_REFERENCE.md (checklist) | 5 min |
| "X is broken, help?" | QUICK_REFERENCE.md (troubleshooting) | 15 min |
| "How do I deploy X?" | CONFIGURATION_EXAMPLES.yaml (example) | 10 min |

---

## 🔐 CRITICAL SAFEGUARDS

**These must be verified before production:**

1. ✅ **Scope validation**: `scope_authorization.py` ALWAYS runs first
2. ✅ **Rate limiting**: Enforced at 10 req/s global
3. ✅ **Secrets**: Never in logs or Discord
4. ✅ **Compliance**: Rules-of-engagement checked before automation
5. ✅ **Confidence**: Only POCs with >= 0.80 confidence alert

**Checklist**: QUICK_REFERENCE.md → "Critical Boundaries"

---

## 📅 TIMELINE RECOMMENDATION

```
Week 1: Planning & Understanding
├─ Monday: Read all documents (6 hours)
├─ Tuesday: Architecture review (4 hours)
├─ Wednesday: Design review (4 hours)
├─ Thursday: Stakeholder alignment (2 hours)
└─ Friday: Go/no-go decision (1 hour)

Week 2: Implementation
├─ Monday: LLM integration (4 hours)
├─ Tuesday: State machine modifications (4 hours)
├─ Wednesday: Discord integration (4 hours)
├─ Thursday: Configuration & testing (4 hours)
└─ Friday: Fix issues & demo (4 hours)

Week 3: Validation
├─ Monday: Full test suite (4 hours)
├─ Tuesday: Dry-run campaign (4 hours)
├─ Wednesday: Security review (3 hours)
├─ Thursday: Documentation (3 hours)
└─ Friday: Go-live decision (1 hour)

Week 4+: Production
├─ Live monitoring
├─ TCC documentation
└─ Final deployment
```

---

## ✨ BEST PRACTICES

1. **Start with README_SYSTEM_PROMPT.md** (this file's parent)
2. **Read SYSTEM_PROMPT.md end-to-end** (don't skip sections)
3. **Code along with IMPLEMENTATION_GUIDE.md** (don't just copy-paste)
4. **Use QUICK_REFERENCE.md as your deployment guide**
5. **Refer to DISCORD_EXAMPLES.json for real templates**
6. **Keep CONFIGURATION_EXAMPLES.yaml nearby during setup**

---

## 🚀 NEXT STEP

**You are here**: Reading the INDEX

**Next**: Go back to README_SYSTEM_PROMPT.md and follow the "Quick Start" section

---

**Questions? Issues? Start with the right document above!**

Last Updated: 2026-03-20  
Version: 1.0-Complete
