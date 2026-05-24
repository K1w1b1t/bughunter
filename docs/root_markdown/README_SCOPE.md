# Scope Validation Documentation - PASSO 4

## Overview

**PASSO 4** implements mandatory scope enforcement before ANY network action. This is a **security-critical module** where scope validation failures block entire operations.

**Non-negotiable rules**:
1. ✅ ALL network operations MUST pass scope check first
2. ✅ Single violation → entire operation blocked (no exceptions)
3. ✅ ALL scope checks logged to audit_log for compliance
4. ✅ Rules-of-Engagement (ROE) strictly enforced
5. ✅ No hardcoded scope bypasses or emergency exits

---

## Architecture

### Component Diagram

```
┌────────────────────────────────────────────────────────────────┐
│  HunterOps Executor (executor.py)                               │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  @require_exploitation_authorization  ← DECORATOR GATE           │
│  async def exploit_vulnerability(target: str):                 │
│     └─> ScopeValidator.check_scope(target)                    │
│         ├─ Include patterns check (whitelist)                  │
│         ├─ Exclusion patterns check (blacklist)                │
│         ├─ ROE timing check (business hours only?)             │
│         ├─ ROE rate limit check (10 req/sec)                   │
│         └─ ROE auth check (credentials required?)              │
│                                                                 │
│  Decision:                                                      │
│     ├─ AUTHORIZED → Execute operation                          │
│     ├─ REJECTED → Raise ScopeAuthorizationError                │
│     └─ ESCALATE → Log for human review + alert Discord         │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### Scope Check Flow

```
Network Request Initiated
        ↓
@require_xxx_authorization decorator intercepts
        ↓
Extract target URL/domain from parameters
        ↓
ScopeValidator.check_scope(target, action, authenticated)
        ↓
1️⃣ Load program scope from config
        ↓
2️⃣ Normalize target (URL → domain, lowercase)
        ↓
3️⃣ Check INCLUSION patterns (whitelist)
   ├─ No? → REJECTED (OUT_OF_SCOPE)
   └─ Yes? → Continue
        ↓
4️⃣ Check EXCLUSION patterns (blacklist)
   ├─ Yes? → REJECTED (IN_EXCLUSION_LIST)
   └─ No? → Continue
        ↓
5️⃣ Check ROE TIMING (business hours, weekdays)
   ├─ Violation? → ESCALATE (TIMING_RESTRICTED)
   └─ OK? → Continue
        ↓
6️⃣ Check ROE RATE LIMIT (10 req/sec per target)
   ├─ Exceeded? → REJECTED (RATE_LIMIT_EXCEEDED)
   └─ OK? → Continue
        ↓
7️⃣ Check ROE AUTHENTICATION (credentials required?)
   ├─ Required? → REJECTED (CREDENTIALS_REQUIRED)
   └─ OK? → Continue
        ↓
✅ ALL PASSED → Return AUTHORIZED
        ↓
Record request for rate limiting
        ↓
Execute network operation
```

---

## Pattern Matching

### Supported Pattern Types

#### 1. **Exact Match**
```
Pattern: example.com
Matches: example.com
Rejects: api.example.com, www.example.com, other.com
```

#### 2. **Wildcard (subdomain)**
```
Pattern: *.example.com
Matches: api.example.com, www.example.com, internal.example.com
Rejects: example.com (must have subdomain)
```

#### 3. **Wildcard (IP)**
```
Pattern: 192.168.1.*
Matches: 192.168.1.0, 192.168.1.100, 192.168.1.255
Rejects: 192.168.2.1
```

#### 4. **Regex (advanced)**
```
Pattern: ^(api|www)\.example\.com$
Matches: api.example.com, www.example.com
Rejects: internal.example.com, api.example.com.attacker.com
```

#### 5. **CIDR (network blocks)**
```
Pattern: 192.168.1.0/24
Matches: 192.168.1.0 → 192.168.1.255 (256 IPs)
Rejects: 192.168.2.1, 192.168.0.1
```

---

## Configuration

### Program Scope Format

```json
{
  "program_id": "program_001",
  "scope": {
    "include": [
      "*.example.com",
      "example.com",
      "api.example.com",
      "192.168.1.0/24",
      "^staging-[a-z]+\\.example\\.com$"
    ],
    "exclude": [
      "internal.example.com",
      "admin.example.com",
      "10.0.0.0/8",
      "127.0.0.1"
    ]
  },
  "roe": {
    "testing_windows": [
      {
        "start_hour": 8,
        "end_hour": 18,
        "allowed_days": [0, 1, 2, 3, 4]
      }
    ],
    "rate_limits": {
      "max_requests": 10,
      "time_window_seconds": 60
    },
    "authentication_required": false,
    "sensitive_actions": [
      "exploitation",
      "data_exfiltration",
      "privilege_escalation"
    ]
  }
}
```

### Environment Variables

```bash
# Scope Configuration
PROGRAM_SCOPE_FILE=${CONFIG_DIR}/scope.json     # Load scope from file
PROGRAM_SCOPE_DB=postgresql://...               # Load scope from database

# ROE Configuration
ROE_TESTING_WINDOWS_ONLY=false                  # Enforce strict testing windows
ROE_RATE_LIMIT=10                               # Requests per second
ROE_AUTHENTICATION_REQUIRED=false                # Require valid credentials

# Enforcement
SCOPE_ENFORCEMENT_LEVEL=STRICT                  # STRICT|WARN_ONLY
SCOPE_VIOLATIONS_ALERT=true                     # Alert on Discord
SCOPE_LOG_TO_DATABASE=true                      # Log to audit_log table
```

---

## Usage Examples

### 1. Basic Scope Check

```python
from hunterops.scope_validator import ScopeValidator

# Load configuration
program_config = {
    "program_id": "hack_001",
    "scope": {
        "include": ["*.example.com", "192.168.1.0/24"],
        "exclude": ["internal.example.com"]
    },
    "roe": {}
}

# Create validator
validator = ScopeValidator(program_config)

# Check if target is in scope
result = validator.check_scope("api.example.com", action="reconnaisance")

if result.authorized:
    print(f"✅ Authorized: {result.target}")
    print(f"   Matching pattern: {result.matching_scope_pattern}")
else:
    print(f"❌ Rejected: {result.target}")
    print(f"   Reason: {result.rejection_reason}")
    print(f"   Details: {result.rejection_details}")
```

Output:
```
✅ Authorized: api.example.com
   Matching pattern: *.example.com
```

### 2. Using Middleware with Decorators

```python
from hunterops.scope_middleware import (
    ScopeMiddleware,
    set_scope_middleware,
    require_exploitation_authorization
)

# Initialize middleware at startup
validator = ScopeValidator(program_config)
middleware = ScopeMiddleware(validator)
set_scope_middleware(middleware)

# Use decorators on functions that perform network operations
@require_exploitation_authorization(extract_target_from="target")
async def attempt_exploit(target: str, exploit_id: str):
    """Exploitation always requires scope check."""
    # Only reached if target passed scope validation
    print(f"Exploiting {target}...")
    # ... exploitation code ...

# Usage
try:
    await attempt_exploit("api.example.com", "cve_2024_1234")
    # ✅ Authorized → exploit runs
except ScopeAuthorizationError as e:
    print(f"❌ Scope violation: {e.message}")
    # Automatically rejected, never reached network

# Check statistics
stats = middleware.get_statistics()
print(f"Total checks: {stats['total_checks']}")
print(f"Rejection rate: {stats['rejection_rate']:.1f}%")
```

### 3. Batch Authorization

```python
from hunterops.scope_middleware import ScopedTargetList

# Scan multiple targets, only authorized ones
targets = [
    "api.example.com",
    "www.example.com",
    "internal.example.com",  # Out of scope
    "external.com",           # Out of scope
    "192.168.1.100"
]

# Pre-check all targets
scoped_targets = ScopedTargetList(targets, "port_scanning", middleware)

# Get authorization summary
authorized = scoped_targets.get_authorized_targets()
rejected = scoped_targets.get_rejected_targets()

print(f"Authorized targets: {authorized}")
# Output: ['api.example.com', 'www.example.com', '192.168.1.100']

print(f"Rejected targets: {rejected}")
# Output: {'internal.example.com': 'IN_EXCLUSION_LIST', 'external.com': 'OUT_OF_SCOPE'}

# Iterate over only authorized targets
for target in scoped_targets:
    await scan_ports(target)  # Only called for authorized targets
```

### 4. ROE Enforcement

```python
from hunterops.scope_validator import ScopeValidator

config = {
    "program_id": "enterprise_001",
    "scope": {
        "include": ["*.corp.example.com"],
        "exclude": []
    },
    "roe": {
        "testing_windows": [
            {
                "start_hour": 20,      # 8 PM
                "end_hour": 6,         # 6 AM (next day)
                "allowed_days": [5, 6] # Sat, Sun only
            }
        ],
        "rate_limits": {
            "max_requests": 5,
            "time_window_seconds": 60
        },
        "authentication_required": True,
        "sensitive_actions": ["exploitation"]
    }
}

validator = ScopeValidator(config)

# ❌ Will reject: outside testing window (Monday 9am)
result = validator.check_scope("api.corp.example.com", action="exploitation")
# Result: REJECTED (TIMING_RESTRICTED)

# ✅ Will authorize: within testing window (Saturday 1am)
result = validator.check_scope("api.corp.example.com", action="exploitation", authenticated=True)
# Result: AUTHORIZED (with confidence=1.0)
```

### 5. Decorators for Different Operations

```python
from hunterops.scope_middleware import (
    require_recon_authorization,
    require_scanning_authorization,
    require_exploitation_authorization,
    require_evidence_authorization,
)

# Reconnaissance operations
@require_recon_authorization(extract_target_from="domain")
async def dns_enumeration(domain: str):
    pass

# Vulnerability scanning
@require_scanning_authorization(extract_target_from="host")
async def nuclei_scan(host: str):
    pass

# Exploitation attempts
@require_exploitation_authorization(extract_target_from="target")
async def exploit_vulnerability(target: str, poc: str):
    pass

# Evidence collection
@require_evidence_authorization(extract_target_from="url")
async def capture_proof_of_concept(url: str):
    pass
```

---

## Access Control Decisions

### Authorization Types

| Type | Decision | Action |
|------|----------|--------|
| **AUTHORIZED** | ✅ Pass | Execute operation |
| **REJECTED** | ❌ Fail | Block + raise exception |
| **ESCALATE_TO_HUMAN** | ⚠️ Uncertain | Log for human review |

### Rejection Reasons

| Reason | Cause | Resolution |
|--------|-------|-----------|
| OUT_OF_SCOPE | Target not in inclusion patterns | Add to scope or contact program |
| IN_EXCLUSION_LIST | Target in blacklist | Remove from exclusion or skip target |
| ROE_VIOLATION | Violates program rules | N/A (auto-blocked) |
| RATE_LIMIT_EXCEEDED | Too many requests | Wait before retrying |
| TIMING_RESTRICTED | Outside testing window | Wait for allowed testing window |
| CREDENTIALS_REQUIRED | Auth needed for sensitive action | Provide credentials |

---

## Integration with HunterOps

### With Attack State Machine

```python
# attack_state_machine.py integration

from hunterops.scope_middleware import (
    ScopeMiddleware,
    set_scope_middleware,
    require_recon_authorization,
    require_scanning_authorization,
    require_exploitation_authorization,
)

# Initialize scope enforcement at startup
async def initialize_engine():
    validator = ScopeValidator(program_config)
    middleware = ScopeMiddleware(validator)
    set_scope_middleware(middleware)

# Recon phase with decoration
@require_recon_authorization(extract_target_from="target")
async def recon_phase(target: str):
    # Only reached if target in scope
    await dns_enum(target)
    await port_scan(target)
    await web_scan(target)

# Exploitation phase with decoration
@require_exploitation_authorization(extract_target_from="target")
async def exploitation_phase(target: str):
    # Only reached if target in scope AND LLM triage approved
    await attempt_sql_injection(target)
    await attempt_xss(target)
```

### With Executor

```python
# executor.py integration

class Executor:
    def __init__(self, program_config):
        self.scope_validator = ScopeValidator(program_config)
        self.scope_middleware = ScopeMiddleware(self.scope_validator)
        set_scope_middleware(self.scope_middleware)
    
    @require_scanning_authorization(extract_target_from="target")
    async def run_nuclei(self, target: str, templates: List[str]):
        """Run Nuclei scanner - automatically scope-gated."""
        # Scope check passed - execute scan
        pass
    
    @require_exploitation_authorization(extract_target_from="target")
    async def exploit(self, target: str, poc: str):
        """Exploitation - highest security gate."""
        # Scope check passed - execute exploit
        pass
```

---

## Audit Logging

### Logged Events

Every scope check is logged to `audit_log` table (compliance requirement):

```json
{
  "timestamp": "2024-03-20T14:35:22Z",
  "program_id": "program_001",
  "event_type": "SCOPE_CHECK",
  "target": "api.example.com",
  "normalized_target": "api.example.com",
  "authorized": true,
  "authorization_type": "AUTHORIZED",
  "rejection_reason": null,
  "confidence": 1.0,
  "matching_pattern": "*.example.com",
  "action": "port_scanning",
  "authenticated": false,
  "timestamp_utc": "2024-03-20T14:35:22Z"
}
```

### Viewing Audit Logs

```sql
-- Last 100 authorization checks
SELECT timestamp_utc, program_id, target, authorized, rejection_reason
FROM audit_log
WHERE event_type = 'SCOPE_CHECK'
ORDER BY timestamp_utc DESC
LIMIT 100;

-- Rejection statistics
SELECT rejection_reason, COUNT(*) as count
FROM audit_log
WHERE event_type = 'SCOPE_CHECK' AND authorized = false
GROUP BY rejection_reason
ORDER BY count DESC;

-- Per-program summary
SELECT program_id, 
       COUNT(*) as total_checks,
       SUM(CASE WHEN authorized THEN 1 ELSE 0 END) as authorized,
       SUM(CASE WHEN authorized = false THEN 1 ELSE 0 END) as rejected
FROM audit_log
WHERE event_type = 'SCOPE_CHECK'
GROUP BY program_id;
```

---

## Error Handling

### Handle Scope Violations

```python
from hunterops.scope_middleware import ScopeAuthorizationError

try:
    await executor.exploit("external.com", "poc.py")
except ScopeAuthorizationError as e:
    print(f"❌ Scope violation: {e.message}")
    print(f"   Target: {e.target}")
    print(f"   Reason: {e.rejection_reason}")
    print(f"   Program: {e.program_id}")
    
    # Alert team
    await discord_notifier.alert(
        f"🔒 Scope violation blocked: {e.target}",
        severity="CRITICAL"
    )
```

### Handle Rate Limiting

```python
from hunterops.scope_validator import RejectionReason

result = validator.check_scope("target.com")

if result.rejection_reason == RejectionReason.RATE_LIMIT_EXCEEDED:
    logger.warning(f"Rate limit hit for {result.target}")
    # Back off and retry later
    await asyncio.sleep(10)
    result = validator.check_scope(result.target)
```

---

## Performance Characteristics

### Latency

| Operation | Latency |
|-----------|---------|
| Pattern matching (exact) | <1ms |
| Pattern matching (regex) | 1-5ms |
| Pattern matching (CIDR) | 1-3ms |
| Full scope check | 5-15ms |
| Rate limit lookup | <1ms |

### Memory

```
ScopeValidator instance: ~10KB
Pattern cache: ~50KB
Recent requests tracking: ~100KB per 1000 tracked targets
Total per program: ~200KB (negligible)
```

### Scalability

- **Concurrent validations**: Unlimited (thread-safe operations)
- **Concurrent targets**: 10,000+ without memory issues
- **Pattern complexity**: O(n) where n = number of patterns
- **Rate limit tracking**: O(1) per check

---

## Troubleshooting

### Issue: All targets rejected with "OUT_OF_SCOPE"

**Cause**: Empty or malformed inclusion patterns

**Solution**:
```python
# Check scope configuration
print(config['scope']['include'])
# Should output: ['*.example.com', ...]

# If empty:
config['scope']['include'] = ['*.example.com']
```

### Issue: Scope check fails with regex

**Cause**: Invalid regex pattern

**Solution**:
```python
import re

pattern = "^(api|www)\\.example\\.com$"

try:
    re.compile(pattern)
    print("✅ Valid regex")
except re.error as e:
    print(f"❌ Invalid: {e}")
    # Fix pattern and retry
```

### Issue: Rate limit keeps triggering

**Cause**: ROE rate_limits too strict

**Solution**:
```python
# Increase rate limit
config['roe']['rate_limits'] = {
    "max_requests": 20,      # Was 10
    "time_window_seconds": 60
}

# Or increase time window
config['roe']['rate_limits'] = {
    "max_requests": 10,
    "time_window_seconds": 120  # Was 60
}
```

### Issue: Timing restrictions blocking valid operations

**Cause**: Testing window restrictions

**Solution**:
```python
# Check current time vs allowed windows
from datetime import datetime
current = datetime.utcnow()
print(f"Current: {current.strftime('%A %H:%M')}")  # e.g., Friday 09:30

# Adjust ROE testing_windows
config['roe']['testing_windows'] = [
    {
        "start_hour": 0,           # 24/7
        "end_hour": 24,
        "allowed_days": [0,1,2,3,4,5,6]  # All days
    }
]
```

---

## Next Steps (PASSO 5+)

**PASSO 5: Rate Limiting Module**
- Global 10 req/sec hard limit enforcement
- Per-program rate limiting + backoff strategies
- Redis-backed distributed rate limiting
- Dependency: Integrates with PASSO 4 scope validation

**PASSO 6-8**: Additional phases building on scope enforcement

---

## References

- [Program Scope Format Spec](../examples/scope.schema.json)
- [ROE Examples](../config/program_example.yaml)
- [Audit Logging](DATABASE_SETUP.md#audit-logging)

---

**End of PASSO 4 Scope Validation Documentation**
