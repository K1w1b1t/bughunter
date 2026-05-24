# Rate Limiting Documentation - PASSO 5

## Overview

**PASSO 5** implements a **global 10 req/sec hard limit** with per-program rate limiting and automatic backoff. This prevents:

- DoS attacks (internal or external)
- API quota violations  
- Resource exhaustion
- Cascading failures

**Hard Guarantees**:
- ✅ Maximum 10 requests per second (global, non-negotiable)
- ✅ Per-program rate limits (configurable, never exceed global)
- ✅ Token bucket algorithm (industry standard)
- ✅ Automatic backoff on rejection
- ✅ Distributed consistency (Redis-backed optional)

---

## Architecture

### Token Bucket Algorithm

The **token bucket** algorithm prevents burst traffic:

```
Bucket Configuration:
  - Capacity: 10 tokens (max requests per burst)
  - Refill rate: 10 tokens/second
  - Current tokens: Available for requests

Request Flow:
  1. Check if tokens available
     ├─ Yes: Consume 1 token → ALLOWED
     └─ No: Return wait time → RATE_LIMITED
  
  2. Over time, tokens refill
     - 1 second later: 10 tokens available again
     - 0.1 second later: 1 token available

Example:
  t=0.0s:  10 tokens available
  t=0.0s:  Request 1 → consume 1 token (9 remaining)
  t=0.0s:  Request 2-10 → consume 10 tokens → now at 0
  t=0.0s:  Request 11 → RATE_LIMITED (wait 0.1s)
  t=0.1s:  1 token refilled → Request 11 → ALLOWED
  t=1.0s:  All 10 tokens refilled
```

### Components

```
┌─────────────────────────────────────────────────┐
│  GlobalRateLimiter (Hard 10 req/sec limit)     │
├─────────────────────────────────────────────────┤
│  ├─ Global Token Bucket (10 tokens/sec)        │
│  │  └─ Non-negotiable hard limit               │
│  │                                              │
│  └─ Per-Program Token Buckets (configurable)   │
│     ├─ program_001: Custom limits              │
│     ├─ program_002: Custom limits              │
│     └─ Capped at global limit (10 req/sec)    │
│                                                 │
├─ RateLimitMiddleware (Integration layer)      │
│  ├─ check_rate_limit(program_id)              │
│  ├─ Statistics tracking                        │
│  └─ Error handling + alerts                    │
│                                                 │
├─ Backoff Strategies (Retry logic)             │
│  ├─ Exponential (2^n seconds)                 │
│  ├─ Linear (n seconds)                        │
│  ├─ Fixed (constant delay)                    │
│  └─ Jitter variants (prevent thundering herd) │
│                                                 │
└─ RedisBackedTokenBucket (Optional)            │
   └─ Distributed rate limiting via Redis       │
```

---

## Configuration

### Global Setup

```python
from hunterops.rate_limiter import GlobalRateLimiter, RateLimitMiddleware

# Initialize at startup (executor.py)
limiter = GlobalRateLimiter()  # Hard limit: 10 req/sec

# Optional: Configure individual programs
limiter.configure_program(
    "program_001",
    tokens_per_second=5.0,  # Override to 5 req/sec
    max_tokens=5.0,
    backoff_strategy="EXPONENTIAL_JITTER"
)

# Create middleware for decorators
middleware = RateLimitMiddleware(limiter)
```

### Environment Variables

```bash
# Global Rate Limiting
RATE_LIMIT_GLOBAL_REQ_SEC=10               # Hard limit (do not change)
RATE_LIMIT_ENABLED=true                    # Enable/disable

# Per-Program Overrides
RATE_LIMIT_PROGRAM_001_REQ_SEC=5           # Custom limit for program
RATE_LIMIT_PROGRAM_001_MAX_TOKENS=5

# Backoff Strategy
RATE_LIMIT_BACKOFF_STRATEGY=EXPONENTIAL_JITTER
RATE_LIMIT_BACKOFF_INITIAL=1.0             # Initial wait (seconds)
RATE_LIMIT_BACKOFF_MAX=300.0               # Max wait (5 minutes)
RATE_LIMIT_BACKOFF_MAX_RETRIES=5           # Give up after N retries

# Redis (Optional)
REDIS_RATE_LIMIT_BACKEND=redis://redis:6379/2
RATE_LIMIT_DISTRIBUTED=false               # Enable distributed mode
```

---

## Usage Examples

### 1. Basic Rate Limiting

```python
from hunterops.rate_limiter import GlobalRateLimiter

limiter = GlobalRateLimiter()

# Check if allowed
result = limiter.check_limit("program_001")

if result.allowed:
    print(f"✅ Allowed: {result.tokens_available} tokens remaining")
    # Execute operation
else:
    print(f"❌ Rate limited: Wait {result.wait_seconds:.1f}s")
    print(f"   Retry after: {result.retry_after}")
```

### 2. Middleware Integration

```python
from hunterops.rate_limiter import RateLimitMiddleware, RateLimitError

# Setup
limiter = GlobalRateLimiter()
middleware = RateLimitMiddleware(limiter)

# Usage
try:
    result = await middleware.check_rate_limit("program_001")
    if result.allowed:
        await perform_network_operation()
except RateLimitError as e:
    print(f"Rate limited: {e.message}")
    print(f"Retry after: {e.retry_after}")
    await handle_backoff(e.wait_seconds)
```

### 3. Decorator Integration

```python
from hunterops.rate_limiter import require_rate_limit_authorization

# Automatic rate limiting on decorated functions
@require_rate_limit_authorization(program_id="program_001")
async def scan_ports(target: str):
    # Only executed if rate limit allows
    # If rate limited: RateLimitError raised automatically
    pass

@require_rate_limit_authorization(program_id="program_001", tokens=2)
async def exploit_vulnerability(target: str):
    # Exploitation uses 2 tokens (higher cost than scanning)
    pass
```

### 4. Batch Operations

```python
# Pre-check multiple targets
targets = ["example.com", "api.example.com", "admin.example.com"]

# Check if batch can proceed
result = limiter.check_limit("program_001", tokens=len(targets))

if result.allowed:
    for target in targets:
        await scan(target)
else:
    print(f"Batch rate limited: Wait {result.wait_seconds}s")
```

### 5. Backoff Retry

```python
from hunterops.backoff_strategies import BackoffExecutor, BackoffConfig, BackoffStrategy

# Setup backoff
config = BackoffConfig(
    strategy=BackoffStrategy.EXPONENTIAL,
    initial_delay=1.0,
    max_delay=60.0,
    max_retries=5
)

# Retry with automatic backoff
async def make_request():
    return await http_client.get("https://api.example.com")

try:
    result = await BackoffExecutor.retry_with_backoff(make_request, config)
    # Attempt 1: immediate
    # Attempt 2: wait 1s
    # Attempt 3: wait 2s
    # Attempt 4: wait 4s
    # Attempt 5: wait 8s
except Exception as e:
    print(f"All retries failed: {e}")
```

### 6. Per-Program Configuration

```python
limiter = GlobalRateLimiter()

# Program with relaxed limits
limiter.configure_program(
    "enterprise_program",
    tokens_per_second=10.0,  # Full capacity
    max_tokens=10.0,
    backoff_strategy=BackoffStrategy.LINEAR
)

# Program with strict limits
limiter.configure_program(
    "test_program",
    tokens_per_second=2.0,   # Only 2 req/sec
    max_tokens=2.0,
    backoff_strategy=BackoffStrategy.FIXED
)

# Check status
stats = limiter.get_statistics()
print(f"Global: {stats['global']}")
print(f"Programs: {stats['programs']}")
```

---

## Backoff Strategies

### Exponential (Recommended)

```
Attempt 1: immediate (0s)
Attempt 2: wait 1s   (2^0)
Attempt 3: wait 2s   (2^1)
Attempt 4: wait 4s   (2^2)
Attempt 5: wait 8s   (2^3)
Max: 300s (5 minutes)

Best for: Distributed systems, external APIs
```

### Linear

```
Attempt 1: immediate (0s)
Attempt 2: wait 1s   (1×)
Attempt 3: wait 2s   (2×)
Attempt 4: wait 3s   (3×)
Attempt 5: wait 4s   (4×)
Max: 300s

Best for: Predictable delays
```

### Fixed

```
Attempt 1: immediate (0s)
Attempt 2: wait 1s
Attempt 3: wait 1s
Attempt 4: wait 1s
Attempt 5: wait 1s

Best for: Simple constant backoff
```

### Jitter Variants

Prevents **thundering herd** (all retries at same time):

```
Exponential + Jitter (±10%):
Attempt 2: 1.0s ± 0.1s = [0.9s, 1.1s]
Attempt 3: 2.0s ± 0.2s = [1.8s, 2.2s]
Attempt 4: 4.0s ± 0.4s = [3.6s, 4.4s]
```

---

## Performance Characteristics

### Latency

| Operation | Latency |
|-----------|---------|
| Token bucket check | <1ms |
| Rate limit check | 1-5ms |
| Backoff calculation | <1ms |
| Redis check (if used) | 1-10ms |

### Throughput

```
Single rate limiter:
- Checks per second: ~10,000+
- Concurrent programs: Unlimited
- Memory overhead: ~50KB

6 Workers:
- Total throughput: 60,000+ checks/sec
- Each worker at ~10 req/sec limit
- Total cluster: 60 req/sec (6 × 10)
```

### Memory

```
TokenBucket instance: ~500 bytes
Per-program bucket: ~500 bytes
Middleware: ~1KB
Redis backend: Negligible (state on Redis)

Per program: ~1KB overhead
100 programs: ~100KB
```

---

## Integration with HunterOps

### Executor Integration

```python
# executor.py

class Executor:
    def __init__(self, program_config):
        self.rate_limiter = GlobalRateLimiter()
        self.rate_middleware = RateLimitMiddleware(self.rate_limiter)
    
    @require_rate_limit_authorization(program_id="{program_id}", tokens=1)
    async def recon_phase(self, target: str):
        """Recon uses 1 token per scan."""
        await scanner.run(target)
    
    @require_rate_limit_authorization(program_id="{program_id}", tokens=2)
    async def exploit_phase(self, target: str):
        """Exploitation uses 2 tokens (higher cost)."""
        await exploiter.run(target)
```

### Attack State Machine

```python
# attack_state_machine.py

async def execute_phase(phase_name, targets):
    """Execute with rate limiting."""
    
    # Pre-check if batch fits rate limit
    result = limiter.check_limit(
        program_id,
        tokens=len(targets)  # Check for all targets
    )
    
    if not result.allowed:
        logger.warning(f"Batch rate limited: wait {result.wait_seconds}s")
        await asyncio.sleep(result.wait_seconds)
    
    # Execute rate-limited operations
    for target in targets:
        result = await middleware.check_rate_limit(program_id)
        if result.allowed:
            await execute_on_target(phase_name, target)
```

---

## Monitoring & Alerting

### Get Statistics

```python
stats = middleware.get_statistics()

print(f"Total checks: {stats['total_checks']}")
print(f"Allowed: {stats['allowed']}")
print(f"Rejected: {stats['rejected']}")
print(f"Rejection rate: {stats['rejection_rate']:.1f}%")

# Per-program stats
for program_id, program_stats in stats['limiter_stats']['programs'].items():
    print(f"{program_id}:")
    print(f"  Capacity: {program_stats['capacity']}")
    print(f"  Available: {program_stats['available']:.1f}")
    print(f"  Rejection rate: {program_stats['rejection_rate']:.1f}%")
```

### Alert Conditions

```python
# Alert if rejection rate > 20%
if stats['rejection_rate'] > 20.0:
    await discord.alert(
        f"⚠️ Rate limiting active: {stats['rejection_rate']:.1f}% rejection"
    )

# Alert if approaching capacity
if stats['limiter_stats']['global']['available'] < 2.0:
    await discord.alert(
        f"⚠️ Rate limit capacity low: {stats['limiter_stats']['global']['available']:.1f} tokens"
    )
```

---

## Error Handling

### Handle Rate Limit Error

```python
from hunterops.rate_limiter import RateLimitError

try:
    await perform_network_operation()
except RateLimitError as e:
    logger.warning(f"Rate limited: {e.message}")
    logger.warning(f"Program: {e.program_id}")
    logger.warning(f"Wait: {e.wait_seconds}s")
    logger.warning(f"Retry after: {e.retry_after}")
    
    # Backoff
    await asyncio.sleep(e.wait_seconds)
    
    # Retry
    await perform_network_operation()
```

### Graceful Degradation

```python
try:
    result = await middleware.check_rate_limit(program_id)
except Exception as e:
    # On any error, apply conservative backoff
    logger.error(f"Rate limit check failed: {e}")
    await asyncio.sleep(5.0)  # Safe default wait
    return  # Skip operation
```

---

## Troubleshooting

### Issue: All requests rate limited

**Cause**: Global bucket depleted

**Solution**:
```python
# Check bucket status
stats = limiter.get_statistics()
print(f"Available tokens: {stats['global']['available']}")
print(f"Refill rate: {stats['global']['refill_rate']}")

# Wait for refill (1 second @ 10 tokens/sec = full refill)
await asyncio.sleep(1.0)
```

### Issue: Per-program limit not working

**Cause**: Program not configured

**Solution**:
```python
# Ensure program configured
if program_id not in limiter.program_buckets:
    limiter.configure_program(program_id, tokens_per_second=10.0)
```

### Issue: Backoff retries too aggressive  

**Cause**: Wrong backoff strategy

**Solution**:
```python
# Use linear or fixed for gentler backoff
config = BackoffConfig(
    strategy=BackoffStrategy.LINEAR,      # Less aggressive
    initial_delay=1.0,
    max_delay=60.0,
    max_retries=10
)
```

---

## Testing

### Run Tests

```bash
pytest tests/test_rate_limiting.py -v
pytest tests/test_rate_limiting.py::TestGlobalRateLimiter -v
pytest tests/test_rate_limiting.py -k "backoff" -v
```

### Test Coverage

- ✅ Token bucket algorithm
- ✅ Global rate limiting (hard 10 req/sec)
- ✅ Per-program configuration
- ✅ Rate limit decisions
- ✅ Backoff strategies (exponential, linear, fixed, jitter)
- ✅ Middleware integration
- ✅ Error handling
- ✅ Statistics tracking

---

## Next Steps (PASSO 6+)

**PASSO 6: Evidence Generator**
- Auto-generate proof-of-concept findings
- Integrates with: Scope (PASSO 4) + Rate Limiting (PASSO 5)
- Dependencies: Must be rate-limited

**PASSO 7: Report Engine**
- LLM-powered finding narrative generation
- Uses triage results from PASSO 3
- With rate limitation (PASSO 5)

---

## References

- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [RFC 6585: HTTP Status Code 429](https://tools.ietf.org/html/rfc6585)
- [Exponential Backoff and Jitter](https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/)

---

**End of PASSO 5 Rate Limiting Documentation**
