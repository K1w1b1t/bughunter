# PASSO 10: Strategic Decisions Engine

## Overview

The Strategic Decisions Engine (PASSO 10) coordinates intelligent vulnerability routing, prioritization, resource allocation, and risk management for autonomous bug bounty operations. It combines data from PASSO 9 (Intelligence) with configurable strategies to generate optimal attack plans.

## Architecture

### 4-Step Decision Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    StrategyOrchestrator                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: PRIORITIZE                                              │
│  ├─ Input: Vulnerabilities + Intelligence Data                   │
│  ├─ Component: VulnerabilityPrioritizer                          │
│  ├─ Strategy: 5 prioritization philosophies                      │
│  └─ Output: Ranked vulnerabilities (PriorityScore[])            │
│                          ↓                                        │
│  Step 2: ROUTE                                                   │
│  ├─ Input: Prioritized vulns + Platform Metrics                 │
│  ├─ Component: PlatformRouter                                    │
│  ├─ Strategy: 5 routing approaches                               │
│  └─ Output: Platform assignments (RoutingDecision{})            │
│                          ↓                                        │
│  Step 3: ALLOCATE                                               │
│  ├─ Input: Priority scores + Resource budget                     │
│  ├─ Component: ResourceAllocator                                │
│  ├─ Strategy: 5 allocation patterns                              │
│  └─ Output: Resource distribution (ResourceAllocation)          │
│                          ↓                                        │
│  Step 4: ANALYZE RISK                                            │
│  ├─ Input: Complete strategy plan                                │
│  ├─ Component: RiskAnalyzer                                      │
│  ├─ Assessment: 3 risk factors + mitigations                     │
│  └─ Output: Risk profile (RiskAssessment)                        │
│                          ↓                                        │
└──────────────────────────────────────────────────────────────────┤
                    Output: StrategyPlan                           │
                   (Complete 4-component strategy)                 │
└─────────────────────────────────────────────────────────────────┘
```

### Components

#### 1. VulnerabilityPrioritizer

Ranks vulnerabilities by priority using weighted scoring across 4 dimensions.

**Scoring Dimensions**:
- **Bounty Score**: Predicted reward potential
  - Formula: `(predicted_bounty / 10000) * 100`
  - Range: 0-100 points
  
- **Impact Score**: Severity and scope combined
  - Formula: `(cvss_score / 10) * 80 * scope_multiplier`
  - Scope multiplier: critical=2.0, high=1.5, medium=1.0
  - Range: 0-100 points
  
- **Speed Score**: Ease of exploitation
  - Formula: `(10 - complexity) * 10`
  - Inverse complexity (lower complexity = higher score)
  - Range: 0-100 points
  
- **Trend Score**: Novelty and market demand
  - Increasing: 80 points
  - Stable: 50 points
  - Decreasing: 20 points
  - Range: 20-80 points

**5 Prioritization Strategies**:

| Strategy | Bounty | Impact | Speed | Trend | Use Case |
|----------|--------|--------|-------|-------|----------|
| **BOUNTY_FOCUSED** | 60% | 20% | 10% | 10% | Revenue maximization |
| **IMPACT_FOCUSED** | 20% | 60% | 10% | 10% | Security impact priority |
| **SPEED_FOCUSED** | 20% | 10% | 60% | 10% | Quick wins (short sprint) |
| **BALANCED** | 30% | 30% | 20% | 20% | Mixed objectives |
| **NOVELTY_FOCUSED** | 20% | 20% | 20% | 40% | Trend-following research |

#### 2. PlatformRouter

Allocates vulnerabilities to optimal bug bounty platforms based on platform characteristics.

**Routing Considerations**:
- Platform acceptance rates
- Historical bounty averages
- Vulnerability type affinity
- Parallel submission capability

**5 Routing Strategies**:

| Strategy | Decision Logic | Use Case |
|----------|---|---|
| **MAXIMIZE_ACCEPTANCE** | Route to platform with highest acceptance rate | Maximize accepted vulnerabilities |
| **MAXIMIZE_BOUNTY** | Route to platform with highest avg bounty | Revenue maximization |
| **BALANCED** | Weighted score (0.4 × acceptance + 0.6 × bounty) | Mixed objectives |
| **SEQUENTIAL** | Order by acceptance, with fallback chain | Hierarchical platforms |
| **DIVERSIFIED** | Distribute across platforms evenly | Risk reduction |

**Confidence Scoring**:
- 0.0-0.5: Low confidence (risky platform match)
- 0.5-0.7: Medium confidence (reasonable platform match)
- 0.7-0.9: High confidence (good platform match)
- 0.9-1.0: Very high confidence (excellent platform match)

#### 3. ResourceAllocator

Distributes limited resources (focus, effort time) across prioritized vulnerabilities.

**5 Allocation Strategies**:

| Strategy | Distribution | Use Case |
|----------|---|---|
| **UNIFORM** | Equal distribution (100 / N vulns) | Exploration phase |
| **WEIGHTED** | Proportional to priority | Standard operation |
| **AGGRESSIVE** | Focus on top 1/3 vulnerabilities | Short-term revenue |
| **CONSERVATIVE** | Spread across top 10 vulnerabilities | Risk hedging |
| **ADAPTIVE** | Weight by historical success rates | Learning from history |

**Efficiency Scoring**:
- Measures match quality between priority ranking and resource allocation
- Range: 0-100 (100 = perfect match)
- Formula: Normalized distance between priority rank and allocation proportion

**Projections**:
- **Projected Bounty**: `sum(resources) * $100/unit * acceptance_rate`
- **Projected Acceptance**: Platform acceptance rate or historical average
- **Projected Time**: Resources ÷ throughput (vulnerabilities per week)

#### 4. RiskAnalyzer

Assesses comprehensive risk profile of strategy.

**3 Risk Factors** (each 0-100):

1. **Concentration Risk**: Over-reliance on single vulnerability
   - `highest_allocation / total_resources`
   - HIGH if >70%, MEDIUM if 40-70%, LOW if <40%

2. **Platform Risk**: Dependency on specific platforms
   - Count of platforms used
   - LOW if 3+ platforms, HIGH if 1-2, CRITICAL if 1

3. **Execution Risk**: Complexity of implementation
   - Scales with vulnerability count
   - 5 vulns → 20% risk, 50 vulns → 80% risk

**Risk Levels**:
- **LOW** (<25): Well-diversified, multiple platforms, low concentration
- **MEDIUM** (25-50): Some concentration, 2-3 platforms
- **HIGH** (50-75): Significant concentration or platform dependency
- **CRITICAL** (≥75): Single platform or extreme concentration

**Gain/Loss Calculations**:
- **Potential Gain**: `sum(resources) * (avg_bounty / 100) * acceptance_rate`
- **Potential Loss**: `total_resources * $50/unit * rejection_rate`
- **Win/Loss Ratio**: Gain ÷ Loss (higher = better)

**Mitigations**: 
- HIGH/CRITICAL risk → Diversify platforms, phased rollout, fallback strategy
- MEDIUM risk → Monitor closely, checkpoint reviews
- LOW risk → Continue as planned

## Usage Examples

### Example 1: Bounty Maximization

Focus on revenue generation with balanced risk.

```python
from hunterops.passo10_strategy import StrategyOrchestrator, RoutingStrategy, PrioritizationStrategy, AllocationStrategy

orchestrator = StrategyOrchestrator()

# Create strategy plan focused on bounty
plan = await orchestrator.create_strategy_plan(
    vulnerabilities=vulnerabilities,
    platform_metrics=passo9_intelligence["platform_metrics"],
    intelligence_data=passo9_intelligence,
    routing_strategy=RoutingStrategy.MAXIMIZE_BOUNTY,
    prioritization_strategy=PrioritizationStrategy.BOUNTY_FOCUSED,
    allocation_strategy=AllocationStrategy.WEIGHTED,
    total_resources=100,
)

# Access routing decisions
for vuln_id, decision in plan.routing_decisions.items():
    print(f"{vuln_id} → {decision.recommended_platform} "
          f"(confidence: {decision.confidence:.1%}, "
          f"expected: ${decision.expected_bounty})")

# Check risk profile
print(f"Risk Level: {plan.risk_assessment.risk_level}")
print(f"Potential Gain: ${plan.risk_assessment.potential_gain:,.0f}")
print(f"Potential Loss: ${plan.risk_assessment.potential_loss:,.0f}")
```

### Example 2: Quick Wins (Speed Focused)

Maximize easy-to-exploit vulnerabilities for rapid discoveries.

```python
# Create speed-focused strategy
plan = await orchestrator.create_strategy_plan(
    vulnerabilities=easy_vulns,
    platform_metrics=passo9_intelligence["platform_metrics"],
    intelligence_data=passo9_intelligence,
    routing_strategy=RoutingStrategy.MAXIMIZE_ACCEPTANCE,
    prioritization_strategy=PrioritizationStrategy.SPEED_FOCUSED,
    allocation_strategy=AllocationStrategy.AGGRESSIVE,
    total_resources=100,
)

# Get human-readable summary
summary = await orchestrator.get_strategy_summary(plan)
print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
print(f"Projected bounty: ${summary['projected_bounty']:,.0f}")
print(f"Risk level: {summary['risk_level']}")
print(f"Estimated completion: {summary.get('estimated_days', 'N/A')} days")
```

### Example 3: Risk Diversification

Spread resources across multiple platforms and vulnerabilities.

```python
# Create diversified strategy for risk hedging
plan = await orchestrator.create_strategy_plan(
    vulnerabilities=all_vulns,
    platform_metrics=passo9_intelligence["platform_metrics"],
    intelligence_data=passo9_intelligence,
    routing_strategy=RoutingStrategy.DIVERSIFIED,
    prioritization_strategy=PrioritizationStrategy.BALANCED,
    allocation_strategy=AllocationStrategy.CONSERVATIVE,
    total_resources=100,
)

# Verify platform distribution
platforms_used = set(d.recommended_platform for d in plan.routing_decisions.values())
print(f"Platforms used: {platforms_used}")
print(f"Risk score: {plan.risk_assessment.risk_score}")
```

### Example 4: Adaptive Learning

Use historical data to adjust strategy over time.

```python
# Get statistics on previous strategies
stats = await orchestrator.get_statistics()
print(f"Average acceptance rate: {stats['avg_acceptance_rate']:.1%}")
print(f"Average bounty: ${stats['avg_bounty_projection']:,.0f}")
print(f"Most reliable platform: {stats['platform_reliability']}")

# Create new strategy with adaptive allocation
plan = await orchestrator.create_strategy_plan(
    vulnerabilities=vulns,
    platform_metrics=passo9_intelligence["platform_metrics"],
    intelligence_data=passo9_intelligence,
    allocation_strategy=AllocationStrategy.ADAPTIVE,
)
```

### Example 5: Novelty-Driven Research

Focus on trending vulnerabilities and newly discovered patterns.

```python
# Create research-focused strategy
plan = await orchestrator.create_strategy_plan(
    vulnerabilities=trending_vulns,
    platform_metrics=passo9_intelligence["platform_metrics"],
    intelligence_data=passo9_intelligence,
    routing_strategy=RoutingStrategy.BALANCED,
    prioritization_strategy=PrioritizationStrategy.NOVELTY_FOCUSED,
    allocation_strategy=AllocationStrategy.UNIFORM,  # Explore new types
)

# Verify trend alignment
for vuln_id, score in plan.priority_scores.items():
    print(f"{vuln_id}: Trend contribution: {score.trend_contribution:.0f}%")
```

### Example 6: Compliance-First Approach

Prioritize in-scope vulnerabilities with lower execution risk.

```python
# Filter in-scope, low-complexity vulnerabilities
safe_vulns = [v for v in vulns if v['scope'] == 'in_bounds' and v['complexity'] <= 3]

# Create compliance-focused strategy
plan = await orchestrator.create_strategy_plan(
    vulnerabilities=safe_vulns,
    platform_metrics=passo9_intelligence["platform_metrics"],
    intelligence_data=passo9_intelligence,
    routing_strategy=RoutingStrategy.MAXIMIZE_ACCEPTANCE,
    prioritization_strategy=PrioritizationStrategy.BALANCED,
    allocation_strategy=AllocationStrategy.UNIFORM,
)

# Ensure all mitigations are documented
if plan.risk_assessment.mitigations:
    print("Risk Mitigations Required:")
    for mitigation in plan.risk_assessment.mitigations:
        print(f"  - {mitigation}")
```

## Strategy Selection Guide

### Choosing the Right Strategy

**For Revenue Teams**:
- Prioritization: `BOUNTY_FOCUSED`
- Routing: `MAXIMIZE_BOUNTY`
- Allocation: `WEIGHTED` or `AGGRESSIVE`

**For Security Teams**:
- Prioritization: `IMPACT_FOCUSED`
- Routing: `BALANCED` or `MAXIMIZE_ACCEPTANCE`
- Allocation: `WEIGHTED` or `CONSERVATIVE`

**For Research/Learning**:
- Prioritization: `NOVELTY_FOCUSED`
- Routing: `DIVERSIFIED`
- Allocation: `UNIFORM` or `CONSERVATIVE`

**For Time-Boxed Engagements**:
- Prioritization: `SPEED_FOCUSED`
- Routing: `MAXIMIZE_ACCEPTANCE`
- Allocation: `AGGRESSIVE`

**For Multi-Year Operations**:
- Prioritization: `BALANCED`
- Routing: `DIVERSIFIED`
- Allocation: `ADAPTIVE`

## API Reference

### StrategyOrchestrator

Main orchestration class that coordinates all 4 components.

```python
orchestrator = StrategyOrchestrator()

# Create complete strategy plan
plan = await orchestrator.create_strategy_plan(
    vulnerabilities: List[Dict],
    platform_metrics: Dict,
    intelligence_data: Dict,
    routing_strategy: RoutingStrategy = BALANCED,
    prioritization_strategy: PrioritizationStrategy = BALANCED,
    allocation_strategy: AllocationStrategy = WEIGHTED,
    total_resources: int = 100,
) -> StrategyPlan

# Get human-readable summary
summary = await orchestrator.get_strategy_summary(plan: StrategyPlan) -> Dict

# Get overall statistics
stats = orchestrator.get_statistics() -> Dict
```

### VulnerabilityPrioritizer

Ranks vulnerabilities by priority.

```python
prioritizer = VulnerabilityPrioritizer()

priority_scores = await prioritizer.prioritize(
    vulnerabilities: List[Dict],
    intelligence_data: Dict,
    strategy: PrioritizationStrategy = BALANCED,
) -> List[PriorityScore]
```

**PriorityScore Fields**:
- `vulnerability_id`: str
- `priority_score`: float (0-100)
- `rank`: int (1-based)
- `bounty_contribution`: float (% of score)
- `impact_contribution`: float (% of score)
- `speed_contribution`: float (% of score)
- `trend_contribution`: float (% of score)

### PlatformRouter

Routes vulnerabilities to optimal platforms.

```python
router = PlatformRouter()

decision = await router.decide_platform(
    vulnerability_id: str,
    platform_metrics: Dict,
    vulnerability_data: Dict,
    strategy: RoutingStrategy = BALANCED,
) -> RoutingDecision

decisions = await router.get_all_decisions() -> Dict[str, RoutingDecision]
```

**RoutingDecision Fields**:
- `recommended_platform`: str (platform name)
- `alternative_platforms`: List[str]
- `confidence`: float (0.0-1.0)
- `expected_bounty`: float
- `expected_acceptance_rate`: float

### ResourceAllocator

Distributes resources across vulnerabilities.

```python
allocator = ResourceAllocator()

allocation = await allocator.allocate_resources(
    priority_scores: List[PriorityScore],
    total_resources: int,
    strategy: AllocationStrategy = WEIGHTED,
) -> ResourceAllocation

# Projections available
projected_bounty = allocation.projected_bounty  # float
projected_acceptance = allocation.projected_acceptance  # float
efficiency_score = allocation.efficiency_score  # 0-100
```

**ResourceAllocation Fields**:
- `allocations`: Dict[str, int] (vuln_id → resources)
- `total_resources`: int
- `efficiency_score`: float (0-100)
- `projected_bounty`: float
- `projected_acceptance`: float

### RiskAnalyzer

Analyzes strategy risks and mitigations.

```python
analyzer = RiskAnalyzer()

assessment = await analyzer.analyze_risk(
    strategy_plan: Dict,
    historical_data: Dict,
) -> RiskAssessment
```

**RiskAssessment Fields**:
- `risk_level`: str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
- `risk_score`: float (0-100)
- `concentration_risk`: float (0-100)
- `platform_risk`: float (0-100)
- `execution_risk`: float (0-100)
- `potential_gain`: float
- `potential_loss`: float
- `mitigations`: List[str]

## Integration Points

### Consuming from PASSO 9 (Intelligence)

```python
# PASSO 9 provides intelligence data
intelligence_data = {
    "platform_metrics": {
        "hackerone": {
            "acceptance_rate": 0.75,
            "avg_bounty": 2500,
            "trend_30day": 0.15,
        },
        # ... other platforms
    },
    "trends": {
        "sql_injection": {"trend_direction": "increasing"},
        # ... other trends
    },
    "historical_data": {
        "avg_acceptance_rate": 0.65,
        "avg_rejection_rate": 0.35,
    },
}

# Use in PASSO 10
plan = await orchestrator.create_strategy_plan(
    vulnerabilities=vulns,
    platform_metrics=intelligence_data["platform_metrics"],
    intelligence_data=intelligence_data,
)
```

### Providing to PASSO 11 (Adaptive Learning)

```python
# PASSO 10 outputs strategy plan
plan = await orchestrator.create_strategy_plan(...)

# PASSO 11 consumes routing and allocation decisions
routing_decisions = plan.routing_decisions  # {vuln_id: RoutingDecision}
allocations = plan.resource_allocation.allocations  # {vuln_id: resources}
risk_profile = plan.risk_assessment  # RiskAssessment

# PASSO 11 will iterate and optimize based on outcomes
```

## Performance Characteristics

### Time Complexity

- **Prioritization**: O(N log N) where N = vulnerability count
- **Routing**: O(N × P) where P = platform count
- **Allocation**: O(N) with sorting
- **Risk Analysis**: O(N)
- **Total**: O(N log N + N × P) ≈ O(N × P)

### Scalability

- **Small operations** (10-50 vulns): <100ms
- **Medium operations** (50-500 vulns): 100-500ms
- **Large operations** (500+ vulns): 500ms-2s

### Memory Usage

- **Per strategy**: ~1MB base + 10KB per vulnerability
- **100 vulnerabilities**: ~2MB
- **1,000 vulnerabilities**: ~11MB

## Configuration

### Environment Variables

```bash
# Strategy defaults
PASSO10_DEFAULT_ROUTING_STRATEGY=BALANCED
PASSO10_DEFAULT_PRIORITIZATION_STRATEGY=BALANCED
PASSO10_DEFAULT_ALLOCATION_STRATEGY=WEIGHTED
PASSO10_DEFAULT_TOTAL_RESOURCES=100

# Risk thresholds
PASSO10_CONCENTRATION_THRESHOLD=0.70
PASSO10_PLATFORM_THRESHOLD=2
```

### Runtime Configuration

```python
from hunterops.passo10_strategy import StrategyOrchestrator

# Custom configuration
orchestrator = StrategyOrchestrator(
    max_strategies=100,  # Cache size
    log_level="INFO",
)
```

## Testing

See `tests/test_passo10_strategy.py` for comprehensive test coverage:

```bash
# Run all tests
pytest tests/test_passo10_strategy.py -v

# Run specific component tests
pytest tests/test_passo10_strategy.py::TestVulnerabilityPrioritizer -v

# Run with coverage
pytest tests/test_passo10_strategy.py --cov=hunterops.passo10_strategy --cov-report=html
```

**Test Coverage**: 40+ tests covering:
- All 5 routing strategies
- All 5 prioritization strategies
- All 5 allocation strategies
- All 4 risk levels
- Complete orchestration pipeline
- Integration scenarios

## Troubleshooting

### Issue: Vulnerabilities not prioritized correctly

**Cause**: Intelligence data missing trend information
**Solution**: Ensure PASSO 9 provides complete trend data
```python
# Verify intelligence_data structure
assert "trends" in intelligence_data
assert all("trend_direction" in v for v in intelligence_data["trends"].values())
```

### Issue: Strategy plan includes risky allocation

**Cause**: Resource concentration too high
**Solution**: Use different allocation strategy
```python
# Switch to conservative
plan = await orchestrator.create_strategy_plan(
    ...,
    allocation_strategy=AllocationStrategy.CONSERVATIVE,
)
```

### Issue: Platform routing doesn't match expectations

**Cause**: Platform metrics outdated or platform excluded
**Solution**: Verify platform_metrics completeness
```python
# Check available platforms
print(platform_metrics.keys())
# Ensure all expected platforms are present
```

## Roadmap

- **v1.1**: Machine learning-based strategy optimization
- **v1.2**: Multi-objective optimization (Pareto frontier)
- **v1.3**: User feedback integration
- **v1.4**: Predictive risk scoring
- **v1.5**: Platform-specific vulnerability type affinity learning
