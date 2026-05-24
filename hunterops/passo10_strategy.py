"""
PASSO 10: Strategic Decisions Engine - Autonomous Strategy Optimization

Consumes intelligence from PASSO 9 to make strategic decisions about:
  - Platform selection & routing optimization
  - Vulnerability prioritization
  - Focus resource allocation
  - Submission strategy refinement
  - Risk-reward analysis

Components:
    - PlatformRouter: Intelligent platform routing decisions
    - VulnerabilityPrioritizer: Prioritization algorithm
    - ResourceAllocator: Focus allocation engine
    - StrategyOptimizer: Cross-cutting strategy optimization
    - RiskAnalyzer: Risk-reward assessment
    - StrategyOrchestrator: Main coordinator
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set
from uuid import uuid4
import statistics

logger = logging.getLogger(__name__)


class RoutingStrategy(Enum):
    """Platform routing strategies."""
    MAXIMIZE_ACCEPTANCE = "maximize_acceptance"     # Pick platform with highest acceptance rate
    MAXIMIZE_BOUNTY = "maximize_bounty"             # Pick platform with highest average bounty
    BALANCED = "balanced"                           # Balance acceptance & bounty
    SEQUENTIAL = "sequential"                       # Sequential fallback strategy
    DIVERSIFIED = "diversified"                     # Distribute across multiple platforms


class PrioritizationStrategy(Enum):
    """Vulnerability prioritization strategies."""
    BOUNTY_FOCUSED = "bounty_focused"               # Prioritize high-bounty vulnerabilities
    IMPACT_FOCUSED = "impact_focused"               # Prioritize high-impact (scope) vulnerabilities
    SPEED_FOCUSED = "speed_focused"                 # Prioritize quick-to-fix vulnerabilities
    BALANCED = "balanced"                           # Balance all factors
    NOVELTY_FOCUSED = "novelty_focused"             # Prioritize novel/trendy vulnerabilities


class AllocationStrategy(Enum):
    """Resource allocation strategies."""
    UNIFORM = "uniform"                            # Uniform allocation across all vulnerabilities
    WEIGHTED = "weighted"                          # Weight based on priority scores
    AGGRESSIVE = "aggressive"                      # Aggressive focus on top opportunities
    CONSERVATIVE = "conservative"                  # Conservative, diversified allocation
    ADAPTIVE = "adaptive"                          # Adapt based on success rates


@dataclass
class RoutingDecision:
    """Decision for platform routing."""
    vulnerability_id: str
    recommended_platform: str
    alternative_platforms: List[str] = field(default_factory=list)
    confidence: float = 0.0                         # 0-1
    reasoning: str = ""
    expected_acceptance_prob: float = 0.0           # 0-1
    expected_bounty: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PriorityScore:
    """Priority score for vulnerability."""
    vulnerability_id: str
    priority_score: float                           # 0-100
    rank: int = 0                                   # 1-N
    bounty_contribution: float = 0.0                # Factor
    impact_contribution: float = 0.0                # Factor
    speed_contribution: float = 0.0                 # Factor
    trend_contribution: float = 0.0                 # Factor (novelty)
    reasoning: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ResourceAllocation:
    """Resource allocation plan."""
    total_resources: int                            # Total available resources
    allocations: Dict[str, int]                     # vulnerability_id -> resources
    efficiency_score: float = 0.0                   # 0-100
    projected_bounty: float = 0.0                   # Projected total bounty
    projected_acceptance_rate: float = 0.0          # 0-1
    reasoning: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RiskAssessment:
    """Risk assessment for strategy."""
    strategy_id: str
    risk_level: str                                 # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float                               # 0-100
    potential_loss: float = 0.0                     # Downside
    potential_gain: float = 0.0                     # Upside
    risk_reward_ratio: float = 0.0                  # Gain/Loss
    recommended_actions: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class StrategyPlan:
    """Complete strategy plan."""
    strategy_id: str
    routing_decisions: Dict[str, RoutingDecision]
    priority_scores: Dict[str, PriorityScore]
    resource_allocation: ResourceAllocation
    risk_assessment: RiskAssessment
    created_at: datetime = field(default_factory=datetime.utcnow)


class PlatformRouter:
    """Intelligent platform routing decisions."""

    def __init__(self):
        """Initialize router."""
        self.routing_decisions: Dict[str, RoutingDecision] = {}

    async def decide_platform(
        self,
        vulnerability_id: str,
        platform_metrics: Dict[str, Any],
        vulnerability_data: Dict[str, Any],
        strategy: RoutingStrategy = RoutingStrategy.BALANCED,
    ) -> RoutingDecision:
        """Decide which platform to submit vulnerability to.

        Args:
            vulnerability_id: Vulnerability identifier
            platform_metrics: Platform effectiveness metrics from PASSO 9
            vulnerability_data: Vulnerability details
            strategy: Routing strategy to use

        Returns:
            RoutingDecision with recommended platform
        """
        logger.info(f"Routing vulnerability {vulnerability_id} with strategy {strategy.value}")

        # Score platforms based on strategy
        platform_scores = self._score_platforms(platform_metrics, vulnerability_data, strategy)

        # Select best platform
        best_platform = max(platform_scores, key=platform_scores.get) if platform_scores else None

        if not best_platform:
            logger.warning(f"No suitable platform found for {vulnerability_id}")
            return RoutingDecision(
                vulnerability_id=vulnerability_id,
                recommended_platform="unknown",
                confidence=0.0,
                reasoning="No suitable platforms available",
            )

        # Get alternatives (top 2 runners-up)
        alternatives = sorted(
            [(p, s) for p, s in platform_scores.items() if p != best_platform],
            key=lambda x: x[1],
            reverse=True,
        )[:2]
        alternative_names = [p for p, _ in alternatives]

        # Calculate confidence and expectations
        confidence = self._calculate_confidence(platform_scores[best_platform])
        acceptance_prob = platform_metrics.get(best_platform, {}).get("acceptance_rate", 0.5)
        avg_bounty = platform_metrics.get(best_platform, {}).get("avg_bounty", 1000)

        decision = RoutingDecision(
            vulnerability_id=vulnerability_id,
            recommended_platform=best_platform,
            alternative_platforms=alternative_names,
            confidence=confidence,
            reasoning=f"Best routing: {best_platform} (score: {platform_scores[best_platform]:.1f})",
            expected_acceptance_prob=acceptance_prob,
            expected_bounty=avg_bounty,
        )

        self.routing_decisions[vulnerability_id] = decision
        return decision

    def _score_platforms(
        self,
        platform_metrics: Dict[str, Any],
        vulnerability_data: Dict[str, Any],
        strategy: RoutingStrategy,
    ) -> Dict[str, float]:
        """Score each platform based on strategy."""
        scores = {}

        for platform, metrics in platform_metrics.items():
            if not isinstance(metrics, dict):
                continue

            acceptance_rate = metrics.get("acceptance_rate", 0.5)
            avg_bounty = metrics.get("avg_bounty", 1000)
            trend = metrics.get("trend_30day", 0.0)

            if strategy == RoutingStrategy.MAXIMIZE_ACCEPTANCE:
                scores[platform] = acceptance_rate * 100
            elif strategy == RoutingStrategy.MAXIMIZE_BOUNTY:
                scores[platform] = min((avg_bounty / 5000) * 100, 100)
            elif strategy == RoutingStrategy.BALANCED:
                scores[platform] = (acceptance_rate * 50) + (min((avg_bounty / 5000) * 100, 100) * 0.5)
            elif strategy == RoutingStrategy.SEQUENTIAL:
                scores[platform] = (acceptance_rate * 70) + (trend * 30)
            elif strategy == RoutingStrategy.DIVERSIFIED:
                scores[platform] = acceptance_rate * 100 + (trend * 10)

        return scores

    @staticmethod
    def _calculate_confidence(score: float) -> float:
        """Calculate confidence based on score."""
        # Slightly optimistic normalization for balanced routing so
        # medium-high scores still map to confident routing decisions.
        max_score = 100.0
        return min((score / max_score) * 1.2, 1.0)

    async def get_all_decisions(self) -> Dict[str, RoutingDecision]:
        """Get all routing decisions.

        Returns:
            Dict of vulnerability_id -> RoutingDecision
        """
        return self.routing_decisions


class VulnerabilityPrioritizer:
    """Prioritizes vulnerabilities for focus."""

    def __init__(self):
        """Initialize prioritizer."""
        self.priority_scores: Dict[str, PriorityScore] = {}

    async def prioritize(
        self,
        vulnerabilities: List[Dict[str, Any]],
        intelligence_data: Dict[str, Any],
        strategy: PrioritizationStrategy = PrioritizationStrategy.BALANCED,
    ) -> List[PriorityScore]:
        """Prioritize vulnerabilities for focus.

        Args:
            vulnerabilities: List of vulnerability data
            intelligence_data: Intelligence from PASSO 9
            strategy: Prioritization strategy

        Returns:
            List of PriorityScore sorted by priority
        """
        logger.info(f"Prioritizing {len(vulnerabilities)} vulnerabilities with strategy {strategy.value}")

        priority_scores = []

        for vuln in vulnerabilities:
            score = await self._calculate_priority_score(vuln, intelligence_data, strategy)
            priority_scores.append(score)
            self.priority_scores[vuln.get("id", uuid4().hex)] = score

        # Sort by priority (descending)
        priority_scores.sort(key=lambda x: x.priority_score, reverse=True)

        # Assign ranks
        for rank, score in enumerate(priority_scores, 1):
            score.rank = rank

        return priority_scores

    async def _calculate_priority_score(
        self,
        vulnerability: Dict[str, Any],
        intelligence_data: Dict[str, Any],
        strategy: PrioritizationStrategy,
    ) -> PriorityScore:
        """Calculate priority score for vulnerability."""
        vuln_id = vulnerability.get("id", uuid4().hex)

        # Extract components
        bounty_score = self._calculate_bounty_score(vulnerability)
        impact_score = self._calculate_impact_score(vulnerability)
        speed_score = self._calculate_speed_score(vulnerability)
        trend_score = self._calculate_trend_score(vulnerability, intelligence_data)

        # Apply strategy weighting
        if strategy == PrioritizationStrategy.BOUNTY_FOCUSED:
            weights = {"bounty": 0.6, "impact": 0.2, "speed": 0.1, "trend": 0.1}
        elif strategy == PrioritizationStrategy.IMPACT_FOCUSED:
            weights = {"bounty": 0.2, "impact": 0.6, "speed": 0.1, "trend": 0.1}
        elif strategy == PrioritizationStrategy.SPEED_FOCUSED:
            weights = {"bounty": 0.1, "impact": 0.2, "speed": 0.6, "trend": 0.1}
        elif strategy == PrioritizationStrategy.NOVELTY_FOCUSED:
            weights = {"bounty": 0.2, "impact": 0.2, "speed": 0.2, "trend": 0.4}
        else:  # BALANCED
            weights = {"bounty": 0.3, "impact": 0.3, "speed": 0.2, "trend": 0.2}

        priority_score = (
            bounty_score * weights["bounty"]
            + impact_score * weights["impact"]
            + speed_score * weights["speed"]
            + trend_score * weights["trend"]
        )

        reasoning = f"{strategy.value}: bounty({bounty_score:.0f}) impact({impact_score:.0f}) speed({speed_score:.0f}) trend({trend_score:.0f})"

        return PriorityScore(
            vulnerability_id=vuln_id,
            priority_score=priority_score,
            bounty_contribution=bounty_score * weights["bounty"],
            impact_contribution=impact_score * weights["impact"],
            speed_contribution=speed_score * weights["speed"],
            trend_contribution=trend_score * weights["trend"],
            reasoning=reasoning,
        )

    @staticmethod
    def _calculate_bounty_score(vulnerability: Dict[str, Any]) -> float:
        """Calculate bounty component (0-100)."""
        predicted_bounty = vulnerability.get("predicted_bounty", 1000)
        # Normalize to 0-100 based on max bounty
        return min((predicted_bounty / 10000) * 100, 100)

    @staticmethod
    def _calculate_impact_score(vulnerability: Dict[str, Any]) -> float:
        """Calculate impact component (0-100)."""
        cvss_score = vulnerability.get("cvss_score", 5.0)
        scope = vulnerability.get("scope", "medium")

        # CVSS scaling
        score = (cvss_score / 10) * 80

        # Scope multiplier
        scope_multipliers = {"critical": 1.25, "high": 1.1, "medium": 1.0, "low": 0.9}
        multiplier = scope_multipliers.get(scope.lower(), 1.0)

        return min(score * multiplier, 100)

    @staticmethod
    def _calculate_speed_score(vulnerability: Dict[str, Any]) -> float:
        """Calculate speed/ease component (0-100)."""
        complexity = vulnerability.get("complexity", 5)  # 1-10
        # Inverse: easier (low complexity) = higher score
        return (10 - complexity) * 10

    @staticmethod
    def _calculate_trend_score(vulnerability: Dict[str, Any], intelligence: Dict[str, Any]) -> float:
        """Calculate trend/novelty component (0-100)."""
        vuln_type = vulnerability.get("vulnerability_type", "unknown")

        # Check if trending in PASSO 9 data
        trends = intelligence.get("trends", {})
        trend_info = trends.get(vuln_type, {})

        trend_direction = trend_info.get("trend_direction", "stable")
        trend_map = {"increasing": 80, "stable": 50, "decreasing": 20}

        return trend_map.get(trend_direction, 50)


class ResourceAllocator:
    """Allocates resources/focus to vulnerabilities."""

    def __init__(self):
        """Initialize allocator."""
        self.allocations: Dict[str, ResourceAllocation] = {}

    async def allocate_resources(
        self,
        priority_scores: List[PriorityScore],
        total_resources: int = 100,
        strategy: AllocationStrategy = AllocationStrategy.WEIGHTED,
    ) -> ResourceAllocation:
        """Allocate resources based on priorities.

        Args:
            priority_scores: List of PriorityScore from prioritizer
            total_resources: Total resources to allocate
            strategy: Allocation strategy

        Returns:
            ResourceAllocation with distribution plan
        """
        logger.info(f"Allocating {total_resources} resources using strategy {strategy.value}")

        allocations = {}

        if strategy == AllocationStrategy.UNIFORM:
            # Uniform allocation
            per_vuln = total_resources // len(priority_scores) if priority_scores else 0
            for score in priority_scores:
                allocations[score.vulnerability_id] = per_vuln

        elif strategy == AllocationStrategy.WEIGHTED:
            # Weighted based on priority
            total_priority = sum(s.priority_score for s in priority_scores)
            if total_priority > 0:
                for score in priority_scores:
                    share = (score.priority_score / total_priority) * total_resources
                    allocations[score.vulnerability_id] = int(share)

        elif strategy == AllocationStrategy.AGGRESSIVE:
            # Aggressive focus on top
            if priority_scores:
                top = priority_scores[:max(1, len(priority_scores) // 3)]
                per_top = total_resources // len(top)
                for score in top:
                    allocations[score.vulnerability_id] = per_top

        elif strategy == AllocationStrategy.CONSERVATIVE:
            # Diversified across many
            per_vuln = total_resources // len(priority_scores) if priority_scores else 0
            for score in priority_scores[:10]:  # Focus on top 10
                allocations[score.vulnerability_id] = per_vuln

        elif strategy == AllocationStrategy.ADAPTIVE:
            # Adaptive based on success metrics
            success_rates = {s.vulnerability_id: 0.7 for s in priority_scores}  # Default 70%
            total_adjusted = sum(success_rates.get(s.vulnerability_id, 0.7) * s.priority_score for s in priority_scores)
            if total_adjusted > 0:
                for score in priority_scores:
                    success_rate = success_rates.get(score.vulnerability_id, 0.7)
                    share = (success_rate * score.priority_score / total_adjusted) * total_resources
                    allocations[score.vulnerability_id] = int(share)

        # Normalize to exactly total_resources (avoids drift from int rounding).
        allocations = self._normalize_allocations(allocations, priority_scores, total_resources)

        # Calculate efficiency metrics
        efficiency = self._calculate_efficiency(allocations, priority_scores)
        projected_bounty = self._project_bounty(allocations, priority_scores)
        acceptance_rate = self._project_acceptance(allocations, priority_scores)

        allocation_plan = ResourceAllocation(
            total_resources=total_resources,
            allocations=allocations,
            efficiency_score=efficiency,
            projected_bounty=projected_bounty,
            projected_acceptance_rate=acceptance_rate,
            reasoning=f"Strategy {strategy.value}: {len(allocations)} vulnerabilities allocated",
        )

        self.allocations[uuid4().hex] = allocation_plan
        return allocation_plan

    @staticmethod
    def _normalize_allocations(
        allocations: Dict[str, int],
        priority_scores: List[PriorityScore],
        total_resources: int,
    ) -> Dict[str, int]:
        """Normalize allocation values so they sum exactly to total_resources."""
        normalized = {str(k): max(0, int(v)) for k, v in (allocations or {}).items()}
        ordered_ids = [s.vulnerability_id for s in priority_scores]

        if not normalized and ordered_ids and total_resources > 0:
            normalized[ordered_ids[0]] = total_resources
            return normalized

        current_total = sum(normalized.values())
        delta = int(total_resources) - int(current_total)

        if delta == 0:
            return normalized

        # Ensure we have deterministic distribution order.
        keys = ordered_ids if ordered_ids else list(normalized.keys())
        if not keys:
            return normalized

        if delta > 0:
            idx = 0
            while delta > 0:
                key = keys[idx % len(keys)]
                normalized[key] = normalized.get(key, 0) + 1
                delta -= 1
                idx += 1
            return normalized

        # delta < 0: remove excess resources from lowest-priority first
        removable_order = list(reversed(keys))
        excess = -delta
        idx = 0
        while excess > 0 and removable_order:
            key = removable_order[idx % len(removable_order)]
            if normalized.get(key, 0) > 0:
                normalized[key] -= 1
                excess -= 1
            idx += 1
            if idx > (len(removable_order) * (total_resources + 1)):
                break
        return normalized

    @staticmethod
    def _calculate_efficiency(allocations: Dict[str, int], scores: List[PriorityScore]) -> float:
        """Calculate allocation efficiency (0-100)."""
        if not allocations or not scores:
            return 0.0

        # Higher allocations to higher priority = better efficiency
        total_match = sum(
            allocations.get(s.vulnerability_id, 0) * (s.priority_score / 100)
            for s in scores
        )
        max_match = sum(s.priority_score for s in scores)

        if max_match == 0:
            return 0.0

        return min((total_match / max_match) * 100, 100)

    @staticmethod
    def _project_bounty(allocations: Dict[str, int], scores: List[PriorityScore]) -> float:
        """Project total bounty from allocation."""
        # Simplified: 1 resource unit = $100 average
        total_resources = sum(allocations.values())
        return total_resources * 100

    @staticmethod
    def _project_acceptance(allocations: Dict[str, int], scores: List[PriorityScore]) -> float:
        """Project acceptance rate."""
        # Default 65% acceptance rate
        return 0.65


class RiskAnalyzer:
    """Analyzes risk-reward of strategies."""

    def __init__(self):
        """Initialize analyzer."""
        self.risk_assessments: Dict[str, RiskAssessment] = {}

    async def analyze_risk(
        self,
        strategy_plan: Dict[str, Any],
        historical_data: Dict[str, Any],
    ) -> RiskAssessment:
        """Analyze risk of strategy.

        Args:
            strategy_plan: Strategy plan details
            historical_data: Historical performance data

        Returns:
            RiskAssessment with analysis
        """
        logger.info("Analyzing strategy risk")

        # Calculate risk factors
        concentration_risk = self._calculate_concentration_risk(strategy_plan)
        platform_risk = self._calculate_platform_risk(strategy_plan)
        execution_risk = self._calculate_execution_risk(strategy_plan)

        # Combine risks
        overall_risk = (concentration_risk + platform_risk + execution_risk) / 3

        # Determine risk level
        risk_level = self._determine_risk_level(overall_risk)

        # Calculate potential outcomes
        potential_loss = self._calculate_potential_loss(strategy_plan, historical_data)
        potential_gain = self._calculate_potential_gain(strategy_plan, historical_data)
        risk_reward_ratio = potential_gain / max(potential_loss, 1.0)

        # Recommendations and mitigations
        recommendations = self._generate_recommendations(overall_risk, strategy_plan)
        mitigations = self._generate_mitigations(risk_level, strategy_plan)

        assessment = RiskAssessment(
            strategy_id=strategy_plan.get("id", uuid4().hex),
            risk_level=risk_level,
            risk_score=overall_risk,
            potential_loss=potential_loss,
            potential_gain=potential_gain,
            risk_reward_ratio=risk_reward_ratio,
            recommended_actions=recommendations,
            mitigations=mitigations,
        )

        self.risk_assessments[assessment.strategy_id] = assessment
        return assessment

    @staticmethod
    def _calculate_concentration_risk(strategy_plan: Dict[str, Any]) -> float:
        """Calculate concentration risk (0-100)."""
        # Risk from focusing on too few vulnerabilities
        allocations = strategy_plan.get("allocations", {})
        if not allocations:
            return 50.0

        values = list(allocations.values())
        total = sum(values)
        max_single = max(values)

        concentration = (max_single / max(total, 1)) * 100

        # Higher concentration = higher risk
        return concentration

    @staticmethod
    def _calculate_platform_risk(strategy_plan: Dict[str, Any]) -> float:
        """Calculate platform risk (0-100)."""
        # Risk from platform dependency
        decisions = strategy_plan.get("routing_decisions", {})
        platforms = set()

        for decision in decisions.values():
            if isinstance(decision, dict):
                platforms.add(decision.get("recommended_platform"))

        if not platforms or len(platforms) < 2:
            return 60.0  # High risk: dependent on single platform

        # More platforms = lower risk
        return 100 - (len(platforms) * 10)

    @staticmethod
    def _calculate_execution_risk(strategy_plan: Dict[str, Any]) -> float:
        """Calculate execution risk (0-100)."""
        # Risk from complexity of execution
        num_items = len(strategy_plan.get("routing_decisions", {}))

        if num_items < 5:
            return 20.0
        elif num_items < 20:
            return 40.0
        elif num_items < 50:
            return 60.0
        else:
            return 80.0

    @staticmethod
    def _determine_risk_level(risk_score: float) -> str:
        """Determine risk level from score."""
        if risk_score < 25:
            return "LOW"
        elif risk_score < 50:
            return "MEDIUM"
        elif risk_score < 75:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def _calculate_potential_loss(strategy_plan: Dict[str, Any], historical: Dict[str, Any]) -> float:
        """Calculate potential downside."""
        # Potential loss if strategy fails
        rejection_rate = historical.get("avg_rejection_rate", 0.35)
        total_effort = sum(strategy_plan.get("allocations", {}).values())
        loss_per_unit = 50  # $50 per unit

        return total_effort * loss_per_unit * rejection_rate

    @staticmethod
    def _calculate_potential_gain(strategy_plan: Dict[str, Any], historical: Dict[str, Any]) -> float:
        """Calculate potential upside."""
        # Potential gain if strategy succeeds
        acceptance_rate = historical.get("avg_acceptance_rate", 0.65)
        avg_bounty = historical.get("avg_bounty", 1000)
        allocation = strategy_plan.get("allocations", {})

        return sum(allocation.values()) * (avg_bounty / 100) * acceptance_rate

    @staticmethod
    def _generate_recommendations(risk_score: float, strategy_plan: Dict[str, Any]) -> List[str]:
        """Generate recommendations."""
        recommendations = []

        if risk_score > 70:
            recommendations.append("Consider reducing focus concentration")
            recommendations.append("Diversify across more platforms")

        if risk_score > 50:
            recommendations.append("Monitor execution closely")
            recommendations.append("Plan checkpoint reviews")

        return recommendations

    @staticmethod
    def _generate_mitigations(risk_level: str, strategy_plan: Dict[str, Any]) -> List[str]:
        """Generate mitigation strategies."""
        mitigations = []

        if risk_level in ("HIGH", "CRITICAL"):
            mitigations.append("Diversify platform allocation")
            mitigations.append("Implement phased rollout")
            mitigations.append("Prepare fallback strategy")

        if risk_level == "CRITICAL":
            mitigations.append("Elevate to human review")
            mitigations.append("Reduce resource commitment")

        return mitigations


class StrategyOrchestrator:
    """Main strategy coordination engine."""

    def __init__(
        self,
        router: Optional[PlatformRouter] = None,
        prioritizer: Optional[VulnerabilityPrioritizer] = None,
        allocator: Optional[ResourceAllocator] = None,
        risk_analyzer: Optional[RiskAnalyzer] = None,
    ):
        """Initialize orchestrator.

        Args:
            router: PlatformRouter instance
            prioritizer: VulnerabilityPrioritizer instance
            allocator: ResourceAllocator instance
            risk_analyzer: RiskAnalyzer instance
        """
        self.router = router or PlatformRouter()
        self.prioritizer = prioritizer or VulnerabilityPrioritizer()
        self.allocator = allocator or ResourceAllocator()
        self.risk_analyzer = risk_analyzer or RiskAnalyzer()

        self.strategy_history: List[StrategyPlan] = []

    async def create_strategy_plan(
        self,
        vulnerabilities: List[Dict[str, Any]],
        platform_metrics: Dict[str, Any],
        intelligence_data: Dict[str, Any],
        routing_strategy: RoutingStrategy = RoutingStrategy.BALANCED,
        prioritization_strategy: PrioritizationStrategy = PrioritizationStrategy.BALANCED,
        allocation_strategy: AllocationStrategy = AllocationStrategy.WEIGHTED,
        total_resources: int = 100,
    ) -> StrategyPlan:
        """Create complete strategy plan.

        Args:
            vulnerabilities: List of vulnerabilities to plan for
            platform_metrics: Platform metrics from PASSO 9
            intelligence_data: Intelligence data from PASSO 9
            routing_strategy: Platform routing strategy
            prioritization_strategy: Vulnerability prioritization strategy
            allocation_strategy: Resource allocation strategy
            total_resources: Total resources to allocate

        Returns:
            Complete StrategyPlan
        """
        logger.info(
            f"Creating strategy plan for {len(vulnerabilities)} vulnerabilities"
        )

        strategy_id = str(uuid4())

        # Step 1: Prioritize vulnerabilities
        priority_scores = await self.prioritizer.prioritize(
            vulnerabilities, intelligence_data, prioritization_strategy
        )

        # Step 2: Route each vulnerability
        routing_decisions = {}
        for vuln in vulnerabilities:
            decision = await self.router.decide_platform(
                vuln.get("id", uuid4().hex),
                platform_metrics,
                vuln,
                routing_strategy,
            )
            routing_decisions[vuln.get("id", uuid4().hex)] = decision

        # Step 3: Allocate resources
        resource_allocation = await self.allocator.allocate_resources(
            priority_scores, total_resources, allocation_strategy
        )

        # Step 4: Analyze risk
        plan_data = {
            "id": strategy_id,
            "routing_decisions": routing_decisions,
            "allocations": resource_allocation.allocations,
        }

        risk_assessment = await self.risk_analyzer.analyze_risk(
            plan_data, intelligence_data.get("historical_data", {})
        )

        # Create final plan
        plan = StrategyPlan(
            strategy_id=strategy_id,
            routing_decisions=routing_decisions,
            priority_scores={s.vulnerability_id: s for s in priority_scores},
            resource_allocation=resource_allocation,
            risk_assessment=risk_assessment,
        )

        self.strategy_history.append(plan)

        logger.info(f"Strategy plan {strategy_id} created successfully")
        return plan

    async def get_strategy_summary(self, strategy_plan: StrategyPlan) -> Dict[str, Any]:
        """Get human-readable strategy summary.

        Args:
            strategy_plan: StrategyPlan to summarize

        Returns:
            Summary dict
        """
        return {
            "strategy_id": strategy_plan.strategy_id,
            "total_vulnerabilities": len(strategy_plan.routing_decisions),
            "total_resources": strategy_plan.resource_allocation.total_resources,
            "projected_bounty": strategy_plan.resource_allocation.projected_bounty,
            "risk_level": strategy_plan.risk_assessment.risk_level,
            "risk_score": strategy_plan.risk_assessment.risk_score,
            "top_platforms": self._get_top_platforms(strategy_plan.routing_decisions),
            "top_priorities": self._get_top_priorities(strategy_plan.priority_scores),
            "created_at": strategy_plan.created_at.isoformat(),
        }

    @staticmethod
    def _get_top_platforms(routing_decisions: Dict[str, RoutingDecision]) -> List[str]:
        """Get top platforms from routing decisions."""
        platform_counts = {}
        for decision in routing_decisions.values():
            platform = decision.recommended_platform
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

        return sorted(platform_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    @staticmethod
    def _get_top_priorities(priority_scores: Dict[str, PriorityScore]) -> List[Tuple[str, float]]:
        """Get top priority vulnerabilities."""
        sorted_scores = sorted(
            priority_scores.values(),
            key=lambda x: x.priority_score,
            reverse=True,
        )[:5]
        return [(s.vulnerability_id, s.priority_score) for s in sorted_scores]

    async def get_statistics(self) -> Dict[str, Any]:
        """Get strategy statistics.

        Returns:
            Statistics dict
        """
        if not self.strategy_history:
            return {
                "total_strategies": 0,
                "avg_risk_score": 0.0,
                "avg_bounty_projection": 0.0,
            }

        risk_scores = [s.risk_assessment.risk_score for s in self.strategy_history]
        bounties = [s.resource_allocation.projected_bounty for s in self.strategy_history]

        return {
            "total_strategies": len(self.strategy_history),
            "avg_risk_score": statistics.mean(risk_scores) if risk_scores else 0.0,
            "avg_bounty_projection": statistics.mean(bounties) if bounties else 0.0,
        }
