"""
PASSO 9: Intelligence Engine - Submission Analysis & Outcome Intelligence

Autonomous analysis of submission outcomes from PASSO 8 to generate:
  - Impact assessment
  - Platform effectiveness metrics
  - Bounty predictions
  - Vulnerability trend analysis
  - Escalation recommendations

Components:
    - SubmissionAnalyzer: Individual submission outcome analysis
    - PlatformAnalytics: Platform performance tracking
    - BountyPredictor: Bounty amount prediction
    - TrendAnalyzer: Vulnerability trend analysis
    - EscalationEngine: Auto-escalation rule management
    - IntelligenceOrchestrator: Main coordinator
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from uuid import uuid4
import statistics

logger = logging.getLogger(__name__)


class ImpactLevel(Enum):
    """Impact assessment of submission outcome."""
    CRITICAL = "critical"      # Accepted high-bounty vulnerability
    HIGH = "high"               # Accepted medium-bounty or critical scope
    MEDIUM = "medium"           # Accepted low-bounty or duplicate of accepted
    LOW = "low"                 # Rejected or informational
    UNKNOWN = "unknown"         # Not yet evaluated


class EscalationAction(Enum):
    """Actions triggered by escalation rules."""
    RESUBMIT_MODIFIED = "resubmit_modified"      # Modify and resubmit
    SUBMIT_ALTERNATIVE_PLATFORM = "submit_alternative_platform"  # Try another platform
    REQUEST_CLARIFICATION = "request_clarification"  # Ask for feedback
    MARK_DUPLICATE = "mark_duplicate"            # Mark as duplicate
    CLOSE = "close"                              # Stop pursuing
    ELEVATE_TO_HUMAN = "elevate_to_human"        # Human review needed


class AnalysisPhase(Enum):
    """Phases of intelligent analysis."""
    IMMEDIATE = "immediate"        # Instant feedback on submit
    SHORT_TERM = "short_term"      # 24-hour analysis
    MEDIUM_TERM = "medium_term"    # 7-day analysis
    LONG_TERM = "long_term"        # 30-day trend analysis


@dataclass
class SubmissionAnalysis:
    """Analysis result for single submission."""
    submission_id: str
    impact_level: ImpactLevel
    impact_score: float             # 0-100
    confidence: float               # 0-1
    suggested_action: Optional[EscalationAction]
    reasoning: str
    vulnerabilities: List[str]      # Root cause analysis
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PlatformMetrics:
    """Platform performance metrics."""
    platform: str
    total_submitted: int = 0
    total_accepted: int = 0
    total_rejected: int = 0
    total_duplicate: int = 0
    acceptance_rate: float = 0.0   # 0-1
    avg_response_time_hours: float = 0.0
    avg_bounty_usd: float = 0.0
    trend_30day: float = 0.0       # -1.0 to +1.0
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BountyPrediction:
    """Bounty prediction for vulnerability."""
    vulnerability_type: str
    predicted_amount_usd: float
    confidence: float              # 0-1
    platform: str
    severity: str
    reasoning: str
    historical_range: Tuple[float, float]  # (min, max)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VulnerabilityTrend:
    """Trend analysis for vulnerability type."""
    vulnerability_type: str
    trend_direction: str           # "increasing", "decreasing", "stable"
    acceptance_rate_change: float  # Percentage change
    average_bounty_change: float   # Percentage change
    month_over_month_growth: float # 0-1
    platforms_interested: List[str]
    recommendation: str
    period: str = "30_days"
    analyzed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EscalationRule:
    """Rule for automatic escalation decisions."""
    rule_id: str
    name: str
    condition: str                 # e.g., "rejected_count > 3"
    action: EscalationAction
    priority: int = 5
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)


class SubmissionAnalyzer:
    """Analyzes individual submission outcomes."""

    def __init__(self):
        """Initialize analyzer."""
        self.analysis_cache: Dict[str, SubmissionAnalysis] = {}

    async def analyze(
        self,
        submission_id: str,
        status: str,
        platform: str,
        bounty_amount: Optional[float] = None,
        response_time_hours: Optional[float] = None,
        scope: Optional[str] = None,
    ) -> SubmissionAnalysis:
        """Analyze submission outcome.

        Args:
            submission_id: Unique submission ID
            status: Current submission status (ACCEPTED, REJECTED, etc.)
            platform: Platform name
            bounty_amount: Bounty awarded (if known)
            response_time_hours: Response time in hours
            scope: Scope assessment

        Returns:
            SubmissionAnalysis with impact and recommendations
        """
        logger.info(f"Analyzing submission {submission_id} with status {status}")

        impact_level = self._assess_impact(status, bounty_amount, scope)
        impact_score = self._calculate_impact_score(
            impact_level, bounty_amount, response_time_hours
        )
        confidence = self._calculate_confidence(status, response_time_hours)
        action = self._suggest_action(status, impact_level)
        reasoning = self._generate_reasoning(status, bounty_amount, impact_level)
        vulnerabilities = self._analyze_root_causes(status, platform)

        analysis = SubmissionAnalysis(
            submission_id=submission_id,
            impact_level=impact_level,
            impact_score=impact_score,
            confidence=confidence,
            suggested_action=action,
            reasoning=reasoning,
            vulnerabilities=vulnerabilities,
        )

        self.analysis_cache[submission_id] = analysis
        return analysis

    @staticmethod
    def _assess_impact(
        status: str, bounty_amount: Optional[float] = None, scope: Optional[str] = None
    ) -> ImpactLevel:
        """Assess impact level based on status."""
        if status == "ACCEPTED":
            if bounty_amount and bounty_amount >= 2500:
                return ImpactLevel.CRITICAL
            elif bounty_amount and bounty_amount >= 1000:
                return ImpactLevel.HIGH
            elif scope == "critical":
                return ImpactLevel.HIGH
            else:
                return ImpactLevel.MEDIUM
        elif status in ("REJECTED", "DUPLICATE"):
            return ImpactLevel.LOW
        else:
            return ImpactLevel.UNKNOWN

    @staticmethod
    def _calculate_impact_score(
        impact_level: ImpactLevel,
        bounty_amount: Optional[float] = None,
        response_time_hours: Optional[float] = None,
    ) -> float:
        """Calculate impact score 0-100."""
        base_scores = {
            ImpactLevel.CRITICAL: 95,
            ImpactLevel.HIGH: 75,
            ImpactLevel.MEDIUM: 50,
            ImpactLevel.LOW: 25,
            ImpactLevel.UNKNOWN: 10,
        }

        score = base_scores.get(impact_level, 10)

        if bounty_amount:
            bounty_bonus = min((bounty_amount / 10000) * 10, 10)
            score += bounty_bonus

        if response_time_hours and response_time_hours < 24:
            score += 5

        return min(score, 100)

    @staticmethod
    def _calculate_confidence(
        status: str, response_time_hours: Optional[float] = None
    ) -> float:
        """Calculate confidence 0-1."""
        status_confidence = {
            "ACCEPTED": 0.95,
            "REJECTED": 0.9,
            "DUPLICATE": 0.85,
            "TRIAGED": 0.7,
            "PENDING": 0.3,
        }
        confidence = status_confidence.get(status, 0.5)

        if response_time_hours and response_time_hours < 1:
            confidence += 0.1

        return min(confidence, 1.0)

    @staticmethod
    def _suggest_action(
        status: str, impact_level: ImpactLevel
    ) -> Optional[EscalationAction]:
        """Suggest escalation action."""
        if status == "REJECTED":
            return EscalationAction.RESUBMIT_MODIFIED
        elif status == "DUPLICATE":
            return EscalationAction.MARK_DUPLICATE
        elif status == "PENDING":
            return EscalationAction.REQUEST_CLARIFICATION
        return None

    @staticmethod
    def _generate_reasoning(
        status: str, bounty_amount: Optional[float] = None, impact_level: Optional[ImpactLevel] = None
    ) -> str:
        """Generate human-readable reasoning."""
        if status == "ACCEPTED":
            amount_str = f"${bounty_amount:.0f}" if bounty_amount else "unknown"
            return (
                f"Status ACCEPTED by platform. Bounty: {amount_str}. "
                f"Impact Level: {impact_level.value if impact_level else 'unknown'}"
            )
        elif status == "REJECTED":
            return "Submission rejected. Consider modifying POC or scope assessment."
        elif status == "DUPLICATE":
            return "Marked as duplicate. Check if reported to other platforms."
        else:
            return f"Status: {status}. Awaiting platform response."

    @staticmethod
    def _analyze_root_causes(status: str, platform: str) -> List[str]:
        """Analyze root causes of outcome."""
        causes = []

        if status == "REJECTED":
            causes.extend([
                "POC might be incomplete",
                "Scope may not match bounty rules",
                "Severity assessment could be different",
            ])
        elif status == "DUPLICATE":
            causes.append("Previously reported to platform or elsewhere")

        return causes


class PlatformAnalytics:
    """Tracks platform-specific performance metrics."""

    def __init__(self):
        """Initialize analytics."""
        self.platform_metrics: Dict[str, PlatformMetrics] = {}
        self.historical_data: Dict[str, List[SubmissionAnalysis]] = {}

    async def record_submission(
        self,
        platform: str,
        status: str,
        analysis: SubmissionAnalysis,
    ) -> PlatformMetrics:
        """Record submission outcome for platform.

        Args:
            platform: Platform name
            status: Submission status
            analysis: SubmissionAnalysis result

        Returns:
            Updated PlatformMetrics
        """
        if platform not in self.platform_metrics:
            self.platform_metrics[platform] = PlatformMetrics(platform=platform)
            self.historical_data[platform] = []

        metrics = self.platform_metrics[platform]
        metrics.total_submitted += 1

        if status == "ACCEPTED":
            metrics.total_accepted += 1
        elif status == "REJECTED":
            metrics.total_rejected += 1
        elif status == "DUPLICATE":
            metrics.total_duplicate += 1

        metrics.acceptance_rate = (
            metrics.total_accepted / metrics.total_submitted if metrics.total_submitted > 0 else 0
        )

        metrics.last_updated = datetime.utcnow()
        self.historical_data[platform].append(analysis)

        await self._calculate_trends(platform)

        logger.info(f"Recorded submission for {platform}. Acceptance rate: {metrics.acceptance_rate:.2%}")
        return metrics

    async def _calculate_trends(self, platform: str) -> None:
        """Calculate 30-day trends."""
        metrics = self.platform_metrics[platform]
        history = self.historical_data[platform]

        # Get submissions from last 30 days
        cutoff = datetime.utcnow() - timedelta(days=30)
        recent = [a for a in history if a.created_at >= cutoff]

        if len(recent) > 1:
            old_acceptance = sum(1 for a in history[:-len(recent)] if a.impact_level != ImpactLevel.LOW) / max(
                len(history) - len(recent), 1
            )
            new_acceptance = sum(1 for a in recent if a.impact_level != ImpactLevel.LOW) / len(
                recent
            )
            metrics.trend_30day = new_acceptance - old_acceptance

    async def get_metrics(self, platform: Optional[str] = None) -> Dict[str, PlatformMetrics]:
        """Get metrics for platform(s).

        Args:
            platform: Optional specific platform (all if None)

        Returns:
            Dict of platform metrics
        """
        if platform:
            return {platform: self.platform_metrics.get(platform, PlatformMetrics(platform=platform))}
        return self.platform_metrics


class BountyPredictor:
    """Predicts bounty amounts for findings."""

    def __init__(self):
        """Initialize predictor."""
        self.historical_bounties: Dict[str, List[Tuple[str, float]]] = {}  # vuln_type -> [(platform, amount)]

    async def predict_bounty(
        self,
        vulnerability_type: str,
        severity: str,
        platform: str,
    ) -> BountyPrediction:
        """Predict bounty for vulnerability.

        Args:
            vulnerability_type: Type of vulnerability
            severity: Severity level
            platform: Target platform

        Returns:
            BountyPrediction with estimate
        """
        logger.info(f"Predicting bounty for {vulnerability_type} on {platform}")

        historical = self._get_historical_data(vulnerability_type, platform)
        predicted_amount = self._calculate_prediction(historical, severity)
        confidence = self._calculate_confidence_score(historical)
        reasoning = self._generate_reasoning(historical, predicted_amount)
        min_amt, max_amt = self._get_historical_range(historical)

        prediction = BountyPrediction(
            vulnerability_type=vulnerability_type,
            predicted_amount_usd=predicted_amount,
            confidence=confidence,
            platform=platform,
            severity=severity,
            reasoning=reasoning,
            historical_range=(min_amt, max_amt),
        )

        return prediction

    def _get_historical_data(self, vulnerability_type: str, platform: str) -> List[float]:
        """Get historical bounties."""
        if vulnerability_type not in self.historical_bounties:
            return []

        data = [
            amount
            for plat, amount in self.historical_bounties[vulnerability_type]
            if plat == platform
        ]
        return data

    @staticmethod
    def _calculate_prediction(historical: List[float], severity: str) -> float:
        """Calculate bounty prediction."""
        if not historical:
            # Default predictions by severity
            severity_defaults = {
                "critical": 2500,
                "high": 1500,
                "medium": 500,
                "low": 200,
            }
            return severity_defaults.get(severity.lower(), 400)

        mean_bounty = statistics.mean(historical)
        severity_multipliers = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.7,
        }
        multiplier = severity_multipliers.get(severity.lower(), 1.0)

        return mean_bounty * multiplier

    @staticmethod
    def _calculate_confidence_score(historical: List[float]) -> float:
        """Calculate prediction confidence."""
        if not historical:
            return 0.3
        if len(historical) < 3:
            return 0.5
        if len(historical) < 10:
            return 0.7
        return 0.9

    @staticmethod
    def _generate_reasoning(historical: List[float], predicted: float) -> str:
        """Generate reasoning."""
        if not historical:
            return "No historical data. Using default severity-based prediction."
        return f"Based on {len(historical)} historical submissions. Average: ${statistics.mean(historical):.0f}"

    @staticmethod
    def _get_historical_range(historical: List[float]) -> Tuple[float, float]:
        """Get min/max from history."""
        if not historical:
            return (0, 5000)
        return (min(historical), max(historical))

    async def record_bounty(
        self, vulnerability_type: str, platform: str, amount: float
    ) -> None:
        """Record actual bounty for learning.

        Args:
            vulnerability_type: Type of vulnerability
            platform: Platform name
            amount: Bounty amount
        """
        if vulnerability_type not in self.historical_bounties:
            self.historical_bounties[vulnerability_type] = []

        self.historical_bounties[vulnerability_type].append((platform, amount))
        logger.info(f"Recorded bounty: {vulnerability_type} on {platform} = ${amount:.0f}")


class TrendAnalyzer:
    """Analyzes vulnerability trends over time."""

    def __init__(self):
        """Initialize trend analyzer."""
        self.trend_history: Dict[str, List[SubmissionAnalysis]] = {}

    async def analyze_trend(
        self, vulnerability_type: str, period_days: int = 30
    ) -> VulnerabilityTrend:
        """Analyze trend for vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability
            period_days: Analysis period in days

        Returns:
            VulnerabilityTrend with insights
        """
        logger.info(f"Analyzing trend for {vulnerability_type} ({period_days} days)")

        history = self._get_period_history(vulnerability_type, period_days)
        trend_direction = self._determine_trend(history)
        acceptance_change = self._calculate_acceptance_change(history)
        bounty_change = self._calculate_bounty_change(history)
        growth = self._calculate_month_over_month_growth(history)
        platforms = self._identify_interested_platforms(history)
        recommendation = self._generate_recommendation(
            trend_direction, acceptance_change, bounty_change
        )

        trend = VulnerabilityTrend(
            vulnerability_type=vulnerability_type,
            trend_direction=trend_direction,
            acceptance_rate_change=acceptance_change,
            average_bounty_change=bounty_change,
            month_over_month_growth=growth,
            platforms_interested=platforms,
            recommendation=recommendation,
            period=f"{period_days}_days",
        )

        return trend

    def _get_period_history(self, vulnerability_type: str, period_days: int) -> List[SubmissionAnalysis]:
        """Get submissions for period."""
        if vulnerability_type not in self.trend_history:
            return []

        cutoff = datetime.utcnow() - timedelta(days=period_days)
        return [
            a for a in self.trend_history[vulnerability_type]
            if a.created_at >= cutoff
        ]

    @staticmethod
    def _determine_trend(history: List[SubmissionAnalysis]) -> str:
        """Determine trend direction."""
        if not history or len(history) < 2:
            return "stable"

        recent = history[-len(history) // 2 :]
        older = history[: len(history) // 2]

        recent_impact = sum(1 for a in recent if a.impact_level in (ImpactLevel.CRITICAL, ImpactLevel.HIGH))
        older_impact = sum(1 for a in older if a.impact_level in (ImpactLevel.CRITICAL, ImpactLevel.HIGH))

        recent_rate = recent_impact / len(recent) if recent else 0
        older_rate = older_impact / len(older) if older else 0

        if recent_rate > older_rate * 1.2:
            return "increasing"
        elif recent_rate < older_rate * 0.8:
            return "decreasing"
        return "stable"

    @staticmethod
    def _calculate_acceptance_change(history: List[SubmissionAnalysis]) -> float:
        """Calculate acceptance rate change percentage."""
        if not history or len(history) < 2:
            return 0.0

        mid_point = len(history) // 2
        recent = history[mid_point:]
        older = history[:mid_point]

        recent_acceptance = sum(1 for a in recent if a.impact_level != ImpactLevel.LOW) / len(recent)
        older_acceptance = sum(1 for a in older if a.impact_level != ImpactLevel.LOW) / len(older)

        return (recent_acceptance - older_acceptance) * 100

    @staticmethod
    def _calculate_bounty_change(history: List[SubmissionAnalysis]) -> float:
        """Calculate average bounty change percentage."""
        if not history or len(history) < 2:
            return 0.0

        scores = [a.impact_score for a in history]
        mid_point = len(history) // 2
        recent_avg = statistics.mean(scores[mid_point:])
        older_avg = statistics.mean(scores[:mid_point])

        if older_avg == 0:
            return 0.0
        return ((recent_avg - older_avg) / older_avg) * 100

    @staticmethod
    def _calculate_month_over_month_growth(history: List[SubmissionAnalysis]) -> float:
        """Calculate month-over-month growth."""
        if not history or len(history) < 10:
            return 0.0

        # Simplified: compare first and last month
        return min(len(history) / 30, 1.0)  # 0-1 normalized

    @staticmethod
    def _identify_interested_platforms(history: List[SubmissionAnalysis]) -> List[str]:
        """Identify platforms interested in vulnerability type."""
        # Simplified: return high-impact platforms
        return ["hackerone", "intigriti", "bugcrowd"]

    @staticmethod
    def _generate_recommendation(
        trend: str, acceptance_change: float, bounty_change: float
    ) -> str:
        """Generate recommendation."""
        if trend == "increasing" and acceptance_change > 10:
            return "High demand. Increase focus on this vulnerability type."
        elif trend == "decreasing" and acceptance_change < -10:
            return "Decreasing interest. Consider shifting focus."
        else:
            return "Stable trend. Continue normal operations."


class EscalationEngine:
    """Manages escalation rules and decisions."""

    def __init__(self):
        """Initialize escalation engine."""
        self.rules: Dict[str, EscalationRule] = {}
        self._initialize_default_rules()

    def _initialize_default_rules(self) -> None:
        """Initialize default escalation rules."""
        rules = [
            EscalationRule(
                rule_id=str(uuid4()),
                name="Multiple Rejections",
                condition="rejected_count > 3",
                action=EscalationAction.RESUBMIT_MODIFIED,
                priority=7,
            ),
            EscalationRule(
                rule_id=str(uuid4()),
                name="Duplicate Detection",
                condition="status == DUPLICATE",
                action=EscalationAction.MARK_DUPLICATE,
                priority=5,
            ),
            EscalationRule(
                rule_id=str(uuid4()),
                name="Long Pending",
                condition="pending_hours > 72",
                action=EscalationAction.REQUEST_CLARIFICATION,
                priority=3,
            ),
            EscalationRule(
                rule_id=str(uuid4()),
                name="High Value Accepted",
                condition="bounty > 5000",
                action=EscalationAction.CLOSE,  # Success - close
                priority=9,
            ),
        ]

        for rule in rules:
            self.rules[rule.rule_id] = rule

    async def evaluate_rules(
        self, analysis: SubmissionAnalysis
    ) -> List[Tuple[EscalationRule, bool]]:
        """Evaluate all applicable rules.

        Args:
            analysis: SubmissionAnalysis to evaluate

        Returns:
            List of (rule, triggered) tuples
        """
        results = []
        for rule in self.rules.values():
            if not rule.enabled:
                continue

            triggered = await self._evaluate_condition(rule.condition, analysis)
            results.append((rule, triggered))

        return results

    async def _evaluate_condition(self, condition: str, analysis: SubmissionAnalysis) -> bool:
        """Evaluate rule condition."""
        # Simplified condition evaluation
        if "rejected" in condition.lower():
            return analysis.impact_level == ImpactLevel.LOW
        if "duplicate" in condition.lower():
            return "duplicate" in analysis.reasoning.lower()
        return False

    async def add_rule(self, rule: EscalationRule) -> str:
        """Add custom escalation rule.

        Args:
            rule: EscalationRule to add

        Returns:
            Rule ID
        """
        rule_id = str(rule.rule_id or "").strip() or str(uuid4())
        rule.rule_id = rule_id
        self.rules[rule_id] = rule
        logger.info(f"Added escalation rule: {rule.name}")
        return rule_id

    async def get_rules(self) -> Dict[str, EscalationRule]:
        """Get all rules.

        Returns:
            Dict of rules
        """
        return self.rules


class IntelligenceOrchestrator:
    """Main intelligence coordination engine."""

    def __init__(
        self,
        analyzer: Optional[SubmissionAnalyzer] = None,
        platform_analytics: Optional[PlatformAnalytics] = None,
        bounty_predictor: Optional[BountyPredictor] = None,
        trend_analyzer: Optional[TrendAnalyzer] = None,
        escalation_engine: Optional[EscalationEngine] = None,
    ):
        """Initialize orchestrator.

        Args:
            analyzer: SubmissionAnalyzer instance
            platform_analytics: PlatformAnalytics instance
            bounty_predictor: BountyPredictor instance
            trend_analyzer: TrendAnalyzer instance
            escalation_engine: EscalationEngine instance
        """
        self.analyzer = analyzer or SubmissionAnalyzer()
        self.platform_analytics = platform_analytics or PlatformAnalytics()
        self.bounty_predictor = bounty_predictor or BountyPredictor()
        self.trend_analyzer = trend_analyzer or TrendAnalyzer()
        self.escalation_engine = escalation_engine or EscalationEngine()

        self.analysis_history: List[SubmissionAnalysis] = []
        self.escalations_triggered: List[Tuple[str, EscalationAction]] = []

    async def analyze_submission_outcome(
        self,
        submission_id: str,
        status: str,
        platform: str,
        bounty_amount: Optional[float] = None,
        response_time_hours: Optional[float] = None,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Comprehensive analysis of submission outcome.

        Args:
            submission_id: Submission identifier
            status: Current status
            platform: Platform name
            bounty_amount: Bounty amount (if known)
            response_time_hours: Response time in hours
            scope: Scope assessment

        Returns:
            Comprehensive analysis result
        """
        logger.info(f"Analyzing submission {submission_id} on {platform}")

        # Phase 1: Immediate analysis
        analysis = await self.analyzer.analyze(
            submission_id=submission_id,
            status=status,
            platform=platform,
            bounty_amount=bounty_amount,
            response_time_hours=response_time_hours,
            scope=scope,
        )

        # Phase 2: Platform metrics
        metrics = await self.platform_analytics.record_submission(
            platform=platform,
            status=status,
            analysis=analysis,
        )

        # Phase 3: Escalation rules
        escalations = await self.escalation_engine.evaluate_rules(analysis)

        # Phase 4: Bounty prediction (if accepted)
        bounty_pred = None
        if status == "ACCEPTED" and bounty_amount:
            bounty_pred = await self.bounty_predictor.predict_bounty(
                vulnerability_type=submission_id,
                severity=scope or "medium",
                platform=platform,
            )
            await self.bounty_predictor.record_bounty(
                vulnerability_type=submission_id,
                platform=platform,
                amount=bounty_amount,
            )

        self.analysis_history.append(analysis)

        for rule, triggered in escalations:
            if triggered and rule.enabled:
                self.escalations_triggered.append((submission_id, rule.action))
                logger.warning(f"Escalation triggered for {submission_id}: {rule.action.value}")

        return {
            "analysis": analysis,
            "platform_metrics": metrics,
            "bounty_prediction": bounty_pred,
            "escalations": [(rule.name, triggered) for rule, triggered in escalations],
        }

    async def get_platform_effectiveness(self) -> Dict[str, Any]:
        """Get platform effectiveness comparison.

        Returns:
            Platform comparison metrics
        """
        metrics = await self.platform_analytics.get_metrics()
        return {
            platform: {
                "acceptance_rate": m.acceptance_rate,
                "trend_30day": m.trend_30day,
                "avg_bounty": m.avg_bounty_usd,
            }
            for platform, m in metrics.items()
        }

    async def get_statistics(self) -> Dict[str, Any]:
        """Get intelligence statistics.

        Returns:
            Statistics dict
        """
        return {
            "total_analyzed": len(self.analysis_history),
            "total_escalations": len(self.escalations_triggered),
            "avg_impact_score": statistics.mean([a.impact_score for a in self.analysis_history])
            if self.analysis_history
            else 0,
            "active_rules": len([r for r in self.escalation_engine.rules.values() if r.enabled]),
        }
