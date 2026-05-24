"""Prompt templates for LLM integration.

This module contains all system and user prompts for:
- Finding triage and classification
- Severity assessment
- Impact analysis
- Remediation guidance
- Compliance mapping
- Duplicate detection
"""

from hunterops.prompts.triage import (
    TRIAGE_SYSTEM_PROMPT,
    TRIAGE_USER_PROMPT,
    SEVERITY_ASSESSMENT_PROMPT,
    FINDING_CLASSIFICATION_PROMPT,
    DUPLICATE_DETECTION_PROMPT,
    POLICY_VALIDATION_PROMPT,
)

from hunterops.prompts.classification import (
    IMPACT_ASSESSMENT_PROMPT,
    REMEDIATION_GUIDANCE_PROMPT,
    FINDING_DEDUPE_CONTEXT_PROMPT,
    FALSE_POSITIVE_DETECTION_PROMPT,
    FINDING_ENRICHMENT_PROMPT,
    CONFIDENCE_SCORING_PROMPT,
    COMPLIANCE_MAPPING_PROMPT,
)

__all__ = [
    # Triage prompts
    'TRIAGE_SYSTEM_PROMPT',
    'TRIAGE_USER_PROMPT',
    'SEVERITY_ASSESSMENT_PROMPT',
    'FINDING_CLASSIFICATION_PROMPT',
    'DUPLICATE_DETECTION_PROMPT',
    'POLICY_VALIDATION_PROMPT',
    # Classification prompts
    'IMPACT_ASSESSMENT_PROMPT',
    'REMEDIATION_GUIDANCE_PROMPT',
    'FINDING_DEDUPE_CONTEXT_PROMPT',
    'FALSE_POSITIVE_DETECTION_PROMPT',
    'FINDING_ENRICHMENT_PROMPT',
    'CONFIDENCE_SCORING_PROMPT',
    'COMPLIANCE_MAPPING_PROMPT',
]
