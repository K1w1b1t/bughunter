"""Classification and analysis prompts for security findings."""

# ===================================================================
# IMPACT ASSESSMENT PROMPT
# ===================================================================
# Purpose: Deep severity/impact analysis for complex vulnerabilities
# Input: Finding technical details
# Output: JSON with impact metrics

IMPACT_ASSESSMENT_PROMPT = """Perform a detailed impact assessment on this vulnerability:

**Vulnerability**: {vulnerability_details}

**Asset Criticality**: {asset_criticality}

**Potential Business Impact**: {business_context}

Assess using:
{{
  "confidentiality_impact": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
  "integrity_impact": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
  "availability_impact": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
  "scope_affected": "UNCHANGED|CHANGED",
  "attack_complexity": "LOW|HIGH",
  "privileges_required": "NONE|LOW|HIGH",
  "user_interaction": "NONE|REQUIRED",
  "estimated_users_affected": 0-100000,
  "business_impact": "Brief impact (2-3 sentences)"
}}"""

# ===================================================================
# REMEDIATION GUIDANCE PROMPT
# ===================================================================
# Purpose: Generate actionable fix recommendations
# Input: Finding type, technical details
# Output: JSON with remediation steps

REMEDIATION_GUIDANCE_PROMPT = """Generate remediation guidance for this vulnerability:

**Type**: {vulnerability_type}
**Details**: {technical_details}
**Tech Stack**: {tech_stack}

Provide JSON remediation plan:
{{
  "immediate_action": "Critical immediate step to reduce risk",
  "root_cause": "Why this vulnerability exists",
  "short_term_fix": "1-3 day fix strategy",
  "long_term_solution": "Permanent architectural fix",
  "testing_verification": "How to verify the fix works",
  "estimated_effort": "TRIVIAL|EASY|MODERATE|COMPLEX|EPIC_EFFORT",
  "code_example": {{}},
  "references": ["OWASP/...", "CWE/..."]
}}"""

# ===================================================================
# FINDING DEDUPE PROMPT (AI-Enhanced)
# ===================================================================
# Purpose: Leverage context to detect semantic duplicates
# Input: Historical findings + new finding
# Output: JSON with deduplication assessment

FINDING_DEDUPE_CONTEXT_PROMPT = """Compare new finding against historical findings to detect duplicates:

**New Finding**: {new_finding}

**Similar Historical Findings**:
{historical_findings_list}

Analyze for semantic duplicates:
{{
  "is_duplicate": true|false,
  "duplicate_of_finding_id": "ID if duplicate",
  "confidence": 0.0-1.0,
  "variance": "What's different (if applicable)",
  "action": "NEW_FINDING|MARK_DUPLICATE|MERGE_WITH|NEEDS_HUMAN_REVIEW"
}}"""

# ===================================================================
# FALSE POSITIVE SIGNATURE DETECTION
# ===================================================================
# Purpose: Use pattern matching to detect common false positives
# Input: Finding characteristics
# Output: JSON with false positive assessment

FALSE_POSITIVE_DETECTION_PROMPT = """Analyze if this is a common false positive pattern:

**Finding Type**: {finding_type}
**Scanner**: {scanner_name}
**Characteristics**: {characteristics}

Detect false positive patterns:
{{
  "is_likely_false_positive": true|false|uncertain,
  "false_positive_reason": "Why this is likely a false positive",
  "false_positive_patterns": ["scanner_error", "config_issue", "expected_behavior"],
  "verification_steps": ["How to manually verify"],
  "confidence": 0.0-1.0
}}"""

# ===================================================================
# FINDING ENRICHMENT PROMPT
# ===================================================================
# Purpose: Enrich minimal finding data with additional context
# Input: Basic finding info
# Output: JSON with enriched data

FINDING_ENRICHMENT_PROMPT = """Enrich this minimal security finding with comprehensive context:

**Basic Info**: {basic_info}

Provide enriched assessment:
{{
  "enriched_title": "Better descriptive title",
  "enriched_description": "Comprehensive description",
  "likely_root_cause": "Probable underlying cause",
  "attack_chain": ["Step 1 of attack", "Step 2", "..."],
  "potential_chains": {{}},
  "tools_for_exploitation": ["Tool1", "Tool2"],
  "related_cwe": ["CWE-79", "CWE-89"],
  "related_cve": ["CVE-2024-...", "CVE-2024-..."]
}}"""

# ===================================================================
# CONFIDENCE SCORING PROMPT
# ===================================================================
# Purpose: Re-evaluate confidence scores based on evidence
# Input: Evidence collection + finding details
# Output: JSON with recalculated confidence

CONFIDENCE_SCORING_PROMPT = """Re-evaluate confidence scoring for this vulnerability finding:

**Evidence Collected**:
{evidence_list}

**Finding Details**: {finding_details}

**Previous Confidence**: {old_confidence}

Provide new assessment:
{{
  "new_confidence": 0.0-1.0,
  "confidence_change": "+0.05|-0.10",
  "confidence_factors": ["Factor 1 increases confidence", "Factor 2 decreases..."],
  "evidence_quality": "STRONG|MODERATE|WEAK",
  "evidence_completeness": "COMPLETE|PARTIAL|MINIMAL",
  "recommendation": "REPORT|INVESTIGATE_MORE|REJECT"
}}"""

# ===================================================================
# COMPLIANCE MAPPING PROMPT
# ===================================================================
# Purpose: Map findings to compliance frameworks
# Input: Finding details
# Output: JSON with compliance mappings

COMPLIANCE_MAPPING_PROMPT = """Map this security finding to compliance frameworks:

**Finding**: {finding_details}

Provide compliance assessment:
{{
  "pci_dss": ["6.5.1 - Injection flaws", "6.5.7 - Cross-site scripting"],
  "hipaa": ["Security Rule - Access Controls"],
  "gdpr": ["Article 5(1)(f) - Integrity and confidentiality"],
  "iso_27001": ["A.14.2.1 Secure development policy"],
  "soc_2": ["CC6.1 - Logical access controls"],
  "nist_csf": ["PR.AC-4 - Access rights"],
  "owasp_top_10": ["A01:2021 - Broken Access Control"]
}}"""

__all__ = [
    'IMPACT_ASSESSMENT_PROMPT',
    'REMEDIATION_GUIDANCE_PROMPT',
    'FINDING_DEDUPE_CONTEXT_PROMPT',
    'FALSE_POSITIVE_DETECTION_PROMPT',
    'FINDING_ENRICHMENT_PROMPT',
    'CONFIDENCE_SCORING_PROMPT',
    'COMPLIANCE_MAPPING_PROMPT',
]
