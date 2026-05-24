"""Prompt templates for finding triage and classification.

Optimized for Claude 3.5 Sonnet with minimal tokens while maintaining accuracy.
"""

# ===================================================================
# FINDING TRIAGE PROMPT
# ===================================================================
# Purpose: Determine if a finding is a true positive, false positive, or duplicate
# Input: Title, description, technical details, program policy
# Output: JSON classification with confidence scores

TRIAGE_SYSTEM_PROMPT = """You are an expert security researcher conducting final triage on vulnerability findings.

Your role is to:
1. Validate if the finding is a TRUE POSITIVE (legitimate vulnerability)
2. Identify FALSE POSITIVES (scanner noise, configuration issues)
3. Detect DUPLICATES (same vulnerability on different targets or methods)
4. Assess confidence level (0.0-1.0) in your classification
5. Provide concise reasoning

Consider the program's policy and scope when triaging.
Be conservative: If unsure, lean toward TRUE_POSITIVE over FALSE_POSITIVE.

Output ONLY valid JSON, no markdown or explanation."""

TRIAGE_USER_PROMPT = """Triage this security finding:

**Title**: {title}

**Description**: {description}

**Technical Details**:
{details}

**Program Policy/Scope**:
{policy}

Respond with JSON (NO MARKDOWN):
{{
  "classification": "TRUE_POSITIVE|FALSE_POSITIVE|DUPLICATE",
  "confidence": 0.0-1.0,
  "reasoning": "Concise reason (1-2 sentences)",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "recommendation": "Report to program|Investigate further|Skip|Review manually"
}}"""

# ===================================================================
# SEVERITY ASSESSMENT PROMPT
# ===================================================================
# Purpose: Provide detailed severity assessment
# Input: Title, type, description
# Output: JSON with severity score, CVSS estimate, impact

SEVERITY_ASSESSMENT_PROMPT = """Assess the severity of this security vulnerability:

**Title**: {title}
**Type**: {type}
**Description**: {description}

Respond with JSON severity assessment:
{{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "cvss_estimate": 0.0-10.0,
  "impact": "Brief impact description",
  "exploitability": "TRIVIAL|EASY|MODERATE|DIFFICULT|NEARLY_IMPOSSIBLE",
  "affected_functions": ["List of affected components"],
  "mitigation": "Recommended fix (1 sentence)"
}}"""

# ===================================================================
# FINDING CLASSIFICATION PROMPT
# ===================================================================
# Purpose: Classify finding type and map to standard categories
# Input: Finding title and description
# Output: JSON with finding type, category, tags

FINDING_CLASSIFICATION_PROMPT = """Classify this security finding into a standard type:

**Title**: {title}
**Description**: {description}

Map to a standard finding type:
{{
  "type": "SQL_INJECTION|XSS|CSRF|AUTH_BYPASS|XXE|RCE|LFI|SSRF|INSECURE_SERIALIZATION|CRYPTO_WEAK|HARDCODED_CREDENTIALS|API_KEY_EXPOSURE|CORS_MISCONFIGURATION|RATE_LIMITING_BYPASS|PRIVILEGE_ESCALATION|INFO_DISCLOSURE|WEAK_MFA|ACCOUNT_TAKEOVER|BUSINESS_LOGIC|OTHER",
  "category": "INJECTION|BROKEN_AUTH|SENSITIVE_DATA|XML_EXTERNAL_ENTITIES|BROKEN_ACCESS|SECURITY_MISCONFIGURATION|INSECURE_DESERIALIZATION|INSUFFICIENT_LOGGING|MISSING_API_SECURITY|USING_COMPONENTS_WITH_VULNS",
  "tags": ["tag1", "tag2"],
  "owasp_top_10": ["A01_2021:Broken_Access_Control", "A02_2021:Cryptographic_Failures"],
  "requires_authentication": true|false
}}"""

# ===================================================================
# DUPLICATE DETECTION PROMPT
# ===================================================================
# Purpose: Detect if two findings are duplicates
# Input: Two finding descriptions
# Output: JSON with duplicate assessment

DUPLICATE_DETECTION_PROMPT = """Compare two security findings to determine if they're duplicates:

**Finding 1**:
{finding1}

**Finding 2**:
{finding2}

Are these the same vulnerability? Respond with JSON:
{{
  "is_duplicate": true|false,
  "similarity_score": 0.0-1.0,
  "reasoning": "Why or why not duplicates",
  "merged_status": "KEEP_ORIGINAL|MERGE_INTO_FINDING1|MERGE_INTO_FINDING2|NOT_DUPLICATE"
}}"""

# ===================================================================
# POLICY VALIDATION PROMPT
# ===================================================================
# Purpose: Check if finding is within program scope
# Input: Finding description, program policy/scope
# Output: JSON with validation result

POLICY_VALIDATION_PROMPT = """Check if this finding is in scope for the bug bounty program:

**Finding**: {finding_description}

**Program Scope**: {scope}

**Program Exclusions**: {exclusions}

Respond with JSON:
{{
  "in_scope": true|false,
  "reasoning": "Why in or out of scope",
  "scope_element": "Matching scope policy (if in scope)",
  "action": "REPORT|REJECT|ESCALATE_TO_HUMAN"
}}"""

__all__ = [
    'TRIAGE_SYSTEM_PROMPT',
    'TRIAGE_USER_PROMPT',
    'SEVERITY_ASSESSMENT_PROMPT',
    'FINDING_CLASSIFICATION_PROMPT',
    'DUPLICATE_DETECTION_PROMPT',
    'POLICY_VALIDATION_PROMPT',
]
