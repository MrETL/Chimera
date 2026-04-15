"""MITRE ATLAS and OWASP LLM Top 10 mapping utilities."""

from typing import Dict, List, Optional


# MITRE ATLAS Techniques relevant to AI security
MITRE_ATLAS_TECHNIQUES = {
    "T0051": {
        "name": "LLM Jailbreak",
        "description": "Adversary attempts to bypass safety guardrails in LLMs",
        "tactics": ["Initial Access", "Execution"]
    },
    "T0043": {
        "name": "Craft Adversarial Data",
        "description": "Create inputs designed to evade ML model detection",
        "tactics": ["Defense Evasion"]
    },
    "T0020": {
        "name": "Poison Training Data",
        "description": "Inject malicious data into training datasets",
        "tactics": ["ML Model Access"]
    },
    "T0024": {
        "name": "Exfiltrate ML Model",
        "description": "Extract model weights or architecture",
        "tactics": ["Exfiltration"]
    },
}


# OWASP LLM Top 10 (2025)
OWASP_LLM_TOP_10 = {
    "LLM01:2025": {
        "name": "Prompt Injection",
        "description": "Manipulating LLM via crafted inputs",
        "severity": "Critical"
    },
    "LLM02:2025": {
        "name": "Insecure Output Handling",
        "description": "Insufficient validation of LLM outputs",
        "severity": "High"
    },
    "LLM03:2025": {
        "name": "Training Data Poisoning",
        "description": "Tampering with training data",
        "severity": "High"
    },
    "LLM04:2025": {
        "name": "Model Denial of Service",
        "description": "Resource exhaustion attacks",
        "severity": "Medium"
    },
    "LLM06:2025": {
        "name": "Sensitive Information Disclosure",
        "description": "Revealing confidential data",
        "severity": "High"
    },
}


def get_mitre_info(technique_id: str) -> Optional[Dict[str, str]]:
    """Get information about a MITRE ATLAS technique."""
    return MITRE_ATLAS_TECHNIQUES.get(technique_id)


def get_owasp_info(risk_id: str) -> Optional[Dict[str, str]]:
    """Get information about an OWASP LLM risk."""
    return OWASP_LLM_TOP_10.get(risk_id)


def get_remediation_advice(owasp_risk: str) -> List[str]:
    """Get remediation recommendations for an OWASP risk."""
    remediation_map = {
        "LLM01:2025": [
            "Implement input validation and sanitization",
            "Use prompt templates with parameterization",
            "Deploy content filtering on inputs and outputs",
            "Implement privilege separation for different prompt types"
        ],
        "LLM03:2025": [
            "Verify training data sources",
            "Implement data provenance tracking",
            "Use anomaly detection on training datasets",
            "Regularly audit training pipelines"
        ],
        "LLM06:2025": [
            "Implement output filtering for PII",
            "Use differential privacy techniques",
            "Limit model access to sensitive data",
            "Regular security audits of model outputs"
        ],
    }
    return remediation_map.get(owasp_risk, ["Consult OWASP LLM Top 10 documentation"])
