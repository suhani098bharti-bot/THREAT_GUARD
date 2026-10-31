"""Threat classification and severity categorization for ThreatGuard."""

from typing import Dict
from config.settings import SEVERITY_COLORS


# MITRE ATT&CK Framework reference mapping
MITRE_ATTACK_MAPPING: Dict[str, Dict[str, str]] = {
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "Port Scanning": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "Cross-Site Scripting (XSS)": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise / Web Injection",
        "tactic": "Initial Access",
    },
    "Suspicious IP Activity": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol / Repetitive Probing",
        "tactic": "Command and Control / Reconnaissance",
    },
    "Unauthorized Access": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts / Privilege Violation",
        "tactic": "Defense Evasion / Initial Access",
    },
    "Unusual Network Activity": {
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port / Data Channel Anomaly",
        "tactic": "Command and Control",
    },
}


def classify_severity(risk_score: int) -> str:
    """Classify risk score into one of four standard SIEM severity tiers."""
    if risk_score >= 90:
        return "CRITICAL"
    elif risk_score >= 70:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def get_severity_badge_html(severity: str) -> str:
    """Generate HTML badge markup with appropriate color accents."""
    sev_upper = (severity or "LOW").upper()
    color = SEVERITY_COLORS.get(sev_upper, "#00D2FF")
    return (
        f'<span style="background-color: {color}22; color: {color}; '
        f'border: 1px solid {color}88; padding: 2px 10px; border-radius: 12px; '
        f'font-size: 0.78rem; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;">'
        f'{sev_upper}'
        f'</span>'
    )


def get_mitre_mapping(category: str) -> Dict[str, str]:
    """Retrieve MITRE ATT&CK technique information for a threat category."""
    return MITRE_ATTACK_MAPPING.get(
        category,
        {
            "technique_id": "T1000",
            "technique_name": "Uncategorized Anomaly",
            "tactic": "Defense Assessment",
        },
    )
