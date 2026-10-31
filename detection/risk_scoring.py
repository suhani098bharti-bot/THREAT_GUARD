"""Heuristic risk scoring system for ThreatGuard security events."""

from typing import Any, Dict


def calculate_risk_score(
    base_weight: int,
    indicator_strength: float,
    frequency_multiplier: int = 1,
) -> int:
    """Calculate an educational heuristic risk score bounded strictly between 0 and 100.
    
    Formula:
        Raw Score = (Base Weight * Indicator Strength) + (min(Frequency, 10) * 3)
        Bounded: clamp(Raw Score, 0, 100)
        
    Note:
        These scores represent rule-based heuristic threat indicators for triage,
        not scientifically proven probabilities of breach.
    """
    indicator_strength = max(0.1, min(1.0, indicator_strength))
    freq_bonus = min(max(1, frequency_multiplier) - 1, 10) * 3
    raw_score = int((base_weight * indicator_strength) + freq_bonus)
    return max(0, min(100, raw_score))


def get_risk_assessment_details(score: int, category: str) -> Dict[str, Any]:
    """Provide descriptive context for an assigned risk score."""
    if score >= 90:
        tier = "CRITICAL"
        desc = "High-confidence detection or active severe threat vector requiring immediate SOC containment."
    elif score >= 70:
        tier = "HIGH"
        desc = "Multiple corroborating attack signatures or high-risk activity requiring prompt triage."
    elif score >= 40:
        tier = "MEDIUM"
        desc = "Suspicious behavioral anomaly or perimeter probe warranting investigation."
    else:
        tier = "LOW"
        desc = "Low-impact telemetry deviation or isolated failed transaction."

    return {
        "risk_score": score,
        "severity_tier": tier,
        "category": category,
        "triage_summary": desc,
        "is_heuristic": True,
    }
