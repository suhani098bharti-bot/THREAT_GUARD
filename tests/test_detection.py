"""Unit and integration tests for detection rules, threat classification, and risk scoring."""

import pytest
import pandas as pd

from detection.detection_engine import run_threat_detection
from detection.detection_rules import (
    BruteForceRule,
    PortScanningRule,
    SqlInjectionRule,
    SuspiciousIpRule,
    UnauthorizedAccessRule,
    UnusualNetworkActivityRule,
    XssRule,
)
from detection.risk_scoring import calculate_risk_score
from detection.threat_classifier import classify_severity


def test_risk_scoring_bounds():
    """Test risk scoring formula remains bounded in 0-100 range."""
    # Min bound
    score_low = calculate_risk_score(base_weight=10, indicator_strength=0.1, frequency_multiplier=1)
    assert 0 <= score_low <= 100

    # Max bound
    score_high = calculate_risk_score(base_weight=150, indicator_strength=1.0, frequency_multiplier=100)
    assert score_high == 100

    # Normal calculation
    score_mid = calculate_risk_score(base_weight=70, indicator_strength=0.9, frequency_multiplier=5)
    assert 40 <= score_mid <= 90


def test_severity_classification():
    """Test severity tiers mapping."""
    assert classify_severity(95) == "CRITICAL"
    assert classify_severity(90) == "CRITICAL"
    assert classify_severity(85) == "HIGH"
    assert classify_severity(70) == "HIGH"
    assert classify_severity(65) == "MEDIUM"
    assert classify_severity(40) == "MEDIUM"
    assert classify_severity(35) == "LOW"
    assert classify_severity(0) == "LOW"


def test_brute_force_detection():
    """Test RULE-AUTH-001 triggers when failed logins exceed threshold."""
    rule = BruteForceRule()
    thresholds = {"brute_force_failed_attempts": 5}

    # Generate 6 failed logins from same IP
    records = [
        {
            "timestamp": f"2026-10-31 10:0{i}:00",
            "source_ip": "198.51.100.10",
            "destination_ip": "10.0.0.1",
            "username": "admin",
            "event_type": "login",
            "status": "FAILED",
            "port": 443,
            "protocol": "TCP",
            "message": "Auth failure",
        }
        for i in range(6)
    ]
    df = pd.DataFrame(records)
    results = rule.evaluate(df, thresholds)

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "RULE-AUTH-001"
    assert det.source_ip == "198.51.100.10"
    assert det.category == "Brute Force"
    assert det.risk_score >= 70


def test_port_scanning_detection():
    """Test RULE-NET-002 triggers when unique probed destination ports exceed threshold."""
    rule = PortScanningRule()
    thresholds = {"port_scan_port_count": 5}

    ports = [21, 22, 23, 80, 443, 8080]
    records = [
        {
            "timestamp": "2026-10-31 10:15:00",
            "source_ip": "203.0.113.55",
            "destination_ip": "10.0.0.1",
            "username": "unknown",
            "event_type": "network_probe",
            "status": "SYN_SENT",
            "port": p,
            "protocol": "TCP",
            "message": f"Probe on port {p}",
        }
        for p in ports
    ]
    df = pd.DataFrame(records)
    results = rule.evaluate(df, thresholds)

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "RULE-NET-002"
    assert det.source_ip == "203.0.113.55"
    assert det.category == "Port Scanning"


def test_sql_injection_detection():
    """Test RULE-WEB-003 detects SQLi attack patterns."""
    rule = SqlInjectionRule()
    records = [
        {
            "timestamp": "2026-10-31 10:20:00",
            "source_ip": "198.51.100.66",
            "destination_ip": "10.0.0.1",
            "username": "guest",
            "event_type": "http_request",
            "status": "ERROR",
            "port": 443,
            "protocol": "TCP",
            "message": "GET /items?id=1' UNION SELECT username, password FROM users--",
        }
    ]
    df = pd.DataFrame(records)
    results = rule.evaluate(df, {})

    assert len(results) == 1
    assert results[0].rule_id == "RULE-WEB-003"
    assert results[0].category == "SQL Injection"
    assert results[0].severity in ["HIGH", "CRITICAL"]


def test_xss_detection():
    """Test RULE-WEB-004 detects cross-site scripting script tags and handlers."""
    rule = XssRule()
    records = [
        {
            "timestamp": "2026-10-31 10:25:00",
            "source_ip": "198.51.100.77",
            "destination_ip": "10.0.0.1",
            "username": "guest",
            "event_type": "http_request",
            "status": "WARNING",
            "port": 443,
            "protocol": "TCP",
            "message": "POST /feedback text=<script>alert('XSS')</script>",
        }
    ]
    df = pd.DataFrame(records)
    results = rule.evaluate(df, {})

    assert len(results) == 1
    assert results[0].rule_id == "RULE-WEB-004"
    assert results[0].category == "Cross-Site Scripting (XSS)"


def test_suspicious_ip_detection():
    """Test RULE-IP-005 detects repetitive anomaly status behavior."""
    rule = SuspiciousIpRule()
    thresholds = {"suspicious_ip_threshold": 8}
    records = [
        {
            "timestamp": f"2026-10-31 10:30:0{i}",
            "source_ip": "198.51.100.88",
            "destination_ip": "10.0.0.1",
            "username": "guest",
            "event_type": "api_request",
            "status": "DENIED",
            "port": 443,
            "protocol": "TCP",
            "message": "Access denied",
        }
        for i in range(9)
    ]
    df = pd.DataFrame(records)
    results = rule.evaluate(df, thresholds)

    assert len(results) == 1
    assert results[0].rule_id == "RULE-IP-005"
    assert results[0].category == "Suspicious IP Activity"


def test_unauthorized_access_detection():
    """Test RULE-ACCESS-006 detects attempts to read sensitive files."""
    rule = UnauthorizedAccessRule()
    records = [
        {
            "timestamp": "2026-10-31 10:35:00",
            "source_ip": "203.0.113.99",
            "destination_ip": "10.0.0.1",
            "username": "guest",
            "event_type": "file_access",
            "status": "FORBIDDEN",
            "port": 443,
            "protocol": "TCP",
            "message": "GET /etc/passwd HTTP/1.1 403 Forbidden",
        }
    ]
    df = pd.DataFrame(records)
    results = rule.evaluate(df, {})

    assert len(results) == 1
    assert results[0].rule_id == "RULE-ACCESS-006"
    assert results[0].category == "Unauthorized Access"


def test_unusual_network_activity_detection():
    """Test RULE-NET-007 detects backdoor listener connection."""
    rule = UnusualNetworkActivityRule()
    records = [
        {
            "timestamp": "2026-10-31 10:40:00",
            "source_ip": "198.51.100.222",
            "destination_ip": "10.0.0.5",
            "username": "unknown",
            "event_type": "suspicious_traffic",
            "status": "DENIED",
            "port": 4444,  # Metasploit default
            "protocol": "TCP",
            "message": "Inbound connection on Metasploit port",
        }
    ]
    df = pd.DataFrame(records)
    results = rule.evaluate(df, {})

    assert len(results) == 1
    assert results[0].rule_id == "RULE-NET-007"
    assert results[0].category == "Unusual Network Activity"
