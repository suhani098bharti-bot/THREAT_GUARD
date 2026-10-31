"""Playbook and response recommendation engine for security incidents."""

from typing import Any, Dict, List


PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "Brute Force": {
        "title": "Authentication Triage & Account Hardening Playbook",
        "immediate_actions": [
            "Verify whether any attempted logins from the source IP resulted in a successful authentication.",
            "Temporarily apply rate-limiting or IP tarpitting at the web/API gateway.",
            "If targeted accounts are known, verify their status and require password reset.",
        ],
        "long_term_hardening": [
            "Enforce mandatory Multi-Factor Authentication (MFA) across all identity providers.",
            "Implement exponential backoff delays on repeated authentication failures.",
            "Configure adaptive risk-based authentication to challenge unfamiliar geolocations or IP ranges.",
        ],
        "investigation_questions": [
            "Are the targeted usernames active employees or legacy accounts?",
            "Did the IP attempt logins across multiple usernames (credential stuffing) or single username (targeted attack)?",
        ],
    },
    "Port Scanning": {
        "title": "Perimeter Reconnaissance & Service Hardening Playbook",
        "immediate_actions": [
            "Verify whether scanned destination ports correspond to exposed services on perimeter firewalls.",
            "Confirm that closed or administrative ports are not responding with detailed service banners.",
            "Check firewall logs to determine whether the scan was followed by targeted exploit traffic.",
        ],
        "long_term_hardening": [
            "Close all unused perimeter ports and restrict management interfaces (SSH, RDP) behind a VPN.",
            "Enable port-knocking or dynamic firewall drop rules for rapid scanning behaviors.",
            "Audit public-facing IP ranges periodically using authorized internal vulnerability scanners.",
        ],
        "investigation_questions": [
            "Is the scanning source a benign internet indexing engine (e.g., Shodan, Censys) or hostile infrastructure?",
            "Did any destination host accept TCP handshakes on unexpected ports?",
        ],
    },
    "SQL Injection": {
        "title": "Web Application & Database Injection Defense Playbook",
        "immediate_actions": [
            "Inspect the targeted web application endpoint and URI query parameters.",
            "Examine backend database query logs to verify whether the injected payload executed or returned errors.",
            "Enable or tune Web Application Firewall (WAF) SQLi inspection rules on the affected route.",
        ],
        "long_term_hardening": [
            "Refactor data access code to mandate parameterized queries (PreparedStatements) or ORM abstraction.",
            "Enforce database principle of least privilege: ensure application DB user cannot execute DDL or DROP commands.",
            "Disable verbose database error disclosures in HTTP response bodies.",
        ],
        "investigation_questions": [
            "Did the HTTP response code indicate a 500 database error or a successful 200 with data extraction?",
            "Are other endpoints in the same application sharing the vulnerable database access method?",
        ],
    },
    "Cross-Site Scripting (XSS)": {
        "title": "Client-Side Injection & Content Security Playbook",
        "immediate_actions": [
            "Identify the specific input parameter or form field accepting the script payload.",
            "Test whether the payload is reflected back into the DOM or stored persistently in application storage.",
            "Clear any active session tokens or cached client state if stored XSS is suspected.",
        ],
        "long_term_hardening": [
            "Implement contextual output encoding (HTML, JavaScript, CSS) using trusted security libraries.",
            "Deploy Content Security Policy (CSP) HTTP headers with strict script-src and nonce constraints.",
            "Mark all session cookies with HttpOnly, Secure, and SameSite=Strict flags.",
        ],
        "investigation_questions": [
            "Was the payload reflected or stored in application database records?",
            "Could malicious scripts execute within authenticated user contexts?",
        ],
    },
    "Unauthorized Access": {
        "title": "Privilege & Access Control Remediation Playbook",
        "immediate_actions": [
            "Audit access logs for the requested resource to verify if unauthorized access was blocked or granted.",
            "Revoke active session tokens and API keys associated with the offending user or IP address.",
            "Verify file permissions on sensitive assets (e.g. /etc/passwd, .env, cloud service keys).",
        ],
        "long_term_hardening": [
            "Audit Role-Based Access Control (RBAC) middleware across all sensitive endpoints.",
            "Implement zero-trust network segmentation restricting administrative paths to dedicated management subnets.",
            "Ensure directory traversal protections prevent '../' path normalization attacks.",
        ],
        "investigation_questions": [
            "Did the user authenticate before attempting privileged resource access?",
            "Was sensitive data transferred in HTTP response payloads?",
        ],
    },
    "Suspicious IP Activity": {
        "title": "Hostile IP Triage & Perimeter Mitigation Playbook",
        "immediate_actions": [
            "Query external IP reputation feeds (e.g. AbuseIPDB, VirusTotal, AlienVault OTX) for history.",
            "Temporarily throttle or challenge requests from this IP at edge CDN / reverse proxy.",
            "Search historical logs for any prior transactions involving this IP address.",
        ],
        "long_term_hardening": [
            "Subscribe to automated threat intelligence feeds for automated perimeter blocklist updates.",
            "Implement geo-blocking or ASN filtering if organizational traffic has no legitimate presence in the origin region.",
        ],
        "investigation_questions": [
            "Does the IP belong to a known hosting provider, Tor exit node, or residential proxy network?",
            "Are multiple source IPs coordinating identical attack signatures?",
        ],
    },
    "Unusual Network Activity": {
        "title": "Network Anomaly & Backdoor Isolation Playbook",
        "immediate_actions": [
            "Identify the internal host and process listening on the anomalous port.",
            "Perform network socket inspection (e.g., netstat / ss / lsof) to identify process ID and executable path.",
            "If malicious communication is verified, isolate the affected host from the internal VLAN.",
        ],
        "long_term_hardening": [
            "Enforce default-deny egress firewall filtering permitting only approved outbound ports (80, 443, 53).",
            "Deploy Endpoint Detection and Response (EDR) agents to detect unauthorized reverse shells.",
        ],
        "investigation_questions": [
            "Is the destination port known for Metasploit, C2 beacons, or cryptocurrency mining?",
            "What data volume was exchanged during the connection session?",
        ],
    },
}


def get_recommendations_for_incident(category: str) -> Dict[str, Any]:
    """Retrieve actionable response recommendations and playbooks for a threat category."""
    default_playbook = {
        "title": "General Security Incident Triage Playbook",
        "immediate_actions": [
            "Verify telemetry integrity and isolate affected endpoints if compromise is suspected.",
            "Correlate event logs with surrounding firewall, identity, and application server telemetry.",
            "Preserve relevant forensic artifacts (logs, memory captures, network pcaps) before rebooting.",
        ],
        "long_term_hardening": [
            "Review system architecture against cybersecurity defense-in-depth best practices.",
            "Update detection rule thresholds and alert thresholds to minimize recurring blind spots.",
        ],
        "investigation_questions": [
            "What was the attack vector?",
            "Has containment been achieved without business disruption?",
        ],
    }

    playbook = PLAYBOOKS.get(category, default_playbook)
    return {
        "category": category,
        "playbook_title": playbook["title"],
        "immediate_actions": playbook["immediate_actions"],
        "long_term_hardening": playbook["long_term_hardening"],
        "investigation_questions": playbook["investigation_questions"],
        "disclaimer": (
            "NOTICE: ThreatGuard provides defensive advisory recommendations for human SOC analysts. "
            "No firewall rules or blocking actions are executed autonomously."
        ),
    }
