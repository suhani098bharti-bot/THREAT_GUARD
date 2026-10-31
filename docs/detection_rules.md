# ThreatGuard – Predefined SIEM Detection Ruleset

ThreatGuard implements seven modular, rule-based cybersecurity threat detection signatures. Each rule inspects normalized security event logs and maps directly to the **MITRE ATT&CK Framework**.

---

## 1. Rule Catalog

### RULE-AUTH-001: Brute Force Authentication Attack
- **Threat Category**: Brute Force
- **MITRE ATT&CK**: T1110 (Credential Access: Brute Force)
- **Trigger Condition**: $\ge 5$ consecutive failed authentication attempts from the same source IP address within the log monitoring window.
- **Severity**: HIGH (CRITICAL if failed attempts $\ge 15$)
- **Base Risk Score**: 70 (scaled by attempt frequency)
- **Recommended Action**: Review identity records for targeted accounts, enforce Multi-Factor Authentication (MFA), and apply rate-limiting / temporary IP tarpitting at the gateway.

---

### RULE-NET-002: Port Scanning / Service Discovery
- **Threat Category**: Port Scanning
- **MITRE ATT&CK**: T1046 (Discovery: Network Service Discovery)
- **Trigger Condition**: Single source IP address probing $\ge 5$ distinct non-zero destination ports in sequence.
- **Severity**: MEDIUM or HIGH
- **Base Risk Score**: 60
- **Recommended Action**: Examine perimeter firewall access logs for systematic sweep patterns. Verify exposed services are required and patched, and configure dynamic drop rules for rapid scanning.

---

### RULE-WEB-003: SQL Injection (SQLi) Attempt
- **Threat Category**: SQL Injection
- **MITRE ATT&CK**: T1190 (Initial Access: Exploit Public-Facing Application)
- **Trigger Condition**: Inbound payload contains SQL injection syntax signatures including boolean tautologies (`' OR 1=1`), `UNION SELECT`, `DROP TABLE`, `INFORMATION_SCHEMA`, comment characters (`--`, `/*`), or `SLEEP()`.
- **Severity**: HIGH or CRITICAL
- **Base Risk Score**: 85
- **Recommended Action**: Verify backend code uses parameterized prepared statements (e.g. ORM / PDO). Enable or tune Web Application Firewall (WAF) SQLi rulesets and audit database query logs.

---

### RULE-WEB-004: Cross-Site Scripting (XSS) Attack
- **Threat Category**: Cross-Site Scripting (XSS)
- **MITRE ATT&CK**: T1189 (Initial Access: Drive-by Compromise / Web Injection)
- **Trigger Condition**: Request payload or forum input contains `<script>`, `javascript:`, DOM event handlers (`onerror=`, `onload=`), `document.cookie`, or `<iframe>` tags.
- **Severity**: MEDIUM or HIGH
- **Base Risk Score**: 75
- **Recommended Action**: Enforce contextual HTML entity output encoding. Deploy Content Security Policy (CSP) headers restricting inline script execution, and mark session cookies as `HttpOnly` and `SameSite=Strict`.

---

### RULE-IP-005: Suspicious IP Activity
- **Threat Category**: Suspicious IP Activity
- **MITRE ATT&CK**: T1071 (Command and Control / Reconnaissance: Repetitive Probing)
- **Trigger Condition**: Single source IP triggers $\ge 8$ security error or rejected event statuses (`DENIED`, `BLOCKED`, `DROP`, `REJECT`, `403`, `500`).
- **Severity**: MEDIUM or HIGH
- **Base Risk Score**: 65
- **Recommended Action**: Query external IP reputation databases (e.g., AbuseIPDB, VirusTotal). Review reverse proxy telemetry to evaluate temporary blocking or rate-throttling options.

---

### RULE-ACCESS-006: Unauthorized Access Attempt
- **Threat Category**: Unauthorized Access
- **MITRE ATT&CK**: T1078 (Defense Evasion / Initial Access: Valid Accounts / Privilege Violation)
- **Trigger Condition**: Request attempts to access sensitive system paths (`/etc/passwd`, `.env`, `/admin/config.php`, `id_rsa`, `../` directory traversal) paired with rejection status (`UNAUTHORIZED`, `FORBIDDEN`, `401`, `403`).
- **Severity**: HIGH or CRITICAL
- **Base Risk Score**: 80
- **Recommended Action**: Audit authorization checks across protected routes. Ensure directory traversal protections are active and rotate any potentially compromised credentials.

---

### RULE-NET-007: Unusual Network Activity
- **Threat Category**: Unusual Network Activity
- **MITRE ATT&CK**: T1571 (Command and Control: Non-Standard Port / Data Channel Anomaly)
- **Trigger Condition**: Traffic targeting known backdoor/trojan listener ports (e.g. 4444 Metasploit, 31337 Back Orifice, 6667 IRC) or extreme traffic volume spikes ($\ge 25$ events).
- **Severity**: HIGH or CRITICAL
- **Base Risk Score**: 80
- **Recommended Action**: Inspect endpoint process listening on the anomalous port (e.g., `netstat`, `ss`, `lsof`). Enforce default-deny egress firewall filtering and isolate the host for memory forensics if unverified.

---

## 2. Risk Scoring Formula
Risk scores are calculated dynamically:
$$\text{Raw Score} = (\text{Base Weight} \times \text{Indicator Strength}) + (\min(\text{Frequency}, 10) \times 3)$$
$$\text{Final Risk Score} = \text{clamp}(\text{Raw Score}, 0, 100)$$

| Risk Score Range | Severity Tier | Action Required |
|:---:|:---:|:---|
| **90 – 100** | **CRITICAL** | Immediate SOC operator containment required. |
| **70 – 89** | **HIGH** | Corroborating attack signature requiring prompt triage. |
| **40 – 69** | **MEDIUM** | Suspicious telemetry anomaly requiring investigation. |
| **0 – 39** | **LOW** | Minor telemetry deviation or isolated transaction failure. |
