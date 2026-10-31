# ThreatGuard – Project Overview & Academic Problem Statement

## 1. Project Background
In modern computer networks and digital environments, organizations are constantly targeted by an array of cyber threats ranging from credential brute-forcing to sophisticated web application injections and automated reconnaissance scans. For small teams, educational laboratories, and defensive analysts, understanding how security telemetry is ingested, correlated, and triaged is fundamental to developing effective cyber defense postures.

**ThreatGuard** is a modular, lightweight defensive cybersecurity monitoring and Security Information and Event Management (SIEM) simulation platform developed using Python and Streamlit. It was designed specifically for third-year Computer Science Engineering (CSE) academic demonstration, bridging the gap between theoretical cybersecurity principles and practical security operations center (SOC) incident response workflows.

---

## 2. Problem Statement
Traditional enterprise SIEM solutions (e.g., Splunk, IBM QRadar, Microsoft Sentinel) are proprietary, resource-intensive, complex to configure, and require heavyweight infrastructure that is inaccessible for academic laboratory study. Conversely, simple script-based demos lack:
1. An integrated user interface for real-time visualization.
2. Role-Based Access Control (RBAC) and credential security.
3. Persistent incident lifecycle management and response playbooks.
4. Exportable compliance reporting.

**ThreatGuard addresses these challenges** by providing an end-to-end web application that ingests raw telemetry, applies rule-based heuristic threat detection, evaluates heuristic risk scores, and guides human operators through actionable defensive remediation playbooks.

---

## 3. Academic Objectives
- Demonstrate practical log normalization and data validation techniques on CSV and JSON security feeds.
- Implement seven classic cyberattack detection algorithms mapped to the MITRE ATT&CK framework.
- Formulate an educational risk-scoring model that bounds heuristic scores between 0 and 100.
- Model the complete lifecycle of a security incident from detection and assignment to containment and closure.
- Simulate SOC metrics including Mean Time to Resolution (MTTR), threat distribution by severity, and top attacking IP addresses.
- Provide compliance-ready PDF and CSV export capabilities.

---

## 4. Key Limitations & Academic Scope
- **Academic Defensive Simulation**: ThreatGuard is designed for educational laboratory demonstration and is not intended to replace commercial enterprise SIEM platforms.
- **Rule-Based Heuristics**: Detection signatures rely on pattern matching and frequency thresholds. Detections highlight suspicious indicators requiring human verification and do not constitute absolute proof of compromise.
- **Advisory Response**: ThreatGuard does not autonomously alter host firewalls or block IP addresses. All mitigation steps are presented as recommendations for human analysts.
- **Storage Persistence**: On Streamlit Community Cloud, SQLite databases are ephemeral per container lifecycle; external hosted PostgreSQL is recommended for permanent cloud storage.
